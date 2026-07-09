use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    config::{AppConfig, UpstreamMode, UpstreamServer},
    database::{Database, QueryLogEntry},
};

const DNS_HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const TRAFFIC_BUCKET_WINDOW_MINUTES: u64 = 90 * 24 * 60;
const UDP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(200);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_FAILURE_BACKOFF_SECONDS: u64 = 30;
const DOH_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FASTEST_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_millis(180);
const FASTEST_ADDR_MAX_IPS_PER_RESPONSE: usize = 8;
const FASTEST_ADDR_MAX_PROBES: usize = 32;
const DNS_WORK_QUEUE_CAPACITY: usize = 8192;
const QUERY_LOG_QUEUE_CAPACITY: usize = 16384;
const QUERY_LOG_BATCH_SIZE: usize = 128;
const QUERY_LOG_BATCH_WAIT_TIMEOUT: Duration = Duration::from_millis(10);
const DNS_MIN_WORKERS: usize = 4;
const DNS_MAX_WORKERS: usize = 32;
const DNS_CACHE_ENTRY_OVERHEAD_BYTES: usize = 96;
const DNS_CACHE_SHARDS: usize = 64;
const PENDING_QUERY_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const PENDING_QUERY_SHARDS: usize = 64;
const DNSBLACKHOLE_USER_AGENT: &str = "DnsBlackhole/0.1";

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleSummary {
    pub block_rules: usize,
    pub allow_rules: usize,
    pub ignored_rules: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStats {
    pub started_at: Option<u64>,
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub last_query: Option<String>,
    pub last_blocked: Option<String>,
    pub last_error: Option<String>,
    pub query_domains: HashMap<String, u64>,
    pub blocked_domains: HashMap<String, u64>,
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficBucket {
    pub minute: u64,
    pub queries: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamRequestStat {
    pub upstream: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamLatencyStat {
    pub upstream: String,
    pub avg_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub running: bool,
    pub listen_addr: String,
    pub upstream_dns: String,
    pub summary: RuleSummary,
    pub stats: DnsStats,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct CompiledRules {
    blocks: RuleSet,
    allows: RuleSet,
    summary: RuleSummary,
}

#[derive(Clone)]
struct Rule {
    domain: String,
    include_subdomains: bool,
}

#[derive(Clone, Default)]
struct RuleSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

#[derive(Clone)]
struct RuntimeUpstream {
    server: UpstreamServer,
    label: String,
    doh_client: Option<reqwest::blocking::Client>,
    unhealthy_until: Arc<AtomicU64>,
}

struct DnsWorkItem {
    query: Vec<u8>,
    client_addr: SocketAddr,
}

struct DnsWorkerContext {
    socket: Arc<UdpSocket>,
    upstream_servers: Arc<Vec<RuntimeUpstream>>,
    upstream_mode: UpstreamMode,
    next_upstream: AtomicUsize,
    rules: Arc<CompiledRules>,
    stats: Arc<Mutex<DnsStats>>,
    dns_cache: Option<Arc<DnsCacheStore>>,
    dns_cache_config: Option<DnsCacheConfig>,
    pending_queries: Arc<PendingQueries>,
    query_log_sender: Option<mpsc::SyncSender<QueryLogMessage>>,
    anonymize_client_ip: bool,
    detailed_runtime_stats: bool,
}

struct QueryLogMessage {
    entry: QueryLogEntry,
    anonymize_client_ip: bool,
}

#[derive(Clone)]
struct UpstreamForwardResponse {
    response: Vec<u8>,
    upstream: String,
    duration_ms: u64,
}

type PendingQuery = Arc<PendingQueryState>;

struct PendingQueryState {
    result: Mutex<Option<Result<UpstreamForwardResponse, String>>>,
    ready: Condvar,
}

enum PendingQueryRole {
    Leader(PendingQuery),
    Follower(PendingQuery),
}

struct PendingQueries {
    shards: Vec<Mutex<HashMap<QueryCacheKey, PendingQuery>>>,
}

struct IpLatencyProbe {
    response_index: usize,
    duration: Duration,
}

#[derive(Debug, Clone)]
struct DnsCacheConfig {
    enabled: bool,
    max_size_bytes: usize,
    min_ttl: u32,
    max_ttl: u32,
    optimistic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryCacheKey {
    domain: String,
    qtype: u16,
    qclass: u16,
}

struct CachedDnsResponse {
    response: Vec<u8>,
    expires_at: u64,
    size: usize,
    last_used: u64,
    refreshing: bool,
}

struct CacheHit {
    response: Vec<u8>,
    refresh: bool,
}

struct RawCacheHit {
    response: Vec<u8>,
    ttl: u32,
    refresh: bool,
}

struct DnsCache {
    config: DnsCacheConfig,
    entries: HashMap<QueryCacheKey, CachedDnsResponse>,
    total_size: usize,
    access_counter: u64,
}

struct DnsCacheStore {
    shards: Vec<Mutex<DnsCache>>,
}

pub struct DnsServer {
    listen_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    cache: Option<Arc<DnsCacheStore>>,
}

impl DnsServer {
    pub fn start(
        config: AppConfig,
        rules_text: String,
        stats: Arc<Mutex<DnsStats>>,
        database: Arc<Database>,
    ) -> Result<Self, String> {
        config.validate()?;

        let listen_addr = config.listen_socket_addr()?;
        let upstream_servers = Arc::new(build_runtime_upstreams(config.upstream_servers()?)?);
        let upstream_mode = config.upstream_mode.clone();
        let query_log_enabled = config.query_log_enabled;
        let anonymize_client_ip = config.anonymize_client_ip;
        let dns_cache_config = DnsCacheConfig::from_config(&config);
        let dns_cache =
            DnsCacheStore::from_config(dns_cache_config.clone(), DNS_CACHE_SHARDS).map(Arc::new);
        let dns_cache_config = dns_cache.as_ref().map(|_| dns_cache_config);
        let rules = Arc::new(compile_rules(&rules_text));
        let socket =
            UdpSocket::bind(listen_addr).map_err(|e| format!("监听 {listen_addr} 失败：{e}"))?;
        configure_udp_listener_socket(&socket)?;
        socket
            .set_read_timeout(Some(UDP_READ_TIMEOUT))
            .map_err(|e| format!("设置 DNS 读取超时失败：{e}"))?;
        let socket = Arc::new(socket);

        reset_stats(&stats);
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        let mut query_log_thread = None;
        let query_log_sender = if query_log_enabled {
            let (sender, receiver) = mpsc::sync_channel(QUERY_LOG_QUEUE_CAPACITY);
            query_log_thread = Some(spawn_query_log_writer(Arc::clone(&database), receiver));
            Some(sender)
        } else {
            None
        };

        let worker_context = Arc::new(DnsWorkerContext {
            socket: Arc::clone(&socket),
            upstream_servers,
            upstream_mode,
            next_upstream: AtomicUsize::new(0),
            rules,
            stats: Arc::clone(&stats),
            dns_cache: dns_cache.clone(),
            dns_cache_config,
            pending_queries: Arc::new(PendingQueries::new(PENDING_QUERY_SHARDS)),
            query_log_sender,
            anonymize_client_ip,
            detailed_runtime_stats: !query_log_enabled,
        });

        let worker_count = dns_worker_count();
        let worker_queue_capacity = dns_worker_queue_capacity(worker_count);
        let mut work_senders = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (work_sender, work_receiver) = mpsc::sync_channel(worker_queue_capacity);
            work_senders.push(work_sender);
            let worker_context = Arc::clone(&worker_context);
            let worker_stop = Arc::clone(&stop);
            threads.push(thread::spawn(move || {
                dns_worker_loop(work_receiver, worker_context, worker_stop);
            }));
        }

        let listener_socket = Arc::clone(&socket);
        let listener_stats = Arc::clone(&stats);
        let listener_stop = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            serve_udp(listener_socket, work_senders, listener_stats, listener_stop);
        }));
        if let Some(thread) = query_log_thread {
            threads.push(thread);
        }

        Ok(Self {
            listen_addr,
            stop,
            threads,
            cache: dns_cache,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn clear_cache(&self) -> Result<(), String> {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
        Ok(())
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
fn configure_udp_listener_socket(socket: &UdpSocket) -> Result<(), String> {
    use std::{ffi::c_void, io, os::windows::io::AsRawSocket, ptr};

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            _: usize,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: *mut u32,
            _: *mut c_void,
            _: *mut c_void,
        ) -> i32;
    }

    // Windows 默认会把 UDP ICMP reset 映射成下一次 recv_from 的 WSAECONNRESET。
    // DNS 监听端不应因为客户端端口关闭而中断接收循环，所以关闭该通知。
    let mut behavior = 0_u32;
    let mut bytes_returned = 0_u32;
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&mut behavior as *mut u32).cast::<c_void>(),
            std::mem::size_of_val(&behavior) as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "关闭 Windows UDP reset 通知失败：{}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(not(windows))]
fn configure_udp_listener_socket(_socket: &UdpSocket) -> Result<(), String> {
    Ok(())
}

fn build_runtime_upstreams(
    upstream_servers: Vec<UpstreamServer>,
) -> Result<Vec<RuntimeUpstream>, String> {
    upstream_servers
        .into_iter()
        .map(RuntimeUpstream::new)
        .collect()
}

impl RuntimeUpstream {
    fn new(server: UpstreamServer) -> Result<Self, String> {
        let label = format_upstream_server(&server);
        let doh_client = match &server {
            UpstreamServer::Udp(_) => None,
            UpstreamServer::Doh(_) => Some(build_doh_client()?),
        };

        Ok(Self {
            server,
            label,
            doh_client,
            unhealthy_until: Arc::new(AtomicU64::new(0)),
        })
    }
}

fn build_doh_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .connect_timeout(UPSTREAM_TIMEOUT)
        .pool_idle_timeout(Some(DOH_CLIENT_POOL_IDLE_TIMEOUT))
        .pool_max_idle_per_host(2)
        .user_agent(DNSBLACKHOLE_USER_AGENT)
        .build()
        .map_err(|e| format!("创建 DoH 客户端失败：{e}"))
}

fn dns_worker_count() -> usize {
    thread::available_parallelism()
        .map(|count| count.get().saturating_mul(2))
        .unwrap_or(DNS_MIN_WORKERS)
        .clamp(DNS_MIN_WORKERS, DNS_MAX_WORKERS)
}

fn dns_worker_queue_capacity(worker_count: usize) -> usize {
    DNS_WORK_QUEUE_CAPACITY
        .checked_div(worker_count.max(1))
        .unwrap_or(DNS_WORK_QUEUE_CAPACITY)
        .max(1)
}

fn spawn_query_log_writer(
    database: Arc<Database>,
    receiver: mpsc::Receiver<QueryLogMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut batch = Vec::with_capacity(QUERY_LOG_BATCH_SIZE);

        while let Ok(message) = receiver.recv() {
            batch.push((message.entry, message.anonymize_client_ip));

            while batch.len() < QUERY_LOG_BATCH_SIZE {
                match receiver.recv_timeout(QUERY_LOG_BATCH_WAIT_TIMEOUT) {
                    Ok(message) => batch.push((message.entry, message.anonymize_client_ip)),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }

            if let Err(error) = database.insert_query_logs(&batch) {
                eprintln!("{error}");
            }
            batch.clear();
        }
    })
}

impl DnsCacheConfig {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            enabled: config.dns_cache_enabled,
            max_size_bytes: config.dns_cache_size,
            min_ttl: config.dns_cache_min_ttl,
            max_ttl: config.dns_cache_max_ttl,
            optimistic: config.dns_cache_optimistic,
        }
    }
}

impl QueryCacheKey {
    fn from_question(question: &Question) -> Self {
        Self {
            domain: question.domain.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        }
    }
}

impl PendingQueries {
    fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Mutex::new(HashMap::new()));
        }

        Self { shards }
    }

    fn begin(&self, cache_key: &QueryCacheKey) -> PendingQueryRole {
        let shard_index = self.shard_index(cache_key);
        if let Some(shard) = self.shards.get(shard_index)
            && let Ok(mut pending_queries) = shard.lock()
        {
            if let Some(pending_query) = pending_queries.get(cache_key) {
                return PendingQueryRole::Follower(Arc::clone(pending_query));
            }

            let pending_query = new_pending_query();
            pending_queries.insert(cache_key.clone(), Arc::clone(&pending_query));
            return PendingQueryRole::Leader(pending_query);
        }

        PendingQueryRole::Leader(new_pending_query())
    }

    fn finish(&self, cache_key: &QueryCacheKey, pending_query: &PendingQuery) {
        let shard_index = self.shard_index(cache_key);
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let Ok(mut pending_queries) = shard.lock() else {
            return;
        };

        let should_remove = pending_queries
            .get(cache_key)
            .is_some_and(|current| Arc::ptr_eq(current, pending_query));
        if should_remove {
            pending_queries.remove(cache_key);
        }
    }

    fn shard_index(&self, cache_key: &QueryCacheKey) -> usize {
        query_cache_key_shard_index(cache_key, self.shards.len())
    }
}

fn new_pending_query() -> PendingQuery {
    Arc::new(PendingQueryState {
        result: Mutex::new(None),
        ready: Condvar::new(),
    })
}

impl DnsCacheStore {
    fn from_config(config: DnsCacheConfig, shard_count: usize) -> Option<Self> {
        if !config.enabled || config.max_size_bytes == 0 {
            return None;
        }

        let shard_count = shard_count
            .max(1)
            .min((config.max_size_bytes / 4096).max(1));
        let shard_size = (config.max_size_bytes / shard_count).max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            let mut shard_config = config.clone();
            shard_config.max_size_bytes = shard_size;
            if let Some(cache) = DnsCache::from_config(shard_config) {
                shards.push(Mutex::new(cache));
            }
        }

        if shards.is_empty() {
            None
        } else {
            Some(Self { shards })
        }
    }

    fn lookup(&self, cache_key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        let shard = self.shard(cache_key)?;
        shard.lock().ok()?.lookup(cache_key, now)
    }

    fn insert_with_ttl(&self, cache_key: QueryCacheKey, response: Vec<u8>, now: u64, ttl: u32) {
        let Some(shard) = self.shard(&cache_key) else {
            return;
        };
        if let Ok(mut cache) = shard.lock() {
            cache.insert_with_ttl(cache_key, response, now, ttl);
        }
    }

    fn finish_refresh(&self, cache_key: &QueryCacheKey) {
        let Some(shard) = self.shard(cache_key) else {
            return;
        };
        if let Ok(mut cache) = shard.lock() {
            cache.finish_refresh(cache_key);
        }
    }

    fn clear(&self) {
        for shard in &self.shards {
            if let Ok(mut cache) = shard.lock() {
                cache.clear();
            }
        }
    }

    fn shard(&self, cache_key: &QueryCacheKey) -> Option<&Mutex<DnsCache>> {
        self.shards
            .get(query_cache_key_shard_index(cache_key, self.shards.len()))
    }
}

fn query_cache_key_shard_index(cache_key: &QueryCacheKey, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    (hasher.finish() % shard_count.max(1) as u64) as usize
}

impl DnsCache {
    fn from_config(config: DnsCacheConfig) -> Option<Self> {
        if !config.enabled || config.max_size_bytes == 0 {
            return None;
        }

        Some(Self {
            config,
            entries: HashMap::new(),
            total_size: 0,
            access_counter: 0,
        })
    }

    fn lookup(&mut self, key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        self.access_counter = self.access_counter.wrapping_add(1);
        let access = self.access_counter;
        let entry = self.entries.get_mut(key)?;

        let fresh = entry.expires_at > now;
        if !fresh && !self.config.optimistic {
            let size = entry.size;
            self.total_size = self.total_size.saturating_sub(size);
            self.entries.remove(key);
            return None;
        }

        entry.last_used = access;
        let refresh = !fresh && !entry.refreshing;
        if refresh {
            entry.refreshing = true;
        }
        let ttl = if fresh {
            u32::try_from(entry.expires_at.saturating_sub(now))
                .unwrap_or(u32::MAX)
                .max(1)
        } else {
            1
        };
        Some(RawCacheHit {
            response: entry.response.clone(),
            ttl,
            refresh,
        })
    }

    #[cfg(test)]
    fn insert(&mut self, key: QueryCacheKey, response: Vec<u8>, now: u64) {
        let Some(ttl) = cache_ttl_seconds(&response, &self.config) else {
            return;
        };
        if ttl == 0 {
            return;
        }

        self.insert_with_ttl(key, response, now, ttl);
    }

    fn insert_with_ttl(&mut self, key: QueryCacheKey, response: Vec<u8>, now: u64, ttl: u32) {
        if ttl == 0 {
            return;
        }

        self.access_counter = self.access_counter.wrapping_add(1);
        let size = response
            .len()
            .saturating_add(key.domain.len())
            .saturating_add(DNS_CACHE_ENTRY_OVERHEAD_BYTES);
        if size > self.config.max_size_bytes {
            return;
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.total_size = self.total_size.saturating_sub(previous.size);
        }

        self.total_size = self.total_size.saturating_add(size);
        self.entries.insert(
            key,
            CachedDnsResponse {
                response,
                expires_at: now.saturating_add(u64::from(ttl)),
                size,
                last_used: self.access_counter,
                refreshing: false,
            },
        );
        self.evict_over_limit(now);
    }

    fn finish_refresh(&mut self, key: &QueryCacheKey) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.refreshing = false;
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.total_size = 0;
    }

    fn evict_over_limit(&mut self, now: u64) {
        if self.total_size > self.config.max_size_bytes {
            self.evict_expired(now);
        }

        while self.total_size > self.config.max_size_bytes {
            let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                self.total_size = 0;
                return;
            };

            if let Some(entry) = self.entries.remove(&key) {
                self.total_size = self.total_size.saturating_sub(entry.size);
            }
        }
    }

    fn evict_expired(&mut self, now: u64) {
        let mut removed_size = 0_usize;
        self.entries.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed_size = removed_size.saturating_add(entry.size);
            }
            keep
        });
        self.total_size = self.total_size.saturating_sub(removed_size);
    }
}

pub fn summarize_rules(raw: &str) -> RuleSummary {
    compile_rules(raw).summary
}

pub fn compile_rules(raw: &str) -> CompiledRules {
    let mut blocks = RuleSet::default();
    let mut allows = RuleSet::default();
    let mut summary = RuleSummary::default();

    for line in raw.lines() {
        match parse_rule(line) {
            ParsedRule::Block(rule) => {
                summary.block_rules += 1;
                blocks.insert(rule);
            }
            ParsedRule::Allow(rule) => {
                summary.allow_rules += 1;
                allows.insert(rule);
            }
            ParsedRule::Ignored => summary.ignored_rules += 1,
        }
    }

    CompiledRules {
        blocks,
        allows,
        summary,
    }
}

pub fn empty_status(
    config: &AppConfig,
    running: bool,
    summary: RuleSummary,
    stats: DnsStats,
    error: Option<String>,
) -> RuntimeStatus {
    let listen_addr = config
        .listen_socket_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| format!("{}:{}", config.listen_host, config.listen_port));

    RuntimeStatus {
        running,
        listen_addr,
        upstream_dns: config.upstream_dns.clone(),
        summary,
        stats,
        error,
    }
}

fn reset_stats(stats: &Arc<Mutex<DnsStats>>) {
    if let Ok(mut current) = stats.lock() {
        *current = DnsStats {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs()),
            ..DnsStats::default()
        };
    }
}

fn serve_udp(
    socket: Arc<UdpSocket>,
    work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
    stats: Arc<Mutex<DnsStats>>,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; 4096];
    let mut next_worker = 0_usize;

    while !stop.load(Ordering::Relaxed) {
        let (len, client_addr) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                record_error(&stats, format!("接收 DNS 请求失败：{error}"));
                continue;
            }
        };

        if len == 0 {
            continue;
        }

        let work_item = DnsWorkItem {
            query: buffer[..len].to_vec(),
            client_addr,
        };
        match dispatch_dns_work(&work_senders, work_item, &mut next_worker) {
            Ok(()) => {}
            Err(DispatchDnsWorkError::Full) => {
                record_error(&stats, "DNS 请求队列已满，已丢弃请求".to_string());
            }
            Err(DispatchDnsWorkError::Disconnected) => break,
        }
    }
}

enum DispatchDnsWorkError {
    Full,
    Disconnected,
}

fn dispatch_dns_work(
    senders: &[mpsc::SyncSender<DnsWorkItem>],
    work_item: DnsWorkItem,
    next_worker: &mut usize,
) -> Result<(), DispatchDnsWorkError> {
    if senders.is_empty() {
        return Err(DispatchDnsWorkError::Disconnected);
    }

    let start = *next_worker % senders.len();
    let mut pending = Some(work_item);
    let mut has_full_queue = false;
    for offset in 0..senders.len() {
        let index = (start + offset) % senders.len();
        let item = pending
            .take()
            .expect("pending DNS work item should exist before send attempt");

        match senders[index].try_send(item) {
            Ok(()) => {
                *next_worker = index.wrapping_add(1);
                return Ok(());
            }
            Err(mpsc::TrySendError::Full(item)) => {
                has_full_queue = true;
                pending = Some(item);
            }
            Err(mpsc::TrySendError::Disconnected(item)) => {
                pending = Some(item);
            }
        }
    }

    if has_full_queue {
        Err(DispatchDnsWorkError::Full)
    } else {
        Err(DispatchDnsWorkError::Disconnected)
    }
}

fn dns_worker_loop(
    receiver: mpsc::Receiver<DnsWorkItem>,
    context: Arc<DnsWorkerContext>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let work_item = match receiver.recv_timeout(WORKER_RECV_TIMEOUT) {
            Ok(work_item) => work_item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        handle_dns_query(&context, work_item);
    }
}

fn handle_dns_query(context: &DnsWorkerContext, work_item: DnsWorkItem) {
    let query = work_item.query.as_slice();
    let client_addr = work_item.client_addr;
    let question = match parse_question(query) {
        Ok(question) => question,
        Err(error) => {
            record_error(&context.stats, error);
            return;
        }
    };

    if context.rules.is_blocked(&question.domain) {
        let response = build_block_response(query, &question);
        if let Err(error) = context.socket.send_to(&response, client_addr) {
            let message = format!("返回黑名单响应失败：{error}");
            record_query(
                &context.stats,
                &question.domain,
                context.detailed_runtime_stats,
            );
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &question.domain,
                client_addr,
                true,
                false,
                true,
                None,
                None,
                Some(message),
            );
            return;
        }
        record_blocked_query(
            &context.stats,
            &question.domain,
            context.detailed_runtime_stats,
        );
        queue_query_log(
            context,
            &question.domain,
            client_addr,
            true,
            false,
            false,
            None,
            None,
            None,
        );
        return;
    }

    record_query(
        &context.stats,
        &question.domain,
        context.detailed_runtime_stats,
    );

    let cache_key = QueryCacheKey::from_question(&question);
    if let Some(cache_hit) =
        lookup_cached_response(&context.dns_cache, &cache_key, query, current_second())
    {
        if let Err(error) = context.socket.send_to(&cache_hit.response, client_addr) {
            let message = format!("返回 DNS 缓存响应失败：{error}");
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &question.domain,
                client_addr,
                false,
                false,
                true,
                None,
                None,
                Some(message),
            );
        } else {
            queue_query_log(
                context,
                &question.domain,
                client_addr,
                false,
                false,
                false,
                None,
                Some(0),
                None,
            );
            if cache_hit.refresh {
                refresh_expired_cache_async(
                    work_item.query,
                    cache_key,
                    Arc::clone(&context.upstream_servers),
                    context.upstream_mode.clone(),
                    context.dns_cache.clone(),
                    context.dns_cache_config.clone(),
                );
            }
        }
        return;
    }

    let pending_query = match begin_pending_query(context, &cache_key) {
        PendingQueryRole::Leader(pending_query) => pending_query,
        PendingQueryRole::Follower(pending_query) => {
            match wait_pending_query(&pending_query) {
                Ok(forwarded) => {
                    let response = prepare_forwarded_response(&forwarded.response, query);
                    if let Err(error) = context.socket.send_to(&response, client_addr) {
                        let message = format!("转发复用响应给客户端失败：{error}");
                        record_error(&context.stats, message.clone());
                        queue_query_log(
                            context,
                            &question.domain,
                            client_addr,
                            false,
                            true,
                            true,
                            Some(&forwarded.upstream),
                            Some(forwarded.duration_ms),
                            Some(message),
                        );
                    } else {
                        queue_query_log(
                            context,
                            &question.domain,
                            client_addr,
                            false,
                            false,
                            false,
                            Some(&forwarded.upstream),
                            Some(forwarded.duration_ms),
                            None,
                        );
                    }
                }
                Err(error) => {
                    record_error(&context.stats, error.clone());
                    queue_query_log(
                        context,
                        &question.domain,
                        client_addr,
                        false,
                        false,
                        true,
                        None,
                        None,
                        Some(error),
                    );
                }
            }
            return;
        }
    };

    let forward_result = forward_query(
        query,
        context.upstream_servers.as_ref(),
        &context.upstream_mode,
        &context.next_upstream,
    );
    finish_pending_query(context, &cache_key, &pending_query, forward_result.clone());

    match forward_result {
        Ok(forwarded) => {
            insert_cached_response(
                &context.dns_cache,
                context.dns_cache_config.as_ref(),
                cache_key,
                forwarded.response.clone(),
                current_second(),
            );
            if let Err(error) = context.socket.send_to(&forwarded.response, client_addr) {
                let message = format!("转发响应给客户端失败：{error}");
                record_error(&context.stats, message.clone());
                queue_query_log(
                    context,
                    &question.domain,
                    client_addr,
                    false,
                    true,
                    true,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    Some(message),
                );
            } else {
                record_forwarded(&context.stats, context.detailed_runtime_stats);
                queue_query_log(
                    context,
                    &question.domain,
                    client_addr,
                    false,
                    true,
                    false,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    None,
                );
            }
        }
        Err(error) => {
            record_error(&context.stats, error.clone());
            queue_query_log(
                context,
                &question.domain,
                client_addr,
                false,
                false,
                true,
                None,
                None,
                Some(error),
            );
        }
    }
}

fn forward_query(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
) -> Result<UpstreamForwardResponse, String> {
    match mode {
        UpstreamMode::LoadBalance => forward_load_balanced(query, upstream_servers, next_upstream),
        UpstreamMode::ParallelRequests => forward_parallel(query, upstream_servers),
        UpstreamMode::FastestAddr => forward_fastest_addr(query, upstream_servers),
    }
}

fn lookup_cached_response(
    dns_cache: &Option<Arc<DnsCacheStore>>,
    cache_key: &QueryCacheKey,
    query: &[u8],
    now: u64,
) -> Option<CacheHit> {
    let cache = dns_cache.as_ref()?;
    let raw_hit = cache.lookup(cache_key, now)?;
    let response = prepare_cached_response(&raw_hit.response, query, raw_hit.ttl)?;
    Some(CacheHit {
        response,
        refresh: raw_hit.refresh,
    })
}

fn insert_cached_response(
    dns_cache: &Option<Arc<DnsCacheStore>>,
    cache_config: Option<&DnsCacheConfig>,
    cache_key: QueryCacheKey,
    response: Vec<u8>,
    now: u64,
) {
    let Some(cache) = dns_cache else {
        return;
    };
    let Some(config) = cache_config else {
        return;
    };
    let Some(ttl) = cache_ttl_seconds(&response, config) else {
        return;
    };
    cache.insert_with_ttl(cache_key, response, now, ttl);
}

fn begin_pending_query(context: &DnsWorkerContext, cache_key: &QueryCacheKey) -> PendingQueryRole {
    context.pending_queries.begin(cache_key)
}

fn finish_pending_query(
    context: &DnsWorkerContext,
    cache_key: &QueryCacheKey,
    pending_query: &PendingQuery,
    result: Result<UpstreamForwardResponse, String>,
) {
    if let Ok(mut current) = pending_query.result.lock() {
        *current = Some(result);
        pending_query.ready.notify_all();
    }

    context.pending_queries.finish(cache_key, pending_query);
}

fn wait_pending_query(pending_query: &PendingQuery) -> Result<UpstreamForwardResponse, String> {
    let result = pending_query
        .result
        .lock()
        .map_err(|_| "等待重复 DNS 请求结果失败".to_string())?;
    let (result, timeout) = pending_query
        .ready
        .wait_timeout_while(result, PENDING_QUERY_WAIT_TIMEOUT, |result| {
            result.is_none()
        })
        .map_err(|_| "等待重复 DNS 请求结果失败".to_string())?;

    if timeout.timed_out() && result.is_none() {
        return Err("等待重复 DNS 请求结果超时".to_string());
    }

    result
        .as_ref()
        .cloned()
        .unwrap_or_else(|| Err("重复 DNS 请求没有可用结果".to_string()))
}

fn prepare_forwarded_response(response: &[u8], query: &[u8]) -> Vec<u8> {
    let mut response = response.to_vec();
    if response.len() >= 2 && query.len() >= 2 {
        response[0..2].copy_from_slice(&query[0..2]);
    }
    response
}

fn refresh_expired_cache_async(
    query: Vec<u8>,
    cache_key: QueryCacheKey,
    upstream_servers: Arc<Vec<RuntimeUpstream>>,
    upstream_mode: UpstreamMode,
    dns_cache: Option<Arc<DnsCacheStore>>,
    dns_cache_config: Option<DnsCacheConfig>,
) {
    let Some(cache) = dns_cache else {
        return;
    };
    let Some(cache_config) = dns_cache_config else {
        return;
    };

    thread::spawn(move || {
        let next_upstream = AtomicUsize::new(0);
        match forward_query(
            &query,
            upstream_servers.as_ref(),
            &upstream_mode,
            &next_upstream,
        ) {
            Ok(forwarded) => {
                let cache_for_insert = Some(Arc::clone(&cache));
                insert_cached_response(
                    &cache_for_insert,
                    Some(&cache_config),
                    cache_key,
                    forwarded.response,
                    current_second(),
                );
            }
            Err(_) => {
                cache.finish_refresh(&cache_key);
            }
        }
    });
}

fn forward_load_balanced(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    next_upstream: &AtomicUsize,
) -> Result<UpstreamForwardResponse, String> {
    let mut last_error = None;
    let server_count = upstream_servers.len();

    if server_count == 0 {
        return Err("没有可用的上游 DNS".into());
    }

    let start = next_upstream.fetch_add(1, Ordering::Relaxed) % server_count;
    let now = current_second();
    let mut skipped_unhealthy = false;

    for pass in 0..2 {
        for offset in 0..server_count {
            let upstream = &upstream_servers[(start + offset) % server_count];
            let unhealthy = is_upstream_temporarily_unhealthy(upstream, now);
            if pass == 0 && unhealthy {
                skipped_unhealthy = true;
                continue;
            }
            if pass == 1 && !unhealthy {
                continue;
            }

            match forward_to_upstream(query, upstream) {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
        }

        if !skipped_unhealthy {
            break;
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_parallel(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
) -> Result<UpstreamForwardResponse, String> {
    if upstream_servers.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    for upstream in upstream_servers {
        let upstream = upstream.clone();
        let sender = sender.clone();
        let query = Arc::clone(&query);
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(query.as_ref().as_slice(), &upstream));
        });
    }
    drop(sender);

    let mut last_error = None;
    for result in receiver.iter().take(upstream_servers.len()) {
        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_fastest_addr(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
) -> Result<UpstreamForwardResponse, String> {
    if upstream_servers.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    for upstream in upstream_servers {
        let upstream = upstream.clone();
        let sender = sender.clone();
        let query = Arc::clone(&query);
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(query.as_ref().as_slice(), &upstream));
        });
    }
    drop(sender);

    let mut responses = Vec::new();
    let mut last_error = None;
    for result in receiver.iter().take(upstream_servers.len()) {
        match result {
            Ok(response) => responses.push(response),
            Err(error) => last_error = Some(error),
        }
    }

    if responses.is_empty() {
        return Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()));
    }

    if let Some(index) = fastest_response_index(&responses) {
        return Ok(responses.swap_remove(index));
    }

    Ok(responses.remove(0))
}

fn fastest_response_index(responses: &[UpstreamForwardResponse]) -> Option<usize> {
    let candidates = responses
        .iter()
        .enumerate()
        .flat_map(|(index, response)| {
            extract_response_ips(&response.response)
                .into_iter()
                .take(FASTEST_ADDR_MAX_IPS_PER_RESPONSE)
                .map(move |ip| (index, ip))
        })
        .take(FASTEST_ADDR_MAX_PROBES)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return None;
    }

    let (sender, receiver) = mpsc::channel();
    for (response_index, ip) in candidates {
        let sender = sender.clone();
        thread::spawn(move || {
            if let Some(duration) = measure_ip_latency(ip) {
                let _ = sender.send(IpLatencyProbe {
                    response_index,
                    duration,
                });
            }
        });
    }
    drop(sender);

    receiver
        .into_iter()
        .min_by_key(|probe| probe.duration)
        .map(|probe| probe.response_index)
}

fn measure_ip_latency(ip: IpAddr) -> Option<Duration> {
    [443, 80]
        .into_iter()
        .filter_map(|port| {
            let addr = SocketAddr::new(ip, port);
            let start = Instant::now();
            TcpStream::connect_timeout(&addr, FASTEST_ADDR_CONNECT_TIMEOUT)
                .ok()
                .map(|_| start.elapsed())
        })
        .min()
}

fn forward_to_upstream(
    query: &[u8],
    upstream: &RuntimeUpstream,
) -> Result<UpstreamForwardResponse, String> {
    let started = Instant::now();
    let response = match &upstream.server {
        UpstreamServer::Udp(addr) => forward_udp(query, *addr),
        UpstreamServer::Doh(url) => {
            let client = upstream
                .doh_client
                .as_ref()
                .ok_or_else(|| "DoH 客户端未初始化".to_string())?;
            forward_doh(query, url, client)
        }
    };
    let response = match response {
        Ok(response) => {
            mark_upstream_available(upstream);
            response
        }
        Err(error) => {
            mark_upstream_unhealthy(upstream);
            return Err(error);
        }
    };
    Ok(UpstreamForwardResponse {
        response,
        upstream: format_upstream(upstream),
        duration_ms: duration_ms(started.elapsed()),
    })
}

fn is_upstream_temporarily_unhealthy(upstream: &RuntimeUpstream, now: u64) -> bool {
    upstream.unhealthy_until.load(Ordering::Relaxed) > now
}

fn mark_upstream_available(upstream: &RuntimeUpstream) {
    upstream.unhealthy_until.store(0, Ordering::Relaxed);
}

fn mark_upstream_unhealthy(upstream: &RuntimeUpstream) {
    upstream.unhealthy_until.store(
        current_second().saturating_add(UPSTREAM_FAILURE_BACKOFF_SECONDS),
        Ordering::Relaxed,
    );
}

fn format_upstream(upstream: &RuntimeUpstream) -> String {
    upstream.label.clone()
}

fn format_upstream_server(server: &UpstreamServer) -> String {
    match server {
        UpstreamServer::Udp(addr) => addr.to_string(),
        UpstreamServer::Doh(url) => normalize_doh_upstream_label(url),
    }
}

fn normalize_doh_upstream_label(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return url.to_string(),
    };
    let slash_index = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash_index];
    if authority.contains(':') {
        return url.to_string();
    }
    format!(
        "{scheme}://{authority}:{default_port}{}",
        &rest[slash_index..]
    )
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn forward_udp(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, String> {
    let bind_addr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("创建上游 DNS UDP 连接失败：{e}"))?;
    socket
        .set_read_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS 超时失败：{e}"))?;
    socket
        .send_to(query, upstream_addr)
        .map_err(|e| format!("请求上游 DNS 失败：{e}"))?;

    let mut response = vec![0_u8; 4096];
    let len = socket
        .recv(&mut response)
        .map_err(|e| format!("读取上游 DNS 响应失败：{e}"))?;
    response.truncate(len);
    Ok(response)
}

fn forward_doh(
    query: &[u8],
    url: &str,
    client: &reqwest::blocking::Client,
) -> Result<Vec<u8>, String> {
    let mut request_body = query.to_vec();
    if request_body.len() >= 2 {
        request_body[0] = 0;
        request_body[1] = 0;
    }

    let response = client
        .post(url)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .body(request_body)
        .send()
        .map_err(|e| format!("请求 DoH 上游失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("DoH 上游返回错误：{e}"))?;

    response
        .bytes()
        .map(|bytes| {
            let mut response = bytes.to_vec();
            if response.len() >= 2 && query.len() >= 2 {
                response[0..2].copy_from_slice(&query[0..2]);
            }
            response
        })
        .map_err(|e| format!("读取 DoH 响应失败：{e}"))
}

impl CompiledRules {
    fn is_blocked(&self, domain: &str) -> bool {
        if self.allows.contains(domain) {
            return false;
        }
        self.blocks.contains(domain)
    }
}

impl RuleSet {
    fn insert(&mut self, rule: Rule) {
        if rule.include_subdomains {
            self.suffix.insert(rule.domain);
        } else {
            self.exact.insert(rule.domain);
        }
    }

    fn contains(&self, domain: &str) -> bool {
        if self.exact.contains(domain) || self.suffix.contains(domain) {
            return true;
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if self.suffix.contains(&domain[offset..]) {
                return true;
            }
        }

        false
    }
}

enum ParsedRule {
    Block(Rule),
    Allow(Rule),
    Ignored,
}

fn parse_rule(line: &str) -> ParsedRule {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedRule::Ignored;
    }

    if let Some(rule) = parse_hosts_rule(trimmed) {
        return ParsedRule::Block(rule);
    }

    parse_filter_rule(trimmed)
}

fn parse_hosts_rule(line: &str) -> Option<Rule> {
    let mut parts = line.split_whitespace();
    let ip = parts.next()?;
    let domain = parts.next()?;
    let is_block_ip = matches!(ip, "0.0.0.0" | "127.0.0.1" | "::" | "::1");
    if !is_block_ip {
        return None;
    }

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains: false,
    })
}

fn parse_filter_rule(line: &str) -> ParsedRule {
    let (is_allow, rest) = if let Some(value) = line.strip_prefix("@@") {
        (true, value)
    } else {
        (false, line)
    };

    let pattern = rest.split('$').next().unwrap_or(rest).trim();
    let Some(rule) = parse_pattern(pattern) else {
        return ParsedRule::Ignored;
    };

    if is_allow {
        ParsedRule::Allow(rule)
    } else {
        ParsedRule::Block(rule)
    }
}

fn parse_pattern(pattern: &str) -> Option<Rule> {
    if pattern.starts_with('/') && pattern.ends_with('/') {
        return None;
    }

    if let Some(rest) = pattern.strip_prefix("||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('|');
        return normalize_domain(domain).map(|domain| Rule {
            domain,
            include_subdomains: true,
        });
    }

    let domain = pattern
        .trim_matches('|')
        .trim_end_matches('^')
        .strip_prefix("*.")
        .unwrap_or_else(|| pattern.trim_matches('|').trim_end_matches('^'));
    let include_subdomains = pattern.starts_with("*.");

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains,
    })
}

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty() {
        return None;
    }
    if domain.contains('/') || domain.contains('*') || domain.contains(' ') {
        return None;
    }
    if !domain
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }

    Some(domain)
}

struct Question {
    domain: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
}

fn parse_question(packet: &[u8]) -> Result<Question, String> {
    if packet.len() < DNS_HEADER_LEN {
        return Err("DNS 请求长度不足".into());
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    if question_count == 0 {
        return Err("DNS 请求没有 question".into());
    }

    let mut offset = DNS_HEADER_LEN;
    let mut domain = String::with_capacity(packet.len().saturating_sub(DNS_HEADER_LEN).min(253));

    loop {
        if offset >= packet.len() {
            return Err("DNS 域名解析越界".into());
        }

        let label_len = packet[offset] as usize;
        offset += 1;

        if label_len == 0 {
            break;
        }

        if label_len > 63 {
            return Err("DNS label 长度超过 63 字节".into());
        }

        if label_len & 0b1100_0000 != 0 {
            return Err("暂不支持压缩格式的 DNS question".into());
        }

        if offset + label_len > packet.len() {
            return Err("DNS label 长度越界".into());
        }

        if !domain.is_empty() {
            domain.push('.');
        }
        push_ascii_lowercase_lossy(&mut domain, &packet[offset..offset + label_len]);
        offset += label_len;
    }

    if offset + 4 > packet.len() {
        return Err("DNS question 缺少类型或类别".into());
    }

    let qtype = read_u16(packet, offset).ok_or("DNS qtype 读取失败")?;
    let qclass = read_u16(packet, offset + 2).ok_or("DNS qclass 读取失败")?;
    let question_end = offset + 4;

    Ok(Question {
        domain,
        qtype,
        qclass,
        question_end,
    })
}

fn push_ascii_lowercase_lossy(target: &mut String, bytes: &[u8]) {
    if bytes.is_ascii() {
        for byte in bytes {
            target.push(char::from(byte.to_ascii_lowercase()));
        }
        return;
    }

    for ch in String::from_utf8_lossy(bytes).chars() {
        if ch.is_ascii() {
            target.push(ch.to_ascii_lowercase());
        } else {
            target.push(ch);
        }
    }
}

fn build_block_response(query: &[u8], question: &Question) -> Vec<u8> {
    let answer_count = if matches!(question.qtype, TYPE_A | TYPE_AAAA) {
        1_u16
    } else {
        0_u16
    };
    let mut response = Vec::with_capacity(question.question_end + 32);

    response.extend_from_slice(&query[0..2]);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80);
    write_u16(&mut response, 1);
    write_u16(&mut response, answer_count);
    write_u16(&mut response, 0);
    write_u16(&mut response, 0);
    response.extend_from_slice(&query[DNS_HEADER_LEN..question.question_end]);

    if answer_count == 1 {
        response.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut response, question.qtype);
        write_u16(&mut response, question.qclass);
        response.extend_from_slice(&60_u32.to_be_bytes());
        if question.qtype == TYPE_A {
            write_u16(&mut response, 4);
            response.extend_from_slice(&[0, 0, 0, 0]);
        } else {
            write_u16(&mut response, 16);
            response.extend_from_slice(&[0; 16]);
        }
    }

    response
}

fn extract_response_ips(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < DNS_HEADER_LEN {
        return Vec::new();
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    let answer_count = read_u16(packet, 6).unwrap_or(0);
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        let Some(next_offset) = skip_dns_name(packet, offset) else {
            return Vec::new();
        };
        offset = next_offset.saturating_add(4);
        if offset > packet.len() {
            return Vec::new();
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        let Some(next_offset) = skip_dns_name(packet, offset) else {
            break;
        };
        offset = next_offset;
        if offset + 10 > packet.len() {
            break;
        }

        let record_type = read_u16(packet, offset).unwrap_or_default();
        let record_class = read_u16(packet, offset + 2).unwrap_or_default();
        let data_len = read_u16(packet, offset + 8).unwrap_or_default() as usize;
        let data_offset = offset + 10;
        let data_end = data_offset.saturating_add(data_len);
        if data_end > packet.len() {
            break;
        }

        if record_class == 1 && record_type == TYPE_A && data_len == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(
                packet[data_offset],
                packet[data_offset + 1],
                packet[data_offset + 2],
                packet[data_offset + 3],
            )));
        }

        if record_class == 1 && record_type == TYPE_AAAA && data_len == 16 {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[data_offset..data_end]);
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }

        offset = data_end;
    }

    ips
}

fn cache_ttl_seconds(packet: &[u8], config: &DnsCacheConfig) -> Option<u32> {
    let ttl = response_cache_ttl(packet)?;
    if ttl == 0 {
        return None;
    }

    let mut ttl = ttl;
    if config.min_ttl > 0 {
        ttl = ttl.max(config.min_ttl);
    }
    if config.max_ttl > 0 {
        ttl = ttl.min(config.max_ttl);
    }
    Some(ttl)
}

fn response_cache_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let rcode = packet[3] & 0x0f;
    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        return None;
    }
    let answer_count = read_u16(packet, 6)?;
    let authority_count = read_u16(packet, 8)?;
    let additional_count = read_u16(packet, 10)?;

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        let next_offset = skip_dns_name(packet, offset)?;
        if next_offset + 4 > packet.len() {
            return None;
        }
        offset = next_offset;
    }
    let question_type = read_u16(packet, offset)?;
    offset = offset.checked_add(4)?;
    if offset > packet.len() {
        return None;
    }

    let mut min_ttl = None;
    let mut has_answer = false;
    let mut has_ip_answer = false;
    for _ in 0..answer_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            has_answer = true;
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        if record.record_class == 1 && matches!(record.record_type, TYPE_A | TYPE_AAAA) {
            has_ip_answer = true;
        }
        offset = record.next_offset;
    }

    let mut has_soa_authority = false;
    let mut has_ns_authority = false;
    for _ in 0..authority_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        match record.record_type {
            TYPE_SOA => has_soa_authority = true,
            TYPE_NS => has_ns_authority = true,
            _ => {}
        }
        offset = record.next_offset;
    }

    for _ in 0..additional_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        offset = record.next_offset;
    }

    let authoritative_negative = has_soa_authority && !has_ns_authority;
    let cacheable = match rcode {
        RCODE_NOERROR => {
            if has_answer {
                !matches!(question_type, TYPE_A | TYPE_AAAA) || has_ip_answer
            } else {
                authoritative_negative
            }
        }
        RCODE_NXDOMAIN => authoritative_negative,
        _ => false,
    };
    if !cacheable {
        return None;
    }

    min_ttl
}

struct DnsRecordHeader {
    record_type: u16,
    record_class: u16,
    ttl: u32,
    next_offset: usize,
}

fn read_dns_record(packet: &[u8], offset: usize) -> Option<DnsRecordHeader> {
    let header_offset = skip_dns_name(packet, offset)?;
    if header_offset + 10 > packet.len() {
        return None;
    }

    let record_type = read_u16(packet, header_offset)?;
    let record_class = read_u16(packet, header_offset + 2)?;
    let ttl = read_u32(packet, header_offset + 4)?;
    let data_len = read_u16(packet, header_offset + 8)? as usize;
    let next_offset = header_offset.checked_add(10)?.checked_add(data_len)?;
    if next_offset > packet.len() {
        return None;
    }

    Some(DnsRecordHeader {
        record_type,
        record_class,
        ttl,
        next_offset,
    })
}

#[cfg(test)]
fn response_min_record_ttl(packet: &[u8]) -> Option<u32> {
    response_cache_ttl(packet)
}

fn prepare_cached_response(cached_response: &[u8], query: &[u8], ttl: u32) -> Option<Vec<u8>> {
    if cached_response.len() < 2 || query.len() < 2 {
        return None;
    }

    let mut response = cached_response.to_vec();
    response[0..2].copy_from_slice(&query[0..2]);
    rewrite_response_ttls(&mut response, ttl)?;
    Some(response)
}

fn rewrite_response_ttls(packet: &mut [u8], ttl: u32) -> Option<()> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    let answer_count = read_u16(packet, 6).unwrap_or(0);
    let authority_count = read_u16(packet, 8).unwrap_or(0);
    let additional_count = read_u16(packet, 10).unwrap_or(0);
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        let next_offset = skip_dns_name(packet, offset)?;
        offset = next_offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    for _ in 0..answer_count
        .saturating_add(authority_count)
        .saturating_add(additional_count)
    {
        let next_offset = skip_dns_name(packet, offset)?;
        offset = next_offset;
        if offset + 10 > packet.len() {
            return None;
        }

        let record_type = read_u16(packet, offset)?;
        if record_type != TYPE_OPT {
            write_u32_at(packet, offset + 4, ttl)?;
        }
        let data_len = read_u16(packet, offset + 8)? as usize;
        offset = offset.checked_add(10)?.checked_add(data_len)?;
        if offset > packet.len() {
            return None;
        }
    }

    Some(())
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)? as usize;
        offset += 1;

        if length == 0 {
            return Some(offset);
        }

        if length & 0b1100_0000 == 0b1100_0000 {
            packet.get(offset)?;
            return Some(offset + 1);
        }

        if length & 0b1100_0000 != 0 {
            return None;
        }

        offset = offset.checked_add(length)?;
        if offset > packet.len() {
            return None;
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([first, second]))
}

fn write_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    let third = *bytes.get(offset + 2)?;
    let fourth = *bytes.get(offset + 3)?;
    Some(u32::from_be_bytes([first, second, third, fourth]))
}

fn write_u32_at(target: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let bytes = value.to_be_bytes();
    target.get_mut(offset..offset + 4)?.copy_from_slice(&bytes);
    Some(())
}

fn record_query(stats: &Arc<Mutex<DnsStats>>, domain: &str, detailed_runtime_stats: bool) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.queries += 1;
        current.last_query = Some(domain.to_string());
        *current.query_domains.entry(domain.to_string()).or_default() += 1;
        record_traffic(&mut current, false);
    }
}

fn record_blocked_query(stats: &Arc<Mutex<DnsStats>>, domain: &str, detailed_runtime_stats: bool) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.queries += 1;
        current.blocked += 1;
        current.last_query = Some(domain.to_string());
        current.last_blocked = Some(domain.to_string());
        *current.query_domains.entry(domain.to_string()).or_default() += 1;
        *current
            .blocked_domains
            .entry(domain.to_string())
            .or_default() += 1;
        record_traffic(&mut current, false);
        record_traffic(&mut current, true);
    }
}

#[cfg(test)]
fn record_blocked(stats: &Arc<Mutex<DnsStats>>, domain: &str, detailed_runtime_stats: bool) {
    if let Ok(mut current) = stats.lock() {
        current.blocked += 1;
        current.last_blocked = Some(domain.to_string());
        if detailed_runtime_stats {
            *current
                .blocked_domains
                .entry(domain.to_string())
                .or_default() += 1;
            record_traffic(&mut current, true);
        }
    }
}

fn record_forwarded(stats: &Arc<Mutex<DnsStats>>, detailed_runtime_stats: bool) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.forwarded += 1;
    }
}

fn record_error(stats: &Arc<Mutex<DnsStats>>, error: String) {
    if let Ok(mut current) = stats.lock() {
        current.failed += 1;
        current.last_error = Some(error);
    }
}

#[allow(clippy::too_many_arguments)]
fn queue_query_log(
    context: &DnsWorkerContext,
    domain: &str,
    client_addr: SocketAddr,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
) {
    let Some(sender) = &context.query_log_sender else {
        return;
    };

    let entry = QueryLogEntry {
        domain: domain.to_string(),
        client_ip: Some(client_addr.ip().to_string()),
        blocked,
        forwarded,
        failed,
        upstream_server: upstream_server.map(str::to_string),
        upstream_duration_ms,
        error,
    };

    let message = QueryLogMessage {
        entry,
        anonymize_client_ip: context.anonymize_client_ip,
    };
    match sender.try_send(message) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            record_error(&context.stats, "查询日志队列已满，已丢弃日志".to_string());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            record_error(&context.stats, "查询日志写入队列已关闭".to_string());
        }
    }
}

fn record_traffic(stats: &mut DnsStats, blocked: bool) {
    let minute = current_minute();

    if let Some(bucket) = stats.traffic.last_mut()
        && bucket.minute == minute
    {
        increment_traffic_bucket(bucket, blocked);
        return;
    }

    if let Some(bucket) = stats
        .traffic
        .iter_mut()
        .find(|bucket| bucket.minute == minute)
    {
        increment_traffic_bucket(bucket, blocked);
        return;
    }

    let oldest_minute = minute.saturating_sub(TRAFFIC_BUCKET_WINDOW_MINUTES);
    stats
        .traffic
        .retain(|bucket| bucket.minute >= oldest_minute);
    stats.traffic.push(TrafficBucket {
        minute,
        ..TrafficBucket::default()
    });

    let bucket = stats
        .traffic
        .last_mut()
        .expect("traffic bucket should exist after push");
    increment_traffic_bucket(bucket, blocked);
}

fn increment_traffic_bucket(bucket: &mut TrafficBucket, blocked: bool) {
    if blocked {
        bucket.blocked += 1;
    } else {
        bucket.queries += 1;
    }
}

fn current_minute() -> u64 {
    current_second() / 60
}

fn current_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adguard_style_rule_blocks_domain_and_subdomain() {
        let rules = compile_rules("||example.org^");

        assert!(rules.is_blocked("example.org"));
        assert!(rules.is_blocked("ads.example.org"));
        assert!(!rules.is_blocked("badexample.org"));
    }

    #[test]
    fn allow_rule_overrides_block_rule() {
        let rules = compile_rules("||example.org^\n@@||safe.example.org^");

        assert!(rules.is_blocked("track.example.org"));
        assert!(!rules.is_blocked("safe.example.org"));
        assert!(!rules.is_blocked("cdn.safe.example.org"));
    }

    #[test]
    fn hosts_style_rule_blocks_exact_domain_only() {
        let rules = compile_rules("0.0.0.0 example.org");

        assert!(rules.is_blocked("example.org"));
        assert!(!rules.is_blocked("www.example.org"));
    }

    #[test]
    fn block_response_returns_zero_address_for_a_query() {
        let query = a_query("blocked.test");
        let question = parse_question(&query).expect("query should parse");
        let response = build_block_response(&query, &question);

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn runtime_stats_record_domain_counts_and_traffic() {
        let stats = Arc::new(Mutex::new(DnsStats::default()));

        record_query(&stats, "ads.example.org", true);
        record_blocked(&stats, "ads.example.org", true);

        let current = stats.lock().expect("stats should lock");
        assert_eq!(current.queries, 1);
        assert_eq!(current.blocked, 1);
        assert_eq!(current.query_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.blocked_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.traffic.len(), 1);
        assert_eq!(current.traffic[0].queries, 1);
        assert_eq!(current.traffic[0].blocked, 1);
    }

    #[test]
    fn extracts_a_record_ips_from_dns_response() {
        let response = a_response("example.org", [1, 2, 3, 4]);

        assert_eq!(
            extract_response_ips(&response),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
    }

    #[test]
    fn dns_cache_rewrites_transaction_id_and_ttl() {
        let query = a_query("example.org");
        let question = parse_question(&query).expect("query should parse");
        let key = QueryCacheKey::from_question(&question);
        let mut cache = DnsCache {
            config: DnsCacheConfig {
                enabled: true,
                max_size_bytes: 16 * 1024,
                min_ttl: 0,
                max_ttl: 60,
                optimistic: true,
            },
            entries: HashMap::new(),
            total_size: 0,
            access_counter: 0,
        };

        cache.insert(key.clone(), a_response("example.org", [1, 2, 3, 4]), 100);
        let mut next_query = query.clone();
        next_query[0] = 0xab;
        next_query[1] = 0xcd;
        let raw_hit = cache.lookup(&key, 130).expect("cache should hit");
        let response = prepare_cached_response(&raw_hit.response, &next_query, raw_hit.ttl)
            .expect("cached response should prepare");

        assert!(!raw_hit.refresh);
        assert_eq!(&response[0..2], &[0xab, 0xcd]);
        assert_eq!(response_min_record_ttl(&response), Some(30));
    }

    #[test]
    fn dns_cache_stores_authoritative_nxdomain_response() {
        let query = a_query("missing.example.org");
        let question = parse_question(&query).expect("query should parse");
        let key = QueryCacheKey::from_question(&question);
        let response = nxdomain_response("missing.example.org", 300);
        let config = DnsCacheConfig {
            enabled: true,
            max_size_bytes: 16 * 1024,
            min_ttl: 0,
            max_ttl: 120,
            optimistic: true,
        };
        let mut cache = DnsCache {
            config: config.clone(),
            entries: HashMap::new(),
            total_size: 0,
            access_counter: 0,
        };

        assert_eq!(cache_ttl_seconds(&response, &config), Some(120));
        cache.insert(key.clone(), response, 100);
        let mut next_query = query.clone();
        next_query[0] = 0xab;
        next_query[1] = 0xcd;
        let raw_hit = cache.lookup(&key, 130).expect("cache should hit");
        let response = prepare_cached_response(&raw_hit.response, &next_query, raw_hit.ttl)
            .expect("cached response should prepare");

        assert_eq!(&response[0..2], &[0xab, 0xcd]);
        assert_eq!(response[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(response_min_record_ttl(&response), Some(90));
    }

    #[test]
    fn upstream_failure_backoff_can_be_marked_and_cleared() {
        let upstream = RuntimeUpstream::new(UpstreamServer::Udp("127.0.0.1:53".parse().unwrap()))
            .expect("upstream should build");

        assert!(!is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
        mark_upstream_unhealthy(&upstream);
        assert!(is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
        mark_upstream_available(&upstream);
        assert!(!is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
    }

    fn a_query(domain: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn a_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&ip);
        packet
    }

    fn nxdomain_response(domain: &str, ttl: u32) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_SOA.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&24_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&1_u32.to_be_bytes());
        packet.extend_from_slice(&3600_u32.to_be_bytes());
        packet.extend_from_slice(&600_u32.to_be_bytes());
        packet.extend_from_slice(&86400_u32.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet
    }
}
