use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use crate::config::{UpstreamMode, UpstreamServer, resolve_hostname_socket_addrs};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};

use super::{
    protocol::{
        MAX_DNS_PACKET_SIZE, extract_response_ips, response_is_truncated,
        validate_response_for_query,
    },
    stats::current_second,
    task_pool,
};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_FAILURE_BACKOFF_SECONDS: u64 = 30;
const DOH_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FASTEST_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_millis(180);
const FASTEST_ADDR_MAX_IPS_PER_RESPONSE: usize = 8;
const FASTEST_ADDR_MAX_PROBES: usize = 32;
const FASTEST_ADDR_PROBE_WAIT: Duration = Duration::from_secs(1);
const MAX_PARALLEL_UPSTREAMS_PER_QUERY: usize = 8;
// 上游整体等待需要覆盖单次超时加上线程池排队的余量
const PARALLEL_RESULT_WAIT: Duration = Duration::from_secs(6);
const UDP_SOCKET_POOL_CAPACITY: usize = 8;
const PROBE_CACHE_TTL_SECONDS: u64 = 600;
const PROBE_CACHE_MAX_ENTRIES: usize = 4096;
const DNSBLACKHOLE_USER_AGENT: &str = concat!("DnsBlackhole/", env!("CARGO_PKG_VERSION"));

#[derive(Clone)]
pub(crate) struct RuntimeUpstream {
    server: UpstreamServer,
    label: String,
    unhealthy_until: Arc<AtomicU64>,
    bootstrap_servers: Arc<Vec<SocketAddr>>,
    resolution_retry_at: Arc<AtomicU64>,
    udp_state: Arc<Mutex<Option<UdpRuntimeState>>>,
    doh_client: Arc<Mutex<Option<reqwest::blocking::Client>>>,
}

#[derive(Clone)]
struct UdpRuntimeState {
    addresses: Arc<Vec<SocketAddr>>,
    // 每个解析地址使用独立的已连接 UDP socket 池，避免不同地址之间误复用。
    socket_pools: Arc<Vec<Mutex<Vec<UdpSocket>>>>,
    next_address: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(crate) struct UpstreamForwardResponse {
    pub(crate) response: Vec<u8>,
    pub(crate) upstream: String,
    pub(crate) duration_ms: u64,
}

struct IpLatencyProbe {
    response_index: usize,
    duration: Duration,
}

pub(crate) fn build_runtime_upstreams(
    upstream_servers: Vec<UpstreamServer>,
    bootstrap_servers: &[SocketAddr],
) -> Vec<RuntimeUpstream> {
    upstream_servers
        .into_iter()
        .map(|server| RuntimeUpstream::new(server, bootstrap_servers))
        .collect()
}

impl RuntimeUpstream {
    pub(crate) fn new(server: UpstreamServer, bootstrap_servers: &[SocketAddr]) -> Self {
        let label = format_upstream_server(&server);
        let initial_udp_state = resolve_udp_state(&server, bootstrap_servers).ok().flatten();
        let initial_doh_client = match &server {
            UpstreamServer::Doh(url) => build_doh_client(url, bootstrap_servers).ok(),
            UpstreamServer::Udp(_) | UpstreamServer::UdpHostname { .. } => None,
        };
        let resolution_available = initial_udp_state.is_some() || initial_doh_client.is_some();
        let resolution_retry_at = if !resolution_available
            && matches!(
                server,
                UpstreamServer::UdpHostname { .. } | UpstreamServer::Doh(_)
            ) {
            current_second().saturating_add(UPSTREAM_FAILURE_BACKOFF_SECONDS)
        } else {
            0
        };

        Self {
            server,
            label,
            unhealthy_until: Arc::new(AtomicU64::new(0)),
            bootstrap_servers: Arc::new(bootstrap_servers.to_vec()),
            resolution_retry_at: Arc::new(AtomicU64::new(resolution_retry_at)),
            udp_state: Arc::new(Mutex::new(initial_udp_state)),
            doh_client: Arc::new(Mutex::new(initial_doh_client)),
        }
    }
}

fn resolve_udp_state(
    server: &UpstreamServer,
    bootstrap_servers: &[SocketAddr],
) -> Result<Option<UdpRuntimeState>, String> {
    let addresses = match server {
        UpstreamServer::Udp(addr) => vec![*addr],
        UpstreamServer::UdpHostname { hostname, port } => {
            resolve_hostname_socket_addrs(hostname, *port, bootstrap_servers)?
        }
        UpstreamServer::Doh(_) => return Ok(None),
    };
    let socket_pools = (0..addresses.len())
        .map(|_| Mutex::new(Vec::new()))
        .collect::<Vec<_>>();
    Ok(Some(UdpRuntimeState {
        addresses: Arc::new(addresses),
        socket_pools: Arc::new(socket_pools),
        next_address: Arc::new(AtomicUsize::new(0)),
    }))
}

fn build_doh_client(
    url: &str,
    bootstrap_servers: &[SocketAddr],
) -> Result<reqwest::blocking::Client, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("DoH 地址无效：{e}"))?;
    let hostname = parsed
        .host_str()
        .ok_or_else(|| "DoH 地址缺少主机名".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "DoH 地址缺少有效端口".to_string())?;
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .connect_timeout(UPSTREAM_TIMEOUT)
        .pool_idle_timeout(Some(DOH_CLIENT_POOL_IDLE_TIMEOUT))
        .pool_max_idle_per_host(2)
        .user_agent(DNSBLACKHOLE_USER_AGENT);

    if hostname.parse::<IpAddr>().is_err() {
        let addrs = resolve_hostname_socket_addrs(hostname, port, bootstrap_servers)?;
        builder = builder.resolve_to_addrs(hostname, &addrs);
    }

    builder
        .build()
        .map_err(|e| format!("创建 DoH 客户端失败：{e}"))
}

fn current_udp_state(upstream: &RuntimeUpstream) -> Result<UdpRuntimeState, String> {
    let mut current = upstream
        .udp_state
        .lock()
        .map_err(|_| "读取上游 DNS 地址状态失败".to_string())?;
    if let Some(state) = current.clone() {
        return Ok(state);
    }
    ensure_resolution_retry_due(upstream)?;

    let state = resolve_udp_state(&upstream.server, &upstream.bootstrap_servers)?
        .ok_or_else(|| "上游 DNS 没有可用地址".to_string())?;
    *current = Some(state.clone());
    upstream.resolution_retry_at.store(0, Ordering::Relaxed);
    Ok(state)
}

fn current_doh_client(
    upstream: &RuntimeUpstream,
    url: &str,
) -> Result<reqwest::blocking::Client, String> {
    let mut current = upstream
        .doh_client
        .lock()
        .map_err(|_| "读取 DoH 客户端状态失败".to_string())?;
    if let Some(client) = current.clone() {
        return Ok(client);
    }
    ensure_resolution_retry_due(upstream)?;

    let client = build_doh_client(url, &upstream.bootstrap_servers)?;
    *current = Some(client.clone());
    upstream.resolution_retry_at.store(0, Ordering::Relaxed);
    Ok(client)
}

fn ensure_resolution_retry_due(upstream: &RuntimeUpstream) -> Result<(), String> {
    let now = current_second();
    let retry_at = upstream.resolution_retry_at.load(Ordering::Relaxed);
    if retry_at > now {
        return Err(format!("上游 {} 暂不可用，稍后重新解析", upstream.label));
    }
    Ok(())
}

fn invalidate_resolved_endpoint(upstream: &RuntimeUpstream) {
    match &upstream.server {
        UpstreamServer::UdpHostname { .. } => {
            if let Ok(mut state) = upstream.udp_state.lock() {
                *state = None;
            }
        }
        UpstreamServer::Doh(_) => {
            if let Ok(mut client) = upstream.doh_client.lock() {
                *client = None;
            }
        }
        UpstreamServer::Udp(_) => return,
    }
    upstream.resolution_retry_at.store(
        current_second().saturating_add(UPSTREAM_FAILURE_BACKOFF_SECONDS),
        Ordering::Relaxed,
    );
}

pub(crate) fn forward_query(
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
    let selected_upstreams = select_parallel_upstreams(upstream_servers);
    if selected_upstreams.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (receiver, expected, synchronous_fallback) =
        spawn_parallel_forwards(query, selected_upstreams);
    if expected == 0 {
        return synchronous_fallback
            .ok_or_else(|| "并发任务队列已满".to_string())
            .and_then(|upstream| forward_to_upstream(query, &upstream));
    }
    let deadline = Instant::now() + PARALLEL_RESULT_WAIT;
    let mut last_error = None;
    for _ in 0..expected {
        match recv_until(&receiver, deadline) {
            Some(Ok(response)) => return Ok(response),
            Some(Err(error)) => last_error = Some(error),
            None => break,
        }
    }

    Err(last_error.unwrap_or_else(|| "并行请求上游 DNS 超时".into()))
}

fn forward_fastest_addr(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
) -> Result<UpstreamForwardResponse, String> {
    let selected_upstreams = select_parallel_upstreams(upstream_servers);
    if selected_upstreams.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (receiver, expected, synchronous_fallback) =
        spawn_parallel_forwards(query, selected_upstreams);
    if expected == 0 {
        return synchronous_fallback
            .ok_or_else(|| "并发任务队列已满".to_string())
            .and_then(|upstream| forward_to_upstream(query, &upstream));
    }
    let deadline = Instant::now() + PARALLEL_RESULT_WAIT;
    let mut responses = Vec::new();
    let mut last_error = None;
    for _ in 0..expected {
        match recv_until(&receiver, deadline) {
            Some(Ok(response)) => responses.push(response),
            Some(Err(error)) => last_error = Some(error),
            None => break,
        }
    }

    if responses.is_empty() {
        return Err(last_error.unwrap_or_else(|| "并行请求上游 DNS 超时".into()));
    }

    if let Some(index) = fastest_response_index(&responses) {
        return Ok(responses.swap_remove(index));
    }

    Ok(responses.remove(0))
}

fn spawn_parallel_forwards(
    query: &[u8],
    selected_upstreams: Vec<RuntimeUpstream>,
) -> (
    mpsc::Receiver<Result<UpstreamForwardResponse, String>>,
    usize,
    Option<RuntimeUpstream>,
) {
    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    let mut scheduled = 0;
    let mut synchronous_fallback = None;
    for upstream in selected_upstreams {
        let sender = sender.clone();
        let query = Arc::clone(&query);
        let fallback = upstream.clone();
        if task_pool::spawn_task(move || {
            let _ = sender.send(forward_to_upstream(query.as_ref().as_slice(), &upstream));
        }) {
            scheduled += 1;
        } else {
            synchronous_fallback = Some(fallback);
            break;
        }
    }
    (receiver, scheduled, synchronous_fallback)
}

fn recv_until<T>(receiver: &mpsc::Receiver<T>, deadline: Instant) -> Option<T> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    receiver.recv_timeout(remaining).ok()
}

fn select_parallel_upstreams(upstream_servers: &[RuntimeUpstream]) -> Vec<RuntimeUpstream> {
    let now = current_second();
    let mut selected = upstream_servers
        .iter()
        .filter(|upstream| !is_upstream_temporarily_unhealthy(upstream, now))
        .take(MAX_PARALLEL_UPSTREAMS_PER_QUERY)
        .cloned()
        .collect::<Vec<_>>();

    if selected.is_empty() {
        selected = upstream_servers
            .iter()
            .take(MAX_PARALLEL_UPSTREAMS_PER_QUERY)
            .cloned()
            .collect();
    }

    selected
}

fn fastest_response_index(responses: &[UpstreamForwardResponse]) -> Option<usize> {
    let candidates = responses
        .iter()
        .enumerate()
        .flat_map(|(index, response)| {
            extract_response_ips(&response.response)
                .into_iter()
                .filter(|ip| is_probe_allowed(*ip))
                .take(FASTEST_ADDR_MAX_IPS_PER_RESPONSE)
                .map(move |ip| (index, ip))
        })
        .take(FASTEST_ADDR_MAX_PROBES)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return None;
    }

    // 先用缓存的拨测结果，只有未知 IP 才真正发起 TCP 探测
    let now = current_second();
    let mut best: Option<IpLatencyProbe> = None;
    let mut pending = Vec::new();
    for (response_index, ip) in candidates {
        match cached_probe_duration(ip, now) {
            Some(Some(duration)) => update_best_probe(
                &mut best,
                IpLatencyProbe {
                    response_index,
                    duration,
                },
            ),
            Some(None) => {}
            None => pending.push((response_index, ip)),
        }
    }

    if !pending.is_empty() {
        let mut expected = 0;
        let (sender, receiver) = mpsc::channel();
        for (response_index, ip) in pending {
            let sender = sender.clone();
            if task_pool::spawn_task(move || {
                let duration = measure_ip_latency(ip);
                store_probe_duration(ip, duration);
                if let Some(duration) = duration {
                    let _ = sender.send(IpLatencyProbe {
                        response_index,
                        duration,
                    });
                }
            }) {
                expected += 1;
            }
        }
        drop(sender);

        let deadline = Instant::now() + FASTEST_ADDR_PROBE_WAIT;
        for _ in 0..expected {
            match recv_until(&receiver, deadline) {
                Some(probe) => update_best_probe(&mut best, probe),
                None => break,
            }
        }
    }

    best.map(|probe| probe.response_index)
}

fn update_best_probe(best: &mut Option<IpLatencyProbe>, probe: IpLatencyProbe) {
    if best
        .as_ref()
        .is_none_or(|current| probe.duration < current.duration)
    {
        *best = Some(probe);
    }
}

struct ProbeCacheEntry {
    duration: Option<Duration>,
    expires_at: u64,
}

static PROBE_CACHE: OnceLock<Mutex<HashMap<IpAddr, ProbeCacheEntry>>> = OnceLock::new();

fn probe_cache() -> &'static Mutex<HashMap<IpAddr, ProbeCacheEntry>> {
    PROBE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 返回 None 表示缓存未命中；Some(None) 表示缓存了一次拨测失败。
fn cached_probe_duration(ip: IpAddr, now: u64) -> Option<Option<Duration>> {
    let cache = probe_cache().lock().ok()?;
    let entry = cache.get(&ip)?;
    if entry.expires_at <= now {
        return None;
    }
    Some(entry.duration)
}

fn store_probe_duration(ip: IpAddr, duration: Option<Duration>) {
    let Ok(mut cache) = probe_cache().lock() else {
        return;
    };
    let now = current_second();
    if cache.len() >= PROBE_CACHE_MAX_ENTRIES {
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= PROBE_CACHE_MAX_ENTRIES {
            cache.clear();
        }
    }
    cache.insert(
        ip,
        ProbeCacheEntry {
            duration,
            expires_at: now.saturating_add(PROBE_CACHE_TTL_SECONDS),
        },
    );
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

fn is_probe_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(
                (a, b, c),
                (0, _, _)
                    | (10, _, _)
                    | (100, 64..=127, _)
                    | (127, _, _)
                    | (169, 254, _)
                    | (172, 16..=31, _)
                    | (192, 0, 0)
                    | (192, 0, 2)
                    | (192, 168, _)
                    | (198, 18..=19, _)
                    | (198, 51, 100)
                    | (203, 0, 113)
                    | (224..=255, _, _)
            )
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_probe_allowed(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && segments[..6] != [0; 6]
                && segments[0] & 0xfe00 != 0xfc00
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xffc0 != 0xfec0
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn forward_to_upstream(
    query: &[u8],
    upstream: &RuntimeUpstream,
) -> Result<UpstreamForwardResponse, String> {
    let started = Instant::now();
    let response = match &upstream.server {
        UpstreamServer::Udp(_) | UpstreamServer::UdpHostname { .. } => current_udp_state(upstream)
            .and_then(|state| {
                forward_udp_addresses(
                    query,
                    &state.addresses,
                    &state.socket_pools,
                    &state.next_address,
                )
            }),
        UpstreamServer::Doh(url) => {
            current_doh_client(upstream, url).and_then(|client| forward_doh(query, url, &client))
        }
    };
    let response = match response {
        Ok(response) => {
            if let Err(error) = validate_response_for_query(query, &response) {
                mark_upstream_unhealthy(upstream);
                return Err(format!("上游 {} 响应无效：{error}", upstream.label));
            }
            mark_upstream_available(upstream);
            response
        }
        Err(error) => {
            invalidate_resolved_endpoint(upstream);
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

pub(crate) fn is_upstream_temporarily_unhealthy(upstream: &RuntimeUpstream, now: u64) -> bool {
    upstream.unhealthy_until.load(Ordering::Relaxed) > now
}

pub(crate) fn mark_upstream_available(upstream: &RuntimeUpstream) {
    upstream.unhealthy_until.store(0, Ordering::Relaxed);
}

pub(crate) fn mark_upstream_unhealthy(upstream: &RuntimeUpstream) {
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
        UpstreamServer::UdpHostname { hostname, port } => format!("{hostname}:{port}"),
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

fn forward_udp_addresses(
    query: &[u8],
    upstream_addrs: &[SocketAddr],
    socket_pools: &[Mutex<Vec<UdpSocket>>],
    next_address: &AtomicUsize,
) -> Result<Vec<u8>, String> {
    if upstream_addrs.is_empty() || upstream_addrs.len() != socket_pools.len() {
        return Err("上游 DNS 没有可用地址".into());
    }

    let start = next_address.fetch_add(1, Ordering::Relaxed) % upstream_addrs.len();
    let mut last_error = None;
    for offset in 0..upstream_addrs.len() {
        let index = (start + offset) % upstream_addrs.len();
        match forward_udp(query, upstream_addrs[index], &socket_pools[index]) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(format!("{}：{error}", upstream_addrs[index])),
        }
    }

    Err(last_error.unwrap_or_else(|| "上游 DNS 没有可用地址".into()))
}

fn forward_udp(
    query: &[u8],
    upstream_addr: SocketAddr,
    socket_pool: &Mutex<Vec<UdpSocket>>,
) -> Result<Vec<u8>, String> {
    let socket = checkout_udp_socket(socket_pool, upstream_addr)?;
    // 出错（含超时）的 socket 缓冲区里可能有迟到的旧响应，直接丢弃不归还
    let response = udp_exchange(&socket, query)?;
    return_udp_socket(socket_pool, socket);

    if response_is_truncated(&response) {
        return forward_tcp(query, upstream_addr);
    }
    Ok(response)
}

fn checkout_udp_socket(
    socket_pool: &Mutex<Vec<UdpSocket>>,
    upstream_addr: SocketAddr,
) -> Result<UdpSocket, String> {
    if let Ok(mut sockets) = socket_pool.lock()
        && let Some(socket) = sockets.pop()
    {
        return Ok(socket);
    }

    let bind_addr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("创建上游 DNS UDP 连接失败：{e}"))?;
    socket
        .connect(upstream_addr)
        .map_err(|e| format!("连接上游 DNS 失败：{e}"))?;
    Ok(socket)
}

fn return_udp_socket(socket_pool: &Mutex<Vec<UdpSocket>>, socket: UdpSocket) {
    if let Ok(mut sockets) = socket_pool.lock()
        && sockets.len() < UDP_SOCKET_POOL_CAPACITY
    {
        sockets.push(socket);
    }
}

fn udp_exchange(socket: &UdpSocket, query: &[u8]) -> Result<Vec<u8>, String> {
    socket
        .send(query)
        .map_err(|e| format!("请求上游 DNS 失败：{e}"))?;

    let deadline = Instant::now() + UPSTREAM_TIMEOUT;
    let mut buffer = [0_u8; MAX_DNS_PACKET_SIZE];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "读取上游 DNS 响应超时".to_string())?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|e| format!("设置上游 DNS 超时失败：{e}"))?;

        let len = socket
            .recv(&mut buffer)
            .map_err(|e| format!("读取上游 DNS 响应失败：{e}"))?;
        // 复用的 socket 可能收到上一次超时查询的迟到响应，用 txid 过滤后继续等待
        if len >= 2 && buffer[0..2] == query[0..2] {
            return Ok(buffer[..len].to_vec());
        }
    }
}

fn forward_tcp(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, String> {
    let query_len =
        u16::try_from(query.len()).map_err(|_| "DNS TCP 请求长度超过 65535 字节".to_string())?;
    let mut stream = TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT)
        .map_err(|e| format!("创建上游 DNS TCP 连接失败：{e}"))?;
    stream
        .set_read_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS TCP 读取超时失败：{e}"))?;
    stream
        .set_write_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS TCP 写入超时失败：{e}"))?;

    stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|_| stream.write_all(query))
        .map_err(|e| format!("请求上游 DNS TCP 失败：{e}"))?;

    let mut len_buf = [0_u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("读取上游 DNS TCP 响应长度失败：{e}"))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len == 0 {
        return Err("上游 DNS TCP 返回空响应".to_string());
    }

    let mut response = vec![0_u8; response_len];
    stream
        .read_exact(&mut response)
        .map_err(|e| format!("读取上游 DNS TCP 响应失败：{e}"))?;
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

    let mut response = client
        .post(url)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .body(request_body)
        .send()
        .map_err(|e| format!("请求 DoH 上游失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("DoH 上游返回错误：{e}"))?;

    validate_doh_response_headers(response.headers())?;
    let mut response = read_limited_doh_body(&mut response)?;
    if response.len() >= 2 && query.len() >= 2 {
        response[0..2].copy_from_slice(&query[0..2]);
    }
    Ok(response)
}

fn validate_doh_response_headers(headers: &reqwest::header::HeaderMap) -> Result<(), String> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
    {
        return Err(format!("DoH 上游返回了无效 Content-Type：{content_type}"));
    }

    if let Some(content_length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && content_length > MAX_DNS_PACKET_SIZE as u64
    {
        return Err("DoH 响应长度超过 65535 字节".into());
    }
    Ok(())
}

fn read_limited_doh_body(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    reader
        .take((MAX_DNS_PACKET_SIZE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|e| format!("读取 DoH 响应失败：{e}"))?;
    if response.len() > MAX_DNS_PACKET_SIZE {
        return Err("DoH 响应长度超过 65535 字节".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn unavailable_hostname_upstream_does_not_abort_runtime_build() {
        let upstreams = build_runtime_upstreams(
            vec![
                UpstreamServer::Doh("https://".into()),
                UpstreamServer::Udp("127.0.0.1:53".parse().unwrap()),
            ],
            &[],
        );

        assert_eq!(upstreams.len(), 2);
        assert!(upstreams[0].doh_client.lock().unwrap().is_none());
        assert!(upstreams[1].udp_state.lock().unwrap().is_some());
    }

    #[test]
    fn hostname_udp_upstream_can_be_resolved_again_after_failure() {
        let upstream = RuntimeUpstream::new(
            UpstreamServer::UdpHostname {
                hostname: "localhost".into(),
                port: 53,
            },
            &[],
        );
        assert!(upstream.udp_state.lock().unwrap().is_some());

        invalidate_resolved_endpoint(&upstream);
        assert!(upstream.udp_state.lock().unwrap().is_none());
        assert!(upstream.resolution_retry_at.load(Ordering::Relaxed) > current_second());

        upstream.resolution_retry_at.store(0, Ordering::Relaxed);
        let state = current_udp_state(&upstream).expect("hostname should resolve again");
        assert!(!state.addresses.is_empty());
        assert_eq!(upstream.resolution_retry_at.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fastest_address_probe_rejects_non_public_targets() {
        assert!(!is_probe_allowed("127.0.0.1".parse().unwrap()));
        assert!(!is_probe_allowed("192.168.1.1".parse().unwrap()));
        assert!(!is_probe_allowed("169.254.169.254".parse().unwrap()));
        assert!(!is_probe_allowed("::1".parse().unwrap()));
        assert!(!is_probe_allowed("fc00::1".parse().unwrap()));
        assert!(is_probe_allowed("8.8.8.8".parse().unwrap()));
        assert!(is_probe_allowed("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn doh_body_reader_enforces_dns_message_limit() {
        let mut valid = Cursor::new(vec![0_u8; MAX_DNS_PACKET_SIZE]);
        assert_eq!(
            read_limited_doh_body(&mut valid).unwrap().len(),
            MAX_DNS_PACKET_SIZE
        );

        let mut oversized = Cursor::new(vec![0_u8; MAX_DNS_PACKET_SIZE + 1]);
        assert!(read_limited_doh_body(&mut oversized).is_err());
    }

    #[test]
    fn doh_headers_require_dns_message_content_type() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/dns-message".parse().unwrap());
        assert!(validate_doh_response_headers(&headers).is_ok());

        headers.insert(CONTENT_TYPE, "text/html".parse().unwrap());
        assert!(validate_doh_response_headers(&headers).is_err());

        headers.insert(CONTENT_TYPE, "application/dns-message".parse().unwrap());
        headers.insert(
            CONTENT_LENGTH,
            (MAX_DNS_PACKET_SIZE + 1).to_string().parse().unwrap(),
        );
        assert!(validate_doh_response_headers(&headers).is_err());
    }
}
