use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::config::{
    UpstreamMode, UpstreamServer, resolve_hostname_socket_addrs,
    resolve_hostname_socket_addrs_until,
};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};

use super::{
    protocol::{
        MAX_DNS_PACKET_SIZE, extract_response_ips, response_is_truncated,
        validate_response_for_query,
    },
    stats::{DnsStats, current_second, record_upstream_task_queue_rejected},
    task_pool,
};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_FAILURE_BACKOFF_SECONDS: u64 = 30;
const UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS: u64 = 1;
const DOH_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FASTEST_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_millis(180);
const FASTEST_ADDR_MAX_IPS_PER_RESPONSE: usize = 8;
const FASTEST_ADDR_MAX_PROBES: usize = 32;
const FASTEST_ADDR_PROBE_WAIT: Duration = Duration::from_secs(1);
const MAX_PARALLEL_UPSTREAMS_PER_QUERY: usize = 8;
const PARALLEL_HEDGE_DELAY: Duration = Duration::from_millis(25);
// 上游整体等待需要覆盖单次超时加上线程池排队的余量
const PARALLEL_RESULT_WAIT: Duration = Duration::from_secs(6);
const UDP_SOCKET_POOL_CAPACITY: usize = 8;
const PROBE_CACHE_TTL_SECONDS: u64 = 600;
const PROBE_CACHE_MAX_ENTRIES: usize = 4096;
const UPSTREAM_INIT_MAX_WORKERS: usize = 8;
const DNSBLACKHOLE_USER_AGENT: &str = concat!("DnsBlackhole/", env!("CARGO_PKG_VERSION"));

#[derive(Clone)]
pub(crate) struct RuntimeUpstream {
    server: UpstreamServer,
    label: String,
    unhealthy_until: Arc<AtomicU64>,
    half_open_probe_after: Arc<AtomicU64>,
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

struct ParallelForwardBatch {
    receiver: mpsc::Receiver<Result<UpstreamForwardResponse, String>>,
    expected: usize,
    synchronous_fallback: Option<RuntimeUpstream>,
    control: Arc<ParallelRequestControl>,
}

struct ParallelRequestControl {
    deadline: Instant,
    cancelled: AtomicBool,
}

impl ParallelRequestControl {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: AtomicBool::new(false),
        }
    }

    fn can_start(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

pub(crate) fn build_runtime_upstreams(
    upstream_servers: Vec<UpstreamServer>,
    bootstrap_servers: &[SocketAddr],
) -> Vec<RuntimeUpstream> {
    let worker_count = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, UPSTREAM_INIT_MAX_WORKERS);
    let mut servers = upstream_servers.into_iter();
    let mut initialized = Vec::new();
    loop {
        let batch = servers.by_ref().take(worker_count).collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        let mut batch = thread::scope(|scope| {
            batch
                .into_iter()
                .map(|server| scope.spawn(move || RuntimeUpstream::new(server, bootstrap_servers)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| worker.join().expect("上游初始化线程不应异常退出"))
                .collect::<Vec<_>>()
        });
        initialized.append(&mut batch);
    }
    initialized
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
            current_second().saturating_add(UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS)
        } else {
            0
        };

        Self {
            server,
            label,
            unhealthy_until: Arc::new(AtomicU64::new(0)),
            half_open_probe_after: Arc::new(AtomicU64::new(0)),
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
    Ok(Some(build_udp_runtime_state(addresses)))
}

fn resolve_udp_state_until(
    server: &UpstreamServer,
    bootstrap_servers: &[SocketAddr],
    deadline: Instant,
) -> Result<Option<UdpRuntimeState>, String> {
    let addresses = match server {
        UpstreamServer::Udp(addr) => vec![*addr],
        UpstreamServer::UdpHostname { hostname, port } => {
            resolve_hostname_socket_addrs_until(hostname, *port, bootstrap_servers, deadline)?
        }
        UpstreamServer::Doh(_) => return Ok(None),
    };
    Ok(Some(build_udp_runtime_state(addresses)))
}

fn build_udp_runtime_state(addresses: Vec<SocketAddr>) -> UdpRuntimeState {
    let socket_pools = (0..addresses.len())
        .map(|_| Mutex::new(Vec::new()))
        .collect::<Vec<_>>();
    UdpRuntimeState {
        addresses: Arc::new(addresses),
        socket_pools: Arc::new(socket_pools),
        next_address: Arc::new(AtomicUsize::new(0)),
    }
}

fn build_doh_client(
    url: &str,
    bootstrap_servers: &[SocketAddr],
) -> Result<reqwest::blocking::Client, String> {
    build_doh_client_with_resolver(url, |hostname, port| {
        resolve_hostname_socket_addrs(hostname, port, bootstrap_servers)
    })
}

fn build_doh_client_until(
    url: &str,
    bootstrap_servers: &[SocketAddr],
    deadline: Instant,
) -> Result<reqwest::blocking::Client, String> {
    build_doh_client_with_resolver(url, |hostname, port| {
        resolve_hostname_socket_addrs_until(hostname, port, bootstrap_servers, deadline)
    })
}

fn build_doh_client_with_resolver(
    url: &str,
    resolve_hostname: impl FnOnce(&str, u16) -> Result<Vec<SocketAddr>, String>,
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
        let addrs = resolve_hostname(hostname, port)?;
        builder = builder.resolve_to_addrs(hostname, &addrs);
    }

    builder
        .build()
        .map_err(|e| format!("创建 DoH 客户端失败：{e}"))
}

fn current_udp_state(
    upstream: &RuntimeUpstream,
    deadline: Instant,
) -> Result<UdpRuntimeState, String> {
    {
        let current = lock_until(&upstream.udp_state, deadline, "读取上游 DNS 地址状态失败")?;
        ensure_resolution_retry_due(upstream)?;
        if let Some(state) = current.clone() {
            return Ok(state);
        }
    }

    let state = resolve_udp_state_until(&upstream.server, &upstream.bootstrap_servers, deadline)?
        .ok_or_else(|| "上游 DNS 没有可用地址".to_string())?;
    remaining_upstream_timeout(deadline)?;
    let mut current = lock_until(&upstream.udp_state, deadline, "更新上游 DNS 地址状态失败")?;
    if let Some(current) = current.clone() {
        return Ok(current);
    }
    ensure_resolution_retry_due(upstream)?;
    upstream.resolution_retry_at.store(0, Ordering::Relaxed);
    *current = Some(state.clone());
    Ok(state)
}

fn current_doh_client(
    upstream: &RuntimeUpstream,
    url: &str,
    deadline: Instant,
) -> Result<reqwest::blocking::Client, String> {
    {
        let current = lock_until(&upstream.doh_client, deadline, "读取 DoH 客户端状态失败")?;
        ensure_resolution_retry_due(upstream)?;
        if let Some(client) = current.clone() {
            return Ok(client);
        }
    }

    let client = build_doh_client_until(url, &upstream.bootstrap_servers, deadline)?;
    remaining_upstream_timeout(deadline)?;
    let mut current = lock_until(&upstream.doh_client, deadline, "更新 DoH 客户端状态失败")?;
    if let Some(current) = current.clone() {
        return Ok(current);
    }
    ensure_resolution_retry_due(upstream)?;
    upstream.resolution_retry_at.store(0, Ordering::Relaxed);
    *current = Some(client.clone());
    Ok(client)
}

fn lock_until<'a, T>(
    mutex: &'a Mutex<T>,
    deadline: Instant,
    poisoned_error: &str,
) -> Result<MutexGuard<'a, T>, String> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(poisoned_error.to_string()),
            Err(TryLockError::WouldBlock) => {
                let remaining = remaining_upstream_timeout(deadline)?;
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
        }
    }
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
            upstream.resolution_retry_at.store(
                current_second().saturating_add(UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS),
                Ordering::Relaxed,
            );
            if let Ok(mut state) = upstream.udp_state.lock() {
                *state = None;
            }
        }
        UpstreamServer::Doh(_) => {
            upstream.resolution_retry_at.store(
                current_second().saturating_add(UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS),
                Ordering::Relaxed,
            );
            if let Ok(mut client) = upstream.doh_client.lock() {
                *client = None;
            }
        }
        UpstreamServer::Udp(_) => {}
    }
}

pub(crate) fn forward_query(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
    deadline: Instant,
    stats: &Arc<Mutex<DnsStats>>,
) -> Result<UpstreamForwardResponse, String> {
    match mode {
        UpstreamMode::LoadBalance => {
            forward_load_balanced(query, upstream_servers, next_upstream, deadline)
        }
        UpstreamMode::ParallelRequests => forward_parallel(
            query,
            upstream_servers,
            next_upstream,
            deadline,
            Some(stats),
        ),
        UpstreamMode::FastestAddr => {
            forward_fastest_addr(query, upstream_servers, deadline, Some(stats))
        }
    }
}

fn forward_load_balanced(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    next_upstream: &AtomicUsize,
    deadline: Instant,
) -> Result<UpstreamForwardResponse, String> {
    let mut last_error = None;
    let server_count = upstream_servers.len();

    if server_count == 0 {
        return Err("没有可用的上游 DNS".into());
    }

    let start = next_upstream.fetch_add(1, Ordering::Relaxed) % server_count;
    for upstream in select_available_upstreams(upstream_servers, start, usize::MAX) {
        if Instant::now() >= deadline {
            break;
        }
        match forward_to_upstream(query, &upstream, deadline) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| "所有上游 DNS 暂不可用".into()))
}

fn forward_parallel(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    next_upstream: &AtomicUsize,
    query_deadline: Instant,
    stats: Option<&Arc<Mutex<DnsStats>>>,
) -> Result<UpstreamForwardResponse, String> {
    if upstream_servers.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }
    let start = next_upstream.fetch_add(1, Ordering::Relaxed) % upstream_servers.len();
    let mut selected_upstreams = select_parallel_upstreams(upstream_servers, start);
    if selected_upstreams.is_empty() {
        return Err("所有上游 DNS 暂不可用".into());
    }

    let deadline = (Instant::now() + PARALLEL_RESULT_WAIT).min(query_deadline);
    let (sender, receiver) = mpsc::channel();
    let shared_query = Arc::new(query.to_vec());
    let control = Arc::new(ParallelRequestControl::new(deadline));
    let primary = selected_upstreams.remove(0);
    let mut pending = 0;
    let mut last_error = None;

    match spawn_parallel_forward_task(&shared_query, primary, &sender, &control, true, stats) {
        Ok(()) => {
            pending = 1;
            let hedge_deadline = (Instant::now() + PARALLEL_HEDGE_DELAY).min(deadline);
            match recv_until(&receiver, hedge_deadline) {
                Some(Ok(response)) => {
                    control.cancel();
                    return Ok(response);
                }
                Some(Err(error)) => {
                    pending = 0;
                    last_error = Some(error);
                }
                None => {}
            }
        }
        Err(upstream) => match forward_to_upstream(query, &upstream, deadline) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        },
    }

    let mut synchronous_fallback = None;
    for upstream in selected_upstreams {
        match spawn_parallel_forward_task(&shared_query, upstream, &sender, &control, true, stats) {
            Ok(()) => pending += 1,
            Err(upstream) => {
                synchronous_fallback = Some(upstream);
                break;
            }
        }
    }
    drop(sender);

    // 队列满时立即在当前线程执行一个兜底；其他已提交任务仍在并行运行。
    // 不能等到批次 deadline 后再执行，否则会在最拥塞时额外增加一个网络超时。
    if let Some(upstream) = synchronous_fallback.take() {
        match forward_to_upstream(query, &upstream, deadline) {
            Ok(response) => {
                control.cancel();
                return Ok(response);
            }
            Err(error) => last_error = Some(error),
        }
    }

    if pending == 0 {
        control.cancel();
        return Err(last_error.unwrap_or_else(|| "并发任务队列已满".to_string()));
    }

    for _ in 0..pending {
        match recv_until(&receiver, deadline) {
            Some(Ok(response)) => {
                control.cancel();
                return Ok(response);
            }
            Some(Err(error)) => last_error = Some(error),
            None => break,
        }
    }

    // 调用方不再等待后，尚未开始的同组任务应直接丢弃，避免网络异常时积压旧请求。
    control.cancel();
    Err(last_error.unwrap_or_else(|| "并行请求上游 DNS 超时".into()))
}

fn forward_fastest_addr(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    query_deadline: Instant,
    stats: Option<&Arc<Mutex<DnsStats>>>,
) -> Result<UpstreamForwardResponse, String> {
    let selected_upstreams = select_parallel_upstreams(upstream_servers, 0);
    if selected_upstreams.is_empty() {
        return Err(if upstream_servers.is_empty() {
            "没有可用的上游 DNS".into()
        } else {
            "所有上游 DNS 暂不可用".into()
        });
    }

    let deadline = (Instant::now() + PARALLEL_RESULT_WAIT).min(query_deadline);
    let batch = spawn_parallel_forwards(query, selected_upstreams, deadline, false, stats);
    let mut responses = Vec::new();
    let mut last_error = None;
    if let Some(upstream) = batch.synchronous_fallback.as_ref() {
        match forward_to_upstream(query, upstream, deadline) {
            Ok(response) => responses.push(response),
            Err(error) => last_error = Some(error),
        }
    }
    for _ in 0..batch.expected {
        match recv_until(&batch.receiver, deadline) {
            Some(Ok(response)) => responses.push(response),
            Some(Err(error)) => last_error = Some(error),
            None => break,
        }
    }
    batch.control.cancel();

    if responses.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            if batch.expected == 0 {
                "并发任务队列已满".into()
            } else {
                "并行请求上游 DNS 超时".into()
            }
        }));
    }

    if let Some(index) = fastest_response_index(&responses, deadline, stats) {
        return Ok(responses.swap_remove(index));
    }

    Ok(responses.remove(0))
}

fn spawn_parallel_forwards(
    query: &[u8],
    selected_upstreams: Vec<RuntimeUpstream>,
    deadline: Instant,
    cancel_on_success: bool,
    stats: Option<&Arc<Mutex<DnsStats>>>,
) -> ParallelForwardBatch {
    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    let control = Arc::new(ParallelRequestControl::new(deadline));
    let mut scheduled = 0;
    let mut synchronous_fallback = None;
    for upstream in selected_upstreams {
        match spawn_parallel_forward_task(
            &query,
            upstream,
            &sender,
            &control,
            cancel_on_success,
            stats,
        ) {
            Ok(()) => scheduled += 1,
            Err(upstream) => {
                synchronous_fallback = Some(upstream);
                break;
            }
        }
    }
    ParallelForwardBatch {
        receiver,
        expected: scheduled,
        synchronous_fallback,
        control,
    }
}

fn spawn_parallel_forward_task(
    query: &Arc<Vec<u8>>,
    upstream: RuntimeUpstream,
    sender: &mpsc::Sender<Result<UpstreamForwardResponse, String>>,
    control: &Arc<ParallelRequestControl>,
    cancel_on_success: bool,
    stats: Option<&Arc<Mutex<DnsStats>>>,
) -> Result<(), RuntimeUpstream> {
    let fallback = upstream.clone();
    let sender = sender.clone();
    let query = Arc::clone(query);
    let task_control = Arc::clone(control);
    if task_pool::spawn_task(move || {
        if !task_control.can_start() {
            return;
        }
        let result =
            forward_to_upstream(query.as_ref().as_slice(), &upstream, task_control.deadline);
        if cancel_on_success && result.is_ok() {
            task_control.cancel();
        }
        let _ = sender.send(result);
    }) {
        Ok(())
    } else {
        if let Some(stats) = stats {
            record_upstream_task_queue_rejected(stats);
        }
        Err(fallback)
    }
}

fn recv_until<T>(receiver: &mpsc::Receiver<T>, deadline: Instant) -> Option<T> {
    match receiver.try_recv() {
        Ok(value) => return Some(value),
        Err(mpsc::TryRecvError::Disconnected) => return None,
        Err(mpsc::TryRecvError::Empty) => {}
    }
    let remaining = deadline.checked_duration_since(Instant::now())?;
    receiver.recv_timeout(remaining).ok()
}

fn select_parallel_upstreams(
    upstream_servers: &[RuntimeUpstream],
    start: usize,
) -> Vec<RuntimeUpstream> {
    select_available_upstreams(upstream_servers, start, MAX_PARALLEL_UPSTREAMS_PER_QUERY)
}

fn select_available_upstreams(
    upstream_servers: &[RuntimeUpstream],
    start: usize,
    limit: usize,
) -> Vec<RuntimeUpstream> {
    if upstream_servers.is_empty() {
        return Vec::new();
    }
    let now = current_second();
    let healthy = (0..upstream_servers.len())
        .map(|offset| &upstream_servers[(start + offset) % upstream_servers.len()])
        .filter(|upstream| !is_upstream_temporarily_unhealthy(upstream, now))
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    if !healthy.is_empty() {
        return healthy;
    }

    // 全部上游都在退避时，仅允许一个上游按固定间隔进行半开探测。
    // 这样网络恢复后无需等待完整退避期，同时避免故障期间形成请求风暴。
    (0..upstream_servers.len())
        .map(|offset| &upstream_servers[(start + offset) % upstream_servers.len()])
        .find(|upstream| try_claim_half_open_probe(upstream, now))
        .cloned()
        .into_iter()
        .collect()
}

fn try_claim_half_open_probe(upstream: &RuntimeUpstream, now: u64) -> bool {
    let next_probe = now.saturating_add(UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS);
    let mut probe_after = upstream.half_open_probe_after.load(Ordering::Acquire);
    loop {
        if probe_after > now {
            return false;
        }
        match upstream.half_open_probe_after.compare_exchange_weak(
            probe_after,
            next_probe,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => probe_after = current,
        }
    }
}

fn fastest_response_index(
    responses: &[UpstreamForwardResponse],
    query_deadline: Instant,
    stats: Option<&Arc<Mutex<DnsStats>>>,
) -> Option<usize> {
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

    if !pending.is_empty() && Instant::now() < query_deadline {
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
            } else if let Some(stats) = stats {
                record_upstream_task_queue_rejected(stats);
            }
        }
        drop(sender);

        let deadline = (Instant::now() + FASTEST_ADDR_PROBE_WAIT).min(query_deadline);
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
    deadline: Instant,
) -> Result<UpstreamForwardResponse, String> {
    remaining_upstream_timeout(deadline)?;
    let started = Instant::now();
    let response = match &upstream.server {
        UpstreamServer::Udp(_) | UpstreamServer::UdpHostname { .. } => {
            current_udp_state(upstream, deadline).and_then(|state| {
                forward_udp_addresses(
                    query,
                    &state.addresses,
                    &state.socket_pools,
                    &state.next_address,
                    deadline,
                )
            })
        }
        UpstreamServer::Doh(url) => current_doh_client(upstream, url, deadline)
            .and_then(|client| forward_doh(query, url, &client, deadline)),
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
    upstream.half_open_probe_after.store(0, Ordering::Release);
}

pub(crate) fn mark_upstream_unhealthy(upstream: &RuntimeUpstream) {
    let now = current_second();
    upstream.unhealthy_until.store(
        now.saturating_add(UPSTREAM_FAILURE_BACKOFF_SECONDS),
        Ordering::Relaxed,
    );
    upstream.half_open_probe_after.store(
        now.saturating_add(UPSTREAM_HALF_OPEN_PROBE_INTERVAL_SECONDS),
        Ordering::Release,
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
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    if upstream_addrs.is_empty() || upstream_addrs.len() != socket_pools.len() {
        return Err("上游 DNS 没有可用地址".into());
    }

    let start = next_address.fetch_add(1, Ordering::Relaxed) % upstream_addrs.len();
    let mut last_error = None;
    for offset in 0..upstream_addrs.len() {
        remaining_upstream_timeout(deadline)?;
        let index = (start + offset) % upstream_addrs.len();
        match forward_udp(query, upstream_addrs[index], &socket_pools[index], deadline) {
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
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let socket = checkout_udp_socket(socket_pool, upstream_addr)?;
    // 出错（含超时）的 socket 缓冲区里可能有迟到的旧响应，直接丢弃不归还
    let response = udp_exchange(&socket, query, deadline)?;
    return_udp_socket(socket_pool, socket);

    if response_is_truncated(&response) {
        return forward_tcp(query, upstream_addr, deadline);
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

fn udp_exchange(
    socket: &UdpSocket,
    query: &[u8],
    query_deadline: Instant,
) -> Result<Vec<u8>, String> {
    socket
        .send(query)
        .map_err(|e| format!("请求上游 DNS 失败：{e}"))?;

    let deadline = (Instant::now() + UPSTREAM_TIMEOUT).min(query_deadline);
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

fn forward_tcp(
    query: &[u8],
    upstream_addr: SocketAddr,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let query_len =
        u16::try_from(query.len()).map_err(|_| "DNS TCP 请求长度超过 65535 字节".to_string())?;
    let connect_timeout = remaining_upstream_timeout(deadline)?;
    let mut stream = TcpStream::connect_timeout(&upstream_addr, connect_timeout)
        .map_err(|e| format!("创建上游 DNS TCP 连接失败：{e}"))?;
    let write_timeout = remaining_upstream_timeout(deadline)?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|e| format!("设置上游 DNS TCP 写入超时失败：{e}"))?;

    stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|_| stream.write_all(query))
        .map_err(|e| format!("请求上游 DNS TCP 失败：{e}"))?;

    let mut len_buf = [0_u8; 2];
    let read_timeout = remaining_upstream_timeout(deadline)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| format!("设置上游 DNS TCP 读取超时失败：{e}"))?;
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("读取上游 DNS TCP 响应长度失败：{e}"))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len == 0 {
        return Err("上游 DNS TCP 返回空响应".to_string());
    }

    let mut response = vec![0_u8; response_len];
    let read_timeout = remaining_upstream_timeout(deadline)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| format!("设置上游 DNS TCP 读取超时失败：{e}"))?;
    stream
        .read_exact(&mut response)
        .map_err(|e| format!("读取上游 DNS TCP 响应失败：{e}"))?;
    Ok(response)
}

fn forward_doh(
    query: &[u8],
    url: &str,
    client: &reqwest::blocking::Client,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut request_body = query.to_vec();
    if request_body.len() >= 2 {
        request_body[0] = 0;
        request_body[1] = 0;
    }

    let mut response = client
        .post(url)
        .timeout(remaining_upstream_timeout(deadline)?)
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

fn remaining_upstream_timeout(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(UPSTREAM_TIMEOUT))
        .ok_or_else(|| "上游 DNS 查询超过总超时".to_string())
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

    fn example_a_query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    fn spawn_udp_upstream(
        response_delay: Duration,
        valid_response: bool,
    ) -> (
        RuntimeUpstream,
        mpsc::Receiver<Instant>,
        thread::JoinHandle<()>,
    ) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("测试 UDP 上游应可绑定");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("应可设置测试 UDP 上游超时");
        let address = socket.local_addr().unwrap();
        let upstream = RuntimeUpstream::new(UpstreamServer::Udp(address), &[]);
        let (received_sender, received_receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut buffer = [0_u8; MAX_DNS_PACKET_SIZE];
            let (len, client) = socket
                .recv_from(&mut buffer)
                .expect("测试 UDP 上游应收到查询");
            let _ = received_sender.send(Instant::now());
            thread::sleep(response_delay);
            if valid_response {
                buffer[2] |= 0x80;
            }
            socket
                .send_to(&buffer[..len], client)
                .expect("测试 UDP 上游应可返回响应");
        });
        (upstream, received_receiver, handle)
    }

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
    fn hostname_udp_upstream_uses_system_fallback_only_during_startup() {
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
        let error = match current_udp_state(&upstream, Instant::now() + Duration::from_secs(1)) {
            Ok(_) => panic!("runtime resolution must not recurse through the system DNS resolver"),
            Err(error) => error,
        };
        assert!(error.contains("bootstrap DNS"));
    }

    #[test]
    fn runtime_udp_and_doh_resolution_respect_query_deadline() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").expect("blackhole bootstrap should bind");
        let bootstrap = blackhole.local_addr().unwrap();

        let mut udp =
            RuntimeUpstream::new(UpstreamServer::Udp("127.0.0.1:53".parse().unwrap()), &[]);
        udp.server = UpstreamServer::UdpHostname {
            hostname: "dns.example.test".into(),
            port: 53,
        };
        udp.bootstrap_servers = Arc::new(vec![bootstrap]);
        *udp.udp_state.lock().unwrap() = None;

        let started = Instant::now();
        assert!(
            current_udp_state(&udp, started + Duration::from_millis(150)).is_err(),
            "UDP hostname resolution should time out"
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        let mut doh = RuntimeUpstream::new(
            UpstreamServer::Doh("https://127.0.0.1/dns-query".into()),
            &[],
        );
        doh.server = UpstreamServer::Doh("https://dns.example.test/dns-query".into());
        doh.bootstrap_servers = Arc::new(vec![bootstrap]);
        *doh.doh_client.lock().unwrap() = None;

        let started = Instant::now();
        assert!(
            current_doh_client(
                &doh,
                "https://dns.example.test/dns-query",
                started + Duration::from_millis(150),
            )
            .is_err(),
            "DoH hostname resolution should time out"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn resolved_endpoint_lock_wait_respects_query_deadline() {
        let upstream = RuntimeUpstream::new(
            UpstreamServer::UdpHostname {
                hostname: "localhost".into(),
                port: 53,
            },
            &[],
        );
        let state = Arc::clone(&upstream.udp_state);
        let (locked_sender, locked_receiver) = mpsc::channel();
        let holder = thread::spawn(move || {
            let _guard = state.lock().unwrap();
            locked_sender.send(()).unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        locked_receiver.recv().unwrap();

        let started = Instant::now();
        let error = match current_udp_state(&upstream, started + Duration::from_millis(50)) {
            Ok(_) => panic!("等待解析状态锁也应受查询截止时间限制"),
            Err(error) => error,
        };
        assert!(error.contains("超过总超时"));
        assert!(started.elapsed() < Duration::from_millis(200));
        holder.join().unwrap();
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

    #[test]
    fn parallel_request_control_rejects_cancelled_and_expired_tasks() {
        let active = ParallelRequestControl::new(Instant::now() + Duration::from_secs(1));
        assert!(active.can_start());
        active.cancel();
        assert!(!active.can_start());

        let expired = ParallelRequestControl::new(Instant::now());
        assert!(!expired.can_start());
    }

    #[test]
    fn recv_until_returns_buffered_value_after_deadline() {
        let (sender, receiver) = mpsc::channel();
        sender.send(42).unwrap();

        assert_eq!(recv_until(&receiver, Instant::now()), Some(42));
    }

    #[test]
    fn parallel_upstream_selection_rotates_and_skips_unhealthy_servers() {
        let upstreams = [5301, 5302, 5303].map(|port| {
            RuntimeUpstream::new(UpstreamServer::Udp(([127, 0, 0, 1], port).into()), &[])
        });
        upstreams[1]
            .unhealthy_until
            .store(u64::MAX, Ordering::Relaxed);

        let selected = select_parallel_upstreams(&upstreams, 1)
            .into_iter()
            .map(|upstream| upstream.label)
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![upstreams[2].label.clone(), upstreams[0].label.clone()]
        );
    }

    #[test]
    fn all_unhealthy_load_balanced_upstreams_fail_without_retrying() {
        let upstreams = [5301, 5302, 5303].map(|port| {
            RuntimeUpstream::new(UpstreamServer::Udp(([127, 0, 0, 1], port).into()), &[])
        });
        for upstream in &upstreams {
            upstream.unhealthy_until.store(u64::MAX, Ordering::Relaxed);
            upstream
                .half_open_probe_after
                .store(u64::MAX, Ordering::Relaxed);
        }

        let error = match forward_load_balanced(
            &example_a_query(),
            &upstreams,
            &AtomicUsize::new(0),
            Instant::now() + Duration::from_secs(1),
        ) {
            Ok(_) => panic!("全体退避时应快速失败"),
            Err(error) => error,
        };

        assert_eq!(error, "所有上游 DNS 暂不可用");
    }

    #[test]
    fn load_balanced_query_tries_remaining_healthy_upstreams() {
        let (first, first_received, first_handle) = spawn_udp_upstream(Duration::ZERO, false);
        let (second, second_received, second_handle) = spawn_udp_upstream(Duration::ZERO, false);
        let (third, third_received, third_handle) = spawn_udp_upstream(Duration::ZERO, true);
        let third_label = third.label.clone();

        let upstreams = vec![first, second, third];
        let response = forward_load_balanced(
            &example_a_query(),
            &upstreams,
            &AtomicUsize::new(0),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(response.upstream, third_label);
        first_received
            .recv_timeout(Duration::from_secs(1))
            .expect("第一个上游应收到请求");
        second_received
            .recv_timeout(Duration::from_secs(1))
            .expect("第二个上游应作为故障切换收到请求");
        third_received
            .recv_timeout(Duration::from_secs(1))
            .expect("前两个上游失败后应继续尝试第三个上游");

        first_handle.join().unwrap();
        second_handle.join().unwrap();
        third_handle.join().unwrap();
    }

    #[test]
    fn unhealthy_upstream_allows_bounded_half_open_probe() {
        let upstream =
            RuntimeUpstream::new(UpstreamServer::Udp("127.0.0.1:5301".parse().unwrap()), &[]);
        upstream.unhealthy_until.store(u64::MAX, Ordering::Relaxed);
        upstream.half_open_probe_after.store(0, Ordering::Relaxed);

        assert_eq!(
            select_parallel_upstreams(std::slice::from_ref(&upstream), 0).len(),
            1
        );
        assert!(select_parallel_upstreams(std::slice::from_ref(&upstream), 0).is_empty());

        mark_upstream_available(&upstream);
        assert_eq!(select_parallel_upstreams(&[upstream], 0).len(), 1);
    }

    #[test]
    fn load_balanced_query_respects_shared_deadline() {
        let sockets = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let upstreams = sockets
            .iter()
            .map(|socket| {
                RuntimeUpstream::new(UpstreamServer::Udp(socket.local_addr().unwrap()), &[])
            })
            .collect::<Vec<_>>();
        let started = Instant::now();

        assert!(
            forward_load_balanced(
                &example_a_query(),
                &upstreams,
                &AtomicUsize::new(0),
                started + Duration::from_millis(200),
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn parallel_requests_hedge_only_after_primary_wait() {
        let (slow, slow_received, slow_handle) =
            spawn_udp_upstream(Duration::from_millis(150), true);
        let (fast, fast_received, fast_handle) = spawn_udp_upstream(Duration::ZERO, true);
        let fast_label = fast.label.clone();
        let upstreams = vec![slow, fast];

        let response = forward_parallel(
            &example_a_query(),
            &upstreams,
            &AtomicUsize::new(0),
            Instant::now() + Duration::from_secs(2),
            None,
        )
        .expect("hedged 上游应成功响应");
        let primary_received_at = slow_received
            .recv_timeout(Duration::from_secs(1))
            .expect("主上游应收到请求");
        let hedge_received_at = fast_received
            .recv_timeout(Duration::from_secs(1))
            .expect("备用上游应收到 hedged 请求");

        assert_eq!(response.upstream, fast_label);
        assert!(
            hedge_received_at
                .checked_duration_since(primary_received_at)
                .is_some_and(|delay| delay >= Duration::from_millis(10)),
            "备用请求不应与主请求同时投递"
        );

        slow_handle.join().unwrap();
        fast_handle.join().unwrap();
    }
}
