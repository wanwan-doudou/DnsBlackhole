use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::{
    config::AppConfig,
    database::{Database, QueryPersistenceEntry},
};

use super::{
    access::ClientAccess,
    cache::{DnsCacheConfig, DnsCacheStatsSnapshot, DnsCacheStore},
    filter_runtime::{FilterRuntime, SharedFilterRuntime, share_filter_runtime},
    protocol::MAX_DNS_PACKET_SIZE,
    security_events::SecurityEventWriter,
    stats::{
        DnsStats, record_error, record_tcp_connection_rejected, record_worker_queue_drop,
        reset_stats,
    },
    upstream::build_runtime_upstreams_with_dnssec,
    upstream_routes::UpstreamRoutes,
    worker::{
        DnsResponseTarget, DnsWorkItem, DnsWorkerContext, PENDING_QUERY_SHARDS, PendingQueries,
        dns_worker_loop,
    },
};

#[cfg(test)]
use super::filter_runtime::build_filter_runtime;

const UDP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const TCP_ACCEPT_SLEEP: Duration = Duration::from_millis(10);
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_MAX_CONNECTIONS: usize = 256;
const TCP_CONNECTION_STACK_SIZE: usize = 512 * 1024;
// 路由器会把多台设备的查询汇聚到同一监听套接字，放大缓冲区以承接瞬时突发。
const UDP_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;
const DNS_WORK_QUEUE_CAPACITY: usize = 8192;
const QUERY_LOG_QUEUE_CAPACITY: usize = 16384;
const QUERY_LOG_BATCH_SIZE: usize = 512;
const QUERY_LOG_BATCH_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const DNS_MIN_WORKERS: usize = 4;
const DNS_MAX_WORKERS: usize = 32;
const DNS_CACHE_SHARDS: usize = 64;

pub struct DnsServer {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    cache: Option<Arc<DnsCacheStore>>,
    filter_runtime: SharedFilterRuntime,
    security_event_writer: Option<SecurityEventWriter>,
}

impl DnsServer {
    #[cfg(test)]
    pub fn start(
        config: AppConfig,
        rules_text: &str,
        stats: Arc<Mutex<DnsStats>>,
        database: Arc<Database>,
    ) -> Result<Self, String> {
        let filter_runtime = build_filter_runtime(&config, rules_text);
        Self::start_with_filter_runtime(
            config,
            filter_runtime,
            stats,
            database,
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub(crate) fn start_with_filter_runtime(
        config: AppConfig,
        filter_runtime: FilterRuntime,
        stats: Arc<Mutex<DnsStats>>,
        database: Arc<Database>,
        protection_paused_until: Arc<AtomicU64>,
    ) -> Result<Self, String> {
        let total_started = Instant::now();
        let config_started = Instant::now();
        config.validate()?;

        let listen_addrs = config.listen_socket_addrs()?;
        let bootstrap_servers = config.bootstrap_servers()?;
        let upstream_config = config.upstream_servers()?;
        let fallback_config = config.fallback_servers()?;
        crate::performance::log_service("DNS 服务实例", "配置解析与校验", config_started);
        let upstream_started = Instant::now();
        let upstream_servers = Arc::new(build_runtime_upstreams_with_dnssec(
            upstream_config,
            &bootstrap_servers,
            config.dnssec_enabled,
        ));
        crate::performance::log_service("DNS 服务实例", "主上游初始化", upstream_started);
        let fallback_started = Instant::now();
        let fallback_upstream_servers = Arc::new(build_runtime_upstreams_with_dnssec(
            fallback_config,
            &bootstrap_servers,
            config.dnssec_enabled,
        ));
        let upstream_routes = Arc::new(UpstreamRoutes::from_config(&config)?);
        crate::performance::log_service("DNS 服务实例", "备用上游初始化", fallback_started);
        let runtime_state_started = Instant::now();
        let upstream_mode = config.upstream_mode.clone();
        let query_log_enabled = config.query_log_enabled;
        let statistics_enabled = config.statistics_enabled;
        let anonymize_client_ip = config.anonymize_client_ip;
        let access = Arc::new(ClientAccess::from_config(&config)?);
        let refuse_any = config.refuse_any;
        let private_reverse_dns_enabled = config.private_reverse_dns_enabled;
        let dns_cache_config = DnsCacheConfig::from_config(&config);
        let dns_cache =
            DnsCacheStore::from_config(dns_cache_config.clone(), DNS_CACHE_SHARDS).map(Arc::new);
        let dns_cache_config = dns_cache.as_ref().map(|_| dns_cache_config);
        let filter_runtime = share_filter_runtime(filter_runtime);
        crate::performance::log_service(
            "DNS 服务实例",
            "访问控制与缓存初始化",
            runtime_state_started,
        );
        let listener_started = Instant::now();
        let listeners = listen_addrs
            .iter()
            .copied()
            .map(|addr| bind_listener_pair(addr, addr.is_ipv6() && config.listen_ipv6))
            .collect::<Result<Vec<_>, _>>()?;
        let monitoring_listener = super::monitoring::prepare(&config)?;
        crate::performance::log_service("DNS 服务实例", "监听端口绑定", listener_started);

        let threads_started = Instant::now();
        reset_stats(&stats);
        // reset_stats 会清空内存队列，这里把落盘的历史安全事件放回去，
        // 让「安全防护」页在重启后仍能显示既有记录。
        match database.recent_security_events(super::SECURITY_EVENT_CAPACITY) {
            Ok(mut events) => {
                let since = super::stats::current_second()
                    .saturating_sub(u64::from(config.security_event_retention_hours) * 3600);
                events.retain(|event| event.last_seen_at >= since);
                super::restore_security_events(&stats, events);
            }
            Err(error) => eprintln!("读取历史安全事件失败：{error}"),
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let security_event_writer = Some(SecurityEventWriter::start(
            Arc::clone(&stats),
            Arc::clone(&database),
        ));
        if let Some(listener) = monitoring_listener {
            threads.push(super::monitoring::spawn(
                listener,
                Arc::clone(&stats),
                Arc::clone(&protection_paused_until),
                Arc::clone(&stop),
            ));
        }

        let mut query_log_thread = None;
        let persistence_sender = if query_log_enabled || statistics_enabled {
            let (sender, receiver) = mpsc::sync_channel(QUERY_LOG_QUEUE_CAPACITY);
            query_log_thread = Some(spawn_query_log_writer(Arc::clone(&database), receiver));
            Some(sender)
        } else {
            None
        };

        let worker_context = Arc::new(DnsWorkerContext {
            upstream_servers,
            fallback_upstream_servers,
            upstream_routes,
            upstream_mode,
            next_upstream: AtomicUsize::new(0),
            fallback_next_upstream: AtomicUsize::new(0),
            access,
            refuse_any,
            private_reverse_dns_enabled,
            protection_paused_until,
            filter_runtime: Arc::clone(&filter_runtime),
            stats: Arc::clone(&stats),
            dns_cache: dns_cache.clone(),
            dns_cache_config,
            pending_queries: Arc::new(PendingQueries::new(PENDING_QUERY_SHARDS)),
            persistence_sender,
            query_log_enabled,
            statistics_enabled,
            anonymize_client_ip,
            detailed_runtime_stats: !statistics_enabled,
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

        let active_tcp_connections = Arc::new(AtomicUsize::new(0));
        for listener in listeners {
            let tcp_work_senders = work_senders.clone();
            let tcp_stats = Arc::clone(&stats);
            let tcp_stop = Arc::clone(&stop);
            let active_tcp_connections = Arc::clone(&active_tcp_connections);
            threads.push(thread::spawn(move || {
                serve_tcp(
                    listener.tcp,
                    tcp_work_senders,
                    tcp_stats,
                    tcp_stop,
                    active_tcp_connections,
                );
            }));

            let listener_stats = Arc::clone(&stats);
            let listener_stop = Arc::clone(&stop);
            let udp_work_senders = work_senders.clone();
            threads.push(thread::spawn(move || {
                serve_udp(
                    listener.udp,
                    udp_work_senders,
                    listener_stats,
                    listener_stop,
                );
            }));
        }
        if let Some(thread) = query_log_thread {
            threads.push(thread);
        }

        let server = Self {
            stop,
            threads,
            cache: dns_cache,
            filter_runtime,
            security_event_writer,
        };
        crate::performance::log_service("DNS 服务实例", "工作线程启动", threads_started);
        crate::performance::log_service("DNS 服务实例", "总计", total_started);
        Ok(server)
    }

    pub fn clear_cache(&self) -> Result<(), String> {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
        Ok(())
    }

    pub(crate) fn cache_stats(&self) -> DnsCacheStatsSnapshot {
        self.cache
            .as_deref()
            .map(DnsCacheStore::stats_snapshot)
            .unwrap_or_default()
    }

    pub(crate) fn filter_runtime_handle(&self) -> SharedFilterRuntime {
        Arc::clone(&self.filter_runtime)
    }

    pub fn rule_summary(&self) -> super::RuleSummary {
        super::filter_runtime::current_filter_runtime(&self.filter_runtime).summary()
    }

    pub fn has_finished_threads(&self) -> bool {
        self.threads.iter().any(JoinHandle::is_finished)
            || self
                .security_event_writer
                .as_ref()
                .is_some_and(SecurityEventWriter::is_finished)
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        if let Some(writer) = self.security_event_writer.take() {
            writer.stop();
        }
    }
}

struct ListenerPair {
    udp: Arc<UdpSocket>,
    tcp: Arc<TcpListener>,
}

fn bind_listener_pair(addr: SocketAddr, ipv6_only: bool) -> Result<ListenerPair, String> {
    let udp = bind_udp_listener(addr, ipv6_only)
        .map_err(|error| format!("监听 UDP {addr} 失败：{error}"))?;
    configure_udp_listener_socket(&udp)?;
    udp.set_read_timeout(Some(UDP_READ_TIMEOUT))
        .map_err(|error| format!("设置 UDP DNS 读取超时失败：{error}"))?;

    let tcp = bind_tcp_listener(addr, ipv6_only)
        .map_err(|error| format!("监听 TCP {addr} 失败：{error}"))?;
    tcp.set_nonblocking(true)
        .map_err(|error| format!("设置 TCP DNS 非阻塞监听失败：{error}"))?;

    Ok(ListenerPair {
        udp: Arc::new(udp),
        tcp: Arc::new(tcp),
    })
}

fn bind_udp_listener(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<UdpSocket> {
    if !ipv6_only {
        return UdpSocket::bind(addr);
    }

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

fn bind_tcp_listener(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<TcpListener> {
    if !ipv6_only {
        return TcpListener::bind(addr);
    }

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

fn configure_udp_listener_socket(socket: &UdpSocket) -> Result<(), String> {
    let socket_ref = SockRef::from(socket);
    socket_ref
        .set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE)
        .map_err(|error| format!("设置 UDP DNS 接收缓冲区失败：{error}"))?;
    socket_ref
        .set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE)
        .map_err(|error| format!("设置 UDP DNS 发送缓冲区失败：{error}"))?;
    configure_windows_udp_listener_socket(socket)
}

#[cfg(windows)]
fn configure_windows_udp_listener_socket(socket: &UdpSocket) -> Result<(), String> {
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
fn configure_windows_udp_listener_socket(_socket: &UdpSocket) -> Result<(), String> {
    Ok(())
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
    receiver: mpsc::Receiver<QueryPersistenceEntry>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut batch = Vec::with_capacity(QUERY_LOG_BATCH_SIZE);

        while let Ok(message) = receiver.recv() {
            batch.push(message);

            while batch.len() < QUERY_LOG_BATCH_SIZE {
                match receiver.recv_timeout(QUERY_LOG_BATCH_WAIT_TIMEOUT) {
                    Ok(message) => batch.push(message),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }

            if let Err(error) = database.insert_query_events(&batch) {
                eprintln!("{error}");
            }
            batch.clear();
        }
    })
}

fn serve_udp(
    socket: Arc<UdpSocket>,
    work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
    stats: Arc<Mutex<DnsStats>>,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; MAX_DNS_PACKET_SIZE];
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
            response_target: DnsResponseTarget::Udp {
                socket: Arc::clone(&socket),
                client_addr,
            },
            queued_at: Instant::now(),
        };
        match dispatch_dns_work(&work_senders, work_item, &mut next_worker) {
            Ok(()) => {}
            Err(DispatchDnsWorkError::Full) => {
                record_worker_queue_drop(&stats, "DNS 请求队列已满，已丢弃请求".to_string());
            }
            Err(DispatchDnsWorkError::Disconnected) => break,
        }
    }
}

fn serve_tcp(
    listener: Arc<TcpListener>,
    work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
    stats: Arc<Mutex<DnsStats>>,
    stop: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (stream, client_addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(TCP_ACCEPT_SLEEP);
                continue;
            }
            Err(error) => {
                record_error(&stats, format!("接收 TCP DNS 连接失败：{error}"));
                thread::sleep(TCP_ACCEPT_SLEEP);
                continue;
            }
        };

        if !try_acquire_tcp_connection_slot(&active_connections) {
            record_tcp_connection_rejected(&stats, "TCP DNS 连接数已满，已拒绝新连接".to_string());
            continue;
        }

        let connection_slot = TcpConnectionSlot {
            active_connections: Arc::clone(&active_connections),
        };
        let work_senders = work_senders.clone();
        let connection_stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        if let Err(error) = thread::Builder::new()
            .name("dns-tcp-connection".to_string())
            .stack_size(TCP_CONNECTION_STACK_SIZE)
            .spawn(move || {
                let _slot = connection_slot;
                handle_tcp_connection(stream, client_addr, work_senders, connection_stats, stop);
            })
        {
            record_error(&stats, format!("创建 TCP DNS 连接线程失败：{error}"));
        }
    }

    while active_connections.load(Ordering::Acquire) > 0 {
        thread::sleep(TCP_ACCEPT_SLEEP);
    }
}

struct TcpConnectionSlot {
    active_connections: Arc<AtomicUsize>,
}

impl Drop for TcpConnectionSlot {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_tcp_connection_slot(active_connections: &AtomicUsize) -> bool {
    active_connections
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < TCP_MAX_CONNECTIONS).then_some(current + 1)
        })
        .is_ok()
}

fn handle_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
    stats: Arc<Mutex<DnsStats>>,
    stop: Arc<AtomicBool>,
) {
    if let Err(error) = configure_tcp_stream(&stream) {
        record_error(&stats, error);
        return;
    }

    let mut next_worker = 0_usize;
    while !stop.load(Ordering::Relaxed) {
        let query = match read_tcp_dns_query(&mut stream, &stop) {
            Ok(Some(query)) => query,
            Ok(None) => break,
            Err(error) => {
                record_error(&stats, format!("读取 TCP DNS 请求失败：{error}"));
                break;
            }
        };

        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        let work_item = DnsWorkItem {
            query,
            client_addr,
            response_target: DnsResponseTarget::Tcp(response_sender),
            queued_at: Instant::now(),
        };

        match dispatch_dns_work(&work_senders, work_item, &mut next_worker) {
            Ok(()) => {}
            Err(DispatchDnsWorkError::Full) => {
                record_worker_queue_drop(&stats, "DNS 请求队列已满，已丢弃 TCP 请求".to_string());
                break;
            }
            Err(DispatchDnsWorkError::Disconnected) => break,
        }

        match response_receiver.recv_timeout(TCP_RESPONSE_TIMEOUT) {
            Ok(Some(response)) => match write_tcp_dns_response(&mut stream, &response) {
                Ok(()) => {}
                // 客户端拿到答案或超时后提前中止连接是 TCP DNS 的常见收尾，静默关闭即可。
                Err(TcpWriteError::ClientDisconnected) => break,
                Err(TcpWriteError::Failed(error)) => {
                    record_error(&stats, format!("写入 TCP DNS 响应失败：{error}"));
                    break;
                }
            },
            Ok(None) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                record_error(&stats, "等待 TCP DNS 响应超时".to_string());
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("设置 TCP DNS 阻塞模式失败：{e}"))?;
    stream
        .set_read_timeout(Some(TCP_READ_TIMEOUT))
        .map_err(|e| format!("设置 TCP DNS 读取超时失败：{e}"))?;
    stream
        .set_write_timeout(Some(TCP_WRITE_TIMEOUT))
        .map_err(|e| format!("设置 TCP DNS 写入超时失败：{e}"))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("设置 TCP DNS nodelay 失败：{e}"))?;
    Ok(())
}

fn read_tcp_dns_query(
    stream: &mut TcpStream,
    stop: &Arc<AtomicBool>,
) -> Result<Option<Vec<u8>>, String> {
    read_tcp_dns_query_with_timeout(stream, stop, TCP_IDLE_TIMEOUT)
}

fn read_tcp_dns_query_with_timeout(
    stream: &mut TcpStream,
    stop: &Arc<AtomicBool>,
    total_timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    let deadline = Instant::now() + total_timeout;
    let mut len_buf = [0_u8; 2];
    if !read_tcp_bytes_until(stream, &mut len_buf, stop, deadline, true)? {
        return Ok(None);
    }

    let query_len = u16::from_be_bytes(len_buf) as usize;
    if query_len == 0 {
        return Ok(None);
    }

    let mut query = vec![0_u8; query_len];
    if !read_tcp_bytes_until(stream, &mut query, stop, deadline, false)? {
        return Ok(None);
    }
    Ok(Some(query))
}

fn read_tcp_bytes_until(
    stream: &mut TcpStream,
    target: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
    clean_eof_if_empty: bool,
) -> Result<bool, String> {
    let mut offset = 0;
    while offset < target.len() {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero());
        let Some(remaining) = remaining else {
            if clean_eof_if_empty && offset == 0 {
                return Ok(false);
            }
            return Err("读取 TCP DNS 请求总超时".into());
        };
        stream
            .set_read_timeout(Some(remaining.min(TCP_READ_TIMEOUT)))
            .map_err(|error| error.to_string())?;

        match stream.read(&mut target[offset..]) {
            Ok(0) if clean_eof_if_empty && offset == 0 => return Ok(false),
            Ok(0) => return Err("TCP DNS 请求在完整读取前关闭".into()),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) if is_client_disconnect(error.kind()) => {
                return Ok(false);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(true)
}

/// 客户端在服务端读写完成前主动断开，在 TCP DNS 中属于常见收尾，不应记为服务端故障。
fn is_client_disconnect(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

enum TcpWriteError {
    ClientDisconnected,
    Failed(String),
}

fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> Result<(), TcpWriteError> {
    let response_len = u16::try_from(response.len())
        .map_err(|_| TcpWriteError::Failed("TCP DNS 响应长度超过 65535 字节".to_string()))?;
    stream
        .write_all(&response_len.to_be_bytes())
        .and_then(|_| stream.write_all(response))
        .map_err(|error| {
            if is_client_disconnect(error.kind()) {
                TcpWriteError::ClientDisconnected
            } else {
                TcpWriteError::Failed(error.to_string())
            }
        })
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

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use crate::{config::AppConfig, database::Database};

    use super::super::protocol::{RCODE_NXDOMAIN, parse_question, read_u16};
    use super::super::stats::{DnsStats, DnsTransport, SecurityEventType};
    use super::*;

    fn example_a_query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    fn available_local_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("临时 TCP 端口应可绑定")
            .local_addr()
            .expect("应可读取临时 TCP 地址")
            .port()
    }

    #[test]
    fn ipv6_udp_listener_does_not_claim_ipv4_port() {
        let ipv6 = bind_udp_listener("[::]:0".parse().unwrap(), true)
            .expect("IPv6 UDP listener should bind");
        let port = ipv6.local_addr().unwrap().port();

        bind_udp_listener(SocketAddr::from(([0, 0, 0, 0], port)), false)
            .expect("IPv4 UDP listener should share the port");
    }

    #[test]
    fn ipv6_tcp_listener_does_not_claim_ipv4_port() {
        let ipv6 = bind_tcp_listener("[::]:0".parse().unwrap(), true)
            .expect("IPv6 TCP listener should bind");
        let port = ipv6.local_addr().unwrap().port();

        bind_tcp_listener(SocketAddr::from(([0, 0, 0, 0], port)), false)
            .expect("IPv4 TCP listener should share the port");
    }

    #[test]
    fn tcp_query_body_has_cumulative_read_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&4_u16.to_be_bytes()).unwrap();
        client.write_all(&[1]).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let error = read_tcp_dns_query_with_timeout(&mut server, &stop, Duration::from_millis(100))
            .expect_err("partial TCP query should time out");

        assert!(error.contains("总超时"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn tcp_query_reports_disconnect_during_body() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&4_u16.to_be_bytes()).unwrap();
        client.write_all(&[1]).unwrap();
        drop(client);

        let stop = Arc::new(AtomicBool::new(false));
        let error = read_tcp_dns_query_with_timeout(&mut server, &stop, Duration::from_millis(500))
            .expect_err("partial TCP query should report disconnect");

        assert!(error.contains("完整读取前关闭"));
    }

    #[test]
    fn client_disconnect_kinds_are_not_treated_as_server_failure() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
        ] {
            assert!(is_client_disconnect(kind), "{kind:?} 应视为客户端断开");
        }

        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
            ErrorKind::InvalidData,
        ] {
            assert!(!is_client_disconnect(kind), "{kind:?} 不应视为客户端断开");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_connection_abort_and_reset_are_client_disconnect() {
        // 10053 WSAECONNABORTED 与 10054 WSAECONNRESET 都来自客户端提前中止连接。
        for raw in [10053, 10054] {
            let error = std::io::Error::from_raw_os_error(raw);
            assert!(
                is_client_disconnect(error.kind()),
                "os error {raw} 应视为客户端断开"
            );
        }
    }

    #[test]
    fn tcp_write_reports_client_disconnect_instead_of_failure() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        // linger 归零让客户端断开时直接发 RST，稳定复现客户端中止已建立连接的场景。
        SockRef::from(&client)
            .set_linger(Some(Duration::ZERO))
            .expect("应可设置测试连接的 linger");
        drop(client);

        let response = vec![0_u8; 64];
        for _ in 0..50 {
            match write_tcp_dns_response(&mut server, &response) {
                Ok(()) => thread::sleep(Duration::from_millis(10)),
                Err(TcpWriteError::ClientDisconnected) => return,
                Err(TcpWriteError::Failed(error)) => {
                    panic!("客户端中止连接不应记为写入失败：{error}")
                }
            }
        }

        panic!("客户端中止连接后应返回 ClientDisconnected");
    }

    #[cfg(windows)]
    #[test]
    fn configured_tcp_stream_restores_blocking_mode_after_nonblocking_accept() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let _client = TcpStream::connect(address).unwrap();
        let (mut server, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
                Err(error) => panic!("接受测试 TCP 连接失败：{error}"),
            }
        };

        configure_tcp_stream(&server).expect("TCP 连接配置应成功");
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("应可缩短测试读取超时");

        let started = Instant::now();
        let error = server
            .read(&mut [0_u8; 1])
            .expect_err("空闲阻塞连接应在读取超时后返回错误");

        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "空闲读取不应因继承非阻塞模式而立即返回"
        );
    }

    #[test]
    fn finished_runtime_thread_marks_server_unhealthy() {
        let finished_thread = thread::spawn(|| {});
        while !finished_thread.is_finished() {
            thread::yield_now();
        }
        let server = DnsServer {
            stop: Arc::new(AtomicBool::new(false)),
            threads: vec![finished_thread],
            security_event_writer: None,
            cache: None,
            filter_runtime: share_filter_runtime(build_filter_runtime(&AppConfig::default(), "")),
        };

        assert!(server.has_finished_threads());
        server.stop();
    }

    #[test]
    fn denied_client_udp_is_dropped_tcp_is_refused_and_both_are_audited() {
        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: "127.0.0.1:9".into(),
            fallback_dns: String::new(),
            blocked_clients: Ipv4Addr::LOCALHOST.to_string(),
            query_log_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let server = DnsServer::start(config, "", Arc::clone(&stats), database)
            .expect("测试 DNS 服务应可启动");
        let query = example_a_query();

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_millis(700)))
            .expect("应可设置 UDP 读取超时");
        udp.send_to(&query, (Ipv4Addr::LOCALHOST, port))
            .expect("应可发送 UDP 查询");
        let mut udp_response = [0_u8; 512];
        let udp_error = udp
            .recv_from(&mut udp_response)
            .expect_err("被拒 UDP 查询不应收到响应");
        assert!(matches!(
            udp_error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));

        let mut tcp =
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("TCP 客户端应可连接测试服务");
        tcp.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("应可设置 TCP 读取超时");
        tcp.write_all(&(query.len() as u16).to_be_bytes())
            .and_then(|_| tcp.write_all(&query))
            .expect("应可发送 TCP 查询");
        let mut response_length = [0_u8; 2];
        tcp.read_exact(&mut response_length)
            .expect("TCP 查询应收到响应长度");
        let mut tcp_response = vec![0_u8; u16::from_be_bytes(response_length) as usize];
        tcp.read_exact(&mut tcp_response)
            .expect("TCP 查询应收到完整响应");
        assert_eq!(tcp_response[3] & 0x0f, 5, "TCP 响应应为 REFUSED");

        let snapshot = stats.lock().expect("统计锁不应中毒").clone();
        assert_eq!(snapshot.access_denied_total, 2);
        assert_eq!(snapshot.dropped_udp_total, 1);
        assert_eq!(snapshot.security_events.len(), 2);
        assert!(snapshot.security_events.iter().any(|event| {
            event.event_type == SecurityEventType::AccessDenied
                && event.protocol == DnsTransport::Udp
                && event.client_ip == Ipv4Addr::LOCALHOST.to_string()
        }));
        assert!(snapshot.security_events.iter().any(|event| {
            event.event_type == SecurityEventType::AccessDenied
                && event.protocol == DnsTransport::Tcp
                && event.client_ip == Ipv4Addr::LOCALHOST.to_string()
        }));

        server.stop();
    }

    #[test]
    fn dnsrewrite_udp_and_tcp_responses_are_logged_without_blocking() {
        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: "127.0.0.1:9".into(),
            fallback_dns: String::new(),
            dns_cache_enabled: false,
            statistics_enabled: true,
            query_log_enabled: true,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().unwrap());
        let mut query = example_a_query();
        let domain = super::super::protocol::parse_question(&query)
            .unwrap()
            .domain;
        let rules = format!(
            "||{domain}^\n||{domain}^$dnsrewrite=1.2.3.4\n||{domain}^$dnsrewrite=5.6.7.8\n||{domain}^$dnsrewrite=2001:db8::1"
        );
        let server =
            DnsServer::start(config, &rules, Arc::clone(&stats), Arc::clone(&database)).unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        udp.send_to(&query, (Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut response = [0_u8; 512];
        let (len, _) = udp.recv_from(&mut response).unwrap();
        let summary = super::super::protocol::summarize_response(&response[..len]).unwrap();
        assert_eq!(summary.answer_count, 2);
        assert_eq!(
            summary
                .answers
                .iter()
                .map(|answer| answer.value.as_str())
                .collect::<Vec<_>>(),
            vec!["1.2.3.4", "5.6.7.8"]
        );
        let qtype_offset = query.len() - 4;
        query[qtype_offset..qtype_offset + 2].copy_from_slice(&28_u16.to_be_bytes());
        let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
        tcp.write_all(&query).unwrap();
        let mut length = [0_u8; 2];
        tcp.read_exact(&mut length).unwrap();
        let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
        tcp.read_exact(&mut response).unwrap();
        let summary = super::super::protocol::summarize_response(&response).unwrap();
        assert_eq!(summary.answer_count, 1);
        assert_eq!(summary.answers[0].value, "2001:db8::1");
        drop(tcp);
        server.stop();
        let stats = stats.lock().unwrap();
        assert_eq!(stats.queries, 2);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.forwarded, 0);
        assert_eq!(stats.failed, 0);
        let logs = database.query_logs(24, "all", "", 1, 20).unwrap();
        assert_eq!(logs.records.len(), 2);
        for log in logs.records {
            assert!(!log.blocked && !log.failed && !log.forwarded);
            assert_eq!(log.response_source.as_deref(), Some("rewrite"));
            assert!(log.matched_rule.is_some());
        }
        let persisted = database.log_stats(24).unwrap();
        assert_eq!(persisted.queries, 2);
        assert_eq!(persisted.blocked, 0);
    }

    fn ptr_query(name: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&12_u16.to_be_bytes()); // PTR
        packet.extend_from_slice(&1_u16.to_be_bytes()); // IN
        packet
    }

    #[test]
    fn private_reverse_dnsrewrite_takes_priority_over_local_nxdomain() {
        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: "127.0.0.1:9".into(),
            fallback_dns: String::new(),
            dns_cache_enabled: false,
            query_log_enabled: false,
            statistics_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let rules = "||17.1.168.192.in-addr.arpa^$dnsrewrite=NOERROR;PTR;printer.lan";
        let server =
            DnsServer::start(config, rules, stats, database).expect("测试 DNS 服务应可启动");

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("应可设置 UDP 读取超时");
        udp.send_to(
            &ptr_query("17.1.168.192.in-addr.arpa"),
            (Ipv4Addr::LOCALHOST, port),
        )
        .expect("应可发送私有反查");
        let mut response = [0_u8; 512];
        let (len, _) = udp.recv_from(&mut response).expect("应收到 PTR 重写应答");
        let summary = super::super::protocol::summarize_response(&response[..len]).unwrap();
        assert_eq!(summary.code, 0);
        assert_eq!(summary.answer_count, 1);
        assert_eq!(summary.answers[0].record_type, 12);
        assert_eq!(summary.answers[0].value, "printer.lan");

        server.stop();
    }

    /// 带 RFC 7873 cookie 的 example.com A 查询。
    fn cookie_a_query(id: u16, include_server_cookie: bool) -> Vec<u8> {
        let mut packet = example_a_query();
        packet[0..2].copy_from_slice(&id.to_be_bytes());
        packet[11] = 1; // ARCOUNT
        packet.push(0); // OPT owner = root
        packet.extend_from_slice(&41_u16.to_be_bytes());
        packet.extend_from_slice(&1232_u16.to_be_bytes());
        packet.extend_from_slice(&0_u32.to_be_bytes());
        let mut cookie = vec![0, 10, 0, if include_server_cookie { 16 } else { 8 }];
        cookie.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        if include_server_cookie {
            cookie.extend_from_slice(&[0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]);
        }
        packet.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        packet.extend_from_slice(&cookie);
        packet
    }

    #[test]
    fn repeated_cookie_queries_always_reach_the_upstream() {
        let _probe_guard = super::super::upstream::HALF_OPEN_PROBE_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("模拟上游应可绑定");
        upstream
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("应可设置模拟上游超时");
        let upstream_address = upstream.local_addr().expect("应可读取模拟上游地址");
        let upstream_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            let mut served = 0_usize;
            for _ in 0..2 {
                let Ok((len, peer)) = upstream.recv_from(&mut request) else {
                    break;
                };
                served += 1;
                let question_end = super::super::protocol::parse_question(&request[..len])
                    .expect("模拟上游应能解析问题段")
                    .question_end;
                let mut response = request[..question_end].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                response[10..12].copy_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&[
                    0xc0, 0x0c, // NAME 指向问题域名
                    0x00, 0x01, // A
                    0x00, 0x01, // IN
                    0x00, 0x00, 0x01, 0x2c, // TTL 300
                    0x00, 0x04, // RDLENGTH
                    93, 184, 216, 34,
                ]);
                response.extend_from_slice(&[
                    0x00, // OPT owner = root
                    0x00, 0x29, // OPT
                    0x04, 0xd0, // UDP 1232
                    0x00, 0x00, 0x00, 0x00, // extended RCODE / version / flags
                    0x00, 0x14, // RDLENGTH: option header + 16-byte cookie
                    0x00, 0x0a, 0x00, 0x10, // COOKIE, length 16
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // client cookie
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, // server cookie
                ]);
                let _ = upstream.send_to(&response, peer);
            }
            served
        });

        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: upstream_address.to_string(),
            fallback_dns: String::new(),
            use_filters: false,
            dns_cache_enabled: true,
            dns_cache_prefetch_enabled: false,
            dns_cache_optimistic: false,
            query_log_enabled: false,
            statistics_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let server = DnsServer::start(config, "", Arc::clone(&stats), database)
            .expect("测试 DNS 服务应可启动");

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("应可设置 UDP 读取超时");
        let mut response = [0_u8; 512];

        // 第一次：冷查询，必然打上游
        udp.send_to(&cookie_a_query(0x1111, false), (Ipv4Addr::LOCALHOST, port))
            .expect("应可发送首次 cookie 查询");
        let (first_len, _) = udp.recv_from(&mut response).expect("应收到首次应答");
        assert_eq!(response[3] & 0x0f, 0, "首次查询应返回 NOERROR");
        let first = response[..first_len].to_vec();

        // 第二次携带第一次拿到的 server cookie，仍然必须直达上游接受校验。
        udp.send_to(&cookie_a_query(0x2222, true), (Ipv4Addr::LOCALHOST, port))
            .expect("应可发送第二次 cookie 查询");
        let (second_len, _) = udp.recv_from(&mut response).expect("应收到第二次应答");
        let second = response[..second_len].to_vec();

        assert_eq!(&second[0..2], &0x2222_u16.to_be_bytes(), "应改写事务 ID");
        assert!(
            first
                .windows(8)
                .any(|w| w == [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97])
                && second
                    .windows(8)
                    .any(|w| w == [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]),
            "两次应答都应包含上游生成的 server cookie",
        );

        server.stop();
        let served = upstream_thread.join().expect("模拟上游线程应正常结束");
        assert_eq!(
            served, 2,
            "带 cookie 的查询不能命中普通 DNS 缓存，实际只转发了 {served} 次",
        );
    }

    #[test]
    fn private_reverse_queries_never_reach_the_upstream() {
        let _probe_guard = super::super::upstream::HALF_OPEN_PROBE_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("模拟上游应可绑定");
        upstream
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("应可设置模拟上游超时");
        let upstream_address = upstream.local_addr().expect("应可读取模拟上游地址");
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let upstream_seen = Arc::clone(&seen);
        let upstream_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            // 收两轮：私有反查不应该到这里，公网反查应该到
            for _ in 0..2 {
                let Ok((len, peer)) = upstream.recv_from(&mut request) else {
                    break;
                };
                let domain = parse_question(&request[..len])
                    .map(|question| question.domain)
                    .unwrap_or_else(|_| "<解析失败>".to_string());
                upstream_seen.lock().expect("记录锁不应中毒").push(domain);
                let mut response = request[..len].to_vec();
                response[2] = 0x81;
                response[3] = 0x83; // NXDOMAIN
                let _ = upstream.send_to(&response, peer);
            }
        });

        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: upstream_address.to_string(),
            fallback_dns: String::new(),
            dns_cache_enabled: false,
            query_log_enabled: false,
            statistics_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let server = DnsServer::start(config, "", Arc::clone(&stats), database)
            .expect("测试 DNS 服务应可启动");

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("应可设置 UDP 读取超时");

        // 私有地址反查：必须本地应答，且带 SOA 供客户端负缓存
        udp.send_to(
            &ptr_query("17.1.168.192.in-addr.arpa"),
            (Ipv4Addr::LOCALHOST, port),
        )
        .expect("应可发送私有反查");
        let mut response = [0_u8; 512];
        let (len, _) = udp.recv_from(&mut response).expect("应收到本地反查应答");
        assert_eq!(
            response[3] & 0x0f,
            RCODE_NXDOMAIN,
            "私有反查应返回 NXDOMAIN"
        );
        assert_eq!(
            read_u16(&response[..len], 8),
            Some(1),
            "应带 1 条 SOA 权威记录，客户端才能负缓存",
        );

        // 公网地址反查：不能被误拦，必须照常转发
        udp.send_to(
            &ptr_query("8.8.8.8.in-addr.arpa"),
            (Ipv4Addr::LOCALHOST, port),
        )
        .expect("应可发送公网反查");
        let _ = udp.recv_from(&mut response);

        server.stop();
        upstream_thread.join().expect("模拟上游线程应正常结束");

        let seen = seen.lock().expect("记录锁不应中毒").clone();
        assert!(
            !seen
                .iter()
                .any(|domain| domain.ends_with("168.192.in-addr.arpa")),
            "私有地址反查绝不能出网，实际到达上游的是：{seen:?}",
        );
        assert!(
            seen.iter().any(|domain| domain == "8.8.8.8.in-addr.arpa"),
            "公网反查应正常转发，实际到达上游的是：{seen:?}",
        );
    }

    #[test]
    fn private_reverse_domain_route_overrides_client_route() {
        let _probe_guard = super::super::upstream::HALF_OPEN_PROBE_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let internal = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("内网上游应可绑定");
        let public = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("公共上游应可绑定");
        for socket in [&internal, &public] {
            socket
                .set_read_timeout(Some(Duration::from_millis(1200)))
                .expect("应可设置模拟上游超时");
        }
        let internal_address = internal.local_addr().unwrap();
        let public_address = public.local_addr().unwrap();
        let internal_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            let Ok((len, peer)) = internal.recv_from(&mut request) else {
                return false;
            };
            let mut response = request[..len].to_vec();
            response[2] = 0x81;
            response[3] = 0x83;
            internal.send_to(&response, peer).is_ok()
        });
        let public_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            public.recv_from(&mut request).is_ok()
        });

        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: public_address.to_string(),
            fallback_dns: String::new(),
            domain_upstream_rules: format!("*.168.192.in-addr.arpa => {internal_address}"),
            client_upstream_rules: format!("127.0.0.1/32 => {public_address}"),
            dns_cache_enabled: false,
            query_log_enabled: false,
            statistics_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let server = DnsServer::start(config, "", stats, database).expect("测试 DNS 服务应可启动");

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("应可设置 UDP 读取超时");
        udp.send_to(
            &ptr_query("17.1.168.192.in-addr.arpa"),
            (Ipv4Addr::LOCALHOST, port),
        )
        .expect("应可发送私有反查");
        let mut response = [0_u8; 512];
        let (len, _) = udp.recv_from(&mut response).expect("应收到内网上游应答");
        assert_eq!(response[..len][3] & 0x0f, RCODE_NXDOMAIN);

        server.stop();
        assert!(
            internal_thread.join().expect("内网上游线程应正常结束"),
            "私有反查应命中显式域名分流",
        );
        assert!(
            !public_thread.join().expect("公共上游线程应正常结束"),
            "客户端分流不能覆盖私有反查的显式域名分流",
        );
    }

    #[test]
    fn udp_rebinding_response_is_blocked_before_reaching_the_client() {
        let _probe_guard = super::super::upstream::HALF_OPEN_PROBE_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let upstream =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("模拟上游 UDP 服务应可绑定");
        upstream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("应可设置模拟上游超时");
        let upstream_address = upstream.local_addr().expect("应可读取模拟上游地址");
        let upstream_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            let (request_len, peer) = upstream
                .recv_from(&mut request)
                .expect("模拟上游应收到查询");
            let mut response = request[..request_len].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&[
                0xc0, 0x0c, // NAME 指向问题域名。
                0x00, 0x01, // A
                0x00, 0x01, // IN
                0x00, 0x00, 0x00, 0x3c, // TTL 60
                0x00, 0x04, // RDLENGTH
                192, 168, 1, 10,
            ]);
            upstream
                .send_to(&response, peer)
                .expect("模拟上游应可返回私网地址");
        });

        let port = available_local_port();
        let config = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: upstream_address.to_string(),
            fallback_dns: String::new(),
            dns_cache_enabled: false,
            query_log_enabled: false,
            statistics_enabled: false,
            ..AppConfig::default()
        };
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let server = DnsServer::start(config, "", Arc::clone(&stats), database)
            .expect("测试 DNS 服务应可启动");

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP 客户端应可绑定");
        udp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("应可设置 UDP 读取超时");
        udp.send_to(&example_a_query(), (Ipv4Addr::LOCALHOST, port))
            .expect("应可发送 UDP 查询");
        let mut response = [0_u8; 512];
        let (response_len, _) = udp.recv_from(&mut response).expect("应收到拦截响应");

        assert_eq!(&response[response_len - 4..response_len], &[0, 0, 0, 0]);
        let snapshot = stats.lock().expect("统计锁不应中毒").clone();
        assert_eq!(snapshot.rebinding_blocked_total, 1);
        assert_eq!(snapshot.blocked, 1);

        server.stop();
        upstream_thread.join().expect("模拟上游线程应正常结束");
    }
}
