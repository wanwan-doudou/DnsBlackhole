use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};

use crate::{config::AppConfig, database::Database};

use super::{
    access::ClientAccess,
    cache::{DnsCacheConfig, DnsCacheStore},
    filter_runtime::{SharedFilterRuntime, build_filter_runtime, share_filter_runtime},
    protocol::MAX_DNS_PACKET_SIZE,
    stats::{DnsStats, record_error, reset_stats},
    upstream::build_runtime_upstreams,
    worker::{
        DnsResponseTarget, DnsWorkItem, DnsWorkerContext, PENDING_QUERY_SHARDS, PendingQueries,
        QueryLogMessage, dns_worker_loop,
    },
};

const UDP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const TCP_ACCEPT_SLEEP: Duration = Duration::from_millis(100);
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_MAX_CONNECTIONS: usize = 256;
const DNS_WORK_QUEUE_CAPACITY: usize = 8192;
const QUERY_LOG_QUEUE_CAPACITY: usize = 16384;
const QUERY_LOG_BATCH_SIZE: usize = 128;
const QUERY_LOG_BATCH_WAIT_TIMEOUT: Duration = Duration::from_millis(10);
const DNS_MIN_WORKERS: usize = 4;
const DNS_MAX_WORKERS: usize = 32;
const DNS_CACHE_SHARDS: usize = 64;

pub struct DnsServer {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    cache: Option<Arc<DnsCacheStore>>,
    filter_runtime: SharedFilterRuntime,
}

impl DnsServer {
    pub fn start(
        config: AppConfig,
        rules_text: &str,
        stats: Arc<Mutex<DnsStats>>,
        database: Arc<Database>,
    ) -> Result<Self, String> {
        config.validate()?;

        let listen_addrs = config.listen_socket_addrs()?;
        let bootstrap_servers = config.bootstrap_servers()?;
        let upstream_servers = Arc::new(build_runtime_upstreams(
            config.upstream_servers()?,
            &bootstrap_servers,
        ));
        let fallback_upstream_servers = Arc::new(build_runtime_upstreams(
            config.fallback_servers()?,
            &bootstrap_servers,
        ));
        let upstream_mode = config.upstream_mode.clone();
        let query_log_enabled = config.query_log_enabled;
        let anonymize_client_ip = config.anonymize_client_ip;
        let access = Arc::new(ClientAccess::from_config(&config)?);
        let refuse_any = config.refuse_any;
        let dns_cache_config = DnsCacheConfig::from_config(&config);
        let dns_cache =
            DnsCacheStore::from_config(dns_cache_config.clone(), DNS_CACHE_SHARDS).map(Arc::new);
        let dns_cache_config = dns_cache.as_ref().map(|_| dns_cache_config);
        let filter_runtime = share_filter_runtime(build_filter_runtime(&config, rules_text));
        let listeners = listen_addrs
            .into_iter()
            .map(|addr| bind_listener_pair(addr, addr.is_ipv6() && config.listen_ipv6))
            .collect::<Result<Vec<_>, _>>()?;

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
            upstream_servers,
            fallback_upstream_servers,
            upstream_mode,
            next_upstream: AtomicUsize::new(0),
            fallback_next_upstream: AtomicUsize::new(0),
            access,
            refuse_any,
            filter_runtime: Arc::clone(&filter_runtime),
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

        Ok(Self {
            stop,
            threads,
            cache: dns_cache,
            filter_runtime,
        })
    }

    pub fn clear_cache(&self) -> Result<(), String> {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
        Ok(())
    }

    pub(crate) fn filter_runtime_handle(&self) -> SharedFilterRuntime {
        Arc::clone(&self.filter_runtime)
    }

    pub fn rule_summary(&self) -> super::RuleSummary {
        super::filter_runtime::current_filter_runtime(&self.filter_runtime).summary()
    }

    pub fn has_finished_threads(&self) -> bool {
        self.threads.iter().any(JoinHandle::is_finished)
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
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
            record_error(&stats, "TCP DNS 连接数已满，已拒绝新连接".to_string());
            continue;
        }

        let connection_slot = TcpConnectionSlot {
            active_connections: Arc::clone(&active_connections),
        };
        let work_senders = work_senders.clone();
        let stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let _slot = connection_slot;
            handle_tcp_connection(stream, client_addr, work_senders, stats, stop);
        });
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
        };

        match dispatch_dns_work(&work_senders, work_item, &mut next_worker) {
            Ok(()) => {}
            Err(DispatchDnsWorkError::Full) => {
                record_error(&stats, "DNS 请求队列已满，已丢弃 TCP 请求".to_string());
                break;
            }
            Err(DispatchDnsWorkError::Disconnected) => break,
        }

        match response_receiver.recv_timeout(TCP_RESPONSE_TIMEOUT) {
            Ok(Some(response)) => {
                if let Err(error) = write_tcp_dns_response(&mut stream, &response) {
                    record_error(&stats, format!("写入 TCP DNS 响应失败：{error}"));
                    break;
                }
            }
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
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(false);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(true)
}

fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> Result<(), String> {
    let response_len =
        u16::try_from(response.len()).map_err(|_| "TCP DNS 响应长度超过 65535 字节".to_string())?;
    stream
        .write_all(&response_len.to_be_bytes())
        .and_then(|_| stream.write_all(response))
        .map_err(|error| error.to_string())
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
    fn finished_runtime_thread_marks_server_unhealthy() {
        let finished_thread = thread::spawn(|| {});
        while !finished_thread.is_finished() {
            thread::yield_now();
        }
        let server = DnsServer {
            stop: Arc::new(AtomicBool::new(false)),
            threads: vec![finished_thread],
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
}
