use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};

use super::{
    BRIDGE_PROTOCOL_VERSION, BRIDGE_SOCKET_PATH, BridgeTransport, ClientMessage, ServiceMessage,
    read_message, write_message,
};

const DNS_PACKET_SIZE: usize = 65_535;
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_MAX_CONNECTIONS: usize = 256;
// 等待 GUI 响应的查询上限：超过说明 GUI 处理不过来，直接丢弃新请求让客户端重试
const MAX_PENDING_QUERIES: usize = 4096;
const PENDING_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
// 特权 daemon 只服务 DNS：低位端口仅允许 53，防止本机进程借 root 绑定任意特权端口
const ALLOWED_PRIVILEGED_PORT: u16 = 53;
const MAX_LISTEN_ADDRS: usize = 16;

// UDP 响应由 IPC 读循环直接回写 socket，TCP 响应交还给各自的连接线程
enum PendingTarget {
    Udp {
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
    },
    Tcp(mpsc::SyncSender<Option<Vec<u8>>>),
}

struct PendingEntry {
    target: PendingTarget,
    created: Instant,
}

type PendingResponses = Arc<Mutex<HashMap<u64, PendingEntry>>>;
type SharedWriter = Arc<Mutex<UnixStream>>;

pub fn run_daemon() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("dnsblackhole-service 必须由 macOS LaunchDaemon 以 root 身份运行".to_string());
    }

    let socket_path = Path::new(BRIDGE_SOCKET_PATH);
    let socket_dir = socket_path
        .parent()
        .ok_or_else(|| "后台服务 IPC 路径缺少父目录".to_string())?;
    fs::create_dir_all(socket_dir)
        .map_err(|error| format!("创建后台服务 IPC 目录失败：{error}"))?;
    fs::set_permissions(socket_dir, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("设置后台服务 IPC 目录权限失败：{error}"))?;
    if socket_path.exists() {
        fs::remove_file(socket_path).map_err(|error| format!("清理旧 IPC socket 失败：{error}"))?;
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|error| format!("创建后台服务 IPC 失败：{error}"))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("设置后台服务 IPC 权限失败：{error}"))?;

    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|error| format!("接受后台服务 IPC 连接失败：{error}"))?;
        if let Err(error) = handle_client(stream) {
            eprintln!("{error}");
        }
    }
}

fn handle_client(mut stream: UnixStream) -> Result<(), String> {
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 写入超时失败：{error}"))?;

    match read_message::<_, ClientMessage>(&mut stream)? {
        ClientMessage::Hello {
            protocol_version,
            app_version: _,
        } if protocol_version == BRIDGE_PROTOCOL_VERSION => {}
        ClientMessage::Hello {
            protocol_version, ..
        } => {
            return Err(format!(
                "客户端 IPC 协议版本不兼容：服务 {}，客户端 {protocol_version}",
                BRIDGE_PROTOCOL_VERSION
            ));
        }
        _ => return Err("客户端未执行 IPC 握手".to_string()),
    }

    write_message(
        &mut stream,
        &ServiceMessage::Hello {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )?;
    // 握手完成后改为阻塞读：带超时的 read_exact 一旦部分读取会破坏帧边界，
    // 连接的终止统一依赖对端关闭或本端 shutdown
    stream
        .set_read_timeout(None)
        .map_err(|error| format!("设置 IPC 阻塞读取失败：{error}"))?;

    let writer = Arc::new(Mutex::new(
        stream
            .try_clone()
            .map_err(|error| format!("复制 IPC 连接失败：{error}"))?,
    ));
    let pending: PendingResponses = Arc::new(Mutex::new(HashMap::new()));
    let next_request_id = Arc::new(AtomicU64::new(1));
    let mut runtime: Option<NetworkRuntime> = None;

    let result = loop {
        let message = match read_message::<_, ClientMessage>(&mut stream) {
            Ok(message) => message,
            Err(error) => break Err(error),
        };

        match message {
            ClientMessage::Configure {
                request_id,
                listen_addrs,
            } => {
                fail_pending(&pending);
                if let Some(runtime) = runtime.take() {
                    runtime.stop();
                }
                let start_result = validate_listen_addrs(&listen_addrs).and_then(|_| {
                    NetworkRuntime::start(
                        listen_addrs,
                        Arc::clone(&writer),
                        Arc::clone(&pending),
                        Arc::clone(&next_request_id),
                    )
                });
                match start_result {
                    Ok(new_runtime) => {
                        runtime = Some(new_runtime);
                        send_result(&writer, request_id, None)?;
                    }
                    Err(error) => {
                        send_result(&writer, request_id, Some(error))?;
                    }
                }
            }
            ClientMessage::Stop { request_id } => {
                fail_pending(&pending);
                if let Some(runtime) = runtime.take() {
                    runtime.stop();
                }
                send_result(&writer, request_id, None)?;
            }
            ClientMessage::Response {
                request_id,
                response,
            } => {
                let entry = pending
                    .lock()
                    .ok()
                    .and_then(|mut pending| pending.remove(&request_id));
                if let Some(entry) = entry {
                    dispatch_response(entry.target, response);
                }
            }
            ClientMessage::Ping { request_id } => {
                send_result(&writer, request_id, None)?;
            }
            ClientMessage::Hello { .. } => {}
        }
    };

    if let Some(runtime) = runtime.take() {
        runtime.stop();
    }
    fail_pending(&pending);
    result
}

fn dispatch_response(target: PendingTarget, response: Option<Vec<u8>>) {
    match target {
        PendingTarget::Udp {
            socket,
            client_addr,
        } => {
            if let Some(response) = response {
                let _ = socket.send_to(&response, client_addr);
            }
        }
        PendingTarget::Tcp(sender) => {
            let _ = sender.try_send(response);
        }
    }
}

fn validate_listen_addrs(listen_addrs: &[SocketAddr]) -> Result<(), String> {
    if listen_addrs.is_empty() {
        return Err("DNS 监听地址不能为空".to_string());
    }
    if listen_addrs.len() > MAX_LISTEN_ADDRS {
        return Err(format!(
            "DNS 监听地址数量超过上限 {MAX_LISTEN_ADDRS}：{}",
            listen_addrs.len()
        ));
    }
    for addr in listen_addrs {
        let port = addr.port();
        if port < 1024 && port != ALLOWED_PRIVILEGED_PORT {
            return Err(format!(
                "后台服务只允许监听 DNS 端口 {ALLOWED_PRIVILEGED_PORT} 或非特权端口，拒绝 {addr}"
            ));
        }
    }
    Ok(())
}

fn verify_peer(stream: &UnixStream) -> Result<(), String> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(format!(
            "读取 IPC 客户端身份失败：{}",
            std::io::Error::last_os_error()
        ));
    }

    let console_uid = fs::metadata("/dev/console")
        .map(|metadata| metadata.uid())
        .map_err(|error| format!("读取当前 macOS 控制台用户失败：{error}"))?;
    if uid != 0 && uid != console_uid {
        return Err(format!("拒绝非当前控制台用户连接后台服务：uid={uid}"));
    }
    Ok(())
}

fn send_result(
    writer: &SharedWriter,
    request_id: u64,
    error: Option<String>,
) -> Result<(), String> {
    let mut writer = writer
        .lock()
        .map_err(|_| "后台服务 IPC 写入锁已损坏".to_string())?;
    write_message(&mut *writer, &ServiceMessage::Result { request_id, error })
}

// IPC 写失败后帧边界已不可信，立即关闭连接促使双方走重连恢复
fn send_query_or_shutdown(writer: &SharedWriter, message: &ServiceMessage) -> bool {
    let Ok(mut writer) = writer.lock() else {
        return false;
    };
    if let Err(error) = write_message(&mut *writer, message) {
        eprintln!("{error}");
        let _ = writer.shutdown(Shutdown::Both);
        return false;
    }
    true
}

fn fail_pending(pending: &PendingResponses) {
    let targets = pending
        .lock()
        .map(|mut pending| {
            pending
                .drain()
                .map(|(_, entry)| entry.target)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for target in targets {
        dispatch_response(target, None);
    }
}

fn prune_expired_pending(pending: &PendingResponses) {
    if let Ok(mut pending) = pending.lock() {
        pending.retain(|_, entry| entry.created.elapsed() < RESPONSE_TIMEOUT);
    }
}

fn register_pending(pending: &PendingResponses, request_id: u64, target: PendingTarget) -> bool {
    let Ok(mut pending) = pending.lock() else {
        return false;
    };
    if pending.len() >= MAX_PENDING_QUERIES {
        return false;
    }
    pending.insert(
        request_id,
        PendingEntry {
            target,
            created: Instant::now(),
        },
    );
    true
}

struct NetworkRuntime {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl NetworkRuntime {
    fn start(
        listen_addrs: Vec<SocketAddr>,
        writer: SharedWriter,
        pending: PendingResponses,
        next_request_id: Arc<AtomicU64>,
    ) -> Result<Self, String> {
        let mut listeners = Vec::with_capacity(listen_addrs.len());
        for addr in listen_addrs {
            listeners.push(bind_listener_pair(addr)?);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let active_tcp_connections = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::with_capacity(listeners.len() * 2);
        for listener in listeners {
            let udp_stop = Arc::clone(&stop);
            let udp_writer = Arc::clone(&writer);
            let udp_pending = Arc::clone(&pending);
            let udp_next_request_id = Arc::clone(&next_request_id);
            threads.push(thread::spawn(move || {
                serve_udp(
                    listener.udp,
                    udp_writer,
                    udp_pending,
                    udp_next_request_id,
                    udp_stop,
                );
            }));

            let tcp_stop = Arc::clone(&stop);
            let tcp_writer = Arc::clone(&writer);
            let tcp_pending = Arc::clone(&pending);
            let tcp_next_request_id = Arc::clone(&next_request_id);
            let tcp_connections = Arc::clone(&active_tcp_connections);
            threads.push(thread::spawn(move || {
                serve_tcp(
                    listener.tcp,
                    tcp_writer,
                    tcp_pending,
                    tcp_next_request_id,
                    tcp_stop,
                    tcp_connections,
                );
            }));
        }
        Ok(Self { stop, threads })
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

struct ListenerPair {
    udp: Arc<UdpSocket>,
    tcp: Arc<TcpListener>,
}

fn bind_listener_pair(addr: SocketAddr) -> Result<ListenerPair, String> {
    let only_v6 = addr.is_ipv6();
    let udp = bind_udp(addr, only_v6)
        .map_err(|error| format!("后台服务监听 UDP {addr} 失败：{error}"))?;
    udp.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("设置 UDP {addr} 读取超时失败：{error}"))?;

    let tcp = bind_tcp(addr, only_v6)
        .map_err(|error| format!("后台服务监听 TCP {addr} 失败：{error}"))?;
    tcp.set_nonblocking(true)
        .map_err(|error| format!("设置 TCP {addr} 非阻塞失败：{error}"))?;

    Ok(ListenerPair {
        udp: Arc::new(udp),
        tcp: Arc::new(tcp),
    })
}

fn bind_udp(addr: SocketAddr, only_v6: bool) -> std::io::Result<UdpSocket> {
    if !only_v6 {
        return UdpSocket::bind(addr);
    }
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

fn bind_tcp(addr: SocketAddr, only_v6: bool) -> std::io::Result<TcpListener> {
    if !only_v6 {
        return TcpListener::bind(addr);
    }
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

fn serve_udp(
    socket: Arc<UdpSocket>,
    writer: SharedWriter,
    pending: PendingResponses,
    next_request_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; DNS_PACKET_SIZE];
    let mut last_prune = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if last_prune.elapsed() >= PENDING_PRUNE_INTERVAL {
            prune_expired_pending(&pending);
            last_prune = Instant::now();
        }

        let (length, client_addr) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => {
                eprintln!("后台服务接收 UDP DNS 请求失败：{error}");
                continue;
            }
        };
        if length == 0 {
            continue;
        }

        // 只登记查询并转发给 GUI，响应由 IPC 读循环异步回写，避免慢查询阻塞收包
        let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        let target = PendingTarget::Udp {
            socket: Arc::clone(&socket),
            client_addr,
        };
        if !register_pending(&pending, request_id, target) {
            prune_expired_pending(&pending);
            continue;
        }
        let message = ServiceMessage::Query {
            request_id,
            transport: BridgeTransport::Udp,
            client_addr,
            query: buffer[..length].to_vec(),
        };
        if !send_query_or_shutdown(&writer, &message) {
            if let Ok(mut pending) = pending.lock() {
                pending.remove(&request_id);
            }
            return;
        }
    }
}

fn serve_tcp(
    listener: Arc<TcpListener>,
    writer: SharedWriter,
    pending: PendingResponses,
    next_request_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (stream, client_addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => {
                eprintln!("后台服务接受 TCP DNS 连接失败：{error}");
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };

        if active_connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < TCP_MAX_CONNECTIONS).then_some(current + 1)
            })
            .is_err()
        {
            continue;
        }

        let writer = Arc::clone(&writer);
        let pending = Arc::clone(&pending);
        let next_request_id = Arc::clone(&next_request_id);
        let stop = Arc::clone(&stop);
        let active_connections = Arc::clone(&active_connections);
        thread::spawn(move || {
            handle_tcp_connection(stream, client_addr, writer, pending, next_request_id, stop);
            active_connections.fetch_sub(1, Ordering::AcqRel);
        });
    }

    while active_connections.load(Ordering::Acquire) > 0 {
        thread::sleep(Duration::from_millis(100));
    }
}

fn handle_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    writer: SharedWriter,
    pending: PendingResponses,
    next_request_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    while !stop.load(Ordering::Relaxed) {
        let query = match read_tcp_query(&mut stream, &stop) {
            Ok(Some(query)) => query,
            Ok(None) => break,
            Err(error) => {
                eprintln!("后台服务读取 TCP DNS 请求失败：{error}");
                break;
            }
        };
        let Some(response) = forward_tcp_query(
            &writer,
            &pending,
            &next_request_id,
            client_addr,
            query,
        ) else {
            break;
        };
        let Ok(length) = u16::try_from(response.len()) else {
            break;
        };
        if stream
            .write_all(&length.to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .is_err()
        {
            break;
        }
    }
}

fn read_tcp_query(stream: &mut TcpStream, stop: &AtomicBool) -> Result<Option<Vec<u8>>, String> {
    let deadline = Instant::now() + TCP_IDLE_TIMEOUT;
    let mut length = [0_u8; 2];
    if !read_until(stream, &mut length, stop, deadline, true)? {
        return Ok(None);
    }
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Ok(None);
    }
    let mut query = vec![0_u8; length];
    if !read_until(stream, &mut query, stop, deadline, false)? {
        return Ok(None);
    }
    Ok(Some(query))
}

fn read_until(
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
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        stream
            .set_read_timeout(Some(remaining.min(IO_TIMEOUT)))
            .map_err(|error| error.to_string())?;
        match stream.read(&mut target[offset..]) {
            Ok(0) if clean_eof_if_empty && offset == 0 => return Ok(false),
            Ok(0) => return Err("TCP DNS 请求在完整读取前关闭".to_string()),
            Ok(length) => offset += length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return Ok(false),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(true)
}

fn forward_tcp_query(
    writer: &SharedWriter,
    pending: &PendingResponses,
    next_request_id: &AtomicU64,
    client_addr: SocketAddr,
    query: Vec<u8>,
) -> Option<Vec<u8>> {
    let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
    let (response_sender, response_receiver) = mpsc::sync_channel(1);
    if !register_pending(pending, request_id, PendingTarget::Tcp(response_sender)) {
        return None;
    }

    let message = ServiceMessage::Query {
        request_id,
        transport: BridgeTransport::Tcp,
        client_addr,
        query,
    };
    if !send_query_or_shutdown(writer, &message) {
        if let Ok(mut pending) = pending.lock() {
            pending.remove(&request_id);
        }
        return None;
    }

    let response = response_receiver
        .recv_timeout(RESPONSE_TIMEOUT)
        .ok()
        .flatten();
    if let Ok(mut pending) = pending.lock() {
        pending.remove(&request_id);
    }
    response
}
