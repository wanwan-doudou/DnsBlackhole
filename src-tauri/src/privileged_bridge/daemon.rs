use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use super::{
    BRIDGE_SOCKET_PATH,
    rpc_server::{handle_requests, initialize_state, perform_handshake, start_background_tasks},
};

const SYSTEM_DATA_DIR: &str = "/Library/Application Support/DnsBlackhole";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn run_daemon() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("macOS DNS 后台服务必须以 root 身份运行".to_string());
    }

    let state = initialize_state(PathBuf::from(SYSTEM_DATA_DIR))?;
    start_background_tasks(&state);

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
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("设置后台服务 IPC 非阻塞失败：{error}"))?;

    let restart_requested = Arc::new(AtomicBool::new(false));
    while !restart_requested.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let stream = match prepare_accepted_stream(stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("{error}");
                        continue;
                    }
                };
                let state = Arc::clone(&state);
                let restart_requested = Arc::clone(&restart_requested);
                thread::spawn(move || match handle_macos_client(stream, state) {
                    Ok(true) => restart_requested.store(true, Ordering::Release),
                    Ok(false) => {}
                    Err(error) => eprintln!("{error}"),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(format!("接受后台服务 IPC 连接失败：{error}")),
        }
    }

    state.shutdown();
    let _ = fs::remove_file(socket_path);
    Ok(())
}

/// 将从非阻塞 listener 接收的客户端连接恢复为阻塞模式，保证帧读取等待客户端写入。
fn prepare_accepted_stream(stream: UnixStream) -> Result<UnixStream, String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("设置后台服务 IPC 客户端阻塞模式失败：{error}"))?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置后台服务握手读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置后台服务握手写入超时失败：{error}"))?;
    Ok(stream)
}

fn handle_macos_client(
    mut stream: UnixStream,
    state: Arc<crate::service_core::AppState>,
) -> Result<bool, String> {
    verify_peer(&stream)?;
    if !perform_handshake(&mut stream)? {
        return Ok(false);
    }
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务请求读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务请求写入超时失败：{error}"))?;
    handle_requests(stream, state)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::privileged_bridge::rpc_server::write_result;
    use crate::privileged_bridge::{
        BRIDGE_PROTOCOL_VERSION, HelloParams, RpcRequest, RpcResponse, read_message, write_message,
    };

    #[test]
    fn handshake_keeps_connection_open_for_rpc_request() {
        let (mut client, mut server) = UnixStream::pair().expect("应能创建 Unix socket 对");
        client
            .set_read_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端读取超时");
        client
            .set_write_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端写入超时");

        let server_thread = thread::spawn(move || -> Result<(), String> {
            assert!(perform_handshake(&mut server)?);
            let request: RpcRequest = read_message(&mut server)?;
            assert_eq!(request.id, 2);
            assert_eq!(request.method, "get_storage_info");
            write_result(&mut server, request.id, &serde_json::json!({ "ok": true }))
        });

        write_message(
            &mut client,
            &RpcRequest {
                id: 1,
                method: "hello".to_string(),
                params: serde_json::to_value(HelloParams {
                    protocol_version: BRIDGE_PROTOCOL_VERSION,
                    app_version: env!("CARGO_PKG_VERSION").to_string(),
                })
                .expect("握手参数应可序列化"),
            },
        )
        .expect("应能写入握手请求");
        let hello: RpcResponse = read_message(&mut client).expect("应能读取握手响应");
        assert_eq!(hello.id, 1);
        assert!(hello.error.is_none());

        write_message(
            &mut client,
            &RpcRequest {
                id: 2,
                method: "get_storage_info".to_string(),
                params: serde_json::json!({}),
            },
        )
        .expect("握手后仍应能写入业务请求");
        let response: RpcResponse = read_message(&mut client).expect("应能读取业务响应");
        assert_eq!(response.id, 2);
        assert_eq!(response.result.expect("业务响应应有结果")["ok"], true);

        server_thread
            .join()
            .expect("服务端测试线程不应 panic")
            .expect("服务端握手与业务请求应成功");
    }

    // 验证真实非阻塞 listener 接收的连接会等待延迟到达的握手请求。
    #[test]
    fn accepted_stream_from_nonblocking_listener_waits_for_handshake() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间应晚于 UNIX_EPOCH")
            .as_nanos();
        let socket_path =
            std::path::PathBuf::from(format!("/tmp/dbh-{}-{unique}.sock", std::process::id()));

        let listener = UnixListener::bind(&socket_path).expect("应能绑定临时 Unix listener");
        listener
            .set_nonblocking(true)
            .expect("应能设置 listener 非阻塞");

        let server_thread = thread::spawn(move || -> Result<(), String> {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let mut stream = prepare_accepted_stream(stream)?;
                        assert!(perform_handshake(&mut stream)?);
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(error) => return Err(format!("测试 listener accept 失败：{error}")),
                }
            }
        });

        let mut client = UnixStream::connect(&socket_path).expect("客户端应能连接临时 socket");
        client
            .set_read_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端读取超时");
        client
            .set_write_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端写入超时");

        thread::sleep(Duration::from_millis(50));
        write_message(
            &mut client,
            &RpcRequest {
                id: 1,
                method: "hello".to_string(),
                params: serde_json::to_value(HelloParams {
                    protocol_version: BRIDGE_PROTOCOL_VERSION,
                    app_version: env!("CARGO_PKG_VERSION").to_string(),
                })
                .expect("握手参数应可序列化"),
            },
        )
        .expect("延迟写入握手请求后服务端仍应等待");
        let hello: RpcResponse = read_message(&mut client).expect("应能读取握手响应");
        assert_eq!(hello.id, 1);
        assert!(hello.error.is_none());

        server_thread
            .join()
            .expect("服务端测试线程不应 panic")
            .expect("服务端应能等待延迟到达的握手请求");
        let _ = fs::remove_file(&socket_path);
    }
}
