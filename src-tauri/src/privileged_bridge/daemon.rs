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

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    config::AppConfig,
    database::Database,
    service_core::{
        AppState, clear_dns_cache_blocking, clear_filter_cache_blocking, query_logs_blocking,
        save_config_blocking, spawn_filter_auto_update, spawn_initial_runtime,
        spawn_runtime_watchdog, start_dns_blocking, stop_dns_blocking, update_filters_blocking,
    },
    storage,
};

use super::{
    BRIDGE_PROTOCOL_VERSION, BRIDGE_SOCKET_PATH, HelloParams, HelloResult, RpcRequest, RpcResponse,
    read_message, write_message,
};

const SYSTEM_DATA_DIR: &str = "/Library/Application Support/DnsBlackhole";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Deserialize)]
struct StatusParams {
    #[serde(default)]
    force_log_stats: bool,
    #[serde(default = "default_true")]
    include_log_stats: bool,
}

#[derive(Debug, Deserialize)]
struct QueryLogsParams {
    filter: Option<String>,
    search: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ConfigParams {
    config: AppConfig,
}

#[derive(Debug, Deserialize)]
struct MigrationParams {
    target_path: String,
}

pub fn run_daemon() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("macOS DNS 后台服务必须以 root 身份运行".to_string());
    }

    let state = initialize_state()?;
    spawn_initial_runtime(Arc::clone(&state));
    spawn_runtime_watchdog(Arc::clone(&state));
    spawn_filter_auto_update(Arc::clone(&state), |_| {});

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
                thread::spawn(move || {
                    if let Err(error) = handle_client(stream, state, restart_requested) {
                        eprintln!("{error}");
                    }
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

fn initialize_state() -> Result<Arc<AppState>, String> {
    let bootstrap = storage::initialize_at(PathBuf::from(SYSTEM_DATA_DIR))?;
    let database = Arc::new(Database::open(&bootstrap.data_dir)?);
    let config = database.load_or_default_config()?;
    storage::finish_pending_cleanup(&bootstrap.default_dir, &bootstrap.data_dir)?;
    let state = Arc::new(AppState::new(
        config,
        database,
        bootstrap.default_dir,
        bootstrap.data_dir,
    ));
    if let Some(error) = bootstrap.migration_error {
        state.set_error(Some(error));
    }
    Ok(state)
}

/// 将从非阻塞 listener 接收的客户端连接恢复为阻塞模式，保证帧读取等待客户端写入。
fn prepare_accepted_stream(stream: UnixStream) -> Result<UnixStream, String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("设置后台服务 IPC 客户端阻塞模式失败：{error}"))?;
    Ok(stream)
}

fn handle_client(
    mut stream: UnixStream,
    state: Arc<AppState>,
    restart_requested: Arc<AtomicBool>,
) -> Result<(), String> {
    verify_peer(&stream)?;
    if !perform_handshake(&mut stream)? {
        return Ok(());
    }

    loop {
        let request: RpcRequest = match read_message(&mut stream) {
            Ok(request) => request,
            Err(error)
                if error.contains("UnexpectedEof")
                    || error.contains("failed to fill whole buffer") =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match dispatch_request(&state, &request.method, request.params) {
            Ok((result, should_restart)) => {
                write_response(
                    &mut stream,
                    RpcResponse {
                        id: request.id,
                        result: Some(result),
                        error: None,
                    },
                )?;
                if should_restart {
                    restart_requested.store(true, Ordering::Release);
                    return Ok(());
                }
            }
            Err(error) => write_error(&mut stream, request.id, error)?,
        }
    }
}

fn perform_handshake(stream: &mut UnixStream) -> Result<bool, String> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 写入超时失败：{error}"))?;

    let request: RpcRequest = read_message(stream)?;
    if request.method != "hello" {
        return Err("客户端未执行 IPC 握手".to_string());
    }
    let hello: HelloParams = parse_params(request.params)?;
    if hello.protocol_version != BRIDGE_PROTOCOL_VERSION {
        write_error(
            stream,
            request.id,
            format!(
                "客户端 IPC 协议版本不兼容：服务 {}，客户端 {}",
                BRIDGE_PROTOCOL_VERSION, hello.protocol_version
            ),
        )?;
        return Ok(false);
    }
    write_result(
        stream,
        request.id,
        &HelloResult {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )?;
    // 握手后保留有限的请求级超时，避免异常客户端的空闲连接永久占用服务线程。
    // （此前注释称 Darwin 对 set_read_timeout(None) 返回 EDOM，经核对 xnu 源码不成立，
    // 0.1.33 断管的真实根因未定论，勿据此排查。）
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置 IPC 请求读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置 IPC 请求写入超时失败：{error}"))?;
    Ok(true)
}

fn dispatch_request(
    state: &Arc<AppState>,
    method: &str,
    params: Value,
) -> Result<(Value, bool), String> {
    let result = match method {
        "ping" => Value::Null,
        "get_config" => to_value(state.current_config()?)?,
        "get_storage_info" => to_value(storage::storage_info(
            &state.default_data_dir,
            &state.data_dir,
        )?)?,
        "request_data_migration" => {
            let params: MigrationParams = parse_params(params)?;
            let target_path = Path::new(params.target_path.trim());
            if target_path.as_os_str().is_empty() {
                return Err("请选择新的数据存储目录".to_string());
            }
            let info =
                storage::request_migration(&state.default_data_dir, &state.data_dir, target_path)?;
            let should_restart = info.pending_path.is_some();
            return Ok((to_value(info)?, should_restart));
        }
        "save_config" => {
            let params: ConfigParams = parse_params(params)?;
            to_value(save_config_blocking(Arc::clone(state), params.config)?)?
        }
        "get_status" => {
            let params: StatusParams = parse_params(params)?;
            to_value(state.status_with_log_stats(params.force_log_stats, params.include_log_stats))?
        }
        "get_query_logs" => {
            let params: QueryLogsParams = parse_params(params)?;
            to_value(query_logs_blocking(
                Arc::clone(state),
                params.filter,
                params.search,
                params.page,
                params.page_size,
            )?)?
        }
        "update_filters" => {
            let params: ConfigParams = parse_params(params)?;
            to_value(update_filters_blocking(Arc::clone(state), params.config)?)?
        }
        "start_dns" => to_value(start_dns_blocking(Arc::clone(state))?)?,
        "stop_dns" => to_value(stop_dns_blocking(Arc::clone(state))?)?,
        "clear_dns_cache" => to_value(clear_dns_cache_blocking(state)?)?,
        "clear_filter_cache" => to_value(clear_filter_cache_blocking(Arc::clone(state))?)?,
        "restart_service" => return Ok((Value::Null, true)),
        _ => return Err(format!("未知的后台服务方法：{method}")),
    };
    Ok((result, false))
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

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|error| format!("后台服务请求参数无效：{error}"))
}

fn to_value<T: Serialize>(result: T) -> Result<Value, String> {
    serde_json::to_value(result).map_err(|error| format!("序列化后台服务响应失败：{error}"))
}

fn write_result<T: Serialize>(stream: &mut UnixStream, id: u64, result: &T) -> Result<(), String> {
    write_response(
        stream,
        RpcResponse {
            id,
            result: Some(to_value(result)?),
            error: None,
        },
    )
}

fn write_error(stream: &mut UnixStream, id: u64, error: String) -> Result<(), String> {
    write_response(
        stream,
        RpcResponse {
            id,
            result: None,
            error: Some(error),
        },
    )
}

fn write_response(stream: &mut UnixStream, response: RpcResponse) -> Result<(), String> {
    write_message(stream, &response)
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
