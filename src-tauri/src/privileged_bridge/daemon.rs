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

fn handle_client(
    mut stream: UnixStream,
    state: Arc<AppState>,
    restart_requested: Arc<AtomicBool>,
) -> Result<(), String> {
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置 IPC 写入超时失败：{error}"))?;

    let request: RpcRequest = read_message(&mut stream)?;
    if request.method != "hello" {
        return Err("客户端未执行 IPC 握手".to_string());
    }
    let hello: HelloParams = parse_params(request.params)?;
    if hello.protocol_version != BRIDGE_PROTOCOL_VERSION {
        write_error(
            &mut stream,
            request.id,
            format!(
                "客户端 IPC 协议版本不兼容：服务 {}，客户端 {}",
                BRIDGE_PROTOCOL_VERSION, hello.protocol_version
            ),
        )?;
        return Ok(());
    }
    write_result(
        &mut stream,
        request.id,
        &HelloResult {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )?;
    stream
        .set_read_timeout(None)
        .map_err(|error| format!("设置 IPC 阻塞读取失败：{error}"))?;

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

fn dispatch_request(
    state: &Arc<AppState>,
    method: &str,
    params: Value,
) -> Result<(Value, bool), String> {
    let result = match method {
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
