use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

#[cfg(target_os = "macos")]
use crate::service_core::spawn_initial_runtime;
use crate::{
    config::AppConfig,
    database::Database,
    service_core::{
        AppState, clear_dns_cache_blocking, clear_filter_cache_blocking, clear_query_logs_blocking,
        clear_statistics_blocking, query_logs_blocking, save_config_blocking,
        spawn_filter_auto_update, spawn_runtime_watchdog, start_dns_blocking, stop_dns_blocking,
        update_filters_blocking,
    },
    storage,
};

#[cfg(windows)]
use super::windows_system_dns;
use super::{
    BRIDGE_PROTOCOL_VERSION, HelloParams, HelloResult, RpcRequest, RpcResponse, read_message,
    write_message,
};

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

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct SystemDnsFallbackParams {
    preset: windows_system_dns::WindowsSystemDnsFallback,
}

pub(crate) fn initialize_state(default_dir: PathBuf) -> Result<Arc<AppState>, String> {
    let total_started = Instant::now();
    let storage_started = Instant::now();
    let bootstrap = storage::initialize_at(default_dir)?;
    crate::performance::log_service("服务启动", "存储目录初始化", storage_started);
    let database_started = Instant::now();
    let database = Arc::new(Database::open(&bootstrap.data_dir)?);
    crate::performance::log_service("服务启动", "数据库打开与结构检查", database_started);
    let config_started = Instant::now();
    let config = database.load_or_default_config()?;
    crate::performance::log_service("服务启动", "配置读取", config_started);
    let cleanup_started = Instant::now();
    storage::finish_pending_cleanup(&bootstrap.default_dir, &bootstrap.data_dir)?;
    crate::performance::log_service("服务启动", "迁移残留清理", cleanup_started);
    let state = Arc::new(AppState::new(
        config,
        database,
        bootstrap.default_dir,
        bootstrap.data_dir,
    ));
    if let Some(error) = bootstrap.migration_error {
        state.set_error(Some(error));
    }
    crate::performance::log_service("服务启动", "状态初始化总计", total_started);
    Ok(state)
}

#[cfg(target_os = "macos")]
pub(crate) fn start_background_tasks(state: &Arc<AppState>) {
    spawn_initial_runtime(Arc::clone(state));
    start_maintenance_tasks(state);
}

pub(crate) fn start_maintenance_tasks(state: &Arc<AppState>) {
    spawn_runtime_watchdog(Arc::clone(state));
    spawn_filter_auto_update(Arc::clone(state), |_| {});
}

#[cfg(windows)]
pub(crate) fn handle_client<S>(mut stream: S, state: Arc<AppState>) -> Result<bool, String>
where
    S: Read + Write,
{
    let handshake_complete = match perform_handshake(&mut stream) {
        Ok(complete) => complete,
        Err(error) if connection_closed(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    if !handshake_complete {
        return Ok(false);
    }
    handle_requests(stream, state)
}

pub(crate) fn handle_requests<S>(mut stream: S, state: Arc<AppState>) -> Result<bool, String>
where
    S: Read + Write,
{
    loop {
        let request: RpcRequest = match read_message(&mut stream) {
            Ok(request) => request,
            Err(error) if connection_closed(&error) => return Ok(false),
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
                    return Ok(true);
                }
            }
            Err(error) => write_error(&mut stream, request.id, error)?,
        }
    }
}

pub(crate) fn perform_handshake<S>(stream: &mut S) -> Result<bool, String>
where
    S: Read + Write,
{
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
            #[cfg(windows)]
            validate_managed_system_dns_config(state, &params.config)?;
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
        "clear_query_logs" => to_value(clear_query_logs_blocking(state)?)?,
        "clear_statistics" => to_value(clear_statistics_blocking(state)?)?,
        "update_filters" => {
            let params: ConfigParams = parse_params(params)?;
            to_value(update_filters_blocking(Arc::clone(state), params.config)?)?
        }
        "get_filter_update_progress" => to_value(state.filter_update_progress()?)?,
        "cancel_filter_update" => to_value(state.request_filter_update_cancel()?)?,
        "start_dns" => to_value(start_dns_blocking(Arc::clone(state))?)?,
        "stop_dns" => {
            #[cfg(windows)]
            ensure_system_dns_not_managed(state)?;
            to_value(stop_dns_blocking(Arc::clone(state))?)?
        }
        "clear_dns_cache" => to_value(clear_dns_cache_blocking(state)?)?,
        "clear_filter_cache" => to_value(clear_filter_cache_blocking(Arc::clone(state))?)?,
        #[cfg(windows)]
        "get_windows_system_dns_status" => to_value(windows_system_dns::system_dns_status(
            &state.default_data_dir,
        )?)?,
        #[cfg(windows)]
        "take_over_windows_system_dns" => {
            validate_system_dns_takeover(state)?;
            to_value(windows_system_dns::take_over_system_dns(
                &state.default_data_dir,
            )?)?
        }
        #[cfg(windows)]
        "restore_windows_system_dns" => to_value(windows_system_dns::restore_system_dns(
            &state.default_data_dir,
        )?)?,
        #[cfg(windows)]
        "replace_unmanaged_windows_system_dns" => {
            let params: SystemDnsFallbackParams = parse_params(params)?;
            to_value(windows_system_dns::replace_unmanaged_local_dns(
                &state.default_data_dir,
                params.preset,
            )?)?
        }
        #[cfg(windows)]
        "restore_windows_system_dns_with_fallback" => {
            let params: SystemDnsFallbackParams = parse_params(params)?;
            to_value(windows_system_dns::restore_system_dns_with_fallback(
                &state.default_data_dir,
                params.preset,
            )?)?
        }
        "restart_service" => return Ok((Value::Null, true)),
        _ => return Err(format!("未知的后台服务方法：{method}")),
    };
    Ok((result, false))
}

#[cfg(windows)]
fn validate_system_dns_takeover(state: &AppState) -> Result<(), String> {
    let config = state.current_config()?;
    if !config.enabled || !state.status(false).running {
        return Err("请先启动 DnsBlackhole DNS 服务，再接管系统 DNS".to_string());
    }
    validate_system_dns_config(&config)
}

#[cfg(windows)]
fn validate_managed_system_dns_config(state: &AppState, config: &AppConfig) -> Result<(), String> {
    if windows_system_dns::system_dns_is_managed(&state.default_data_dir) {
        if !config.enabled {
            return Err(
                "系统 DNS 正由 DnsBlackhole 接管，请先恢复原 DNS，再关闭自动运行".to_string(),
            );
        }
        validate_system_dns_config(config)
            .map_err(|error| format!("系统 DNS 正由 DnsBlackhole 接管，请先恢复原 DNS。{error}"))?;
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_system_dns_not_managed(state: &AppState) -> Result<(), String> {
    if windows_system_dns::system_dns_is_managed(&state.default_data_dir) {
        return Err(
            "系统 DNS 正由 DnsBlackhole 接管，请先在设置中恢复原 DNS，再停止服务".to_string(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_system_dns_config(config: &AppConfig) -> Result<(), String> {
    use std::net::Ipv4Addr;

    if config.listen_port != 53 {
        return Err("接管系统 DNS 前，请将 DNS 监听端口设置为 53".to_string());
    }
    let listen_host = config
        .listen_host
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| "接管系统 DNS 前，监听地址必须是 0.0.0.0 或 127.0.0.1".to_string())?;
    if listen_host != Ipv4Addr::UNSPECIFIED && listen_host != Ipv4Addr::LOCALHOST {
        return Err("接管系统 DNS 前，监听地址必须是 0.0.0.0 或 127.0.0.1".to_string());
    }
    if !config.listen_ipv6 {
        return Err("接管系统 DNS 前，请启用 IPv6 双栈监听，避免 IPv6 DNS 绕过过滤".to_string());
    }
    Ok(())
}

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|error| format!("后台服务请求参数无效：{error}"))
}

fn to_value<T: Serialize>(result: T) -> Result<Value, String> {
    serde_json::to_value(result).map_err(|error| format!("序列化后台服务响应失败：{error}"))
}

pub(crate) fn write_result<S, T>(stream: &mut S, id: u64, result: &T) -> Result<(), String>
where
    S: Write,
    T: Serialize,
{
    write_response(
        stream,
        RpcResponse {
            id,
            result: Some(to_value(result)?),
            error: None,
        },
    )
}

fn write_error<S>(stream: &mut S, id: u64, error: String) -> Result<(), String>
where
    S: Write,
{
    write_response(
        stream,
        RpcResponse {
            id,
            result: None,
            error: Some(error),
        },
    )
}

fn write_response<S>(stream: &mut S, response: RpcResponse) -> Result<(), String>
where
    S: Write,
{
    write_message(stream, &response)
}

fn connection_closed(error: &str) -> bool {
    error.contains("UnexpectedEof")
        || error.contains("failed to fill whole buffer")
        || error.contains("管道已结束")
        || error.contains("broken pipe")
}

fn default_true() -> bool {
    true
}
