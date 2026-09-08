use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{
        HeaderMap, HeaderValue, Request, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crate::{
    config::AppConfig, config_transfer, dns::RuntimeStatus, privileged_bridge::rpc_server,
    service_core::AppState,
};

const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

#[derive(RustEmbed)]
#[folder = "../dist/"]
struct WebAssets;

pub(crate) struct WebAdminHandle {
    thread: Option<thread::JoinHandle<()>>,
}

impl WebAdminHandle {
    pub(crate) fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
struct WebState {
    core: Arc<AppState>,
    request_security: Arc<RequestSecurity>,
}

struct RequestSecurity {
    allowed_hosts: HashSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticExportRequest {
    config: AppConfig,
    status: Option<RuntimeStatus>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub(crate) fn start(
    core: Arc<AppState>,
    listen: &str,
    shutdown: Arc<AtomicBool>,
) -> Result<WebAdminHandle, String> {
    let address = listen
        .parse::<SocketAddr>()
        .map_err(|error| format!("Web 管理监听地址无效（{listen}）：{error}"))?;
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| format!("监听 Web 管理地址 {listen} 失败：{error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("设置 Web 管理 listener 非阻塞失败：{error}"))?;
    let state = WebState {
        core,
        request_security: Arc::new(RequestSecurity::load()),
    };
    let router = router(state);

    eprintln!("Web 管理后台正在监听 http://{address}");
    let thread = thread::Builder::new()
        .name("dnsblackhole-web-admin".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("创建 Web 管理运行时失败：{error}");
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        eprintln!("初始化 Web 管理 listener 失败：{error}");
                        return;
                    }
                };
                let service = router.into_make_service_with_connect_info::<SocketAddr>();
                let shutdown_signal = async move {
                    while !shutdown.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                };
                if let Err(error) = axum::serve(listener, service)
                    .with_graceful_shutdown(shutdown_signal)
                    .await
                {
                    eprintln!("Web 管理后台退出：{error}");
                }
            });
        })
        .map_err(|error| format!("启动 Web 管理线程失败：{error}"))?;
    Ok(WebAdminHandle {
        thread: Some(thread),
    })
}

fn router(state: WebState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/admin/version", get(version))
        .route("/api/v1/admin/config", get(get_config).put(save_config))
        .route("/api/v1/admin/config/import", post(import_config))
        .route("/api/v1/admin/status", get(get_status))
        .route("/api/v1/admin/status/query", post(query_status))
        .route("/api/v1/admin/query-logs/search", post(search_query_logs))
        .route("/api/v1/admin/query-logs", delete(clear_query_logs))
        .route("/api/v1/admin/query-logs/rule", post(apply_query_log_rule))
        .route("/api/v1/admin/rules/analyze", post(analyze_custom_rules))
        .route("/api/v1/admin/diagnostics/query", post(run_dns_diagnostic))
        .route(
            "/api/v1/admin/diagnostics/export",
            post(export_diagnostic_report),
        )
        .route("/api/v1/admin/statistics", delete(clear_statistics))
        .route(
            "/api/v1/admin/security-events",
            delete(clear_security_events),
        )
        .route("/api/v1/admin/filters/update", post(update_filters))
        .route("/api/v1/admin/filters/progress", get(get_filter_progress))
        .route("/api/v1/admin/filters/cancel", post(cancel_filter_update))
        .route("/api/v1/admin/filters/cache", delete(clear_filter_cache))
        .route("/api/v1/admin/dns/start", post(start_dns))
        .route("/api/v1/admin/dns/stop", post(stop_dns))
        .route("/api/v1/admin/dns/pause", post(pause_protection))
        .route("/api/v1/admin/dns/resume", post(resume_protection))
        .route("/api/v1/admin/dns/cache", delete(clear_dns_cache))
        .route("/api/v1/admin/system-dns", get(get_system_dns))
        .route(
            "/api/v1/admin/system-dns/takeover",
            post(take_over_system_dns),
        )
        .route("/api/v1/admin/system-dns/restore", post(restore_system_dns))
        .fallback(static_asset)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

impl RequestSecurity {
    fn load() -> Self {
        let allowed_hosts = std::env::var("DNSBLACKHOLE_WEB_ALLOWED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        Self { allowed_hosts }
    }

    fn validate(&self, headers: &HeaderMap, require_origin: bool) -> ApiResult<()> {
        let host = headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::forbidden("请求缺少 Host"))?;
        let hostname =
            hostname_from_host_header(host).ok_or_else(|| ApiError::forbidden("Host 格式无效"))?;
        let allowed = hostname == "localhost"
            || hostname.parse::<IpAddr>().is_ok()
            || self.allowed_hosts.contains(&hostname);
        if !allowed {
            return Err(ApiError::forbidden("Host 不在允许列表中"));
        }
        if require_origin {
            let origin = headers
                .get(ORIGIN)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| ApiError::forbidden("修改请求缺少 Origin"))?;
            if origin != format!("http://{host}") && origin != format!("https://{host}") {
                return Err(ApiError::forbidden("Origin 与 Host 不匹配"));
            }
        }
        Ok(())
    }
}

async fn version(State(state): State<WebState>, headers: HeaderMap) -> ApiResult<Response> {
    state.request_security.validate(&headers, false)?;
    Ok(Json(env!("CARGO_PKG_VERSION")).into_response())
}

async fn health(State(state): State<WebState>) -> Response {
    let status = state.core.status(false);
    Json(json!({
        "status": if status.running { "ok" } else { "degraded" },
        "dnsRunning": status.running,
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response()
}

macro_rules! read_handler {
    ($name:ident, $method:literal, $params:expr) => {
        async fn $name(State(state): State<WebState>, headers: HeaderMap) -> ApiResult<Response> {
            state.request_security.validate(&headers, false)?;
            dispatch(&state, $method, $params).await
        }
    };
}

macro_rules! mutation_handler {
    ($name:ident, $method:literal) => {
        async fn $name(State(state): State<WebState>, headers: HeaderMap) -> ApiResult<Response> {
            state.request_security.validate(&headers, true)?;
            dispatch(&state, $method, Value::Null).await
        }
    };
}

read_handler!(get_config, "get_config", Value::Null);
read_handler!(
    get_status,
    "get_status",
    json!({
        "force_log_stats": false,
        "include_log_stats": true,
        "statistics_hours": null
    })
);
read_handler!(
    get_filter_progress,
    "get_filter_update_progress",
    Value::Null
);
read_handler!(get_system_dns, "get_linux_system_dns_status", Value::Null);

mutation_handler!(clear_query_logs, "clear_query_logs");
mutation_handler!(clear_statistics, "clear_statistics");
mutation_handler!(clear_security_events, "clear_security_events");
mutation_handler!(cancel_filter_update, "cancel_filter_update");
mutation_handler!(clear_filter_cache, "clear_filter_cache");
mutation_handler!(start_dns, "start_dns");
mutation_handler!(stop_dns, "stop_dns");
mutation_handler!(resume_protection, "resume_protection");
mutation_handler!(clear_dns_cache, "clear_dns_cache");
mutation_handler!(take_over_system_dns, "take_over_linux_system_dns");
mutation_handler!(restore_system_dns, "restore_linux_system_dns");

async fn save_config(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(config): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    dispatch(&state, "save_config", json!({ "config": config })).await
}

async fn import_config(
    State(state): State<WebState>,
    headers: HeaderMap,
    content: String,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    let config = config_transfer::parse_imported_config(&content).map_err(ApiError::bad_request)?;
    Ok(Json(config).into_response())
}

async fn query_status(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(mut params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    rename_field(&mut params, "force", "force_log_stats");
    rename_field(&mut params, "includeLogStats", "include_log_stats");
    rename_field(&mut params, "statisticsHours", "statistics_hours");
    dispatch(&state, "get_status", params).await
}

async fn analyze_custom_rules(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    dispatch(&state, "analyze_custom_rules", params).await
}

async fn search_query_logs(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(mut params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    rename_field(&mut params, "queryType", "query_type");
    rename_field(&mut params, "pageSize", "page_size");
    dispatch(&state, "get_query_logs", params).await
}

async fn apply_query_log_rule(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    dispatch(&state, "apply_query_log_rule", params).await
}

async fn run_dns_diagnostic(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(mut params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    rename_field(&mut params, "queryType", "query_type");
    rename_field(&mut params, "clientIp", "client_ip");
    dispatch(&state, "run_dns_diagnostic", params).await
}

async fn export_diagnostic_report(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(request): Json<DiagnosticExportRequest>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    Ok(Json(config_transfer::diagnostic_report(
        request.config,
        request.status,
    ))
    .into_response())
}

async fn update_filters(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(config): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    dispatch(&state, "update_filters", json!({ "config": config })).await
}

async fn pause_protection(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(mut params): Json<Value>,
) -> ApiResult<Response> {
    state.request_security.validate(&headers, true)?;
    rename_field(&mut params, "durationSeconds", "duration_seconds");
    dispatch(&state, "pause_protection", params).await
}

async fn dispatch(state: &WebState, method: &'static str, params: Value) -> ApiResult<Response> {
    let core = Arc::clone(&state.core);
    let result =
        tokio::task::spawn_blocking(move || rpc_server::dispatch_request(&core, method, params))
            .await
            .map_err(|error| ApiError::internal(format!("管理任务异常：{error}")))?
            .map_err(ApiError::bad_request)?;
    if result.1 {
        return Err(ApiError::bad_request("该操作需要通过本机 CLI 完成"));
    }
    Ok(Json(result.0).into_response())
}

async fn static_asset(uri: Uri) -> Response {
    let request_path = uri.path().trim_start_matches('/');
    if request_path == "api" || request_path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let asset_path = if request_path.is_empty() {
        "index.html"
    } else {
        request_path
    };
    let (asset, served_path) = match WebAssets::get(asset_path) {
        Some(asset) => (asset, asset_path),
        None => match WebAssets::get("index.html") {
            Some(asset) => (asset, "index.html"),
            None => return (StatusCode::INTERNAL_SERVER_ERROR, "Web 资源未嵌入").into_response(),
        },
    };
    let mime = mime_guess::from_path(served_path).first_or_octet_stream();
    let mut response = Response::new(Body::from(asset.data.into_owned()));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    let cache = if served_path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if is_api {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn hostname_from_host_header(host: &str) -> Option<String> {
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(hostname, _)| hostname.to_ascii_lowercase());
    }
    let hostname = host
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|character| character.is_ascii_digit()))
        .map(|(hostname, _)| hostname)
        .unwrap_or(host);
    (!hostname.is_empty()).then(|| hostname.to_ascii_lowercase())
}

fn rename_field(value: &mut Value, from: &str, to: &str) {
    if let Some(object) = value.as_object_mut()
        && let Some(field) = object.remove(from)
    {
        object.insert(to.to_string(), field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parser_supports_ipv4_ipv6_and_names() {
        assert_eq!(
            hostname_from_host_header("192.168.1.2:3000").as_deref(),
            Some("192.168.1.2")
        );
        assert_eq!(
            hostname_from_host_header("[::1]:3000").as_deref(),
            Some("::1")
        );
        assert_eq!(
            hostname_from_host_header("LOCALHOST:3000").as_deref(),
            Some("localhost")
        );
    }
}
