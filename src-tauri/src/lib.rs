mod config;
mod database;
mod dns;
mod filters;
mod tray;

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use config::AppConfig;
use database::{Database, LogStats, QueryLogPage};
use dns::{DnsServer, DnsStats, RuleSummary, RuntimeStatus};
use filters::FilterUpdateReport;
use serde::Serialize;
use tauri::{Manager, WindowEvent};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

const LOG_STATS_CACHE_SECONDS: u64 = 15;
const LOG_PRUNE_INTERVAL_SECONDS: u64 = 60 * 60;
const DNS_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);

struct AppState {
    config: Mutex<AppConfig>,
    server: Mutex<Option<DnsServer>>,
    effective_rules: Mutex<String>,
    effective_summary: Mutex<RuleSummary>,
    stats: Arc<Mutex<DnsStats>>,
    database: Arc<Database>,
    log_stats_cache: Mutex<Option<CachedLogStats>>,
    last_prune_at: Mutex<u64>,
    last_error: Mutex<Option<String>>,
}

#[derive(Debug, Clone)]
struct CachedLogStats {
    retention_hours: u32,
    created_at: u64,
    stats: LogStats,
}

#[derive(Debug, Clone, Serialize)]
struct FilterUpdateResult {
    status: RuntimeStatus,
    updated: usize,
    failed: usize,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct FilterCacheClearResult {
    status: RuntimeStatus,
    removed_files: usize,
    removed_bytes: u64,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct DnsDiagnosticsResult {
    domain: String,
    listen_addr: String,
    udp: DnsProbeResult,
    tcp: DnsProbeResult,
}

#[derive(Debug, Clone, Serialize)]
struct DnsProbeResult {
    ok: bool,
    duration_ms: Option<u64>,
    rcode: Option<u8>,
    answers: Option<u16>,
    error: Option<String>,
}

impl AppState {
    fn new(config: AppConfig, effective_rules: String, database: Arc<Database>) -> Self {
        let effective_summary = dns::summarize_rules(&effective_rules);
        Self {
            config: Mutex::new(config),
            server: Mutex::new(None),
            effective_rules: Mutex::new(effective_rules),
            effective_summary: Mutex::new(effective_summary),
            stats: Arc::new(Mutex::new(DnsStats::default())),
            database,
            log_stats_cache: Mutex::new(None),
            last_prune_at: Mutex::new(0),
            last_error: Mutex::new(None),
        }
    }

    fn current_config(&self) -> Result<AppConfig, String> {
        self.config
            .lock()
            .map(|config| config.clone())
            .map_err(|_| "读取配置失败".into())
    }

    fn replace_config(&self, config: AppConfig) -> Result<(), String> {
        let mut current = self.config.lock().map_err(|_| "写入配置失败")?;
        *current = config;
        Ok(())
    }

    fn replace_effective_rules(&self, rules: String) -> Result<(), String> {
        let summary = dns::summarize_rules(&rules);
        let mut current = self
            .effective_rules
            .lock()
            .map_err(|_| "写入规则缓存失败")?;
        *current = rules;
        let mut current_summary = self
            .effective_summary
            .lock()
            .map_err(|_| "写入规则摘要失败")?;
        *current_summary = summary;
        Ok(())
    }

    fn start_current(&self) -> Result<(), String> {
        self.stop_current()?;

        let config = self.current_config()?;
        let rules_text = self
            .effective_rules
            .lock()
            .map(|rules| rules.clone())
            .map_err(|_| "读取规则缓存失败")?;
        let server = DnsServer::start(
            config,
            rules_text,
            Arc::clone(&self.stats),
            Arc::clone(&self.database),
        )?;
        let mut current = self.server.lock().map_err(|_| "更新 DNS 服务状态失败")?;
        *current = Some(server);
        self.set_error(None);
        Ok(())
    }

    fn stop_current(&self) -> Result<(), String> {
        let server = {
            let mut current = self.server.lock().map_err(|_| "读取 DNS 服务状态失败")?;
            current.take()
        };

        if let Some(server) = server {
            server.stop();
        }
        Ok(())
    }

    fn set_error(&self, error: Option<String>) {
        if let Ok(mut current) = self.last_error.lock() {
            *current = error;
        }
    }

    fn status(&self, force_log_stats: bool) -> RuntimeStatus {
        let config = self.current_config().unwrap_or_default();
        let summary = self
            .effective_summary
            .lock()
            .map(|summary| summary.clone())
            .unwrap_or_default();
        let mut stats = self
            .stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_default();
        if config.query_log_enabled {
            match self.cached_log_stats(config.query_log_retention_hours, force_log_stats) {
                Ok(log_stats) => {
                    stats.queries = log_stats.queries;
                    stats.blocked = log_stats.blocked;
                    stats.forwarded = log_stats.forwarded;
                    stats.failed = log_stats.failed;
                    stats.query_domains = log_stats.query_domains;
                    stats.blocked_domains = log_stats.blocked_domains;
                    stats.traffic = log_stats.traffic;
                    stats.upstream_requests = log_stats.upstream_requests;
                    stats.upstream_avg_latency = log_stats.upstream_avg_latency;
                }
                Err(error) => self.set_error(Some(error)),
            }
        }
        let error = self.last_error.lock().ok().and_then(|error| error.clone());
        let running = self
            .server
            .lock()
            .ok()
            .and_then(|server| server.as_ref().map(|server| server.listen_addr()))
            .is_some();

        dns::empty_status(&config, running, summary, stats, error)
    }

    fn cached_log_stats(
        &self,
        retention_hours: u32,
        force_refresh: bool,
    ) -> Result<LogStats, String> {
        let now = unix_now();
        let cached_stats = if force_refresh {
            None
        } else {
            self.log_stats_cache
                .lock()
                .map_err(|_| "读取日志统计缓存失败".to_string())?
                .clone()
        };
        if let Some(cached) = cached_stats
            && cached.retention_hours == retention_hours
            && now.saturating_sub(cached.created_at) < LOG_STATS_CACHE_SECONDS
        {
            return Ok(cached.stats);
        }

        self.prune_query_logs_if_due(retention_hours, now)?;
        let stats = self.database.log_stats(retention_hours)?;
        let mut cache = self
            .log_stats_cache
            .lock()
            .map_err(|_| "写入日志统计缓存失败".to_string())?;
        *cache = Some(CachedLogStats {
            retention_hours,
            created_at: now,
            stats: stats.clone(),
        });
        Ok(stats)
    }

    fn prune_query_logs_if_due(&self, retention_hours: u32, now: u64) -> Result<(), String> {
        let mut last_prune_at = self
            .last_prune_at
            .lock()
            .map_err(|_| "读取日志清理时间失败".to_string())?;
        if now.saturating_sub(*last_prune_at) < LOG_PRUNE_INTERVAL_SECONDS {
            return Ok(());
        }

        self.database.prune_query_logs(retention_hours)?;
        *last_prune_at = now;
        Ok(())
    }

    fn invalidate_log_stats_cache(&self) {
        if let Ok(mut cache) = self.log_stats_cache.lock() {
            *cache = None;
        }
    }
}

#[tauri::command]
fn get_config(state: tauri::State<'_, Arc<AppState>>) -> Result<AppConfig, String> {
    state.current_config()
}

#[tauri::command]
fn save_config(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    mut config: AppConfig,
) -> Result<RuntimeStatus, String> {
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
    apply_autostart_config(&app, config.launch_at_startup)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;

    if config.enabled {
        if let Err(error) = state.start_current() {
            state.set_error(Some(error.clone()));
            return Err(error);
        }
    } else {
        state.stop_current()?;
        state.set_error(None);
    }

    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

#[tauri::command]
async fn get_status(
    state: tauri::State<'_, Arc<AppState>>,
    force: Option<bool>,
) -> Result<RuntimeStatus, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || state.status(force.unwrap_or(false)))
        .await
        .map_err(|error| format!("获取状态失败：{error}"))
}

#[tauri::command]
async fn get_query_logs(
    state: tauri::State<'_, Arc<AppState>>,
    filter: Option<String>,
    search: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
) -> Result<QueryLogPage, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let config = state.current_config()?;
        if !config.query_log_enabled {
            return Ok(QueryLogPage {
                records: Vec::new(),
                total: 0,
                page: page.unwrap_or(1).max(1),
                page_size: page_size.unwrap_or(50).clamp(20, 200),
            });
        }

        state.prune_query_logs_if_due(config.query_log_retention_hours, unix_now())?;
        state.database.query_logs(
            config.query_log_retention_hours,
            filter.as_deref().unwrap_or("all"),
            search.as_deref().unwrap_or(""),
            page.unwrap_or(1),
            page_size.unwrap_or(50),
        )
    })
    .await
    .map_err(|error| format!("获取查询日志失败：{error}"))?
}

#[tauri::command]
async fn update_filters(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    config: AppConfig,
) -> Result<FilterUpdateResult, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || update_filters_blocking(app, state, config))
        .await
        .map_err(|error| format!("过滤器更新任务异常：{error}"))?
}

fn update_filters_blocking(
    app: tauri::AppHandle,
    state: Arc<AppState>,
    mut config: AppConfig,
) -> Result<FilterUpdateResult, String> {
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
    let report = filters::update_enabled_filters(&app, &mut config)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;

    if config.enabled {
        state.start_current().inspect_err(|error| {
            state.set_error(Some(error.clone()));
        })?;
    }

    apply_update_report_error(&state, &report);

    Ok(FilterUpdateResult {
        status: state.status(true),
        updated: report.updated,
        failed: report.failed,
        message: report.message,
    })
}

#[tauri::command]
fn start_dns(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<RuntimeStatus, String> {
    let mut config = state.current_config()?;
    config::migrate_legacy_defaults(&mut config);
    config.enabled = true;
    config.validate()?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;
    state.start_current().inspect_err(|error| {
        state.set_error(Some(error.clone()));
    })?;
    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

#[tauri::command]
fn stop_dns(state: tauri::State<'_, Arc<AppState>>) -> Result<RuntimeStatus, String> {
    let mut config = state.current_config()?;
    config.enabled = false;
    state.database.save_config(&config)?;
    state.replace_config(config)?;
    state.stop_current()?;
    state.set_error(None);
    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

#[tauri::command]
fn clear_dns_cache(state: tauri::State<'_, Arc<AppState>>) -> Result<RuntimeStatus, String> {
    let server = state
        .server
        .lock()
        .map_err(|_| "读取 DNS 服务状态失败".to_string())?;
    if let Some(server) = server.as_ref() {
        server.clear_cache()?;
    }
    drop(server);
    Ok(state.status(true))
}

#[tauri::command]
async fn clear_filter_cache(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<FilterCacheClearResult, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || clear_filter_cache_blocking(app, state))
        .await
        .map_err(|error| format!("清理过滤器缓存任务异常：{error}"))?
}

#[tauri::command]
async fn run_dns_diagnostics(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<DnsDiagnosticsResult, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let config = state.current_config()?;
        run_dns_diagnostics_blocking(&config)
    })
    .await
    .map_err(|error| format!("DNS 诊断任务异常：{error}"))?
}

fn clear_filter_cache_blocking(
    app: tauri::AppHandle,
    state: Arc<AppState>,
) -> Result<FilterCacheClearResult, String> {
    let mut config = state.current_config()?;
    let stats = config::clear_filter_cache(&app, &mut config)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;

    if config.enabled {
        state.start_current().inspect_err(|error| {
            state.set_error(Some(error.clone()));
        })?;
    } else {
        state.set_error(None);
    }

    let message = if stats.removed_files == 0 {
        "没有可清理的过滤器缓存".to_string()
    } else {
        format!(
            "已清理 {} 个过滤器缓存（{}），远程黑名单需要重新检查更新",
            stats.removed_files,
            format_bytes(stats.removed_bytes)
        )
    };

    Ok(FilterCacheClearResult {
        status: state.status(true),
        removed_files: stats.removed_files,
        removed_bytes: stats.removed_bytes,
        message,
    })
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;

    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / KIB)
    } else {
        format!("{:.1} MB", bytes as f64 / MIB)
    }
}

fn apply_update_report_error(state: &AppState, report: &FilterUpdateReport) {
    if report.failed > 0 {
        state.set_error(Some(report.message.clone()));
    } else {
        state.set_error(None);
    }
}

fn spawn_runtime_watchdog(state: Arc<AppState>) {
    thread::spawn(move || {
        loop {
            let interval = state
                .current_config()
                .map(|config| config.runtime_watchdog_interval_seconds.clamp(10, 3600))
                .unwrap_or_else(|_| AppConfig::default().runtime_watchdog_interval_seconds);
            thread::sleep(Duration::from_secs(interval));

            let config = state.current_config().unwrap_or_default();
            if !config.enabled || !config.runtime_watchdog_enabled {
                continue;
            }

            let should_restart = match state.server.lock() {
                Ok(server) => match server.as_ref() {
                    Some(server) => server.has_finished_threads(),
                    None => true,
                },
                Err(_) => {
                    state.set_error(Some("DNS 自恢复无法读取服务状态".to_string()));
                    false
                }
            };

            if should_restart && let Err(error) = state.start_current() {
                state.set_error(Some(format!("DNS 自恢复重启失败：{error}")));
            }
        }
    });
}

fn run_dns_diagnostics_blocking(config: &AppConfig) -> Result<DnsDiagnosticsResult, String> {
    let listen_addr = config.listen_socket_addr()?;
    let domain = normalize_diagnostics_domain(&config.diagnostics_domain)?;
    let query = build_diagnostic_dns_query(&domain, 1)?;

    Ok(DnsDiagnosticsResult {
        domain,
        listen_addr: listen_addr.to_string(),
        udp: run_udp_dns_probe(listen_addr, &query),
        tcp: run_tcp_dns_probe(listen_addr, &query),
    })
}

fn run_udp_dns_probe(listen_addr: SocketAddr, query: &[u8]) -> DnsProbeResult {
    let started = Instant::now();
    let bind_addr = if listen_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = match UdpSocket::bind(bind_addr) {
        Ok(socket) => socket,
        Err(error) => {
            return dns_probe_error(started, format!("创建 UDP 诊断 socket 失败：{error}"));
        }
    };
    if let Err(error) = socket.set_read_timeout(Some(DNS_DIAGNOSTIC_TIMEOUT)) {
        return dns_probe_error(started, format!("设置 UDP 诊断超时失败：{error}"));
    }
    if let Err(error) = socket.send_to(query, listen_addr) {
        return dns_probe_error(started, format!("发送 UDP DNS 诊断请求失败：{error}"));
    }

    let mut response = [0_u8; 4096];
    match socket.recv_from(&mut response) {
        Ok((len, _)) => parse_dns_probe_response(started, &response[..len], query),
        Err(error) => dns_probe_error(started, format!("读取 UDP DNS 诊断响应失败：{error}")),
    }
}

fn run_tcp_dns_probe(listen_addr: SocketAddr, query: &[u8]) -> DnsProbeResult {
    let started = Instant::now();
    let query_len = match u16::try_from(query.len()) {
        Ok(len) => len,
        Err(_) => return dns_probe_error(started, "DNS 诊断请求过长".to_string()),
    };
    let mut stream = match TcpStream::connect_timeout(&listen_addr, DNS_DIAGNOSTIC_TIMEOUT) {
        Ok(stream) => stream,
        Err(error) => {
            return dns_probe_error(started, format!("连接 TCP DNS 诊断端口失败：{error}"));
        }
    };
    if let Err(error) = stream.set_read_timeout(Some(DNS_DIAGNOSTIC_TIMEOUT)) {
        return dns_probe_error(started, format!("设置 TCP DNS 诊断读取超时失败：{error}"));
    }
    if let Err(error) = stream.set_write_timeout(Some(DNS_DIAGNOSTIC_TIMEOUT)) {
        return dns_probe_error(started, format!("设置 TCP DNS 诊断写入超时失败：{error}"));
    }
    if let Err(error) = stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|_| stream.write_all(query))
    {
        return dns_probe_error(started, format!("发送 TCP DNS 诊断请求失败：{error}"));
    }

    let mut len_buf = [0_u8; 2];
    if let Err(error) = stream.read_exact(&mut len_buf) {
        return dns_probe_error(started, format!("读取 TCP DNS 诊断响应长度失败：{error}"));
    }
    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len == 0 {
        return dns_probe_error(started, "TCP DNS 诊断返回空响应".to_string());
    }

    let mut response = vec![0_u8; response_len];
    match stream.read_exact(&mut response) {
        Ok(()) => parse_dns_probe_response(started, &response, query),
        Err(error) => dns_probe_error(started, format!("读取 TCP DNS 诊断响应失败：{error}")),
    }
}

fn parse_dns_probe_response(started: Instant, response: &[u8], query: &[u8]) -> DnsProbeResult {
    match parse_dns_probe_response_counts(response, query) {
        Ok((rcode, answers)) => DnsProbeResult {
            ok: rcode == 0,
            duration_ms: Some(duration_ms(started.elapsed())),
            rcode: Some(rcode),
            answers: Some(answers),
            error: (rcode != 0).then(|| format!("DNS 响应 rcode={rcode}")),
        },
        Err(error) => dns_probe_error(started, error),
    }
}

fn parse_dns_probe_response_counts(response: &[u8], query: &[u8]) -> Result<(u8, u16), String> {
    if response.len() < 12 || query.len() < 2 {
        return Err("DNS 诊断响应长度不足".to_string());
    }
    if response[0..2] != query[0..2] {
        return Err("DNS 诊断响应 transaction ID 不匹配".to_string());
    }
    if response[2] & 0x80 == 0 {
        return Err("DNS 诊断收到的不是响应包".to_string());
    }

    Ok((
        response[3] & 0x0f,
        read_u16(response, 6).unwrap_or_default(),
    ))
}

fn dns_probe_error(started: Instant, error: String) -> DnsProbeResult {
    DnsProbeResult {
        ok: false,
        duration_ms: Some(duration_ms(started.elapsed())),
        rcode: None,
        answers: None,
        error: Some(error),
    }
}

fn build_diagnostic_dns_query(domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut packet = vec![0x42, 0x44, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in domain.split('.') {
        let label_len =
            u8::try_from(label.len()).map_err(|_| "诊断域名 label 长度超过 63 字节".to_string())?;
        if label_len == 0 || label_len > 63 {
            return Err("诊断域名格式无效".to_string());
        }
        packet.push(label_len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn normalize_diagnostics_domain(value: &str) -> Result<String, String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
    {
        return Err("诊断域名必须是有效域名，例如 example.com".to_string());
    }
    Ok(domain)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([first, second]))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn apply_autostart_config(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    let current = manager
        .is_enabled()
        .map_err(|error| format!("读取开机自启状态失败：{error}"))?;
    match (enabled, current) {
        (true, false) => manager
            .enable()
            .map_err(|error| format!("启用开机自启失败：{error}")),
        (false, true) => manager
            .disable()
            .map_err(|error| format!("关闭开机自启失败：{error}")),
        _ => Ok(()),
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn apply_autostart_config(_app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        Err("当前平台不支持开机自启".to_string())
    } else {
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            get_status,
            get_query_logs,
            update_filters,
            start_dns,
            stop_dns,
            clear_dns_cache,
            clear_filter_cache,
            run_dns_diagnostics
        ])
        .setup(|app| {
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            app.handle()
                .plugin(tauri_plugin_autostart::init(
                    MacosLauncher::LaunchAgent,
                    None,
                ))
                .map_err(|error| io::Error::other(format!("开机自启插件初始化失败：{error}")))?;

            tray::create(app.handle())?;
            let database = Arc::new(
                Database::open(app.handle())
                    .map_err(|error| io::Error::other(format!("数据库初始化失败：{error}")))?,
            );
            let config = match database.load_or_migrate_config(app.handle()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("数据库配置加载失败：{error}");
                    AppConfig::default()
                }
            };
            let should_start = config.enabled;
            let autostart_error = apply_autostart_config(app.handle(), config.launch_at_startup)
                .inspect_err(|error| eprintln!("{error}"))
                .err();
            let effective_rules = config::build_effective_rules(app.handle(), &config);
            let state = Arc::new(AppState::new(config, effective_rules, database));
            if let Some(error) = autostart_error {
                state.set_error(Some(error));
            }
            if should_start && let Err(error) = state.start_current() {
                eprintln!("DNS 服务启动失败：{error}");
                state.set_error(Some(error));
            }
            let watchdog_state = Arc::clone(&state);
            app.manage(state);
            spawn_runtime_watchdog(watchdog_state);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
