mod config;
mod database;
mod dns;
mod filters;
mod tray;

use std::{
    io,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use config::AppConfig;
use database::{Database, LogStats, QueryLogPage};
use dns::{
    DnsServer, DnsStats, RuleSummary, RuntimeStatus, build_filter_runtime, replace_filter_runtime,
};
use filters::FilterUpdateReport;
use serde::Serialize;
use tauri::{Emitter, Manager, WindowEvent};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri_plugin_autostart::MacosLauncher;
#[cfg(all(
    any(target_os = "macos", windows, target_os = "linux"),
    not(debug_assertions)
))]
use tauri_plugin_autostart::ManagerExt;

const LOG_STATS_CACHE_SECONDS: u64 = 15;
const LOG_PRUNE_INTERVAL_SECONDS: u64 = 60 * 60;
const FILTER_AUTO_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const FILTER_AUTO_UPDATE_MIN_BACKOFF_SECONDS: u64 = 5 * 60;
const FILTER_AUTO_UPDATE_MAX_BACKOFF_SECONDS: u64 = 6 * 3600;

struct AppState {
    config: Mutex<AppConfig>,
    server: Mutex<Option<DnsServer>>,
    effective_summary: Mutex<RuleSummary>,
    stats: Arc<Mutex<DnsStats>>,
    database: Arc<Database>,
    log_stats_cache: Mutex<Option<CachedLogStats>>,
    last_prune_at: Mutex<u64>,
    last_error: Mutex<Option<String>>,
    // 手动更新与自动更新共用，避免并发下载清单互相踩踏
    filter_update_lock: Mutex<()>,
    // 启停、配置保存和规则热替换串行执行，避免后台初始化与用户操作互相覆盖
    runtime_update_lock: Mutex<()>,
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

impl AppState {
    fn new(config: AppConfig, database: Arc<Database>) -> Self {
        let effective_summary = configured_rule_summary(&config);
        Self {
            config: Mutex::new(config),
            server: Mutex::new(None),
            effective_summary: Mutex::new(effective_summary),
            stats: Arc::new(Mutex::new(DnsStats::default())),
            database,
            log_stats_cache: Mutex::new(None),
            last_prune_at: Mutex::new(0),
            last_error: Mutex::new(None),
            filter_update_lock: Mutex::new(()),
            runtime_update_lock: Mutex::new(()),
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

    fn set_effective_summary(&self, summary: RuleSummary) -> Result<(), String> {
        let mut current_summary = self
            .effective_summary
            .lock()
            .map_err(|_| "写入规则摘要失败")?;
        *current_summary = summary;
        Ok(())
    }

    fn start_current(&self, rules_text: &str) -> Result<(), String> {
        self.stop_current()?;

        let config = self.current_config()?;
        let server = DnsServer::start(
            config,
            rules_text,
            Arc::clone(&self.stats),
            Arc::clone(&self.database),
        )?;
        let summary = server.rule_summary();
        if let Err(error) = self.set_effective_summary(summary) {
            server.stop();
            return Err(error);
        }
        let mut current = match self.server.lock() {
            Ok(current) => current,
            Err(_) => {
                server.stop();
                return Err("更新 DNS 服务状态失败".into());
            }
        };
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

    fn server_needs_start(&self) -> Result<bool, String> {
        let server = self
            .server
            .lock()
            .map_err(|_| "读取 DNS 服务状态失败".to_string())?;
        Ok(server.as_ref().is_none_or(DnsServer::has_finished_threads))
    }

    /// 规则类配置变更时热替换过滤状态，保留运行中的服务与 DNS 缓存。
    /// 返回 false 表示需要走完整重启路径。
    fn try_hot_swap(
        &self,
        previous: &AppConfig,
        config: &AppConfig,
        rules_text: &str,
    ) -> Result<bool, String> {
        if needs_dns_restart(previous, config) {
            return Ok(false);
        }

        let filter_runtime = {
            let server = self.server.lock().map_err(|_| "读取 DNS 服务状态失败")?;
            let Some(server) = server.as_ref() else {
                return Ok(false);
            };
            if server.has_finished_threads() {
                return Ok(false);
            }

            server.filter_runtime_handle()
        };
        // 规则编译可能较耗时，不占用 server 状态锁，避免状态查询和停止操作被长时间阻塞。
        let runtime = build_filter_runtime(config, rules_text);
        let summary = runtime.summary();
        replace_filter_runtime(&filter_runtime, runtime);
        self.set_effective_summary(summary)?;
        Ok(true)
    }

    /// 应用新配置：能热替换就热替换，否则重启 DNS 服务。
    /// 调用前需要先完成 replace_config。
    fn apply_config_change(
        &self,
        previous: &AppConfig,
        config: &AppConfig,
        rules_text: &str,
    ) -> Result<(), String> {
        if !config.enabled {
            self.stop_current()?;
            self.set_error(None);
            return Ok(());
        }

        if self.try_hot_swap(previous, config, rules_text)? {
            self.set_error(None);
            return Ok(());
        }

        self.start_current(rules_text)
    }

    fn set_error(&self, error: Option<String>) {
        if let Ok(mut current) = self.last_error.lock() {
            *current = error;
        }
    }

    fn status(&self, force_log_stats: bool) -> RuntimeStatus {
        self.status_with_log_stats(force_log_stats, true)
    }

    fn status_with_log_stats(
        &self,
        force_log_stats: bool,
        include_log_stats: bool,
    ) -> RuntimeStatus {
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
        if config.query_log_enabled && include_log_stats {
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
            .and_then(|server| server.as_ref().map(|server| !server.has_finished_threads()))
            .unwrap_or(false);

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

fn configured_rule_summary(config: &AppConfig) -> RuleSummary {
    if !config.use_filters {
        return RuleSummary::default();
    }

    let mut summary = dns::summarize_rules(&config.blacklist);
    for filter in config.filters.iter().filter(|filter| filter.enabled) {
        let block_rules = if filter.block_rule_count == 0
            && filter.allow_rule_count == 0
            && filter.rule_count > 0
        {
            filter.rule_count
        } else {
            filter.block_rule_count
        };
        summary.block_rules = summary.block_rules.saturating_add(block_rules);
        summary.allow_rules = summary.allow_rules.saturating_add(filter.allow_rule_count);
        summary.ignored_rules = summary
            .ignored_rules
            .saturating_add(filter.ignored_rule_count);
        summary.ignored_comment_rules = summary
            .ignored_comment_rules
            .saturating_add(filter.ignored_comment_count);
        summary.ignored_regex_rules = summary
            .ignored_regex_rules
            .saturating_add(filter.ignored_regex_count);
        summary.ignored_unsupported_rules = summary
            .ignored_unsupported_rules
            .saturating_add(filter.ignored_unsupported_count);
        summary.ignored_invalid_rules = summary
            .ignored_invalid_rules
            .saturating_add(filter.ignored_invalid_count);
    }
    summary
}

fn filter_runtime_changed(previous: &AppConfig, next: &AppConfig) -> bool {
    previous.use_filters != next.use_filters
        || previous.filters != next.filters
        || previous.blacklist != next.blacklist
        || previous.blocking_mode != next.blocking_mode
        || previous.blocking_custom_ipv4 != next.blocking_custom_ipv4
        || previous.blocking_custom_ipv6 != next.blocking_custom_ipv6
        || previous.dns_rewrites != next.dns_rewrites
        || previous.query_log_ignored_domains != next.query_log_ignored_domains
}

/// 判断配置差异是否触及 DNS 服务的结构性参数（监听、上游、访问控制、缓存等）。
/// 规则、清单、重写、拦截模式、日志忽略等过滤类字段支持热替换，不在比较范围内。
fn needs_dns_restart(previous: &AppConfig, next: &AppConfig) -> bool {
    previous.listen_host != next.listen_host
        || previous.listen_port != next.listen_port
        || previous.listen_ipv6 != next.listen_ipv6
        || previous.upstream_dns != next.upstream_dns
        || previous.fallback_dns != next.fallback_dns
        || previous.bootstrap_dns != next.bootstrap_dns
        || previous.upstream_mode != next.upstream_mode
        || previous.allow_insecure_http != next.allow_insecure_http
        || previous.allowed_clients != next.allowed_clients
        || previous.blocked_clients != next.blocked_clients
        || previous.rate_limit_per_second != next.rate_limit_per_second
        || previous.refuse_any != next.refuse_any
        || previous.query_log_enabled != next.query_log_enabled
        || previous.anonymize_client_ip != next.anonymize_client_ip
        || previous.dns_cache_enabled != next.dns_cache_enabled
        || previous.dns_cache_size != next.dns_cache_size
        || previous.dns_cache_min_ttl != next.dns_cache_min_ttl
        || previous.dns_cache_max_ttl != next.dns_cache_max_ttl
        || previous.dns_cache_optimistic != next.dns_cache_optimistic
}

#[tauri::command]
fn get_config(state: tauri::State<'_, Arc<AppState>>) -> Result<AppConfig, String> {
    state.current_config()
}

#[tauri::command]
async fn save_config(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    config: AppConfig,
) -> Result<RuntimeStatus, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || save_config_blocking(app, state, config))
        .await
        .map_err(|error| format!("保存配置任务异常：{error}"))?
}

fn save_config_blocking(
    app: tauri::AppHandle,
    state: Arc<AppState>,
    mut config: AppConfig,
) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
    apply_autostart_config(&app, config.launch_at_startup)?;
    let previous = state.current_config()?;
    let filter_changed = filter_runtime_changed(&previous, &config);
    let restart_required = needs_dns_restart(&previous, &config);
    let start_required =
        config.enabled && (!previous.enabled || restart_required || state.server_needs_start()?);
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;

    if !config.enabled {
        state.stop_current()?;
        if filter_changed {
            state.set_effective_summary(configured_rule_summary(&config))?;
        }
        state.set_error(None);
    } else if filter_changed || start_required {
        let rules_text = config::build_effective_rules(&app, &config);
        if let Err(error) = state.apply_config_change(&previous, &config, &rules_text) {
            state.set_error(Some(error.clone()));
            return Err(error);
        }
    } else {
        state.set_error(None);
    }

    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

#[tauri::command]
async fn get_status(
    state: tauri::State<'_, Arc<AppState>>,
    force: Option<bool>,
    include_log_stats: Option<bool>,
) -> Result<RuntimeStatus, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        state.status_with_log_stats(force.unwrap_or(false), include_log_stats.unwrap_or(true))
    })
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
    let _update_guard = state
        .filter_update_lock
        .lock()
        .map_err(|_| "清单更新任务状态异常".to_string())?;
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
    let report = filters::update_enabled_filters(&app, &mut config)?;
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let previous = state.current_config()?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;

    if config.enabled {
        let rules_text = config::build_effective_rules(&app, &config);
        state
            .apply_config_change(&previous, &config, &rules_text)
            .inspect_err(|error| {
                state.set_error(Some(error.clone()));
            })?;
    } else {
        state.set_effective_summary(configured_rule_summary(&config))?;
    }

    apply_update_report_error(&state, &report);
    let _ = app.emit("filters-updated", &config.filters);

    Ok(FilterUpdateResult {
        status: state.status(true),
        updated: report.updated,
        failed: report.failed,
        message: report.message,
    })
}

#[tauri::command]
async fn start_dns(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<RuntimeStatus, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || start_dns_blocking(app, state))
        .await
        .map_err(|error| format!("启动 DNS 服务任务异常：{error}"))?
}

fn start_dns_blocking(
    app: tauri::AppHandle,
    state: Arc<AppState>,
) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let mut config = state.current_config()?;
    config::migrate_legacy_defaults(&mut config);
    config.enabled = true;
    config.validate()?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    let rules_text = config::build_effective_rules(&app, &config);
    state.start_current(&rules_text).inspect_err(|error| {
        state.set_error(Some(error.clone()));
    })?;
    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

#[tauri::command]
async fn stop_dns(state: tauri::State<'_, Arc<AppState>>) -> Result<RuntimeStatus, String> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || stop_dns_blocking(state))
        .await
        .map_err(|error| format!("停止 DNS 服务任务异常：{error}"))?
}

fn stop_dns_blocking(state: Arc<AppState>) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
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

fn clear_filter_cache_blocking(
    app: tauri::AppHandle,
    state: Arc<AppState>,
) -> Result<FilterCacheClearResult, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let previous = state.current_config()?;
    let mut config = previous.clone();
    let stats = config::clear_filter_cache(&app, &mut config)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;

    if config.enabled {
        let rules_text = config::build_effective_rules(&app, &config);
        state
            .apply_config_change(&previous, &config, &rules_text)
            .inspect_err(|error| {
                state.set_error(Some(error.clone()));
            })?;
    } else {
        state.set_effective_summary(configured_rule_summary(&config))?;
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

/// 后台按 filter_update_interval_hours 自动更新启用的远程清单。
/// 成功后靠 last_updated 推进下一轮；失败时指数退避，避免网络故障期间频繁请求远端。
fn spawn_filter_auto_update(app: tauri::AppHandle, state: Arc<AppState>) {
    thread::spawn(move || {
        let mut backoff_until = 0_u64;
        let mut backoff_seconds = 0_u64;

        loop {
            thread::sleep(FILTER_AUTO_UPDATE_CHECK_INTERVAL);

            let now = unix_now();
            if now < backoff_until {
                continue;
            }
            let Ok(config) = state.current_config() else {
                continue;
            };
            if !config.use_filters {
                continue;
            }
            let interval_seconds = u64::from(config.filter_update_interval_hours) * 3600;
            let due = config.filters.iter().any(|filter| {
                filter.enabled
                    && filter
                        .last_updated
                        .is_none_or(|updated| now.saturating_sub(updated) >= interval_seconds)
            });
            if !due {
                continue;
            }

            match update_filters_blocking(app.clone(), Arc::clone(&state), config) {
                Ok(result) if result.failed == 0 => {
                    backoff_seconds = 0;
                    backoff_until = 0;
                }
                _ => {
                    backoff_seconds = (backoff_seconds * 2).clamp(
                        FILTER_AUTO_UPDATE_MIN_BACKOFF_SECONDS,
                        FILTER_AUTO_UPDATE_MAX_BACKOFF_SECONDS,
                    );
                    backoff_until = now.saturating_add(backoff_seconds);
                }
            }
        }
    });
}

fn spawn_runtime_watchdog(app: tauri::AppHandle, state: Arc<AppState>) {
    thread::spawn(move || {
        loop {
            let interval = state
                .current_config()
                .map(|config| config.runtime_watchdog_interval_seconds.clamp(10, 3600))
                .unwrap_or_else(|_| AppConfig::default().runtime_watchdog_interval_seconds);
            thread::sleep(Duration::from_secs(interval));

            let _runtime_guard = match state.runtime_update_lock.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    state.set_error(Some("DNS 自恢复任务状态异常".to_string()));
                    continue;
                }
            };
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

            if should_restart {
                // 规则文本不常驻内存，自恢复时从磁盘清单缓存重建
                let rules_text = config::build_effective_rules(&app, &config);
                if let Err(error) = state.start_current(&rules_text) {
                    state.set_error(Some(format!("DNS 自恢复重启失败：{error}")));
                }
            }
        }
    });
}

fn spawn_initial_runtime(app: tauri::AppHandle, state: Arc<AppState>) {
    thread::spawn(move || {
        let _runtime_guard = match state.runtime_update_lock.lock() {
            Ok(guard) => guard,
            Err(_) => {
                state.set_error(Some("DNS 初始化任务状态异常".to_string()));
                return;
            }
        };
        let config = match state.current_config() {
            Ok(config) => config,
            Err(error) => {
                state.set_error(Some(error));
                return;
            }
        };
        if !config.enabled {
            return;
        }

        let rules_text = config::build_effective_rules(&app, &config);
        if let Err(error) = state.start_current(&rules_text) {
            eprintln!("DNS 服务启动失败：{error}");
            state.set_error(Some(error));
        }
    });
}

#[cfg(all(
    any(target_os = "macos", windows, target_os = "linux"),
    not(debug_assertions)
))]
fn apply_autostart_config(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    let current = manager
        .is_enabled()
        .map_err(|error| format!("读取开机自启状态失败：{error}"))?;

    #[cfg(windows)]
    {
        // Windows 自启项可能仍指向旧安装目录或开发版。启用时始终刷新为当前 exe，
        // 不能只根据注册表中是否存在同名项来判断。
        if enabled {
            return manager
                .enable()
                .map_err(|error| format!("启用开机自启失败：{error}"));
        }
        if current {
            return manager
                .disable()
                .map_err(|error| format!("关闭开机自启失败：{error}"));
        }
        return Ok(());
    }

    #[cfg(not(windows))]
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

#[cfg(all(
    any(target_os = "macos", windows, target_os = "linux"),
    debug_assertions
))]
fn apply_autostart_config(_app: &tauri::AppHandle, _enabled: bool) -> Result<(), String> {
    // 开发版依赖 Vite dev server，不能注册为系统自启程序。
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn apply_autostart_config(_app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        Err("当前平台不支持开机自启".to_string())
    } else {
        Ok(())
    }
}

#[cfg(all(windows, debug_assertions))]
fn cleanup_legacy_debug_autostart(app: &tauri::AppHandle) -> Result<(), String> {
    use winreg::{
        RegKey,
        enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE},
    };

    const RUN_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    let current_exe =
        std::env::current_exe().map_err(|error| format!("读取开发版程序路径失败：{error}"))?;
    let current_exe = current_exe.to_string_lossy();
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE)
        .map_err(|error| format!("读取开机自启注册表失败：{error}"))?;

    let mut app_names = vec![app.package_info().name.clone()];
    if !app_names.iter().any(|name| name == "DnsBlackhole") {
        app_names.push("DnsBlackhole".to_string());
    }

    for app_name in app_names {
        let Ok(command) = key.get_value::<String, _>(&app_name) else {
            continue;
        };
        let registered_exe = command.trim().trim_matches('"');
        if registered_exe.eq_ignore_ascii_case(&current_exe) {
            key.delete_value(&app_name)
                .map_err(|error| format!("清理开发版开机自启项失败：{error}"))?;
        }
    }

    Ok(())
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
            clear_filter_cache
        ])
        .setup(|app| {
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            app.handle()
                .plugin(tauri_plugin_autostart::init(
                    MacosLauncher::LaunchAgent,
                    None,
                ))
                .map_err(|error| io::Error::other(format!("开机自启插件初始化失败：{error}")))?;

            #[cfg(all(windows, debug_assertions))]
            if let Err(error) = cleanup_legacy_debug_autostart(app.handle()) {
                eprintln!("{error}");
            }

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
            let autostart_error = apply_autostart_config(app.handle(), config.launch_at_startup)
                .inspect_err(|error| eprintln!("{error}"))
                .err();
            let state = Arc::new(AppState::new(config, database));
            if let Some(error) = autostart_error {
                state.set_error(Some(error));
            }
            let watchdog_state = Arc::clone(&state);
            let auto_update_state = Arc::clone(&state);
            let initial_runtime_state = Arc::clone(&state);
            app.manage(state);
            spawn_initial_runtime(app.handle().clone(), initial_runtime_state);
            spawn_runtime_watchdog(app.handle().clone(), watchdog_state);
            spawn_filter_auto_update(app.handle().clone(), auto_update_state);
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use super::*;
    use crate::config::FilterSubscription;

    #[test]
    fn unrelated_config_change_does_not_rebuild_filter_runtime() {
        let previous = AppConfig::default();
        let mut next = previous.clone();
        next.launch_at_startup = !next.launch_at_startup;
        next.query_log_retention_hours = 24;

        assert!(!filter_runtime_changed(&previous, &next));
        assert!(!needs_dns_restart(&previous, &next));
    }

    #[test]
    fn filtering_config_change_rebuilds_filter_runtime() {
        let previous = AppConfig::default();
        let mut next = previous.clone();
        next.dns_rewrites = "nas.lan 192.168.1.10".into();

        assert!(filter_runtime_changed(&previous, &next));
    }

    #[test]
    fn configured_summary_uses_filter_metadata_without_reading_cache() {
        let config = AppConfig {
            filters: vec![FilterSubscription {
                block_rule_count: 12,
                allow_rule_count: 3,
                ignored_rule_count: 2,
                ignored_comment_count: 1,
                ignored_regex_count: 1,
                ..FilterSubscription::default()
            }],
            blacklist: "||custom.example^".into(),
            ..AppConfig::default()
        };

        let summary = configured_rule_summary(&config);
        assert_eq!(summary.block_rules, 13);
        assert_eq!(summary.allow_rules, 3);
        assert_eq!(summary.ignored_rules, 2);
    }

    #[test]
    fn filter_state_can_be_hot_swapped_without_restarting_server() {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let previous = AppConfig {
            listen_host: Ipv4Addr::LOCALHOST.to_string(),
            listen_port: port,
            listen_ipv6: false,
            upstream_dns: "127.0.0.1:9".into(),
            fallback_dns: String::new(),
            query_log_enabled: false,
            ..AppConfig::default()
        };
        let database = Arc::new(Database::open_in_memory().unwrap());
        let state = AppState::new(previous.clone(), database);
        state.start_current("").unwrap();

        let mut next = previous.clone();
        next.blacklist = "||example.org^".into();
        assert!(
            state
                .try_hot_swap(&previous, &next, &next.blacklist)
                .unwrap()
        );
        assert_eq!(state.effective_summary.lock().unwrap().block_rules, 1);
        assert!(!state.server_needs_start().unwrap());

        state.stop_current().unwrap();
    }
}
