//! DNS 服务核心：配置、运行状态、日志统计与后台任务。
//! 不依赖任何 Tauri 窗口能力；Windows 和 macOS 由系统后台服务承载。

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{self, AppConfig},
    database::{Database, LogStats, QueryLogPage},
    dns::{
        self, DnsServer, DnsStats, RuleLoadSource, RuleSummary, RuntimeStatus,
        build_filter_runtime_with_rules, load_or_compile_rules, replace_filter_runtime,
    },
    filters,
};

const LOG_STATS_CACHE_SECONDS: u64 = 15;
const LOG_PRUNE_INTERVAL_SECONDS: u64 = 60 * 60;
const FILTER_AUTO_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const FILTER_AUTO_UPDATE_MIN_BACKOFF_SECONDS: u64 = 5 * 60;
const FILTER_AUTO_UPDATE_MAX_BACKOFF_SECONDS: u64 = 6 * 3600;

pub(crate) struct AppState {
    config: Mutex<AppConfig>,
    server: Mutex<Option<DnsServer>>,
    effective_summary: Mutex<RuleSummary>,
    stats: Arc<Mutex<DnsStats>>,
    pub(crate) database: Arc<Database>,
    pub(crate) default_data_dir: PathBuf,
    pub(crate) data_dir: PathBuf,
    log_stats_cache: Mutex<Option<CachedLogStats>>,
    last_prune_at: Mutex<u64>,
    last_error: Mutex<Option<String>>,
    // 手动更新与自动更新共用，避免并发下载清单互相踩踏
    filter_update_lock: Mutex<()>,
    filter_update_progress: Mutex<FilterUpdateProgressState>,
    filter_update_cancel: AtomicBool,
    // 启停、配置保存和规则热替换串行执行，避免后台初始化与用户操作互相覆盖
    pub(crate) runtime_update_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
struct CachedLogStats {
    retention_hours: u32,
    created_at: u64,
    stats: LogStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FilterUpdateResult {
    pub(crate) status: RuntimeStatus,
    pub(crate) updated: usize,
    pub(crate) failed: usize,
    pub(crate) cancelled: usize,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FilterUpdateProgressState {
    pub(crate) running: bool,
    pub(crate) total: usize,
    pub(crate) completed: usize,
    pub(crate) updated: usize,
    pub(crate) failed: usize,
    pub(crate) cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FilterCacheClearResult {
    pub(crate) status: RuntimeStatus,
    pub(crate) removed_files: usize,
    pub(crate) removed_bytes: u64,
    pub(crate) message: String,
}

#[derive(Clone, Copy)]
enum FilterUpdateScope {
    ManualAll,
    AutomaticDueAt(u64),
}

impl AppState {
    pub(crate) fn new(
        config: AppConfig,
        database: Arc<Database>,
        default_data_dir: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        let effective_summary = configured_rule_summary(&config);
        Self {
            config: Mutex::new(config),
            server: Mutex::new(None),
            effective_summary: Mutex::new(effective_summary),
            stats: Arc::new(Mutex::new(DnsStats::default())),
            database,
            default_data_dir,
            data_dir,
            log_stats_cache: Mutex::new(None),
            last_prune_at: Mutex::new(0),
            last_error: Mutex::new(None),
            filter_update_lock: Mutex::new(()),
            filter_update_progress: Mutex::new(FilterUpdateProgressState::default()),
            filter_update_cancel: AtomicBool::new(false),
            runtime_update_lock: Mutex::new(()),
        }
    }

    pub(crate) fn current_config(&self) -> Result<AppConfig, String> {
        self.config
            .lock()
            .map(|config| config.clone())
            .map_err(|_| "读取配置失败".into())
    }

    pub(crate) fn filter_update_progress(&self) -> Result<FilterUpdateProgressState, String> {
        self.filter_update_progress
            .lock()
            .map(|progress| progress.clone())
            .map_err(|_| "读取过滤器更新进度失败".into())
    }

    pub(crate) fn request_filter_update_cancel(&self) -> Result<FilterUpdateProgressState, String> {
        self.filter_update_cancel.store(true, Ordering::Release);
        let mut progress = self
            .filter_update_progress
            .lock()
            .map_err(|_| "写入过滤器取消状态失败".to_string())?;
        if progress.running {
            progress.cancel_requested = true;
        }
        Ok(progress.clone())
    }

    fn begin_filter_update(&self) {
        self.filter_update_cancel.store(false, Ordering::Release);
        if let Ok(mut progress) = self.filter_update_progress.lock() {
            *progress = FilterUpdateProgressState {
                running: true,
                ..FilterUpdateProgressState::default()
            };
        }
    }

    fn record_filter_update_progress(&self, update: filters::FilterUpdateProgress) {
        if let Ok(mut progress) = self.filter_update_progress.lock() {
            progress.total = update.total;
            progress.completed = update.completed;
            progress.updated = update.updated;
            progress.failed = update.failed;
            progress.cancel_requested = self.filter_update_cancel.load(Ordering::Acquire);
        }
    }

    fn finish_filter_update(&self) {
        if let Ok(mut progress) = self.filter_update_progress.lock() {
            progress.running = false;
            progress.cancel_requested = self.filter_update_cancel.load(Ordering::Acquire);
        }
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

    pub(crate) fn start_current(&self) -> Result<RuleLoadSource, String> {
        let total_started = Instant::now();
        let stop_started = Instant::now();
        self.stop_current()?;
        crate::performance::log_service("DNS 核心启动", "停止旧运行实例", stop_started);

        let config = self.current_config()?;
        let rules_started = Instant::now();
        let loaded_rules = load_or_compile_rules(&self.data_dir, &config);
        crate::performance::log_service("DNS 核心启动", "规则加载", rules_started);
        let source = loaded_rules.source;
        let filter_runtime_started = Instant::now();
        let filter_runtime = build_filter_runtime_with_rules(&config, loaded_rules.rules);
        crate::performance::log_service("DNS 核心启动", "过滤运行时构建", filter_runtime_started);
        let server_started = Instant::now();
        let server = DnsServer::start_with_filter_runtime(
            config,
            filter_runtime,
            Arc::clone(&self.stats),
            Arc::clone(&self.database),
        )?;
        crate::performance::log_service("DNS 核心启动", "DNS 服务实例", server_started);
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
        crate::performance::log_service("DNS 核心启动", "总计", total_started);
        Ok(source)
    }

    pub(crate) fn stop_current(&self) -> Result<(), String> {
        let server = {
            let mut current = self.server.lock().map_err(|_| "读取 DNS 服务状态失败")?;
            current.take()
        };

        if let Some(server) = server {
            server.stop();
        }
        Ok(())
    }

    pub(crate) fn server_needs_start(&self) -> Result<bool, String> {
        let server = self
            .server
            .lock()
            .map_err(|_| "读取 DNS 服务状态失败".to_string())?;
        Ok(server.as_ref().is_none_or(DnsServer::has_finished_threads))
    }

    /// 规则类配置变更时热替换过滤状态，保留运行中的服务与 DNS 缓存。
    /// 返回 false 表示需要走完整重启路径。
    pub(crate) fn try_hot_swap(
        &self,
        previous: &AppConfig,
        config: &AppConfig,
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
        let loaded_rules = load_or_compile_rules(&self.data_dir, config);
        let runtime = build_filter_runtime_with_rules(config, loaded_rules.rules);
        let summary = runtime.summary();
        replace_filter_runtime(&filter_runtime, runtime);
        self.set_effective_summary(summary)?;
        Ok(true)
    }

    /// 应用新配置：能热替换就热替换，否则重启 DNS 服务。
    /// 调用前需要先完成 replace_config。
    fn apply_config_change(&self, previous: &AppConfig, config: &AppConfig) -> Result<(), String> {
        if !config.enabled {
            self.stop_current()?;
            self.set_error(None);
            return Ok(());
        }

        if self.try_hot_swap(previous, config)? {
            self.set_error(None);
            return Ok(());
        }

        self.start_current().map(|_| ())
    }

    pub(crate) fn set_error(&self, error: Option<String>) {
        if let Ok(mut current) = self.last_error.lock() {
            *current = error;
        }
    }

    pub(crate) fn status(&self, force_log_stats: bool) -> RuntimeStatus {
        self.status_with_log_stats(force_log_stats, true)
    }

    pub(crate) fn status_with_log_stats(
        &self,
        force_log_stats: bool,
        include_log_stats: bool,
    ) -> RuntimeStatus {
        let total_started = Instant::now();
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
            let log_stats_started = Instant::now();
            match self.cached_log_stats(config.query_log_retention_hours, force_log_stats) {
                Ok(log_stats) => {
                    stats.queries = log_stats.queries;
                    stats.blocked = log_stats.blocked;
                    stats.forwarded = log_stats.forwarded;
                    stats.failed = log_stats.failed;
                    stats.query_domains = log_stats.query_domains;
                    stats.blocked_domains = log_stats.blocked_domains;
                    stats.client_requests = log_stats.client_requests;
                    stats.blocklist_hits = log_stats.blocklist_hits;
                    stats.traffic = log_stats.traffic;
                    stats.upstream_requests = log_stats.upstream_requests;
                    stats.upstream_avg_latency = log_stats.upstream_avg_latency;
                    stats.dashboard_started_at = log_stats.dashboard_started_at;
                    stats.dashboard_ended_at = log_stats.dashboard_ended_at;
                }
                Err(error) => self.set_error(Some(error)),
            }
            if force_log_stats {
                crate::performance::log_service("首页数据", "查询日志统计", log_stats_started);
            }
        }
        let error = self.last_error.lock().ok().and_then(|error| error.clone());
        let running = self
            .server
            .lock()
            .ok()
            .and_then(|server| server.as_ref().map(|server| !server.has_finished_threads()))
            .unwrap_or(false);

        let status = dns::empty_status(&config, running, summary, stats, error);
        if force_log_stats {
            crate::performance::log_service("首页数据", "状态快照总计", total_started);
        }
        status
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

    pub(crate) fn prune_query_logs_if_due(
        &self,
        retention_hours: u32,
        now: u64,
    ) -> Result<(), String> {
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

    /// 立即清理超出保留窗口的查询日志，跳过定时节流。
    /// 用于用户调短保留时间后立刻释放历史数据，无需等待下一轮定时清理。
    pub(crate) fn prune_query_logs_now(
        &self,
        retention_hours: u32,
        now: u64,
    ) -> Result<(), String> {
        let mut last_prune_at = self
            .last_prune_at
            .lock()
            .map_err(|_| "读取日志清理时间失败".to_string())?;
        self.database.prune_query_logs(retention_hours)?;
        *last_prune_at = now;
        Ok(())
    }

    fn invalidate_log_stats_cache(&self) {
        if let Ok(mut cache) = self.log_stats_cache.lock() {
            *cache = None;
        }
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.stop_current();
    }
}

struct FilterUpdateProgressGuard<'a>(&'a AppState);

impl Drop for FilterUpdateProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.finish_filter_update();
    }
}

pub(crate) fn configured_rule_summary(config: &AppConfig) -> RuleSummary {
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

pub(crate) fn filter_runtime_changed(previous: &AppConfig, next: &AppConfig) -> bool {
    previous.use_filters != next.use_filters
        || previous.filters.len() != next.filters.len()
        || previous
            .filters
            .iter()
            .zip(&next.filters)
            .any(|(previous, next)| {
                previous.id != next.id
                    || previous.name != next.name
                    || previous.enabled != next.enabled
            })
        || previous.blacklist != next.blacklist
        || previous.blocking_mode != next.blocking_mode
        || previous.blocking_custom_ipv4 != next.blocking_custom_ipv4
        || previous.blocking_custom_ipv6 != next.blocking_custom_ipv6
        || previous.dns_rewrites != next.dns_rewrites
        || previous.query_log_ignored_domains != next.query_log_ignored_domains
}

/// 判断配置差异是否触及 DNS 服务的结构性参数（监听、上游、访问控制、缓存等）。
/// 规则、清单、重写、拦截模式、日志忽略等过滤类字段支持热替换，不在比较范围内。
pub(crate) fn needs_dns_restart(previous: &AppConfig, next: &AppConfig) -> bool {
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

/// 保存配置并按需热替换或重启 DNS。开机自启等 GUI 侧系统集成由调用方处理。
pub(crate) fn save_config_blocking(
    state: Arc<AppState>,
    mut config: AppConfig,
) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
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
        if let Err(error) = state.apply_config_change(&previous, &config) {
            state.set_error(Some(error.clone()));
            return Err(error);
        }
    } else {
        state.set_error(None);
    }

    // 保留时间调短后立即清理超出新窗口的历史日志，无需等待下一轮定时清理
    if config.query_log_retention_hours < previous.query_log_retention_hours {
        state.prune_query_logs_now(config.query_log_retention_hours, unix_now())?;
    }

    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

pub(crate) fn query_logs_blocking(
    state: Arc<AppState>,
    filter: Option<String>,
    search: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
) -> Result<QueryLogPage, String> {
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
}

/// 更新启用的远程清单并应用。前端事件通知由调用方处理。
pub(crate) fn update_filters_blocking(
    state: Arc<AppState>,
    config: AppConfig,
) -> Result<FilterUpdateResult, String> {
    update_filters_blocking_with_scope(state, config, FilterUpdateScope::ManualAll)
}

fn update_due_filters_blocking(
    state: Arc<AppState>,
    config: AppConfig,
    now: u64,
) -> Result<FilterUpdateResult, String> {
    update_filters_blocking_with_scope(state, config, FilterUpdateScope::AutomaticDueAt(now))
}

fn update_filters_blocking_with_scope(
    state: Arc<AppState>,
    mut config: AppConfig,
    scope: FilterUpdateScope,
) -> Result<FilterUpdateResult, String> {
    let _update_guard = state
        .filter_update_lock
        .lock()
        .map_err(|_| "清单更新任务状态异常".to_string())?;
    config::migrate_legacy_defaults(&mut config);
    config.validate()?;
    state.begin_filter_update();
    let _progress_guard = FilterUpdateProgressGuard(&state);
    let report = match scope {
        FilterUpdateScope::ManualAll => filters::update_enabled_filters(
            &state.data_dir,
            &mut config,
            &state.filter_update_cancel,
            |progress| state.record_filter_update_progress(progress),
        )?,
        FilterUpdateScope::AutomaticDueAt(now) => filters::update_due_filters(
            &state.data_dir,
            &mut config,
            now,
            &state.filter_update_cancel,
            |progress| state.record_filter_update_progress(progress),
        )?,
    };
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let previous = state.current_config()?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;

    let rules_may_have_changed = report.updated > 0 || filter_runtime_changed(&previous, &config);
    if config.enabled && rules_may_have_changed {
        state
            .apply_config_change(&previous, &config)
            .inspect_err(|error| {
                state.set_error(Some(error.clone()));
            })?;
    } else if !config.enabled {
        state.set_effective_summary(configured_rule_summary(&config))?;
    }

    let status = match scope {
        FilterUpdateScope::ManualAll => state.status(true),
        FilterUpdateScope::AutomaticDueAt(_) => state.status_with_log_stats(false, false),
    };
    Ok(FilterUpdateResult {
        status,
        updated: report.updated,
        failed: report.failed,
        cancelled: report.cancelled,
        message: report.message,
    })
}

pub(crate) fn start_dns_blocking(state: Arc<AppState>) -> Result<RuntimeStatus, String> {
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
    state.start_current().inspect_err(|error| {
        state.set_error(Some(error.clone()));
    })?;
    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

pub(crate) fn stop_dns_blocking(state: Arc<AppState>) -> Result<RuntimeStatus, String> {
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

pub(crate) fn clear_dns_cache_blocking(state: &AppState) -> Result<RuntimeStatus, String> {
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

pub(crate) fn clear_filter_cache_blocking(
    state: Arc<AppState>,
) -> Result<FilterCacheClearResult, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let previous = state.current_config()?;
    let mut config = previous.clone();
    let stats = config::clear_filter_cache(&state.data_dir, &mut config)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;

    if config.enabled {
        state
            .apply_config_change(&previous, &config)
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

/// 后台按 filter_update_interval_hours 仅更新已到期或从未成功更新的远程清单。
/// 成功后靠 last_updated 推进下一轮；失败时指数退避，避免网络故障期间频繁请求远端。
/// 更新成功后通过 on_updated 通知调用方（进程内运行的平台借此向前端推送事件）。
pub(crate) fn spawn_filter_auto_update<F>(state: Arc<AppState>, on_updated: F)
where
    F: Fn(&AppConfig) + Send + 'static,
{
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
            if !filters::has_due_filters(&config, now) {
                continue;
            }

            let update_complete = match update_due_filters_blocking(Arc::clone(&state), config, now)
            {
                Ok(result) => {
                    if let Ok(latest) = state.current_config() {
                        on_updated(&latest);
                    }
                    result.failed == 0
                }
                Err(_) => false,
            };
            if update_complete {
                backoff_seconds = 0;
                backoff_until = 0;
            } else {
                backoff_seconds = (backoff_seconds * 2).clamp(
                    FILTER_AUTO_UPDATE_MIN_BACKOFF_SECONDS,
                    FILTER_AUTO_UPDATE_MAX_BACKOFF_SECONDS,
                );
                backoff_until = now.saturating_add(backoff_seconds);
            }
        }
    });
}

pub(crate) fn spawn_runtime_watchdog(state: Arc<AppState>) {
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

            if should_restart && let Err(error) = state.start_current() {
                state.set_error(Some(format!("DNS 自恢复重启失败：{error}")));
            }
        }
    });
}

#[cfg(not(windows))]
pub(crate) fn spawn_initial_runtime(state: Arc<AppState>) {
    thread::spawn(move || {
        initialize_runtime_blocking(&state);
    });
}

pub(crate) fn initialize_runtime_blocking(state: &AppState) -> Option<RuleLoadSource> {
    let total_started = Instant::now();
    let lock_started = Instant::now();
    let _runtime_guard = match state.runtime_update_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            state.set_error(Some("DNS 初始化任务状态异常".to_string()));
            return None;
        }
    };
    crate::performance::log_service("服务启动", "DNS 初始化锁等待", lock_started);
    let config = match state.current_config() {
        Ok(config) => config,
        Err(error) => {
            state.set_error(Some(error));
            return None;
        }
    };
    if !config.enabled {
        return None;
    }

    let result = match state.start_current() {
        Ok(source) => Some(source),
        Err(error) => {
            eprintln!("DNS 服务启动失败：{error}");
            state.set_error(Some(error));
            None
        }
    };
    crate::performance::log_service("服务启动", "DNS 运行时初始化总计", total_started);
    result
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
