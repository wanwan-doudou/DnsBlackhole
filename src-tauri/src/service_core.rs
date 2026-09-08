//! DNS 服务核心：配置、运行状态、日志统计与后台任务。
//! 不依赖任何 Tauri 窗口能力；Windows 和 macOS 由系统后台服务承载。

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{self, AppConfig},
    database::{Database, LogStats, QueryLogPage, QueryLogQuery},
    dns::{
        self, DnsDiagnosticReport, DnsServer, DnsStats, FilterRuntime, RuleLoadSource, RuleSummary,
        RuntimeStatus, apply_cache_stats, build_filter_runtime_with_rules, clear_rule_cache,
        current_filter_runtime, load_or_compile_rules, replace_filter_runtime,
    },
    filters,
};

const LOG_STATS_CACHE_SECONDS: u64 = 15;
const LOG_PRUNE_INTERVAL_SECONDS: u64 = 60 * 60;
const DATABASE_MAINTENANCE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
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
    protection_paused_until: Arc<AtomicU64>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct QueryLogRuleActionResult {
    pub(crate) status: RuntimeStatus,
    pub(crate) config: AppConfig,
    pub(crate) changed: bool,
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
            protection_paused_until: Arc::new(AtomicU64::new(0)),
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

    /// 取出当前生效的过滤运行时。持有它即可保活其中的编译结果。
    fn active_filter_runtime(&self) -> Option<Arc<FilterRuntime>> {
        let server = self.server.lock().ok()?;
        let server = server.as_ref()?;
        Some(current_filter_runtime(&server.filter_runtime_handle()))
    }

    pub(crate) fn start_current(&self) -> Result<RuleLoadSource, String> {
        let total_started = Instant::now();
        // 停止旧实例会连带释放它持有的编译结果；先保活一份，
        // 让规则没有变化时下面的加载可以直接复用内存而不必重新读盘。
        let retained_runtime = self.active_filter_runtime();
        let stop_started = Instant::now();
        self.stop_current()?;
        crate::performance::log_service("DNS 核心启动", "停止旧运行实例", stop_started);

        let config = self.current_config()?;
        let rules_started = Instant::now();
        let loaded_rules = load_or_compile_rules(&self.data_dir, &config);
        drop(retained_runtime);
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
            Arc::clone(&self.protection_paused_until),
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

    fn restore_config_after_failure(
        &self,
        previous: &AppConfig,
        was_running: bool,
        error: String,
    ) -> String {
        self.restore_config_after_failure_with(previous, was_running, error, Vec::new())
    }

    fn restore_config_after_failure_with(
        &self,
        previous: &AppConfig,
        was_running: bool,
        error: String,
        mut failures: Vec<String>,
    ) -> String {
        if let Err(error) = self.database.save_config(previous) {
            failures.push(error);
        }
        if let Err(error) = self.replace_config(previous.clone()) {
            failures.push(error);
        } else {
            let recovery = if was_running {
                self.start_current().map(|_| ())
            } else {
                self.stop_current()
                    .and_then(|()| self.set_effective_summary(configured_rule_summary(previous)))
            };
            if let Err(error) = recovery {
                failures.push(error);
            }
        }
        let message = if failures.is_empty() {
            format!("新配置应用失败：{error}；已恢复原配置及服务状态")
        } else {
            format!(
                "新配置应用失败：{error}；恢复也失败：{}",
                failures.join("；")
            )
        };
        self.set_error(Some(message.clone()));
        message
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
        self.status_with_log_stats_window(force_log_stats, include_log_stats, None)
    }

    pub(crate) fn status_with_log_stats_window(
        &self,
        force_log_stats: bool,
        include_log_stats: bool,
        statistics_hours: Option<u32>,
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
        if config.statistics_enabled && include_log_stats {
            let log_stats_started = Instant::now();
            let statistics_hours =
                resolve_statistics_hours(statistics_hours, config.statistics_retention_hours);
            match self.cached_log_stats(statistics_hours, force_log_stats) {
                Ok(log_stats) => {
                    stats.queries = log_stats.queries;
                    stats.blocked = log_stats.blocked;
                    stats.forwarded = log_stats.forwarded;
                    stats.failed = log_stats.failed;
                    stats.query_domains = log_stats.query_domains;
                    stats.blocked_domains = log_stats.blocked_domains;
                    stats.client_requests = log_stats.client_requests;
                    stats.client_blocked = log_stats.client_blocked;
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
        let running = if let Ok(server) = self.server.lock() {
            if let Some(server) = server.as_ref() {
                apply_cache_stats(&mut stats, server.cache_stats());
                !server.has_finished_threads()
            } else {
                false
            }
        } else {
            false
        };

        let paused_until = active_pause_deadline(&self.protection_paused_until, unix_now());
        let status = dns::empty_status(&config, running, paused_until, summary, stats, error);
        if force_log_stats {
            crate::performance::log_service("首页数据", "状态快照总计", total_started);
        }
        status
    }

    fn cached_log_stats(
        &self,
        statistics_retention_hours: u32,
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
            && cached.retention_hours == statistics_retention_hours
            && now.saturating_sub(cached.created_at) < LOG_STATS_CACHE_SECONDS
        {
            return Ok(cached.stats);
        }

        let stats = self.database.log_stats(statistics_retention_hours)?;
        let mut cache = self
            .log_stats_cache
            .lock()
            .map_err(|_| "写入日志统计缓存失败".to_string())?;
        *cache = Some(CachedLogStats {
            retention_hours: statistics_retention_hours,
            created_at: now,
            stats: stats.clone(),
        });
        Ok(stats)
    }

    fn maintain_persisted_data_if_due(
        &self,
        query_log_retention_hours: u32,
        statistics_retention_hours: u32,
        security_event_retention_hours: u32,
        now: u64,
    ) -> Result<(), String> {
        let mut last_prune_at = self
            .last_prune_at
            .lock()
            .map_err(|_| "读取日志清理时间失败".to_string())?;
        if now.saturating_sub(*last_prune_at) < LOG_PRUNE_INTERVAL_SECONDS {
            return Ok(());
        }

        self.database.prune_expired(
            query_log_retention_hours,
            statistics_retention_hours,
            security_event_retention_hours,
        )?;
        let since = now.saturating_sub(u64::from(security_event_retention_hours) * 3600);
        self.prune_security_events(since)?;
        *last_prune_at = now;
        drop(last_prune_at);
        // 维护线程中按需回收磁盘，不再让首页状态或日志分页承担整库 VACUUM。
        if let Err(error) = self.database.vacuum_if_bloated() {
            eprintln!("定时清理后按需压缩数据库失败：{error}");
        }
        Ok(())
    }

    /// 立即清理超出保留窗口的查询日志和统计数据，跳过定时节流。
    /// 用于用户调短保留时间后立刻释放历史数据，无需等待下一轮定时清理。
    pub(crate) fn prune_persisted_data_now(
        &self,
        query_log_retention_hours: u32,
        statistics_retention_hours: u32,
        security_event_retention_hours: u32,
        now: u64,
    ) -> Result<(), String> {
        let mut last_prune_at = self
            .last_prune_at
            .lock()
            .map_err(|_| "读取日志清理时间失败".to_string())?;
        self.database.prune_expired(
            query_log_retention_hours,
            statistics_retention_hours,
            security_event_retention_hours,
        )?;
        let since = now.saturating_sub(u64::from(security_event_retention_hours) * 3600);
        self.prune_security_events(since)?;
        *last_prune_at = now;
        Ok(())
    }

    fn prune_security_events(&self, since: u64) -> Result<(), String> {
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| "读取安全事件失败".to_string())?;
        dns::flush_security_events(&stats)?;
        self.database.prune_security_events(since)?;
        stats
            .security_events
            .retain(|event| event.last_seen_at >= since);
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

pub(crate) fn resolve_statistics_hours(requested: Option<u32>, configured: u32) -> u32 {
    match requested {
        None => configured,
        Some(0) => 0,
        Some(hours) if configured > 0 => hours.min(configured),
        Some(hours) => hours.min(crate::config::MAX_STATISTICS_RETENTION_HOURS),
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
        || previous.blocking_response_ttl != next.blocking_response_ttl
        || previous.blocking_custom_ipv4 != next.blocking_custom_ipv4
        || previous.blocking_custom_ipv6 != next.blocking_custom_ipv6
        || previous.rebinding_protection_enabled != next.rebinding_protection_enabled
        || previous.rebinding_allowed_domains != next.rebinding_allowed_domains
        || previous.cname_cloaking_enabled != next.cname_cloaking_enabled
        || previous.dns_rewrites != next.dns_rewrites
        || previous.system_hosts_enabled != next.system_hosts_enabled
        || previous.client_filtering_rules != next.client_filtering_rules
        || previous.client_policy_groups != next.client_policy_groups
        || previous.family_safe_search != next.family_safe_search
        || previous.family_blocked_services != next.family_blocked_services
        || previous.query_log_ignored_domains != next.query_log_ignored_domains
        || previous.statistics_ignored_domains != next.statistics_ignored_domains
}

/// 判断配置差异是否触及 DNS 服务的结构性参数（监听、上游、访问控制、缓存等）。
/// 规则、清单、重写、拦截模式、日志忽略等过滤类字段支持热替换，不在比较范围内。
pub(crate) fn needs_dns_restart(previous: &AppConfig, next: &AppConfig) -> bool {
    previous.listen_host != next.listen_host
        || previous.listen_port != next.listen_port
        || previous.listen_ipv6 != next.listen_ipv6
        || previous.listen_ipv6_host != next.listen_ipv6_host
        || previous.upstream_dns != next.upstream_dns
        || previous.fallback_dns != next.fallback_dns
        || previous.bootstrap_dns != next.bootstrap_dns
        || previous.upstream_mode != next.upstream_mode
        || previous.dnssec_enabled != next.dnssec_enabled
        || previous.domain_upstream_rules != next.domain_upstream_rules
        || previous.client_upstream_rules != next.client_upstream_rules
        || previous.allow_insecure_http != next.allow_insecure_http
        || previous.allowed_clients != next.allowed_clients
        || previous.blocked_clients != next.blocked_clients
        || previous.rate_limit_per_second != next.rate_limit_per_second
        || previous.refuse_any != next.refuse_any
        || previous.private_reverse_dns_enabled != next.private_reverse_dns_enabled
        || previous.query_log_enabled != next.query_log_enabled
        || previous.statistics_enabled != next.statistics_enabled
        || previous.anonymize_client_ip != next.anonymize_client_ip
        || previous.dns_cache_enabled != next.dns_cache_enabled
        || previous.dns_cache_size != next.dns_cache_size
        || previous.dns_cache_min_ttl != next.dns_cache_min_ttl
        || previous.dns_cache_max_ttl != next.dns_cache_max_ttl
        || previous.dns_cache_optimistic != next.dns_cache_optimistic
        || previous.dns_cache_optimistic_max_stale_seconds
            != next.dns_cache_optimistic_max_stale_seconds
        || previous.dns_cache_prefetch_enabled != next.dns_cache_prefetch_enabled
        || previous.dns_cache_prefetch_hit_threshold != next.dns_cache_prefetch_hit_threshold
        || previous.monitoring_api_enabled != next.monitoring_api_enabled
        || previous.monitoring_api_listen_host != next.monitoring_api_listen_host
        || previous.monitoring_api_port != next.monitoring_api_port
        || previous.monitoring_api_token != next.monitoring_api_token
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
    let previous = state.current_config()?;
    let submitted_without_statistics_config = config.schema_version < 11;
    let submitted_schema_version = config.schema_version;
    config::migrate_legacy_defaults(&mut config);
    if submitted_without_statistics_config {
        // 旧版界面不知道独立统计配置，保存其他设置时沿用服务端现值，
        // 避免 serde 默认值或旧版日志设置意外覆盖统计保留期。
        config.statistics_enabled = previous.statistics_enabled;
        config.statistics_retention_hours = previous.statistics_retention_hours;
        config.statistics_ignored_domains = previous.statistics_ignored_domains.clone();
    }
    if submitted_schema_version < 16 {
        config.client_policy_groups = previous.client_policy_groups.clone();
        config.family_safe_search = previous.family_safe_search;
        config.family_blocked_services = previous.family_blocked_services.clone();
        config.monitoring_api_enabled = previous.monitoring_api_enabled;
        config.monitoring_api_listen_host = previous.monitoring_api_listen_host.clone();
        config.monitoring_api_port = previous.monitoring_api_port;
        config.monitoring_api_token = previous.monitoring_api_token.clone();
    }
    if submitted_schema_version < 18 {
        config.listen_ipv6_host = previous.listen_ipv6_host.clone();
    }
    config.validate()?;
    let filter_changed = filter_runtime_changed(&previous, &config);
    let restart_required = needs_dns_restart(&previous, &config);
    let start_required =
        config.enabled && (!previous.enabled || restart_required || state.server_needs_start()?);
    let was_running = !state.server_needs_start()?;
    let old_monitor_occupies_new_dns_port =
        previous.monitoring_api_enabled && previous.monitoring_api_port == config.listen_port;
    let can_preflight_dns_listeners = start_required
        && (!was_running
            || (previous.listen_port != config.listen_port && !old_monitor_occupies_new_dns_port));
    if can_preflight_dns_listeners {
        DnsServer::preflight_listeners(&config)
            .map_err(|error| format!("新配置监听条件预检失败：{error}；原配置及服务未更改"))?;
    }
    state.database.save_config(&config)?;
    if let Err(error) = state.replace_config(config.clone()) {
        return Err(state.restore_config_after_failure(&previous, was_running, error));
    }

    let applied = (|| {
        if !config.enabled {
            state.stop_current()?;
            if filter_changed {
                state.set_effective_summary(configured_rule_summary(&config))?;
            }
            state.set_error(None);
        } else if filter_changed || start_required {
            state.apply_config_change(&previous, &config)?;
        } else {
            state.set_error(None);
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = applied {
        return Err(state.restore_config_after_failure(&previous, was_running, error));
    }

    // 新窗口会立即用于所有查询；物理删除和 VACUUM 放到后台，避免保存配置卡住数秒。
    if config.security_event_retention_hours < previous.security_event_retention_hours
        || config.query_log_retention_hours < previous.query_log_retention_hours
        || statistics_retention_was_shortened(
            previous.statistics_retention_hours,
            config.statistics_retention_hours,
        )
    {
        spawn_database_maintenance_now(Arc::clone(&state));
    }

    state.invalidate_log_stats_cache();
    Ok(state.status(true))
}

fn statistics_retention_was_shortened(previous: u32, next: u32) -> bool {
    next != 0 && (previous == 0 || next < previous)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn query_logs_blocking(
    state: Arc<AppState>,
    filter: Option<String>,
    search: Option<String>,
    domain: Option<String>,
    hours: Option<u32>,
    source: Option<String>,
    query_type: Option<String>,
    sort: Option<String>,
    cursor: Option<String>,
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
            next_cursor: None,
        });
    }

    state.database.query_logs_advanced(QueryLogQuery {
        retention_hours: config.query_log_retention_hours,
        hours,
        filter: filter.as_deref().unwrap_or("all"),
        search: search.as_deref().unwrap_or(""),
        domain: domain.as_deref(),
        source: source.as_deref().unwrap_or("all"),
        query_type: query_type.as_deref().unwrap_or("all"),
        sort: sort.as_deref().unwrap_or("newest"),
        cursor: cursor.as_deref(),
        page: page.unwrap_or(1),
        page_size: page_size.unwrap_or(50),
    })
}

pub(crate) fn clear_query_logs_blocking(state: &AppState) -> Result<RuntimeStatus, String> {
    state.database.clear_query_logs()?;
    Ok(state.status_with_log_stats(true, true))
}

pub(crate) fn clear_statistics_blocking(state: &AppState) -> Result<RuntimeStatus, String> {
    state.database.clear_statistics()?;
    state.invalidate_log_stats_cache();
    Ok(state.status_with_log_stats(true, true))
}

pub(crate) fn clear_security_events_blocking(state: &AppState) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let mut stats = state
        .stats
        .lock()
        .map_err(|_| "读取安全事件失败".to_string())?;
    dns::flush_security_events(&stats)?;
    state.database.clear_security_events()?;
    stats.security_events.clear();
    drop(stats);
    Ok(state.status_with_log_stats(true, true))
}

pub(crate) fn apply_query_log_rule_blocking(
    state: Arc<AppState>,
    domain: String,
    action: String,
    target: Option<String>,
) -> Result<QueryLogRuleActionResult, String> {
    let domain = config::normalize_hostname(&domain)
        .ok_or_else(|| "查询日志中的域名无效，无法创建规则".to_string())?;
    let mut next = state.current_config()?;
    let previous_blacklist = next.blacklist.clone();
    let previous_rewrites = next.dns_rewrites.clone();

    next.blacklist = remove_exact_domain_rules(&next.blacklist, &domain);
    next.dns_rewrites = remove_exact_dns_rewrites(&next.dns_rewrites, &domain);
    let message = match action.as_str() {
        "block" => {
            append_config_line(&mut next.blacklist, &format!("||{domain}^"));
            format!("已拦截 {domain}")
        }
        "allow" => {
            append_config_line(&mut next.blacklist, &format!("@@||{domain}^"));
            format!("已放行 {domain}")
        }
        "rewrite" => {
            let target = target.unwrap_or_default();
            let target = target.trim();
            target
                .parse::<IpAddr>()
                .map_err(|_| "DNS 重写目标必须是有效的 IPv4 或 IPv6 地址".to_string())?;
            append_config_line(&mut next.dns_rewrites, &format!("{domain} {target}"));
            format!("已将 {domain} 重写到 {target}")
        }
        _ => return Err("不支持的查询日志快捷操作".to_string()),
    };

    let changed = next.blacklist != previous_blacklist || next.dns_rewrites != previous_rewrites;
    let status = if changed {
        save_config_blocking(Arc::clone(&state), next.clone())?
    } else {
        state.status(false)
    };
    Ok(QueryLogRuleActionResult {
        status,
        config: next,
        changed,
        message,
    })
}

pub(crate) fn run_dns_diagnostic_blocking(
    state: &AppState,
    domain: String,
    query_type: String,
    client_ip: Option<String>,
) -> Result<DnsDiagnosticReport, String> {
    let config = state.current_config()?;
    let filter = state.active_filter_runtime();
    let protection_paused =
        active_pause_deadline(&state.protection_paused_until, unix_now()).is_some();
    dns::run_dns_diagnostic(
        &config,
        filter.as_deref(),
        protection_paused,
        &domain,
        &query_type,
        client_ip.as_deref(),
    )
}

fn remove_exact_domain_rules(raw: &str, domain: &str) -> String {
    let block = format!("||{domain}^");
    let allow = format!("@@||{domain}^");
    raw.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.eq_ignore_ascii_case(&block) && !trimmed.eq_ignore_ascii_case(&allow)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn remove_exact_dns_rewrites(raw: &str, domain: &str) -> String {
    raw.lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_none_or(|candidate| !candidate.eq_ignore_ascii_case(domain))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn append_config_line(raw: &mut String, line: &str) {
    if !raw.is_empty() && !raw.ends_with('\n') {
        raw.push('\n');
    }
    raw.push_str(line);
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
    // 手动更新沿用“提交当前编辑后更新”的语义，但提交必须发生在下载前。
    // 自动更新只从服务端取快照，绝不提交调用方的旧配置。
    if matches!(scope, FilterUpdateScope::ManualAll) {
        save_config_blocking(Arc::clone(&state), config)?;
    }
    config = state.current_config()?;
    state.begin_filter_update();
    let _progress_guard = FilterUpdateProgressGuard(&state);
    let staging = FilterUpdateStaging::new(&state.data_dir)?;
    let report = match scope {
        FilterUpdateScope::ManualAll => filters::update_enabled_filters(
            &staging.0,
            &mut config,
            &state.filter_update_cancel,
            |progress| state.record_filter_update_progress(progress),
        )?,
        FilterUpdateScope::AutomaticDueAt(now) => filters::update_due_filters(
            &staging.0,
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
    let merged = merge_filter_update(&state.data_dir, &staging.0, &previous, &config)?;
    config = merged.config;
    let was_running = !state.server_needs_start()?;
    state.database.save_config(&config)?;
    if let Err(error) = publish_filter_cache_updates(&state.data_dir, &merged.cache_updates) {
        let mut failures = error.rollback_failures;
        if let Err(error) = state.database.save_config(&previous) {
            failures.push(error);
        }
        let message = if failures.is_empty() {
            format!("清单更新应用失败：{}；已恢复原配置和清单缓存", error.cause)
        } else {
            format!(
                "清单更新应用失败：{}；恢复也失败：{}",
                error.cause,
                failures.join("；")
            )
        };
        state.set_error(Some(message.clone()));
        return Err(message);
    }
    if let Err(error) = state.replace_config(config.clone()) {
        let failures = restore_filter_cache_updates(&state.data_dir, &merged.cache_updates)
            .err()
            .into_iter()
            .collect();
        return Err(state.restore_config_after_failure_with(
            &previous,
            was_running,
            error,
            failures,
        ));
    }

    let rules_may_have_changed = report.updated > 0 || filter_runtime_changed(&previous, &config);
    if config.enabled && rules_may_have_changed {
        if let Err(error) = state.apply_config_change(&previous, &config) {
            let failures = restore_filter_cache_updates(&state.data_dir, &merged.cache_updates)
                .err()
                .into_iter()
                .collect();
            return Err(state.restore_config_after_failure_with(
                &previous,
                was_running,
                error,
                failures,
            ));
        }
    } else if !config.enabled
        && let Err(error) = state.set_effective_summary(configured_rule_summary(&config))
    {
        let failures = restore_filter_cache_updates(&state.data_dir, &merged.cache_updates)
            .err()
            .into_iter()
            .collect();
        return Err(state.restore_config_after_failure_with(
            &previous,
            was_running,
            error,
            failures,
        ));
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

struct FilterUpdateStaging(PathBuf);

impl FilterUpdateStaging {
    fn new(data_dir: &std::path::Path) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = data_dir.join(format!("filter-update-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path)
            .map_err(|error| format!("创建清单更新临时目录失败：{error}"))?;
        Ok(Self(path))
    }
}

impl Drop for FilterUpdateStaging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FilterCacheUpdate {
    id: String,
    previous_content: Option<String>,
    next_content: String,
}

struct MergedFilterUpdate {
    config: AppConfig,
    cache_updates: Vec<FilterCacheUpdate>,
}

#[derive(Debug)]
struct FilterCachePublishError {
    cause: String,
    rollback_failures: Vec<String>,
}

// 在运行状态锁内校验订阅身份并准备缓存变更，下载阶段不会改动正在使用的缓存。
fn merge_filter_update(
    data_dir: &std::path::Path,
    staging: &std::path::Path,
    latest: &AppConfig,
    downloaded: &AppConfig,
) -> Result<MergedFilterUpdate, String> {
    let mut merged = latest.clone();
    let mut cache_updates = Vec::new();
    for filter in &mut merged.filters {
        let Some(result) = downloaded.filters.iter().find(|result| {
            result.id == filter.id && result.url == filter.url && result.enabled && filter.enabled
        }) else {
            continue;
        };
        if let Some(content) = config::read_filter_cache(staging, &filter.id)? {
            cache_updates.push(FilterCacheUpdate {
                id: filter.id.clone(),
                previous_content: config::read_filter_cache(data_dir, &filter.id)?,
                next_content: content,
            });
            let name = filter.name.clone();
            *filter = result.clone();
            filter.name = name;
        } else if result.last_error.is_some() {
            filter.last_error = result.last_error.clone();
        }
    }
    Ok(MergedFilterUpdate {
        config: merged,
        cache_updates,
    })
}

fn publish_filter_cache_updates(
    data_dir: &std::path::Path,
    updates: &[FilterCacheUpdate],
) -> Result<(), FilterCachePublishError> {
    for (index, update) in updates.iter().enumerate() {
        if let Err(error) = config::write_filter_cache(data_dir, &update.id, &update.next_content) {
            return Err(FilterCachePublishError {
                cause: error,
                rollback_failures: restore_filter_cache_updates(data_dir, &updates[..index])
                    .err()
                    .into_iter()
                    .collect(),
            });
        }
    }
    Ok(())
}

fn restore_filter_cache_updates(
    data_dir: &std::path::Path,
    updates: &[FilterCacheUpdate],
) -> Result<(), String> {
    let mut failures = Vec::new();
    for update in updates.iter().rev() {
        let result = match &update.previous_content {
            Some(content) => config::write_filter_cache(data_dir, &update.id, content),
            None => config::remove_filter_cache(data_dir, &update.id),
        };
        if let Err(error) = result {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("；"))
    }
}

pub(crate) fn start_dns_blocking(state: Arc<AppState>) -> Result<RuntimeStatus, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let previous = state.current_config()?;
    let was_running = !state.server_needs_start()?;
    let mut config = previous.clone();
    config::migrate_legacy_defaults(&mut config);
    config.enabled = true;
    config.validate()?;
    state.database.save_config(&config)?;
    if let Err(error) = state.replace_config(config.clone()) {
        return Err(state.restore_config_after_failure(&previous, was_running, error));
    }
    if let Err(error) = state.start_current() {
        return Err(state.restore_config_after_failure(&previous, was_running, error));
    }
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

/// 系统 DNS 接管事务专用：在 resolved stub 释放之后把监听端口切到 53。
///
/// 不走 `save_config_blocking`，因为这里只需要落库加热替换，不需要它的过滤器重载、
/// 保留期清理等完整语义；也不能提前走，通配 53 只有在 stub 让开之后才绑得上。
/// 返回原端口，供接管失败时回滚。
#[cfg(all(feature = "system-service", target_os = "linux"))]
pub(crate) fn apply_listen_port_blocking(state: Arc<AppState>, port: u16) -> Result<u16, String> {
    let _runtime_guard = state
        .runtime_update_lock
        .lock()
        .map_err(|_| "DNS 运行状态更新任务异常".to_string())?;
    let mut config = state.current_config()?;
    let previous = config.listen_port;
    if previous == port {
        return Ok(previous);
    }
    config.listen_port = port;
    config.validate()?;
    state.database.save_config(&config)?;
    state.replace_config(config)?;
    Ok(previous)
}

pub(crate) fn pause_protection_blocking(
    state: &AppState,
    duration_seconds: u64,
) -> Result<RuntimeStatus, String> {
    if !(60..=24 * 3600).contains(&duration_seconds) {
        return Err("暂停时长必须在 1 分钟到 24 小时之间".to_string());
    }
    if !state.status(false).running {
        return Err("DNS 服务未运行，无法暂停过滤保护".to_string());
    }
    state.protection_paused_until.store(
        unix_now().saturating_add(duration_seconds),
        Ordering::Release,
    );
    Ok(state.status(false))
}

pub(crate) fn resume_protection_blocking(state: &AppState) -> Result<RuntimeStatus, String> {
    state.protection_paused_until.store(0, Ordering::Release);
    Ok(state.status(false))
}

fn active_pause_deadline(deadline: &AtomicU64, now: u64) -> Option<u64> {
    let deadline = deadline.load(Ordering::Acquire);
    (deadline > now).then_some(deadline)
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
    let stats = clear_rule_cache(&state.data_dir)?;

    let message = if stats.removed_files == 0 {
        "没有可清理的缓存".to_string()
    } else {
        format!(
            "已清理规则编译缓存（{}），远程黑名单和当前过滤规则继续生效",
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

/// 数据保留期清理和整库压缩可能耗时数秒，必须与首页状态、日志分页等交互请求解耦。
/// 维护线程每分钟检查一次，实际清理由小时级节流控制；查询 SQL 自身仍按保留窗口过滤，
/// 因此启动后的短暂延迟不会让过期数据重新出现在界面上。
pub(crate) fn spawn_database_maintenance(state: Arc<AppState>) {
    thread::spawn(move || {
        loop {
            thread::sleep(DATABASE_MAINTENANCE_CHECK_INTERVAL);
            let Ok(_runtime_guard) = state.runtime_update_lock.lock() else {
                continue;
            };
            let Ok(config) = state.current_config() else {
                continue;
            };
            if let Err(error) = state.maintain_persisted_data_if_due(
                config.query_log_retention_hours,
                config.statistics_retention_hours,
                config.security_event_retention_hours,
                unix_now(),
            ) {
                eprintln!("数据库后台维护失败：{error}");
            }
        }
    });
}

fn spawn_database_maintenance_now(state: Arc<AppState>) {
    thread::spawn(move || {
        // 与配置保存串行后再读取当前值，避免连续保存时用旧窗口误删数据。
        let Ok(_runtime_guard) = state.runtime_update_lock.lock() else {
            return;
        };
        let Ok(config) = state.current_config() else {
            return;
        };
        if let Err(error) = state.prune_persisted_data_now(
            config.query_log_retention_hours,
            config.statistics_retention_hours,
            config.security_event_retention_hours,
            unix_now(),
        ) {
            eprintln!("缩短保留期后的后台清理失败：{error}");
            return;
        }
        if let Err(error) = state.database.vacuum() {
            eprintln!("缩短保留期后的后台压缩失败：{error}");
        }
        state.invalidate_log_stats_cache();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_update_preserves_latest_settings_and_rejects_stale_subscriptions() {
        let root = FilterUpdateStaging::new(&std::env::temp_dir()).unwrap();
        let staging = FilterUpdateStaging::new(&root.0).unwrap();
        let mut downloaded = AppConfig::default();
        downloaded.filters.truncate(4);
        for filter in &mut downloaded.filters {
            filter.enabled = true;
            filter.rule_count = 123;
            filter.last_updated = Some(42);
            config::write_filter_cache(&staging.0, &filter.id, "||downloaded.example^").unwrap();
        }
        let mut latest = downloaded.clone();
        latest.enabled = false;
        latest.upstream_dns = "9.9.9.9".into();
        latest.blacklist = "||local.example^".into();
        latest.filters[0].name = "用户重命名".into();
        latest.filters[0].rule_count = 1;
        latest.filters[1].url = "https://example.com/new.txt".into();
        latest.filters[1].rule_count = 2;
        latest.filters[2].enabled = false;
        latest.filters[2].rule_count = 3;
        latest.filters.pop();
        let merged = merge_filter_update(&root.0, &staging.0, &latest, &downloaded).unwrap();
        assert!(!merged.config.enabled);
        assert_eq!(merged.config.upstream_dns, "9.9.9.9");
        assert_eq!(merged.config.blacklist, latest.blacklist);
        assert_eq!(merged.config.filters.len(), 3);
        assert_eq!(merged.config.filters[0].name, "用户重命名");
        assert_eq!(merged.config.filters[0].rule_count, 123);
        assert_eq!(merged.config.filters[1], latest.filters[1]);
        assert_eq!(merged.config.filters[2], latest.filters[2]);
        assert_eq!(merged.cache_updates.len(), 1);
        assert!(
            config::read_filter_cache(&root.0, &downloaded.filters[0].id)
                .unwrap()
                .is_none()
        );
        publish_filter_cache_updates(&root.0, &merged.cache_updates).unwrap();
        assert!(
            config::read_filter_cache(&root.0, &downloaded.filters[0].id)
                .unwrap()
                .is_some()
        );
        for filter in &downloaded.filters[1..] {
            assert!(
                config::read_filter_cache(&root.0, &filter.id)
                    .unwrap()
                    .is_none()
            );
        }
        restore_filter_cache_updates(&root.0, &merged.cache_updates).unwrap();
        assert!(
            config::read_filter_cache(&root.0, &downloaded.filters[0].id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cancelled_filter_without_download_keeps_existing_cache_and_metadata() {
        let root = FilterUpdateStaging::new(&std::env::temp_dir()).unwrap();
        let staging = FilterUpdateStaging::new(&root.0).unwrap();
        let latest = AppConfig::default();
        let filter = &latest.filters[0];
        config::write_filter_cache(&root.0, &filter.id, "||old.example^").unwrap();
        let merged = merge_filter_update(&root.0, &staging.0, &latest, &latest).unwrap();
        assert_eq!(merged.config.filters, latest.filters);
        assert!(merged.cache_updates.is_empty());
        assert_eq!(
            config::read_filter_cache(&root.0, &filter.id)
                .unwrap()
                .unwrap(),
            "||old.example^"
        );
    }

    #[test]
    fn published_filter_cache_can_restore_previous_content() {
        let root = FilterUpdateStaging::new(&std::env::temp_dir()).unwrap();
        let staging = FilterUpdateStaging::new(&root.0).unwrap();
        let latest = AppConfig::default();
        let mut downloaded = latest.clone();
        let filter = &latest.filters[0];
        downloaded.filters[0].last_updated = Some(42);
        downloaded.filters[0].rule_count = 1;
        config::write_filter_cache(&root.0, &filter.id, "||old.example^").unwrap();
        config::write_filter_cache(&staging.0, &filter.id, "||new.example^").unwrap();

        let merged = merge_filter_update(&root.0, &staging.0, &latest, &downloaded).unwrap();
        publish_filter_cache_updates(&root.0, &merged.cache_updates).unwrap();
        assert_eq!(
            config::read_filter_cache(&root.0, &filter.id)
                .unwrap()
                .unwrap(),
            "||new.example^"
        );

        restore_filter_cache_updates(&root.0, &merged.cache_updates).unwrap();
        assert_eq!(
            config::read_filter_cache(&root.0, &filter.id)
                .unwrap()
                .unwrap(),
            "||old.example^"
        );
    }

    #[test]
    fn automatic_download_does_not_overwrite_concurrent_save_or_stop() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::mpsc,
        };
        let root = FilterUpdateStaging::new(&std::env::temp_dir()).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let initial = AppConfig {
            enabled: true,
            listen_host: "127.0.0.1".into(),
            listen_port: port,
            listen_ipv6: false,
            allow_insecure_http: true,
            filter_proxy_mode: config::FilterProxyMode::Direct,
            filters: vec![config::FilterSubscription {
                id: "slow-download".into(),
                name: "slow".into(),
                url: format!("http://{}/filter.txt", http.local_addr().unwrap()),
                ..Default::default()
            }],
            ..AppConfig::default()
        };
        let state = Arc::new(AppState::new(
            initial.clone(),
            Arc::new(Database::open_in_memory().unwrap()),
            root.0.clone(),
            root.0.clone(),
        ));
        save_config_blocking(Arc::clone(&state), initial.clone()).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let http_thread = thread::spawn(move || {
            let (mut stream, _) = http.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let body = "||downloaded.example^";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let updating = Arc::clone(&state);
        let update_thread =
            thread::spawn(move || update_due_filters_blocking(updating, initial, unix_now()));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut edited = state.current_config().unwrap();
        edited.upstream_dns = "9.9.9.9".into();
        edited.blacklist = "||user.example^".into();
        save_config_blocking(Arc::clone(&state), edited).unwrap();
        stop_dns_blocking(Arc::clone(&state)).unwrap();
        release_tx.send(()).unwrap();
        http_thread.join().unwrap();
        let result = update_thread.join().unwrap().unwrap();
        assert_eq!(result.updated, 1);
        assert!(!result.status.running);
        let latest = state.database.load_config().unwrap().unwrap();
        assert!(!latest.enabled);
        assert_eq!(latest.upstream_dns, "9.9.9.9");
        assert_eq!(latest.blacklist, "||user.example^");
        assert!(latest.filters[0].last_updated.is_some());
    }

    #[test]
    fn unavailable_port_restores_config_and_running_dns() {
        use std::net::{TcpListener, TcpStream};
        let state = test_state();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let previous = AppConfig {
            enabled: true,
            listen_host: "127.0.0.1".into(),
            listen_port: port,
            listen_ipv6: false,
            use_filters: false,
            filters: Vec::new(),
            blacklist: "||example.com^".into(),
            ..AppConfig::default()
        };
        save_config_blocking(Arc::clone(&state), previous.clone()).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let next = AppConfig {
            listen_port: occupied.local_addr().unwrap().port(),
            ..previous.clone()
        };
        let error = save_config_blocking(Arc::clone(&state), next).unwrap_err();
        assert!(error.contains("监听条件预检失败"), "{error}");
        assert!(error.contains("原配置及服务未更改"), "{error}");
        assert_eq!(state.current_config().unwrap().listen_port, port);
        assert_eq!(
            state.database.load_config().unwrap().unwrap().listen_port,
            port
        );
        assert!(!state.server_needs_start().unwrap());
        let response = TcpStream::connect(("127.0.0.1", port));
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.send_to(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ("127.0.0.1", port)).unwrap();
        let mut packet = [0; 512];
        let answer = client.recv(&mut packet);
        state.stop_current().unwrap();
        assert!(response.is_ok());
        assert!(answer.unwrap() >= 12);
        assert_eq!(&packet[..2], &[0x12, 0x34]);
        assert_ne!(packet[2] & 0x80, 0);
        assert_eq!(packet[3] & 0x0f, 0);
    }

    #[test]
    fn unavailable_listen_address_is_rejected_before_stopping_running_dns() {
        let state = test_state();
        let previous_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let next_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let previous = AppConfig {
            enabled: true,
            listen_host: "127.0.0.1".into(),
            listen_port: previous_port,
            listen_ipv6: false,
            use_filters: false,
            filters: Vec::new(),
            ..AppConfig::default()
        };
        save_config_blocking(Arc::clone(&state), previous.clone()).unwrap();

        let next = AppConfig {
            listen_host: "192.0.2.1".into(),
            listen_port: next_port,
            ..previous.clone()
        };
        let error = save_config_blocking(Arc::clone(&state), next).unwrap_err();

        assert!(error.contains("监听条件预检失败"), "{error}");
        assert_eq!(state.current_config().unwrap().listen_host, "127.0.0.1");
        assert!(!state.server_needs_start().unwrap());
        state.stop_current().unwrap();
    }

    #[test]
    fn recovery_failure_is_reported_and_retains_previous_config() {
        let state = test_state();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let previous = AppConfig {
            listen_host: "127.0.0.1".into(),
            listen_port: occupied.local_addr().unwrap().port(),
            listen_ipv6: false,
            use_filters: false,
            filters: Vec::new(),
            ..AppConfig::default()
        };
        let error = state.restore_config_after_failure(&previous, true, "模拟新配置失败".into());
        assert!(error.contains("恢复也失败"), "{error}");
        assert!(!error.contains("已恢复原配置"));
        assert!(state.server_needs_start().unwrap());
        assert_eq!(
            state.database.load_config().unwrap().unwrap().listen_port,
            previous.listen_port
        );
    }

    #[test]
    fn legacy_save_preserves_configured_ipv6_listen_address() {
        let state = test_state();
        let current = AppConfig {
            enabled: false,
            listen_ipv6_host: "::1".into(),
            ..AppConfig::default()
        };
        save_config_blocking(Arc::clone(&state), current.clone()).unwrap();
        let legacy_submission = AppConfig {
            schema_version: 17,
            listen_ipv6_host: "::".into(),
            upstream_dns: "9.9.9.9".into(),
            ..current
        };

        save_config_blocking(Arc::clone(&state), legacy_submission).unwrap();

        let saved = state.current_config().unwrap();
        assert_eq!(saved.listen_ipv6_host, "::1");
        assert_eq!(saved.upstream_dns, "9.9.9.9");
    }

    #[test]
    fn failed_start_restores_disabled_config() {
        let state = test_state();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let previous = AppConfig {
            enabled: false,
            listen_host: "127.0.0.1".into(),
            listen_port: occupied.local_addr().unwrap().port(),
            listen_ipv6: false,
            use_filters: false,
            filters: Vec::new(),
            ..AppConfig::default()
        };
        save_config_blocking(Arc::clone(&state), previous.clone()).unwrap();

        let error = start_dns_blocking(Arc::clone(&state)).unwrap_err();

        assert!(error.contains("已恢复原配置及服务状态"), "{error}");
        assert!(!state.current_config().unwrap().enabled);
        assert!(!state.database.load_config().unwrap().unwrap().enabled);
        assert!(state.server_needs_start().unwrap());
    }

    fn test_state() -> Arc<AppState> {
        let database = Arc::new(Database::open_in_memory().expect("内存数据库应可打开"));
        let data_dir = std::env::temp_dir().join("dnsblackhole-service-core-test");
        Arc::new(AppState::new(
            AppConfig::default(),
            database,
            data_dir.clone(),
            data_dir,
        ))
    }

    #[test]
    fn toggling_system_hosts_only_hot_swaps_filter_runtime() {
        let previous = AppConfig::default();
        let next = AppConfig {
            system_hosts_enabled: true,
            ..previous.clone()
        };
        assert!(filter_runtime_changed(&previous, &next));
        assert!(filter_runtime_changed(&next, &previous));
        assert!(!needs_dns_restart(&previous, &next));
    }

    #[test]
    fn clearing_security_events_orders_pending_writes_before_delete() {
        let state = test_state();
        let writer = crate::dns::security_events::SecurityEventWriter::start(
            Arc::clone(&state.stats),
            Arc::clone(&state.database),
        );
        for index in 0..300 {
            crate::dns::stats::record_access_denied(
                &state.stats,
                "192.0.2.1".parse().unwrap(),
                crate::dns::DnsTransport::Udp,
                format!("old-{index}"),
            );
        }
        clear_security_events_blocking(&state).unwrap();
        crate::dns::stats::record_access_denied(
            &state.stats,
            "192.0.2.1".parse().unwrap(),
            crate::dns::DnsTransport::Udp,
            "new".into(),
        );
        writer.stop();
        let events = state.database.recent_security_events(1000).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, "new");
        assert_eq!(state.stats.lock().unwrap().security_events.len(), 1);
    }

    #[test]
    fn pruning_security_events_removes_pending_and_in_memory_history() {
        let state = test_state();
        let writer = crate::dns::security_events::SecurityEventWriter::start(
            Arc::clone(&state.stats),
            Arc::clone(&state.database),
        );
        let old = crate::dns::SecurityEvent {
            event_type: crate::dns::SecurityEventType::AccessDenied,
            protocol: crate::dns::DnsTransport::Udp,
            client_ip: "192.0.2.1".into(),
            reason: "old".into(),
            first_seen_at: 1,
            last_seen_at: 2,
            count: 1,
        };
        {
            let mut stats = state.stats.lock().unwrap();
            stats.security_events.push_back(old.clone());
            stats
                .security_event_sender
                .as_ref()
                .unwrap()
                .send(crate::dns::security_events::SecurityEventMessage::Event(
                    old,
                ))
                .unwrap();
        }
        let now = unix_now();
        state.prune_persisted_data_now(24, 24, 24, now).unwrap();
        assert!(state.stats.lock().unwrap().security_events.is_empty());
        writer.stop();
        assert!(
            state
                .database
                .recent_security_events(1000)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn interactive_reads_do_not_run_database_maintenance() {
        let state = test_state();

        let _ = state.status_with_log_stats(false, true);
        query_logs_blocking(
            Arc::clone(&state),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(1),
            Some(50),
        )
        .expect("查询日志应可读取");

        assert_eq!(
            *state.last_prune_at.lock().expect("清理状态应可读取"),
            0,
            "首页和日志分页都不应触发保留期清理"
        );
    }

    #[test]
    fn maintenance_path_updates_its_own_throttle() {
        let state = test_state();
        let now = unix_now();
        let config = state.current_config().expect("配置应可读取");

        state
            .maintain_persisted_data_if_due(
                config.query_log_retention_hours,
                config.statistics_retention_hours,
                config.security_event_retention_hours,
                now,
            )
            .expect("后台维护应成功");

        assert_eq!(*state.last_prune_at.lock().expect("清理状态应可读取"), now);
    }
}
