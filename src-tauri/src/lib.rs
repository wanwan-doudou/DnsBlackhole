mod config;
mod database;
mod dns;
mod filters;
mod tray;

use std::{
    io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use config::AppConfig;
use database::{Database, LogStats, QueryLogPage};
use dns::{DnsServer, DnsStats, RuleSummary, RuntimeStatus};
use filters::FilterUpdateReport;
use serde::Serialize;
use tauri::{Manager, WindowEvent};

const LOG_STATS_CACHE_SECONDS: u64 = 15;
const LOG_PRUNE_INTERVAL_SECONDS: u64 = 60 * 60;

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
        if !force_refresh {
            if let Some(cached) = self
                .log_stats_cache
                .lock()
                .map_err(|_| "读取日志统计缓存失败".to_string())?
                .clone()
            {
                if cached.retention_hours == retention_hours
                    && now.saturating_sub(cached.created_at) < LOG_STATS_CACHE_SECONDS
                {
                    return Ok(cached.stats);
                }
            }
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
    config: AppConfig,
) -> Result<RuntimeStatus, String> {
    config.validate()?;
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
    config.validate()?;
    let report = filters::update_enabled_filters(&app, &mut config)?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;

    if config.enabled {
        state.start_current().map_err(|error| {
            state.set_error(Some(error.clone()));
            error
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
    config.enabled = true;
    config.validate()?;
    state.database.save_config(&config)?;
    state.replace_config(config.clone())?;
    state.replace_effective_rules(config::build_effective_rules(&app, &config))?;
    state.start_current().map_err(|error| {
        state.set_error(Some(error.clone()));
        error
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

fn apply_update_report_error(state: &AppState, report: &FilterUpdateReport) {
    if report.failed > 0 {
        state.set_error(Some(report.message.clone()));
    } else {
        state.set_error(None);
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
            clear_dns_cache
        ])
        .setup(|app| {
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
            let effective_rules = config::build_effective_rules(app.handle(), &config);
            let state = Arc::new(AppState::new(config, effective_rules, database));
            if should_start {
                if let Err(error) = state.start_current() {
                    eprintln!("DNS 服务启动失败：{error}");
                    state.set_error(Some(error));
                }
            }
            app.manage(state);
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
