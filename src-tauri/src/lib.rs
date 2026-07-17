mod config;
mod database;
mod dns;
mod filters;
pub mod privileged_bridge;
mod service_core;
mod storage;
mod tray;

#[cfg(not(target_os = "macos"))]
use std::path::Path;
use std::{io, sync::Arc};

use config::AppConfig;
#[cfg(not(target_os = "macos"))]
use database::Database;
use database::QueryLogPage;
use dns::RuntimeStatus;
#[cfg(not(target_os = "macos"))]
use service_core::{
    AppState, clear_dns_cache_blocking, clear_filter_cache_blocking, query_logs_blocking,
    save_config_blocking, spawn_filter_auto_update, spawn_initial_runtime, spawn_runtime_watchdog,
    start_dns_blocking, stop_dns_blocking, update_filters_blocking,
};
use service_core::{FilterCacheClearResult, FilterUpdateResult};
use storage::StorageInfo;
use tauri::{Emitter, Manager, WindowEvent};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri_plugin_autostart::MacosLauncher;
#[cfg(all(
    any(target_os = "macos", windows, target_os = "linux"),
    not(debug_assertions)
))]
use tauri_plugin_autostart::ManagerExt;

struct GuiState {
    #[cfg(not(target_os = "macos"))]
    local: Option<Arc<AppState>>,
}

#[cfg(not(target_os = "macos"))]
impl GuiState {
    fn local(&self) -> Result<Arc<AppState>, String> {
        self.local
            .as_ref()
            .cloned()
            .ok_or_else(|| "当前平台的 DNS 核心由后台服务承载".to_string())
    }
}

#[tauri::command]
fn get_config(state: tauri::State<'_, Arc<GuiState>>) -> Result<AppConfig, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        privileged_bridge::ServiceClient::call("get_config", &serde_json::json!({}))
    }
    #[cfg(not(target_os = "macos"))]
    {
        state.local()?.current_config()
    }
}

#[tauri::command]
fn get_storage_info(state: tauri::State<'_, Arc<GuiState>>) -> Result<StorageInfo, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        privileged_bridge::ServiceClient::call("get_storage_info", &serde_json::json!({}))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let state = state.local()?;
        storage::storage_info(&state.default_data_dir, &state.data_dir)
    }
}

#[tauri::command]
fn request_data_migration(
    state: tauri::State<'_, Arc<GuiState>>,
    target_path: String,
) -> Result<StorageInfo, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        privileged_bridge::ServiceClient::call(
            "request_data_migration",
            &serde_json::json!({ "target_path": target_path }),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let state = state.local()?;
        let target_path = Path::new(target_path.trim());
        if target_path.as_os_str().is_empty() {
            return Err("请选择新的数据存储目录".to_string());
        }
        storage::request_migration(&state.default_data_dir, &state.data_dir, target_path)
    }
}

#[tauri::command]
fn get_macos_service_status() -> Result<privileged_bridge::MacosServiceStatus, String> {
    #[cfg(target_os = "macos")]
    {
        privileged_bridge::ensure_macos_service_current()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("当前平台不支持 macOS DNS 后台服务".to_string())
    }
}

#[tauri::command]
fn install_macos_service(
    force: Option<bool>,
) -> Result<privileged_bridge::MacosServiceStatus, String> {
    #[cfg(target_os = "macos")]
    {
        privileged_bridge::macos_service_install(force.unwrap_or(false))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = force;
        Err("当前平台不支持 macOS DNS 后台服务".to_string())
    }
}

#[tauri::command]
fn uninstall_macos_service() -> Result<privileged_bridge::MacosServiceStatus, String> {
    #[cfg(target_os = "macos")]
    {
        privileged_bridge::macos_service_uninstall()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("当前平台不支持 macOS DNS 后台服务".to_string())
    }
}

#[tauri::command]
fn open_macos_service_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        privileged_bridge::macos_service_open_settings();
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("当前平台不支持 macOS DNS 后台服务".to_string())
    }
}

#[tauri::command]
async fn save_config(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<GuiState>>,
    mut config: AppConfig,
) -> Result<RuntimeStatus, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        config::migrate_legacy_defaults(&mut config);
        config.validate()?;
        apply_autostart_config(&app, config.launch_at_startup)?;
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call(
                "save_config",
                &serde_json::json!({ "config": config }),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            save_config_blocking(state.local()?, config)
        }
    })
    .await
    .map_err(|error| format!("保存配置任务异常：{error}"))?
}

#[tauri::command]
async fn get_status(
    state: tauri::State<'_, Arc<GuiState>>,
    force: Option<bool>,
    include_log_stats: Option<bool>,
) -> Result<RuntimeStatus, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call(
                "get_status",
                &serde_json::json!({
                    "force_log_stats": force.unwrap_or(false),
                    "include_log_stats": include_log_stats.unwrap_or(true),
                }),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(state
                .local()?
                .status_with_log_stats(force.unwrap_or(false), include_log_stats.unwrap_or(true)))
        }
    })
    .await
    .map_err(|error| format!("获取状态失败：{error}"))?
}

#[tauri::command]
async fn get_query_logs(
    state: tauri::State<'_, Arc<GuiState>>,
    filter: Option<String>,
    search: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
) -> Result<QueryLogPage, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call(
                "get_query_logs",
                &serde_json::json!({
                    "filter": filter,
                    "search": search,
                    "page": page,
                    "page_size": page_size,
                }),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            query_logs_blocking(state.local()?, filter, search, page, page_size)
        }
    })
    .await
    .map_err(|error| format!("获取查询日志失败：{error}"))?
}

#[tauri::command]
async fn update_filters(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<GuiState>>,
    config: AppConfig,
) -> Result<FilterUpdateResult, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        let result = privileged_bridge::ServiceClient::call(
            "update_filters",
            &serde_json::json!({ "config": config }),
        )?;
        #[cfg(not(target_os = "macos"))]
        let result = update_filters_blocking(state.local()?, config)?;

        let latest = {
            #[cfg(target_os = "macos")]
            {
                privileged_bridge::ServiceClient::call::<_, AppConfig>(
                    "get_config",
                    &serde_json::json!({}),
                )?
            }
            #[cfg(not(target_os = "macos"))]
            {
                state.local()?.current_config()?
            }
        };
        let _ = app.emit("filters-updated", &latest.filters);
        Ok(result)
    })
    .await
    .map_err(|error| format!("过滤器更新任务异常：{error}"))?
}

#[tauri::command]
async fn start_dns(state: tauri::State<'_, Arc<GuiState>>) -> Result<RuntimeStatus, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call("start_dns", &serde_json::json!({}))
        }
        #[cfg(not(target_os = "macos"))]
        {
            start_dns_blocking(state.local()?)
        }
    })
    .await
    .map_err(|error| format!("启动 DNS 服务任务异常：{error}"))?
}

#[tauri::command]
async fn stop_dns(state: tauri::State<'_, Arc<GuiState>>) -> Result<RuntimeStatus, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call("stop_dns", &serde_json::json!({}))
        }
        #[cfg(not(target_os = "macos"))]
        {
            stop_dns_blocking(state.local()?)
        }
    })
    .await
    .map_err(|error| format!("停止 DNS 服务任务异常：{error}"))?
}

#[tauri::command]
fn clear_dns_cache(state: tauri::State<'_, Arc<GuiState>>) -> Result<RuntimeStatus, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        privileged_bridge::ServiceClient::call("clear_dns_cache", &serde_json::json!({}))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let state = state.local()?;
        clear_dns_cache_blocking(&state)
    }
}

#[tauri::command]
async fn clear_filter_cache(
    state: tauri::State<'_, Arc<GuiState>>,
) -> Result<FilterCacheClearResult, String> {
    #[cfg(target_os = "macos")]
    let _ = state;
    #[cfg(not(target_os = "macos"))]
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        {
            privileged_bridge::ServiceClient::call("clear_filter_cache", &serde_json::json!({}))
        }
        #[cfg(not(target_os = "macos"))]
        {
            clear_filter_cache_blocking(state.local()?)
        }
    })
    .await
    .map_err(|error| format!("清理过滤器缓存任务异常：{error}"))?
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            get_config,
            get_storage_info,
            request_data_migration,
            get_macos_service_status,
            install_macos_service,
            uninstall_macos_service,
            open_macos_service_settings,
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
            #[cfg(target_os = "macos")]
            {
                app.manage(Arc::new(GuiState {}));
                if let Err(error) = privileged_bridge::ensure_macos_service_current() {
                    eprintln!("自动修复 macOS DNS 后台服务失败：{error}");
                }
                if let Ok(config) = privileged_bridge::ServiceClient::call::<_, AppConfig>(
                    "get_config",
                    &serde_json::json!({}),
                ) && let Err(error) =
                    apply_autostart_config(app.handle(), config.launch_at_startup)
                {
                    eprintln!("{error}");
                }
            }

            #[cfg(not(target_os = "macos"))]
            {
                let storage = storage::initialize(app.handle())
                    .map_err(|error| io::Error::other(format!("数据目录初始化失败：{error}")))?;
                let database = Arc::new(
                    Database::open(&storage.data_dir)
                        .map_err(|error| io::Error::other(format!("数据库初始化失败：{error}")))?,
                );
                let cleanup_error =
                    storage::finish_pending_cleanup(&storage.default_dir, &storage.data_dir)
                        .inspect_err(|error| eprintln!("迁移后清理原数据失败：{error}"))
                        .err();
                let config = match database.load_or_migrate_config(app.handle()) {
                    Ok(config) => config,
                    Err(error) => {
                        eprintln!("数据库配置加载失败：{error}");
                        AppConfig::default()
                    }
                };
                let autostart_error =
                    apply_autostart_config(app.handle(), config.launch_at_startup)
                        .inspect_err(|error| eprintln!("{error}"))
                        .err();
                let state = Arc::new(AppState::new(
                    config,
                    database,
                    storage.default_dir,
                    storage.data_dir,
                ));
                let startup_error = storage
                    .migration_error
                    .or(cleanup_error.map(|error| format!("迁移后清理原数据失败：{error}")))
                    .or(autostart_error);
                if let Some(error) = startup_error {
                    state.set_error(Some(error));
                }
                let watchdog_state = Arc::clone(&state);
                let auto_update_state = Arc::clone(&state);
                let initial_runtime_state = Arc::clone(&state);
                app.manage(Arc::new(GuiState {
                    local: Some(Arc::clone(&state)),
                }));
                spawn_initial_runtime(initial_runtime_state);
                spawn_runtime_watchdog(watchdog_state);
                let app_handle = app.handle().clone();
                spawn_filter_auto_update(auto_update_state, move |config| {
                    let _ = app_handle.emit("filters-updated", &config.filters);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app, _event| {
            // macOS 关闭窗口后点击 Dock 图标应恢复主窗口
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                tray::show_main_window(_app);
            }
        });
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use super::*;
    use crate::{config::FilterSubscription, database::Database, service_core::AppState};

    #[test]
    fn unrelated_config_change_does_not_rebuild_filter_runtime() {
        let previous = AppConfig::default();
        let mut next = previous.clone();
        next.launch_at_startup = !next.launch_at_startup;
        next.query_log_retention_hours = 24;

        assert!(!service_core::filter_runtime_changed(&previous, &next));
        assert!(!service_core::needs_dns_restart(&previous, &next));
    }

    #[test]
    fn filtering_config_change_rebuilds_filter_runtime() {
        let previous = AppConfig::default();
        let mut next = previous.clone();
        next.dns_rewrites = "nas.lan 192.168.1.10".into();

        assert!(service_core::filter_runtime_changed(&previous, &next));
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

        let summary = service_core::configured_rule_summary(&config);
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
        let data_dir = std::env::temp_dir();
        let state = AppState::new(previous.clone(), database, data_dir.clone(), data_dir);
        state.start_current("").unwrap();

        let mut next = previous.clone();
        next.blacklist = "||example.org^".into();
        assert!(
            state
                .try_hot_swap(&previous, &next, &next.blacklist)
                .unwrap()
        );
        assert_eq!(state.status(false).summary.block_rules, 1);
        assert!(!state.server_needs_start().unwrap());

        state.stop_current().unwrap();
    }
}
