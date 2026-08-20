use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::json;

use crate::{
    config::{AppConfig, CURRENT_CONFIG_SCHEMA_VERSION, migrate_legacy_defaults},
    dns::RuntimeStatus,
};

const MAX_IMPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CSV_EXPORT_BYTES: usize = 32 * 1024 * 1024;

#[tauri::command]
pub(crate) async fn export_config_file(path: String, config: AppConfig) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        config.validate()?;
        write_json(Path::new(&path), &config)
    })
    .await
    .map_err(|error| format!("导出配置任务异常：{error}"))?
}

#[tauri::command]
pub(crate) async fn import_config_file(path: String) -> Result<AppConfig, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(path);
        let metadata = fs::metadata(&path).map_err(|error| format!("读取配置文件失败：{error}"))?;
        if metadata.len() > MAX_IMPORT_BYTES {
            return Err("配置文件超过 4 MiB，已拒绝导入".to_string());
        }
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("配置文件必须是有效的 UTF-8 文本：{error}"))?;
        parse_imported_config(&content)
    })
    .await
    .map_err(|error| format!("导入配置任务异常：{error}"))?
}

fn parse_imported_config(content: &str) -> Result<AppConfig, String> {
    let mut config: AppConfig =
        serde_json::from_str(content).map_err(|error| format!("配置 JSON 格式无效：{error}"))?;
    if config.schema_version > CURRENT_CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "配置版本 {} 高于当前支持的版本 {}，请先升级 DnsBlackhole",
            config.schema_version, CURRENT_CONFIG_SCHEMA_VERSION
        ));
    }
    migrate_legacy_defaults(&mut config);
    config.validate()?;
    Ok(config)
}

#[tauri::command]
pub(crate) async fn export_diagnostic_file(
    path: String,
    config: AppConfig,
    status: Option<RuntimeStatus>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut sanitized_config = config;
        redact_config(&mut sanitized_config);
        let sanitized_status = status.map(sanitize_status);
        let report = json!({
            "format": "dnsblackhole-diagnostic-v1",
            "generated_at_unix": unix_now(),
            "application": {
                "version": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            },
            "privacy": "域名、客户端地址、访问列表、代理地址、上游地址、规则内容和过滤器 URL 已隐藏",
            "config": sanitized_config,
            "runtime": sanitized_status,
        });
        write_json(Path::new(&path), &report)
    })
    .await
    .map_err(|error| format!("导出诊断信息任务异常：{error}"))?
}

#[tauri::command]
pub(crate) async fn export_query_log_file(path: String, content: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        if content.len() > MAX_CSV_EXPORT_BYTES {
            return Err("查询日志导出内容超过 32 MiB，请缩小筛选范围".to_string());
        }
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            return Err("请选择导出文件位置".to_string());
        }
        fs::write(path, content.as_bytes()).map_err(|error| format!("写入查询日志失败：{error}"))
    })
    .await
    .map_err(|error| format!("导出查询日志任务异常：{error}"))?
}

fn redact_config(config: &mut AppConfig) {
    redact_lines(&mut config.upstream_dns);
    redact_lines(&mut config.fallback_dns);
    redact_lines(&mut config.bootstrap_dns);
    redact_lines(&mut config.domain_upstream_rules);
    redact_lines(&mut config.client_upstream_rules);
    redact_lines(&mut config.client_filtering_rules);
    redact_lines(&mut config.allowed_clients);
    redact_lines(&mut config.blocked_clients);
    redact_lines(&mut config.rebinding_allowed_domains);
    redact_lines(&mut config.dns_rewrites);
    redact_lines(&mut config.client_names);
    redact_lines(&mut config.query_log_ignored_domains);
    redact_lines(&mut config.statistics_ignored_domains);
    redact_lines(&mut config.blacklist);
    config.listen_host = "<已隐藏>".to_string();
    config.blocking_custom_ipv4 = redact_value(&config.blocking_custom_ipv4);
    config.blocking_custom_ipv6 = redact_value(&config.blocking_custom_ipv6);
    config.filter_proxy_url = redact_value(&config.filter_proxy_url);
    config.filter_system_proxy_url = redact_value(&config.filter_system_proxy_url);
    for filter in &mut config.filters {
        filter.url = "<已隐藏>".to_string();
        if filter.last_error.is_some() {
            filter.last_error = Some("<已隐藏错误详情>".to_string());
        }
    }
}

fn sanitize_status(mut status: RuntimeStatus) -> RuntimeStatus {
    status.listen_addr = "<已隐藏>".to_string();
    status.upstream_dns = "<已隐藏>".to_string();
    status.error = status.error.map(|_| "<已隐藏错误详情>".to_string());
    status.stats.last_query = status.stats.last_query.map(|_| "<已隐藏>".to_string());
    status.stats.last_blocked = status.stats.last_blocked.map(|_| "<已隐藏>".to_string());
    status.stats.last_error = status
        .stats
        .last_error
        .map(|_| "<已隐藏错误详情>".to_string());
    status.stats.query_domains.clear();
    status.stats.blocked_domains.clear();
    status.stats.client_requests.clear();
    status.stats.client_blocked.clear();
    status.stats.blocklist_hits.clear();
    status.stats.security_events.clear();
    for upstream in &mut status.stats.upstream_requests {
        upstream.upstream = "<已隐藏>".to_string();
    }
    for upstream in &mut status.stats.upstream_avg_latency {
        upstream.upstream = "<已隐藏>".to_string();
    }
    status
}

fn redact_lines(value: &mut String) {
    let count = value
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#') && !line.starts_with('!')
        })
        .count();
    *value = if count == 0 {
        String::new()
    } else {
        format!("<已隐藏 {count} 行>")
    };
}

fn redact_value(value: &str) -> String {
    if value.trim().is_empty() {
        String::new()
    } else {
        "<已隐藏>".to_string()
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("请选择导出文件位置".to_string());
    }
    let mut content =
        serde_json::to_vec_pretty(value).map_err(|error| format!("序列化导出内容失败：{error}"))?;
    content.push(b'\n');
    fs::write(path, content).map_err(|error| format!("写入导出文件失败：{error}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_export_removes_private_fields() {
        let mut config = AppConfig {
            upstream_dns: "https://token@example.test/dns-query".to_string(),
            allowed_clients: "192.168.1.0/24".to_string(),
            blacklist: "||private.example^".to_string(),
            filter_proxy_url: "http://user:pass@proxy.test".to_string(),
            ..AppConfig::default()
        };
        redact_config(&mut config);
        let json = serde_json::to_string(&config).unwrap();

        assert!(!json.contains("token"));
        assert!(!json.contains("192.168.1.0"));
        assert!(!json.contains("private.example"));
        assert!(!json.contains("user:pass"));
        assert!(json.contains("已隐藏"));
    }

    #[test]
    fn future_config_backup_is_not_silently_downgraded() {
        let config = AppConfig {
            schema_version: CURRENT_CONFIG_SCHEMA_VERSION + 1,
            ..AppConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();

        let error = parse_imported_config(&json).unwrap_err();
        assert!(error.contains("高于当前支持的版本"));
    }
}
