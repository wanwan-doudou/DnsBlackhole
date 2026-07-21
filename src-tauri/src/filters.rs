use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use serde::Serialize;

use crate::{
    config::{self, AppConfig, FilterSubscription},
    dns,
};

const FILTER_DOWNLOAD_BUFFER_SIZE: usize = 64 * 1024;
const BYTES_PER_MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct FilterUpdateReport {
    pub updated: usize,
    pub failed: usize,
    pub message: String,
}

pub fn update_enabled_filters(
    data_dir: &Path,
    config: &mut AppConfig,
) -> Result<FilterUpdateReport, String> {
    update_matching_filters(data_dir, config, "没有启用的远程清单", |_| true)
}

pub fn update_due_filters(
    data_dir: &Path,
    config: &mut AppConfig,
    now: u64,
) -> Result<FilterUpdateReport, String> {
    let interval_seconds = u64::from(config.filter_update_interval_hours) * 3600;
    update_matching_filters(data_dir, config, "没有到期的远程清单", |filter| {
        is_filter_due(filter, now, interval_seconds)
    })
}

pub fn has_due_filters(config: &AppConfig, now: u64) -> bool {
    let interval_seconds = u64::from(config.filter_update_interval_hours) * 3600;
    config
        .filters
        .iter()
        .any(|filter| filter.enabled && is_filter_due(filter, now, interval_seconds))
}

fn is_filter_due(filter: &FilterSubscription, now: u64, interval_seconds: u64) -> bool {
    filter
        .last_updated
        .is_none_or(|updated| now.saturating_sub(updated) >= interval_seconds)
}

fn update_matching_filters<F>(
    data_dir: &Path,
    config: &mut AppConfig,
    empty_message: &str,
    should_update: F,
) -> Result<FilterUpdateReport, String>
where
    F: Fn(&FilterSubscription) -> bool,
{
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("DnsBlackhole/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("创建下载客户端失败：{e}"))?;

    let mut updated = 0;
    let mut failed = 0;
    let mut messages = Vec::new();
    let max_size_mb = config.filter_max_size_mb;

    for filter in &mut config.filters {
        if !filter.enabled || !should_update(filter) {
            continue;
        }

        let download_started = Instant::now();
        let download = download_filter(&client, &filter.url, max_size_mb);
        let outcome = if download.is_ok() { "成功" } else { "失败" };
        crate::performance::log_service(
            "远程清单更新",
            &format!("{}（{outcome}）", filter.name),
            download_started,
        );

        match download {
            Ok(content) => {
                let summary = dns::summarize_rules(&content);
                if let Err(error) = config::write_filter_cache(data_dir, &filter.id, &content) {
                    filter.last_error = Some(error.clone());
                    messages.push(format!("{}：{error}", filter.name));
                    failed += 1;
                    continue;
                }
                filter.rule_count = summary.block_rules + summary.allow_rules;
                filter.block_rule_count = summary.block_rules;
                filter.allow_rule_count = summary.allow_rules;
                filter.ignored_rule_count = summary.ignored_rules;
                filter.ignored_comment_count = summary.ignored_comment_rules;
                filter.ignored_regex_count = summary.ignored_regex_rules;
                filter.ignored_unsupported_count = summary.ignored_unsupported_rules;
                filter.ignored_invalid_count = summary.ignored_invalid_rules;
                filter.last_updated = unix_now();
                filter.last_error = None;
                updated += 1;
            }
            Err(error) => {
                filter.last_error = Some(error.clone());
                messages.push(format!("{}：{error}", filter.name));
                failed += 1;
            }
        }
    }

    let message = if updated == 0 && failed == 0 {
        empty_message.to_string()
    } else if failed == 0 {
        format!("已更新 {updated} 个远程清单")
    } else {
        format!(
            "已更新 {updated} 个远程清单，{failed} 个失败：{}",
            messages.join("；")
        )
    };

    Ok(FilterUpdateReport {
        updated,
        failed,
        message,
    })
}

fn download_filter(
    client: &reqwest::blocking::Client,
    url: &str,
    max_size_mb: u32,
) -> Result<String, String> {
    let max_bytes = u64::from(max_size_mb) * BYTES_PER_MIB;
    let mut response = client
        .get(url)
        .send()
        .map_err(|e| format!("下载失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("服务器返回错误：{e}"))?;

    validate_filter_response_headers(&response, max_bytes)?;
    read_limited_text(&mut response, max_bytes)
}

fn validate_filter_response_headers(
    response: &reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<(), String> {
    if let Some(content_length) = response.headers().get(CONTENT_LENGTH)
        && let Ok(content_length) = content_length.to_str()
        && let Ok(content_length) = content_length.parse::<u64>()
        && content_length > max_bytes
    {
        return Err(format!(
            "清单大小 {} MB 超过限制 {} MB",
            bytes_to_mb_ceil(content_length),
            bytes_to_mb_ceil(max_bytes)
        ));
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        let content_type = content_type
            .to_str()
            .map_err(|_| "服务器返回了无效的 Content-Type".to_string())?;
        if !is_allowed_filter_content_type(content_type) {
            return Err(format!("清单 Content-Type 不受信任：{content_type}"));
        }
    }

    Ok(())
}

fn read_limited_text(
    response: &mut reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<String, String> {
    let mut buffer = [0_u8; FILTER_DOWNLOAD_BUFFER_SIZE];
    let mut content = Vec::new();
    let mut total = 0_u64;

    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|e| format!("读取清单内容失败：{e}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(format!(
                "清单解压后大小超过限制 {} MB",
                bytes_to_mb_ceil(max_bytes)
            ));
        }
        content.extend_from_slice(&buffer[..read]);
    }

    Ok(String::from_utf8_lossy(&content).into_owned())
}

fn is_allowed_filter_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    matches!(
        media_type.as_str(),
        "application/octet-stream" | "application/x-adblock-plus" | "application/adblock"
    ) || (media_type.starts_with("text/") && media_type != "text/html")
}

fn bytes_to_mb_ceil(bytes: u64) -> u64 {
    bytes.saturating_add(BYTES_PER_MIB - 1) / BYTES_PER_MIB
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{bytes_to_mb_ceil, has_due_filters, is_allowed_filter_content_type, is_filter_due};
    use crate::config::{AppConfig, FilterSubscription};

    #[test]
    fn allows_plain_filter_content_types() {
        assert!(is_allowed_filter_content_type("text/plain; charset=utf-8"));
        assert!(is_allowed_filter_content_type("application/octet-stream"));
        assert!(is_allowed_filter_content_type("application/x-adblock-plus"));
    }

    #[test]
    fn rejects_html_filter_content_type() {
        assert!(!is_allowed_filter_content_type("text/html; charset=utf-8"));
        assert!(!is_allowed_filter_content_type("application/json"));
    }

    #[test]
    fn formats_size_limit_with_ceiling_mebibytes() {
        assert_eq!(bytes_to_mb_ceil(1), 1);
        assert_eq!(bytes_to_mb_ceil(1024 * 1024), 1);
        assert_eq!(bytes_to_mb_ceil(1024 * 1024 + 1), 2);
    }

    #[test]
    fn determines_filter_due_time_from_last_successful_update() {
        let now = 100_000;
        let interval = 6 * 3600;
        let mut filter = FilterSubscription::default();

        assert!(is_filter_due(&filter, now, interval));

        filter.last_updated = Some(now - interval + 1);
        assert!(!is_filter_due(&filter, now, interval));

        filter.last_updated = Some(now - interval);
        assert!(is_filter_due(&filter, now, interval));

        filter.last_updated = Some(now + 60);
        assert!(!is_filter_due(&filter, now, interval));
    }

    #[test]
    fn automatic_update_ignores_disabled_and_not_due_filters() {
        let now = 100_000;
        let mut config = AppConfig {
            filter_update_interval_hours: 6,
            filters: vec![FilterSubscription {
                enabled: false,
                last_updated: None,
                ..FilterSubscription::default()
            }],
            ..AppConfig::default()
        };

        assert!(!has_due_filters(&config, now));

        config.filters[0].enabled = true;
        config.filters[0].last_updated = Some(now - 5 * 3600);
        assert!(!has_due_filters(&config, now));

        config.filters[0].last_updated = Some(now - 6 * 3600);
        assert!(has_due_filters(&config, now));
    }
}
