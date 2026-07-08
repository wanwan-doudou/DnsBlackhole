use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::AppHandle;

use crate::{
    config::{self, AppConfig},
    dns,
};

#[derive(Debug, Clone, Serialize)]
pub struct FilterUpdateReport {
    pub updated: usize,
    pub failed: usize,
    pub message: String,
}

pub fn update_enabled_filters(
    app: &AppHandle,
    config: &mut AppConfig,
) -> Result<FilterUpdateReport, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("DnsBlackhole/0.1")
        .build()
        .map_err(|e| format!("创建下载客户端失败：{e}"))?;

    let mut updated = 0;
    let mut failed = 0;
    let mut messages = Vec::new();

    for filter in &mut config.filters {
        if !filter.enabled {
            continue;
        }

        match download_filter(&client, &filter.url) {
            Ok(content) => {
                config::write_filter_cache(app, &filter.id, &content)?;
                let summary = dns::summarize_rules(&content);
                filter.rule_count = summary.block_rules + summary.allow_rules;
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
        "没有启用的远程清单".to_string()
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

fn download_filter(client: &reqwest::blocking::Client, url: &str) -> Result<String, String> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("下载失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("服务器返回错误：{e}"))?;

    response
        .text()
        .map_err(|e| format!("读取清单内容失败：{e}"))
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
