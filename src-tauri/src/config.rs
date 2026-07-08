use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub enabled: bool,
    #[serde(default = "default_use_filters")]
    pub use_filters: bool,
    pub listen_host: String,
    pub listen_port: u16,
    pub upstream_dns: String,
    #[serde(default)]
    pub upstream_mode: UpstreamMode,
    #[serde(default = "default_filter_update_interval_hours")]
    pub filter_update_interval_hours: u32,
    #[serde(default = "default_query_log_enabled")]
    pub query_log_enabled: bool,
    #[serde(default)]
    pub anonymize_client_ip: bool,
    #[serde(default = "default_query_log_retention_hours")]
    pub query_log_retention_hours: u32,
    #[serde(default = "default_dns_cache_enabled")]
    pub dns_cache_enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,
    #[serde(default)]
    pub dns_cache_min_ttl: u32,
    #[serde(default = "default_dns_cache_max_ttl")]
    pub dns_cache_max_ttl: u32,
    #[serde(default = "default_dns_cache_optimistic")]
    pub dns_cache_optimistic: bool,
    #[serde(default = "default_filters")]
    pub filters: Vec<FilterSubscription>,
    #[serde(default = "default_custom_rules")]
    pub blacklist: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    LoadBalance,
    ParallelRequests,
    FastestAddr,
}

#[derive(Debug, Clone)]
pub enum UpstreamServer {
    Udp(SocketAddr),
    Doh(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub rule_count: usize,
    pub last_updated: Option<u64>,
    pub last_error: Option<String>,
}

impl Default for FilterSubscription {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            enabled: true,
            rule_count: 0,
            last_updated: None,
            last_error: None,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_filters: default_use_filters(),
            listen_host: "127.0.0.1".into(),
            listen_port: 1053,
            upstream_dns: default_upstream_dns(),
            upstream_mode: UpstreamMode::default(),
            filter_update_interval_hours: default_filter_update_interval_hours(),
            query_log_enabled: default_query_log_enabled(),
            anonymize_client_ip: false,
            query_log_retention_hours: default_query_log_retention_hours(),
            dns_cache_enabled: default_dns_cache_enabled(),
            dns_cache_size: default_dns_cache_size(),
            dns_cache_min_ttl: 0,
            dns_cache_max_ttl: default_dns_cache_max_ttl(),
            dns_cache_optimistic: default_dns_cache_optimistic(),
            filters: default_filters(),
            blacklist: default_custom_rules(),
        }
    }
}

impl AppConfig {
    pub fn listen_socket_addr(&self) -> Result<SocketAddr, String> {
        let host = self.listen_host.trim();
        if host.is_empty() {
            return Err("监听地址不能为空".into());
        }
        if self.listen_port == 0 {
            return Err("监听端口必须大于 0".into());
        }

        let ip: IpAddr = host
            .parse()
            .map_err(|_| "监听地址必须是 IP 地址，例如 127.0.0.1 或 0.0.0.0".to_string())?;
        Ok(SocketAddr::new(ip, self.listen_port))
    }

    pub fn upstream_servers(&self) -> Result<Vec<UpstreamServer>, String> {
        parse_upstream_servers(&self.upstream_dns)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.listen_socket_addr()?;
        self.upstream_servers()?;
        if !matches!(self.filter_update_interval_hours, 6 | 12 | 24 | 72 | 168) {
            return Err("过滤器更新间隔只能是 6、12、24、72 或 168 小时".into());
        }
        if self.query_log_retention_hours == 0 || self.query_log_retention_hours > 24 * 365 {
            return Err("查询日志保留时间必须在 1 小时到 365 天之间".into());
        }
        if self.dns_cache_enabled && self.dns_cache_size == 0 {
            return Err("DNS 缓存大小必须大于 0".into());
        }
        if self.dns_cache_size > 512 * 1024 * 1024 {
            return Err("DNS 缓存大小不能超过 512 MB".into());
        }
        if self.dns_cache_min_ttl > 7 * 24 * 3600 || self.dns_cache_max_ttl > 7 * 24 * 3600 {
            return Err("DNS 缓存 TTL 不能超过 7 天".into());
        }
        if self.dns_cache_max_ttl > 0 && self.dns_cache_min_ttl > self.dns_cache_max_ttl {
            return Err("DNS 缓存最小 TTL 不能大于最大 TTL".into());
        }
        validate_filters(&self.filters)?;
        Ok(())
    }
}

impl Default for UpstreamMode {
    fn default() -> Self {
        Self::ParallelRequests
    }
}

fn default_use_filters() -> bool {
    true
}

fn default_filter_update_interval_hours() -> u32 {
    12
}

fn default_query_log_enabled() -> bool {
    true
}

fn default_query_log_retention_hours() -> u32 {
    90 * 24
}

fn default_dns_cache_enabled() -> bool {
    true
}

fn default_dns_cache_size() -> usize {
    16 * 1024 * 1024
}

fn default_dns_cache_max_ttl() -> u32 {
    24 * 3600
}

fn default_dns_cache_optimistic() -> bool {
    true
}

fn default_upstream_dns() -> String {
    [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "223.5.5.5",
        "119.29.29.29",
    ]
    .join("\n")
}

pub fn default_filters() -> Vec<FilterSubscription> {
    vec![
        FilterSubscription {
            id: "adguard-dns-filter".into(),
            name: "AdGuard DNS filter".into(),
            url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt".into(),
            ..FilterSubscription::default()
        },
        FilterSubscription {
            id: "adaway-default-blocklist".into(),
            name: "AdAway Default Blocklist".into(),
            url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt".into(),
            ..FilterSubscription::default()
        },
        FilterSubscription {
            id: "adblock-dns-filters".into(),
            name: "AdBlock DNS Filters".into(),
            url: "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt".into(),
            ..FilterSubscription::default()
        },
    ]
}

fn default_custom_rules() -> String {
    "! 自定义规则会和启用的远程清单一起生效\n||example-blocked.local^".into()
}

fn validate_filters(filters: &[FilterSubscription]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for filter in filters {
        let id = filter.id.trim();
        if id.is_empty() {
            return Err("黑名单清单 ID 不能为空".into());
        }
        if !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        {
            return Err(format!("黑名单清单 ID 只能包含字母、数字、-、_：{id}"));
        }
        if !ids.insert(id.to_string()) {
            return Err(format!("黑名单清单 ID 重复：{id}"));
        }

        if filter.name.trim().is_empty() {
            return Err("黑名单清单名称不能为空".into());
        }

        let url = filter.url.trim();
        if url.is_empty() {
            return Err(format!("{} 的清单地址不能为空", filter.name));
        }
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(format!(
                "{} 的清单地址必须以 http:// 或 https:// 开头",
                filter.name
            ));
        }
    }
    Ok(())
}

fn parse_upstream_servers(value: &str) -> Result<Vec<UpstreamServer>, String> {
    let servers = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .map(parse_upstream_server)
        .collect::<Result<Vec<_>, _>>()?;

    if servers.is_empty() {
        return Err("上游 DNS 不能为空".into());
    }

    Ok(servers)
}

fn parse_upstream_server(value: &str) -> Result<UpstreamServer, String> {
    if value.starts_with("https://") || value.starts_with("http://") {
        return Ok(UpstreamServer::Doh(value.to_string()));
    }

    parse_dns_socket_addr(value).map(UpstreamServer::Udp)
}

fn parse_dns_socket_addr(value: &str) -> Result<SocketAddr, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("上游 DNS 不能为空".into());
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    let socket_value = if trimmed.contains(':') {
        trimmed.to_string()
    } else {
        format!("{trimmed}:53")
    };
    socket_value
        .to_socket_addrs()
        .map_err(|_| "上游 DNS 必须是 IP、IP:端口、域名:端口 或 DoH 地址".to_string())?
        .next()
        .ok_or_else(|| "无法解析上游 DNS 地址".to_string())
}

fn config_path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("config.json"))
}

fn filters_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join("filters"))
        .map_err(|_| "无法获取配置目录".to_string())
}

fn filter_cache_path(app: &AppHandle, id: &str) -> Result<PathBuf, String> {
    Ok(filters_dir(app)?.join(format!("{id}.txt")))
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_file_name("config.json.bak")
}

fn read_config_file(path: &Path) -> Result<AppConfig, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("读取配置文件失败：{}：{e}", path.display()))?;
    let mut config: AppConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("解析配置文件失败：{}：{e}", path.display()))?;
    migrate_default_port(&mut config);
    config.validate()?;
    Ok(config)
}

fn migrate_default_port(config: &mut AppConfig) {
    if config.listen_host.trim() == "127.0.0.1" && config.listen_port == 5353 {
        config.listen_port = 1053;
    }
}

pub fn load(app: &AppHandle) -> Result<AppConfig, String> {
    let Some(path) = config_path(app) else {
        return Err("无法获取配置目录".into());
    };

    if !path.exists() {
        return Ok(AppConfig::default());
    }

    match read_config_file(&path) {
        Ok(config) => Ok(config),
        Err(primary_error) => {
            let backup = backup_path(&path);
            if backup.exists() {
                read_config_file(&backup).map_err(|backup_error| {
                    format!("{primary_error}；备份配置也无法恢复：{backup_error}")
                })
            } else {
                Err(primary_error)
            }
        }
    }
}

pub fn read_filter_cache(app: &AppHandle, id: &str) -> Result<Option<String>, String> {
    let path = filter_cache_path(app, id)?;
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(&path)
        .map(Some)
        .map_err(|e| format!("读取清单缓存失败：{}：{e}", path.display()))
}

pub fn write_filter_cache(app: &AppHandle, id: &str, content: &str) -> Result<(), String> {
    let dir = filters_dir(app)?;
    fs::create_dir_all(&dir).map_err(|e| format!("创建清单缓存目录失败：{e}"))?;
    let path = filter_cache_path(app, id)?;
    fs::write(&path, content).map_err(|e| format!("写入清单缓存失败：{}：{e}", path.display()))
}

pub fn build_effective_rules(app: &AppHandle, config: &AppConfig) -> String {
    if !config.use_filters {
        return String::new();
    }

    let mut parts = Vec::new();

    for filter in &config.filters {
        if !filter.enabled {
            continue;
        }
        if let Ok(Some(content)) = read_filter_cache(app, &filter.id) {
            parts.push(format!("! {}\n{}", filter.name, content));
        }
    }

    if !config.blacklist.trim().is_empty() {
        parts.push(format!("! 自定义规则\n{}", config.blacklist));
    }

    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_upstream_servers() {
        let servers =
            parse_upstream_servers("https://dns.alidns.com/dns-query\n223.5.5.5\n119.29.29.29:53")
                .expect("upstreams should parse");

        assert_eq!(servers.len(), 3);
        assert!(matches!(servers[0], UpstreamServer::Doh(_)));
        assert!(matches!(servers[1], UpstreamServer::Udp(_)));
        assert!(matches!(servers[2], UpstreamServer::Udp(_)));
    }

    #[test]
    fn migrates_old_mdns_default_port() {
        let mut config = AppConfig::default();
        config.listen_port = 5353;

        migrate_default_port(&mut config);

        assert_eq!(config.listen_port, 1053);
    }
}
