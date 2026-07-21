use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU16, Ordering},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
#[cfg(not(any(target_os = "macos", windows)))]
use tauri::{AppHandle, Manager};

pub const CURRENT_CONFIG_SCHEMA_VERSION: u32 = 9;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESOLVED_UPSTREAM_ADDRESSES: usize = 16;
const MAX_FILTER_SIZE_MB: u32 = 256;
const LEGACY_DEFAULT_RATE_LIMIT_PER_SECOND: u32 = 100;
const LEGACY_ADGUARD_DNS_FILTER_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
const LEGACY_ADAWAY_FILTER_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt";
const DEFAULT_ADGUARD_DNS_FILTER_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filter_1.txt";
const DEFAULT_ADAWAY_FILTER_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filter_2.txt";
static BOOTSTRAP_QUERY_ID: AtomicU16 = AtomicU16::new(0x1234);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    #[serde(default)]
    pub schema_version: u32,
    pub enabled: bool,
    #[serde(default = "default_use_filters")]
    pub use_filters: bool,
    pub listen_host: String,
    pub listen_port: u16,
    #[serde(default = "default_listen_ipv6")]
    pub listen_ipv6: bool,
    pub upstream_dns: String,
    #[serde(default)]
    pub fallback_dns: String,
    #[serde(default = "default_bootstrap_dns")]
    pub bootstrap_dns: String,
    #[serde(default)]
    pub upstream_mode: UpstreamMode,
    #[serde(default = "default_allowed_clients")]
    pub allowed_clients: String,
    #[serde(default)]
    pub blocked_clients: String,
    #[serde(default = "default_rate_limit_per_second")]
    pub rate_limit_per_second: u32,
    #[serde(default = "default_refuse_any")]
    pub refuse_any: bool,
    #[serde(default = "default_filter_update_interval_hours")]
    pub filter_update_interval_hours: u32,
    #[serde(default = "default_filter_max_size_mb")]
    pub filter_max_size_mb: u32,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "default_query_log_enabled")]
    pub query_log_enabled: bool,
    #[serde(default)]
    pub anonymize_client_ip: bool,
    #[serde(default = "default_launch_at_startup")]
    pub launch_at_startup: bool,
    #[serde(default = "default_query_log_retention_hours")]
    pub query_log_retention_hours: u32,
    #[serde(default = "default_dns_cache_enabled")]
    pub dns_cache_enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,
    #[serde(default = "default_dns_cache_min_ttl")]
    pub dns_cache_min_ttl: u32,
    #[serde(default = "default_dns_cache_max_ttl")]
    pub dns_cache_max_ttl: u32,
    #[serde(default = "default_dns_cache_optimistic")]
    pub dns_cache_optimistic: bool,
    #[serde(default = "default_runtime_watchdog_enabled")]
    pub runtime_watchdog_enabled: bool,
    #[serde(default = "default_runtime_watchdog_interval_seconds")]
    pub runtime_watchdog_interval_seconds: u64,
    #[serde(default)]
    pub blocking_mode: BlockingMode,
    #[serde(default)]
    pub blocking_custom_ipv4: String,
    #[serde(default)]
    pub blocking_custom_ipv6: String,
    #[serde(default)]
    pub dns_rewrites: String,
    #[serde(default)]
    pub client_names: String,
    #[serde(default)]
    pub query_log_ignored_domains: String,
    #[serde(default = "default_filters")]
    pub filters: Vec<FilterSubscription>,
    #[serde(default = "default_custom_rules")]
    pub blacklist: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    #[default]
    NullIp,
    Nxdomain,
    Refused,
    CustomIp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    #[default]
    LoadBalance,
    ParallelRequests,
    FastestAddr,
}

#[derive(Debug, Clone)]
pub enum UpstreamServer {
    Udp(SocketAddr),
    UdpHostname { hostname: String, port: u16 },
    Doh(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FilterSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub rule_count: usize,
    #[serde(default)]
    pub block_rule_count: usize,
    #[serde(default)]
    pub allow_rule_count: usize,
    #[serde(default)]
    pub ignored_rule_count: usize,
    #[serde(default)]
    pub ignored_comment_count: usize,
    #[serde(default)]
    pub ignored_regex_count: usize,
    #[serde(default)]
    pub ignored_unsupported_count: usize,
    #[serde(default)]
    pub ignored_invalid_count: usize,
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
            block_rule_count: 0,
            allow_rule_count: 0,
            ignored_rule_count: 0,
            ignored_comment_count: 0,
            ignored_regex_count: 0,
            ignored_unsupported_count: 0,
            ignored_invalid_count: 0,
            last_updated: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterCacheClearStats {
    pub removed_files: usize,
    pub removed_bytes: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_CONFIG_SCHEMA_VERSION,
            enabled: true,
            use_filters: default_use_filters(),
            listen_host: default_listen_host(),
            listen_port: default_listen_port(),
            listen_ipv6: default_listen_ipv6(),
            upstream_dns: default_upstream_dns(),
            fallback_dns: default_fallback_dns(),
            bootstrap_dns: default_bootstrap_dns(),
            upstream_mode: UpstreamMode::default(),
            allowed_clients: default_allowed_clients(),
            blocked_clients: String::new(),
            rate_limit_per_second: default_rate_limit_per_second(),
            refuse_any: default_refuse_any(),
            filter_update_interval_hours: default_filter_update_interval_hours(),
            filter_max_size_mb: default_filter_max_size_mb(),
            allow_insecure_http: false,
            query_log_enabled: default_query_log_enabled(),
            anonymize_client_ip: false,
            launch_at_startup: default_launch_at_startup(),
            query_log_retention_hours: default_query_log_retention_hours(),
            dns_cache_enabled: default_dns_cache_enabled(),
            dns_cache_size: default_dns_cache_size(),
            dns_cache_min_ttl: default_dns_cache_min_ttl(),
            dns_cache_max_ttl: default_dns_cache_max_ttl(),
            dns_cache_optimistic: default_dns_cache_optimistic(),
            runtime_watchdog_enabled: default_runtime_watchdog_enabled(),
            runtime_watchdog_interval_seconds: default_runtime_watchdog_interval_seconds(),
            blocking_mode: BlockingMode::default(),
            blocking_custom_ipv4: String::new(),
            blocking_custom_ipv6: String::new(),
            dns_rewrites: String::new(),
            client_names: String::new(),
            query_log_ignored_domains: String::new(),
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

    pub fn listen_socket_addrs(&self) -> Result<Vec<SocketAddr>, String> {
        let ipv4_addr = self.listen_socket_addr()?;
        if !self.listen_ipv6 {
            return Ok(vec![ipv4_addr]);
        }
        if !ipv4_addr.is_ipv4() {
            return Err("启用 IPv6 双监听时，监听地址必须填写 IPv4 地址".into());
        }

        Ok(vec![
            ipv4_addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.listen_port),
        ])
    }

    pub fn upstream_servers(&self) -> Result<Vec<UpstreamServer>, String> {
        parse_upstream_servers(&self.upstream_dns, self.allow_insecure_http)
    }

    pub fn fallback_servers(&self) -> Result<Vec<UpstreamServer>, String> {
        parse_optional_upstream_servers(&self.fallback_dns, self.allow_insecure_http)
    }

    pub(crate) fn bootstrap_servers(&self) -> Result<Vec<SocketAddr>, String> {
        parse_bootstrap_servers(&self.bootstrap_dns)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.listen_socket_addrs()?;
        self.upstream_servers()?;
        self.fallback_servers()?;
        parse_bootstrap_servers(&self.bootstrap_dns)?;
        if !(10..=3600).contains(&self.runtime_watchdog_interval_seconds) {
            return Err("自恢复检查间隔必须在 10 到 3600 秒之间".into());
        }
        if self.schema_version > CURRENT_CONFIG_SCHEMA_VERSION {
            return Err(format!(
                "配置版本 {} 高于当前支持的版本 {}",
                self.schema_version, CURRENT_CONFIG_SCHEMA_VERSION
            ));
        }
        if !matches!(self.filter_update_interval_hours, 6 | 12 | 24 | 72 | 168) {
            return Err("过滤器更新间隔只能是 6、12、24、72 或 168 小时".into());
        }
        if !(1..=MAX_FILTER_SIZE_MB).contains(&self.filter_max_size_mb) {
            return Err(format!(
                "单个过滤器最大下载大小必须在 1 到 {MAX_FILTER_SIZE_MB} MB 之间"
            ));
        }
        validate_client_list(&self.allowed_clients, "允许客户端")?;
        validate_client_list(&self.blocked_clients, "拒绝客户端")?;
        if self.rate_limit_per_second > 100_000 {
            return Err("每客户端限速不能超过每秒 100000 次查询".into());
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
        validate_filters(&self.filters, self.allow_insecure_http)?;
        validate_blocking_config(self)?;
        validate_dns_rewrites(&self.dns_rewrites)?;
        validate_client_names(&self.client_names)?;
        validate_ignored_domains(&self.query_log_ignored_domains)?;
        Ok(())
    }
}

fn validate_blocking_config(config: &AppConfig) -> Result<(), String> {
    if config.blocking_mode != BlockingMode::CustomIp {
        return Ok(());
    }

    let ipv4 = config.blocking_custom_ipv4.trim();
    let ipv6 = config.blocking_custom_ipv6.trim();
    if ipv4.is_empty() && ipv6.is_empty() {
        return Err("自定义拦截 IP 模式需要至少填写一个 IPv4 或 IPv6 地址".into());
    }
    if !ipv4.is_empty() && ipv4.parse::<Ipv4Addr>().is_err() {
        return Err(format!("自定义拦截 IPv4 地址无效：{ipv4}"));
    }
    if !ipv6.is_empty() && ipv6.parse::<Ipv6Addr>().is_err() {
        return Err(format!("自定义拦截 IPv6 地址无效：{ipv6}"));
    }
    Ok(())
}

fn validate_dns_rewrites(value: &str) -> Result<(), String> {
    for (index, line) in value.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let (Some(domain), Some(ip)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "DNS 重写第 {} 行格式必须是“域名 IP”：{trimmed}",
                index + 1
            ));
        };
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        if normalize_hostname(domain).is_none() {
            return Err(format!("DNS 重写第 {} 行域名无效：{domain}", index + 1));
        }
        if ip.parse::<IpAddr>().is_err() {
            return Err(format!("DNS 重写第 {} 行 IP 地址无效：{ip}", index + 1));
        }
        if parts.next().is_some() {
            return Err(format!(
                "DNS 重写第 {} 行只能包含“域名 IP”两项：{trimmed}",
                index + 1
            ));
        }
    }
    Ok(())
}

fn validate_client_names(value: &str) -> Result<(), String> {
    for (index, line) in value.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let ip = parts.next().unwrap_or_default();
        let name = parts.next().map(str::trim).unwrap_or_default();
        if ip.parse::<IpAddr>().is_err() {
            return Err(format!(
                "客户端名称第 {} 行必须以 IP 地址开头：{ip}",
                index + 1
            ));
        }
        if name.is_empty() {
            return Err(format!(
                "客户端名称第 {} 行缺少名称，格式是“IP 名称”",
                index + 1
            ));
        }
    }
    Ok(())
}

fn validate_ignored_domains(value: &str) -> Result<(), String> {
    for (index, line) in value.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let domain = trimmed.strip_prefix("*.").unwrap_or(trimmed);
        if normalize_hostname(domain).is_none() {
            return Err(format!(
                "日志忽略清单第 {} 行域名无效：{trimmed}",
                index + 1
            ));
        }
    }
    Ok(())
}

fn default_use_filters() -> bool {
    true
}

fn default_listen_host() -> String {
    "0.0.0.0".into()
}

fn default_listen_port() -> u16 {
    53
}

fn default_listen_ipv6() -> bool {
    true
}

fn default_filter_update_interval_hours() -> u32 {
    12
}

fn default_filter_max_size_mb() -> u32 {
    50
}

fn default_query_log_enabled() -> bool {
    true
}

fn default_launch_at_startup() -> bool {
    false
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

fn default_dns_cache_min_ttl() -> u32 {
    60
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

fn default_fallback_dns() -> String {
    // 与主上游（阿里/腾讯）基础设施错开的国内服务，国内网络下才起得到兜底作用
    ["114.114.114.114", "180.76.76.76"].join("\n")
}

fn default_bootstrap_dns() -> String {
    ["223.5.5.5", "119.29.29.29"].join("\n")
}

fn default_allowed_clients() -> String {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ]
    .join("\n")
}

fn default_rate_limit_per_second() -> u32 {
    2_000
}

fn default_refuse_any() -> bool {
    true
}

fn default_runtime_watchdog_enabled() -> bool {
    true
}

fn default_runtime_watchdog_interval_seconds() -> u64 {
    30
}

pub fn default_filters() -> Vec<FilterSubscription> {
    vec![
        FilterSubscription {
            id: "adguard-dns-filter".into(),
            name: "AdGuard DNS filter".into(),
            url: DEFAULT_ADGUARD_DNS_FILTER_URL.into(),
            ..FilterSubscription::default()
        },
        FilterSubscription {
            id: "adaway-default-blocklist".into(),
            name: "AdAway Default Blocklist".into(),
            url: DEFAULT_ADAWAY_FILTER_URL.into(),
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

fn validate_client_list(value: &str, label: &str) -> Result<(), String> {
    for (index, line) in value.lines().enumerate() {
        let item = line.split_whitespace().next().unwrap_or_default().trim();
        if item.is_empty() || item.starts_with('#') || item.starts_with('!') {
            continue;
        }

        if validate_ip_or_cidr(item).is_err() {
            return Err(format!(
                "{label}第 {} 行必须是 IP 地址或 CIDR 网段：{item}",
                index + 1
            ));
        }
    }
    Ok(())
}

fn validate_ip_or_cidr(value: &str) -> Result<(), ()> {
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let Some((ip, prefix_len)) = value.split_once('/') else {
        return Err(());
    };
    let ip = ip.parse::<IpAddr>().map_err(|_| ())?;
    let prefix_len = prefix_len.parse::<u8>().map_err(|_| ())?;
    match ip {
        IpAddr::V4(_) if prefix_len <= 32 => Ok(()),
        IpAddr::V6(_) if prefix_len <= 128 => Ok(()),
        _ => Err(()),
    }
}

fn default_custom_rules() -> String {
    "! 自定义规则会和启用的远程清单一起生效\n||example-blocked.local^".into()
}

fn validate_filters(
    filters: &[FilterSubscription],
    allow_insecure_http: bool,
) -> Result<(), String> {
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
        if url.starts_with("https://") {
            continue;
        }
        if url.starts_with("http://") {
            if allow_insecure_http {
                continue;
            }
            return Err(format!(
                "{} 使用了不安全的 HTTP 清单地址。默认只允许 HTTPS；如确需使用，请在安全防护中启用“允许不安全 HTTP”。",
                filter.name
            ));
        }
        if !url.starts_with("https://") {
            return Err(format!("{} 的清单地址必须以 https:// 开头", filter.name));
        }
    }
    Ok(())
}

fn parse_upstream_servers(
    value: &str,
    allow_insecure_http: bool,
) -> Result<Vec<UpstreamServer>, String> {
    let servers = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .map(|line| parse_upstream_server(line, allow_insecure_http))
        .collect::<Result<Vec<_>, _>>()?;

    if servers.is_empty() {
        return Err("上游 DNS 不能为空".into());
    }

    Ok(servers)
}

fn parse_optional_upstream_servers(
    value: &str,
    allow_insecure_http: bool,
) -> Result<Vec<UpstreamServer>, String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .map(|line| parse_upstream_server(line, allow_insecure_http))
        .collect::<Result<Vec<_>, _>>()
}

fn parse_upstream_server(value: &str, allow_insecure_http: bool) -> Result<UpstreamServer, String> {
    if value.starts_with("https://") {
        return parse_doh_upstream(value);
    }
    if value.starts_with("http://") {
        if allow_insecure_http {
            return parse_doh_upstream(value);
        }
        return Err(
            "HTTP DoH 上游不安全。默认只允许 HTTPS DoH；如确需使用，请在安全防护中启用“允许不安全 HTTP”。"
                .into(),
        );
    }

    parse_dns_upstream(value)
}

fn parse_doh_upstream(value: &str) -> Result<UpstreamServer, String> {
    let url = reqwest::Url::parse(value).map_err(|e| format!("DoH 地址无效：{e}"))?;
    if url.host_str().is_none() || url.port_or_known_default().is_none() {
        return Err("DoH 地址必须包含有效主机名和端口".into());
    }
    Ok(UpstreamServer::Doh(value.to_string()))
}

fn parse_dns_upstream(value: &str) -> Result<UpstreamServer, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("上游 DNS 不能为空".into());
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(UpstreamServer::Udp(addr));
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(UpstreamServer::Udp(SocketAddr::new(ip, 53)));
    }

    if let Some((host, port)) = split_host_port(trimmed)
        && let Some(host) = normalize_hostname(host)
    {
        return Ok(UpstreamServer::UdpHostname {
            hostname: host,
            port,
        });
    }

    Err("上游 DNS 必须是 IP、IP:端口、域名:端口 或 DoH 地址".to_string())
}

fn split_host_port(value: &str) -> Option<(&str, u16)> {
    if let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Some((host.trim_matches(['[', ']']), port));
    }

    normalize_hostname(value).map(|_| (value, 53))
}

fn normalize_hostname(value: &str) -> Option<String> {
    let hostname = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 {
        return None;
    }
    if hostname.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) {
        return None;
    }
    if !hostname
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.'))
    {
        return None;
    }
    Some(hostname)
}

pub(crate) fn resolve_hostname_socket_addrs(
    host: &str,
    port: u16,
    bootstrap_servers: &[SocketAddr],
) -> Result<Vec<SocketAddr>, String> {
    for &server in bootstrap_servers {
        match resolve_hostname_with_bootstrap(host, port, server) {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Err(_) => continue,
            Ok(_) => continue,
        }
    }

    let mut seen = HashSet::new();
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| "无法通过 bootstrap 或系统解析上游 DNS 地址".to_string())?
        .filter(|addr| seen.insert(*addr))
        .take(MAX_RESOLVED_UPSTREAM_ADDRESSES)
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err("无法解析上游 DNS 地址".to_string());
    }
    Ok(addrs)
}

fn parse_bootstrap_servers(value: &str) -> Result<Vec<SocketAddr>, String> {
    let mut servers = Vec::new();
    for (index, line) in value.lines().enumerate() {
        let item = line.split_whitespace().next().unwrap_or_default().trim();
        if item.is_empty() || item.starts_with('#') || item.starts_with('!') {
            continue;
        }

        if let Ok(addr) = item.parse::<SocketAddr>() {
            servers.push(addr);
            continue;
        }
        if let Ok(ip) = item.parse::<IpAddr>() {
            servers.push(SocketAddr::new(ip, 53));
            continue;
        }

        return Err(format!(
            "Bootstrap DNS 第 {} 行必须是 IP 或 IP:端口：{item}",
            index + 1
        ));
    }
    Ok(servers)
}

fn resolve_hostname_with_bootstrap(
    host: &str,
    port: u16,
    server: SocketAddr,
) -> Result<Vec<SocketAddr>, String> {
    let (ipv4, ipv6) = thread::scope(|scope| {
        let ipv4 = scope.spawn(|| query_bootstrap_records(host, server, 1));
        let ipv6 = scope.spawn(|| query_bootstrap_records(host, server, 28));
        (
            ipv4.join()
                .unwrap_or_else(|_| Err("bootstrap A 查询线程异常".into())),
            ipv6.join()
                .unwrap_or_else(|_| Err("bootstrap AAAA 查询线程异常".into())),
        )
    });

    let mut seen = HashSet::new();
    let mut addrs = Vec::new();
    let ordered = if server.is_ipv6() {
        [ipv6, ipv4]
    } else {
        [ipv4, ipv6]
    };
    for result in ordered.into_iter().flatten() {
        for ip in result {
            let addr = SocketAddr::new(ip, port);
            if seen.insert(addr) {
                addrs.push(addr);
            }
        }
    }
    if addrs.is_empty() {
        return Err("bootstrap DNS 没有返回可用 IP".into());
    }
    addrs.truncate(MAX_RESOLVED_UPSTREAM_ADDRESSES);
    Ok(addrs)
}

fn query_bootstrap_records(
    host: &str,
    server: SocketAddr,
    qtype: u16,
) -> Result<Vec<IpAddr>, String> {
    let query = build_dns_query(host, qtype)?;
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).map_err(|e| format!("创建 bootstrap 查询失败：{e}"))?;
    socket
        .set_read_timeout(Some(BOOTSTRAP_TIMEOUT))
        .map_err(|e| format!("设置 bootstrap 查询超时失败：{e}"))?;
    socket
        .connect(server)
        .map_err(|e| format!("连接 bootstrap DNS 失败：{e}"))?;
    socket
        .send(&query)
        .map_err(|e| format!("请求 bootstrap DNS 失败：{e}"))?;

    let mut response = [0_u8; 4096];
    let len = socket
        .recv(&mut response)
        .map_err(|e| format!("读取 bootstrap DNS 响应失败：{e}"))?;
    parse_bootstrap_ip_response(&response[..len], &query, qtype)
}

fn build_dns_query(host: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let query_id = BOOTSTRAP_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let [id_high, id_low] = query_id.to_be_bytes();
    let mut packet = vec![id_high, id_low, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        let label_len =
            u8::try_from(label.len()).map_err(|_| "DNS label 长度超过 63 字节".to_string())?;
        if label_len == 0 || label_len > 63 {
            return Err("DNS 域名格式无效".into());
        }
        packet.push(label_len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn parse_bootstrap_ip_response(
    response: &[u8],
    query: &[u8],
    qtype: u16,
) -> Result<Vec<IpAddr>, String> {
    if response.len() < 12 || query.len() < 2 || response[0..2] != query[0..2] {
        return Err("bootstrap DNS 响应无效".into());
    }
    if response[3] & 0x0f != 0 {
        return Err("bootstrap DNS 未返回可用记录".into());
    }

    let question_count = read_u16(response, 4).ok_or("bootstrap DNS 响应缺少 question")?;
    let answer_count = read_u16(response, 6).ok_or("bootstrap DNS 响应缺少 answer")?;
    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_dns_name(response, offset).ok_or("bootstrap DNS question 格式无效")?;
        offset = offset.saturating_add(4);
        if offset > response.len() {
            return Err("bootstrap DNS question 越界".into());
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        let header_offset =
            skip_dns_name(response, offset).ok_or("bootstrap DNS answer 格式无效")?;
        if header_offset + 10 > response.len() {
            return Err("bootstrap DNS answer 越界".into());
        }

        let record_type = read_u16(response, header_offset).unwrap_or_default();
        let record_class = read_u16(response, header_offset + 2).unwrap_or_default();
        let data_len = read_u16(response, header_offset + 8).unwrap_or_default() as usize;
        let data_offset = header_offset + 10;
        let data_end = data_offset.saturating_add(data_len);
        if data_end > response.len() {
            return Err("bootstrap DNS answer 数据越界".into());
        }

        if record_class == 1 && record_type == qtype {
            if qtype == 1 && data_len == 4 {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    response[data_offset],
                    response[data_offset + 1],
                    response[data_offset + 2],
                    response[data_offset + 3],
                )));
            }
            if qtype == 28 && data_len == 16 {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&response[data_offset..data_end]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }

        offset = data_end;
    }

    if ips.is_empty() {
        return Err("bootstrap DNS 没有返回可用 IP".into());
    }
    Ok(ips)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            return Some(offset);
        }
        if length & 0b1100_0000 == 0b1100_0000 {
            packet.get(offset)?;
            return Some(offset + 1);
        }
        if length & 0b1100_0000 != 0 {
            return None;
        }
        offset = offset.checked_add(length)?;
        if offset > packet.len() {
            return None;
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([first, second]))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn config_path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("config.json"))
}

fn filter_cache_path(data_dir: &Path, id: &str) -> PathBuf {
    crate::storage::filters_dir(data_dir).join(format!("{id}.txt"))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn backup_path(path: &Path) -> PathBuf {
    path.with_file_name("config.json.bak")
}

#[cfg(not(any(target_os = "macos", windows)))]
fn read_config_file(path: &Path) -> Result<AppConfig, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("读取配置文件失败：{}：{e}", path.display()))?;
    let mut config: AppConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("解析配置文件失败：{}：{e}", path.display()))?;
    migrate_legacy_defaults(&mut config);
    config.validate()?;
    Ok(config)
}

pub fn migrate_legacy_defaults(config: &mut AppConfig) {
    if config.listen_host.trim() == "127.0.0.1" && config.listen_port == 5353 {
        config.listen_port = default_listen_port();
    }
    if config.schema_version < 4
        && config.listen_host.trim() == "127.0.0.1"
        && config.listen_port == default_listen_port()
    {
        config.listen_host = default_listen_host();
    }
    // 旧版本允许在主监听地址中直接填写 IPv6，迁移时保留其单地址监听行为。
    if config.schema_version < 7 && config.listen_host.trim().parse::<Ipv6Addr>().is_ok() {
        config.listen_ipv6 = false;
    }
    if config.schema_version < 8
        && config.rate_limit_per_second == LEGACY_DEFAULT_RATE_LIMIT_PER_SECOND
    {
        // 路由器做 DNS 转发时，几十到上百台设备可能共用同一个来源 IP。
        config.rate_limit_per_second = default_rate_limit_per_second();
    }
    if config.schema_version < 9 {
        migrate_legacy_filter_urls(config);
    }
    if config.schema_version < 1 {
        if config.allowed_clients.trim().is_empty() {
            config.allowed_clients = default_allowed_clients();
        }
        if config.rate_limit_per_second == 0 {
            config.rate_limit_per_second = default_rate_limit_per_second();
        }
        config.refuse_any = true;
    }
    if config.schema_version < 2 {
        if config.bootstrap_dns.trim().is_empty() {
            config.bootstrap_dns = default_bootstrap_dns();
        }
        if config.fallback_dns.trim().is_empty() {
            config.fallback_dns = default_fallback_dns();
        }
    }
    if config.schema_version < 3 && config.runtime_watchdog_interval_seconds == 0 {
        config.runtime_watchdog_interval_seconds = default_runtime_watchdog_interval_seconds();
    }
    if config.schema_version < 5 {
        if config.filter_max_size_mb == 0 {
            config.filter_max_size_mb = default_filter_max_size_mb();
        }
        if uses_insecure_http_endpoint(config) {
            config.allow_insecure_http = true;
        }
    }
    // 旧默认 fallback（1.1.1.1/8.8.8.8）在国内网络下基本不可用，仅当用户没改过时替换成新默认值
    if config.schema_version < 6 && is_legacy_default_fallback_dns(&config.fallback_dns) {
        config.fallback_dns = default_fallback_dns();
    }
    config.schema_version = CURRENT_CONFIG_SCHEMA_VERSION;
}

fn migrate_legacy_filter_urls(config: &mut AppConfig) {
    for filter in &mut config.filters {
        let replacement = match filter.url.trim() {
            LEGACY_ADGUARD_DNS_FILTER_URL => Some(DEFAULT_ADGUARD_DNS_FILTER_URL),
            LEGACY_ADAWAY_FILTER_URL => Some(DEFAULT_ADAWAY_FILTER_URL),
            _ => None,
        };
        if let Some(url) = replacement {
            filter.url = url.into();
            // 旧地址的网络错误不应继续污染迁移后的订阅状态。
            filter.last_error = None;
        }
    }
}

fn is_legacy_default_fallback_dns(fallback_dns: &str) -> bool {
    let lines = fallback_dns
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    lines == ["1.1.1.1", "8.8.8.8"]
}

fn uses_insecure_http_endpoint(config: &AppConfig) -> bool {
    config
        .upstream_dns
        .lines()
        .chain(config.fallback_dns.lines())
        .any(|line| line.trim().starts_with("http://"))
        || config
            .filters
            .iter()
            .any(|filter| filter.url.trim().starts_with("http://"))
}

#[cfg(not(any(target_os = "macos", windows)))]
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

pub fn read_filter_cache(data_dir: &Path, id: &str) -> Result<Option<String>, String> {
    let path = filter_cache_path(data_dir, id);
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(&path)
        .map(Some)
        .map_err(|e| format!("读取清单缓存失败：{}：{e}", path.display()))
}

pub fn write_filter_cache(data_dir: &Path, id: &str, content: &str) -> Result<(), String> {
    let dir = crate::storage::filters_dir(data_dir);
    fs::create_dir_all(&dir).map_err(|e| format!("创建清单缓存目录失败：{e}"))?;
    let path = filter_cache_path(data_dir, id);
    write_file_atomically(&dir, &path, content.as_bytes())
        .map_err(|e| format!("写入清单缓存失败：{}：{e}", path.display()))
}

fn write_file_atomically(dir: &Path, path: &Path, content: &[u8]) -> Result<(), String> {
    let tmp_path = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("filter"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = File::create(&tmp_path)
            .map_err(|e| format!("创建临时文件失败：{}：{e}", tmp_path.display()))?;
        file.write_all(content)
            .map_err(|e| format!("写入临时文件失败：{}：{e}", tmp_path.display()))?;
        file.sync_all()
            .map_err(|e| format!("同步临时文件失败：{}：{e}", tmp_path.display()))?;
        drop(file);

        replace_file(&tmp_path, path)?;
        sync_directory(dir);
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    let from = wide(from.as_os_str());
    let to = wide(to.as_os_str());
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if result == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|e| e.to_string())
}

fn sync_directory(dir: &Path) {
    if let Ok(file) = File::open(dir) {
        let _ = file.sync_all();
    }
}

pub fn clear_filter_cache(
    data_dir: &Path,
    config: &mut AppConfig,
) -> Result<FilterCacheClearStats, String> {
    let dir = crate::storage::filters_dir(data_dir);
    let stats = clear_filter_cache_dir(&dir)?;

    for filter in &mut config.filters {
        filter.rule_count = 0;
        filter.block_rule_count = 0;
        filter.allow_rule_count = 0;
        filter.ignored_rule_count = 0;
        filter.ignored_comment_count = 0;
        filter.ignored_regex_count = 0;
        filter.ignored_unsupported_count = 0;
        filter.ignored_invalid_count = 0;
        filter.last_updated = None;
        filter.last_error = None;
    }

    Ok(stats)
}

fn clear_filter_cache_dir(dir: &Path) -> Result<FilterCacheClearStats, String> {
    if !dir.exists() {
        return Ok(FilterCacheClearStats::default());
    }

    let mut stats = FilterCacheClearStats::default();
    let entries =
        fs::read_dir(dir).map_err(|e| format!("读取清单缓存目录失败：{}：{e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取清单缓存文件失败：{e}"))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|e| format!("读取清单缓存文件信息失败：{}：{e}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }

        fs::remove_file(&path).map_err(|e| format!("删除清单缓存失败：{}：{e}", path.display()))?;
        stats.removed_files += 1;
        stats.removed_bytes += metadata.len();
    }

    Ok(stats)
}

pub fn build_effective_rules(data_dir: &Path, config: &AppConfig) -> String {
    if !config.use_filters {
        return String::new();
    }

    let mut rules = String::new();

    for filter in &config.filters {
        if !filter.enabled {
            continue;
        }
        if let Ok(Some(content)) = read_filter_cache(data_dir, &filter.id) {
            let source =
                serde_json::to_string(&filter.name).unwrap_or_else(|_| "\"未知清单\"".into());
            if !rules.is_empty() {
                rules.push('\n');
            }
            rules.push_str("! dnsblackhole-source:");
            rules.push_str(&source);
            rules.push('\n');
            rules.push_str(&content);
        }
    }

    if !config.blacklist.trim().is_empty() {
        if !rules.is_empty() {
            rules.push('\n');
        }
        rules.push_str("! dnsblackhole-source:\"自定义规则\"\n");
        rules.push_str(&config.blacklist);
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_upstream_servers() {
        let servers = parse_upstream_servers(
            "https://dns.alidns.com/dns-query\n223.5.5.5\n119.29.29.29:53",
            false,
        )
        .expect("upstreams should parse");

        assert_eq!(servers.len(), 3);
        assert!(matches!(servers[0], UpstreamServer::Doh(_)));
        assert!(matches!(servers[1], UpstreamServer::Udp(_)));
        assert!(matches!(servers[2], UpstreamServer::Udp(_)));
    }

    #[test]
    fn keeps_hostname_upstream_unresolved_until_runtime_start() {
        let server = parse_upstream_server("dns.example.test:5353", false)
            .expect("hostname upstream should parse without network access");

        assert!(matches!(
            server,
            UpstreamServer::UdpHostname { hostname, port }
                if hostname == "dns.example.test" && port == 5353
        ));
    }

    #[test]
    fn parses_all_bootstrap_addresses_from_response() {
        let query = build_dns_query("dns.example.test", 1).expect("query should build");
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&2_u16.to_be_bytes());
        for octets in [[192, 0, 2, 1], [192, 0, 2, 2]] {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&octets);
        }

        let ips = parse_bootstrap_ip_response(&response, &query, 1)
            .expect("all bootstrap addresses should parse");

        assert_eq!(
            ips,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn resolves_a_and_aaaa_with_the_same_bootstrap_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock bootstrap should bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock timeout should configure");
        let server = socket.local_addr().unwrap();
        let responder = thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0_u8; 512];
                let (len, peer) = socket
                    .recv_from(&mut buffer)
                    .expect("mock bootstrap should receive query");
                let query = &buffer[..len];
                let qtype = read_u16(query, len - 4).expect("query type should exist");
                let mut response = query.to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&qtype.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&60_u32.to_be_bytes());
                if qtype == 1 {
                    response.extend_from_slice(&4_u16.to_be_bytes());
                    response.extend_from_slice(&[192, 0, 2, 10]);
                } else {
                    response.extend_from_slice(&16_u16.to_be_bytes());
                    response.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
                }
                socket
                    .send_to(&response, peer)
                    .expect("mock bootstrap should send response");
            }
        });

        let addrs = resolve_hostname_with_bootstrap("dns.example.test", 443, server)
            .expect("A and AAAA should resolve");
        responder.join().expect("mock bootstrap should finish");

        assert_eq!(
            addrs,
            [
                "192.0.2.10:443".parse().unwrap(),
                "[::1]:443".parse().unwrap()
            ]
        );
    }

    #[test]
    fn default_config_uses_gateway_dns_defaults() {
        let config = AppConfig::default();

        assert_eq!(config.listen_host, "0.0.0.0");
        assert_eq!(config.listen_port, 53);
        assert!(config.listen_ipv6);
        assert_eq!(config.rate_limit_per_second, 2_000);
        assert_eq!(config.filter_max_size_mb, 50);
        assert!(!config.allow_insecure_http);
        assert_eq!(
            config.upstream_dns,
            [
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query",
                "223.5.5.5",
                "119.29.29.29"
            ]
            .join("\n")
        );
        assert_eq!(config.filters.len(), 3);
        assert_eq!(config.filters[0].name, "AdGuard DNS filter");
        assert_eq!(config.filters[0].url, DEFAULT_ADGUARD_DNS_FILTER_URL);
        assert_eq!(config.filters[1].name, "AdAway Default Blocklist");
        assert_eq!(config.filters[1].url, DEFAULT_ADAWAY_FILTER_URL);
        assert_eq!(config.filters[2].name, "AdBlock DNS Filters");
        assert_eq!(
            config.filters[2].url,
            "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
        );
    }

    #[test]
    fn validates_client_access_lists() {
        let mut config = AppConfig {
            allowed_clients: "127.0.0.1\n192.168.0.0/16\n::1/128".into(),
            blocked_clients: "192.168.1.2".into(),
            ..AppConfig::default()
        };

        config.validate().expect("client lists should validate");

        config.allowed_clients = "not-a-network".into();

        assert!(config.validate().is_err());
    }

    #[test]
    fn migrates_old_mdns_default_port() {
        let mut config = AppConfig {
            schema_version: 0,
            listen_host: "127.0.0.1".into(),
            listen_port: 5353,
            ..AppConfig::default()
        };

        migrate_legacy_defaults(&mut config);

        assert_eq!(config.listen_host, "0.0.0.0");
        assert_eq!(config.listen_port, 53);
    }

    #[test]
    fn migrates_schema_defaults() {
        let mut config = AppConfig {
            schema_version: 0,
            allowed_clients: String::new(),
            rate_limit_per_second: 0,
            refuse_any: false,
            fallback_dns: String::new(),
            bootstrap_dns: String::new(),
            ..AppConfig::default()
        };

        migrate_legacy_defaults(&mut config);

        assert_eq!(config.schema_version, CURRENT_CONFIG_SCHEMA_VERSION);
        assert!(!config.allowed_clients.trim().is_empty());
        assert_eq!(
            config.rate_limit_per_second,
            default_rate_limit_per_second()
        );
        assert!(config.refuse_any);
        assert!(!config.fallback_dns.trim().is_empty());
        assert!(!config.bootstrap_dns.trim().is_empty());
        assert!(config.runtime_watchdog_enabled);
        assert_eq!(
            config.runtime_watchdog_interval_seconds,
            default_runtime_watchdog_interval_seconds()
        );
        assert_eq!(config.filter_max_size_mb, default_filter_max_size_mb());
    }

    #[test]
    fn migrates_old_default_rate_limit_but_preserves_custom_value() {
        let mut legacy_default = AppConfig {
            schema_version: 7,
            rate_limit_per_second: LEGACY_DEFAULT_RATE_LIMIT_PER_SECOND,
            ..AppConfig::default()
        };
        migrate_legacy_defaults(&mut legacy_default);
        assert_eq!(
            legacy_default.rate_limit_per_second,
            default_rate_limit_per_second()
        );

        let mut custom = AppConfig {
            schema_version: 7,
            rate_limit_per_second: 500,
            ..AppConfig::default()
        };
        migrate_legacy_defaults(&mut custom);
        assert_eq!(custom.rate_limit_per_second, 500);
    }

    #[test]
    fn migrates_legacy_filter_urls_but_preserves_custom_sources() {
        let mut config = AppConfig {
            schema_version: 8,
            filters: vec![
                FilterSubscription {
                    id: "adguard-dns-filter".into(),
                    url: LEGACY_ADGUARD_DNS_FILTER_URL.into(),
                    last_error: Some("旧地址下载失败".into()),
                    ..FilterSubscription::default()
                },
                FilterSubscription {
                    id: "adaway-default-blocklist".into(),
                    url: LEGACY_ADAWAY_FILTER_URL.into(),
                    ..FilterSubscription::default()
                },
                FilterSubscription {
                    id: "custom".into(),
                    url: "https://example.com/custom.txt".into(),
                    ..FilterSubscription::default()
                },
            ],
            ..AppConfig::default()
        };

        migrate_legacy_defaults(&mut config);

        assert_eq!(config.schema_version, CURRENT_CONFIG_SCHEMA_VERSION);
        assert_eq!(config.filters[0].url, DEFAULT_ADGUARD_DNS_FILTER_URL);
        assert!(config.filters[0].last_error.is_none());
        assert_eq!(config.filters[1].url, DEFAULT_ADAWAY_FILTER_URL);
        assert_eq!(config.filters[2].url, "https://example.com/custom.txt");
    }

    #[test]
    fn builds_ipv4_and_ipv6_listen_addresses() {
        let config = AppConfig::default();

        assert_eq!(
            config
                .listen_socket_addrs()
                .expect("listen addresses should validate"),
            ["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
        );
    }

    #[test]
    fn preserves_legacy_ipv6_only_listener() {
        let mut config = AppConfig {
            schema_version: 6,
            listen_host: "::1".into(),
            ..AppConfig::default()
        };

        migrate_legacy_defaults(&mut config);

        assert!(!config.listen_ipv6);
        assert_eq!(
            config
                .listen_socket_addrs()
                .expect("legacy listener should validate"),
            ["[::1]:53".parse().unwrap()]
        );
    }

    #[test]
    fn migrates_legacy_default_fallback_dns() {
        let mut config = AppConfig {
            schema_version: 5,
            fallback_dns: "1.1.1.1\n8.8.8.8".into(),
            ..AppConfig::default()
        };
        migrate_legacy_defaults(&mut config);
        assert_eq!(config.fallback_dns, default_fallback_dns());

        // 用户自定义的 fallback 不应被迁移覆盖
        let mut custom = AppConfig {
            schema_version: 5,
            fallback_dns: "9.9.9.9".into(),
            ..AppConfig::default()
        };
        migrate_legacy_defaults(&mut custom);
        assert_eq!(custom.fallback_dns, "9.9.9.9");
    }

    #[test]
    fn rejects_http_endpoints_by_default() {
        let mut config = AppConfig {
            upstream_dns: "http://dns.example.test/dns-query".into(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());

        config.allow_insecure_http = true;
        config
            .validate()
            .expect("explicit HTTP opt-in should validate");
    }

    #[test]
    fn rejects_malformed_doh_url_during_validation() {
        let config = AppConfig {
            upstream_dns: "https://".into(),
            ..AppConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn migrates_legacy_http_configs_to_explicit_opt_in() {
        let mut config = AppConfig {
            schema_version: 4,
            upstream_dns: "http://dns.example.test/dns-query".into(),
            ..AppConfig::default()
        };
        config.allow_insecure_http = false;

        migrate_legacy_defaults(&mut config);

        assert!(config.allow_insecure_http);
        config
            .validate()
            .expect("legacy HTTP config should remain valid");
    }

    #[test]
    fn clears_filter_cache_files_without_removing_subdirectories() {
        let dir = std::env::temp_dir().join(format!(
            "dnsblackhole-filter-cache-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("nested")).expect("test cache directory should create");
        fs::write(dir.join("a.txt"), "abc").expect("test cache file should write");
        fs::write(dir.join("nested").join("keep.txt"), "x").expect("nested test file should write");

        let stats = clear_filter_cache_dir(&dir).expect("cache should clear");

        assert_eq!(stats.removed_files, 1);
        assert_eq!(stats.removed_bytes, 3);
        assert!(!dir.join("a.txt").exists());
        assert!(dir.join("nested").join("keep.txt").exists());

        fs::remove_dir_all(dir).expect("test cache directory should remove");
    }
}
