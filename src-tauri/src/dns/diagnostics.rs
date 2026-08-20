use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, UpstreamMode, normalize_hostname};

use super::{
    filter_runtime::FilterRuntime,
    protocol::{DnsResponseAnswer, summarize_response},
    stats::DnsStats,
    upstream::{RuntimeUpstream, build_runtime_upstreams_with_dnssec, forward_query},
};

const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(3);
static DIAGNOSTIC_QUERY_ID: AtomicU16 = AtomicU16::new(0x7000);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DnsDiagnosticReport {
    pub(crate) domain: String,
    pub(crate) query_type: String,
    pub(crate) client_ip: Option<String>,
    #[serde(default = "default_client_policy")]
    pub(crate) client_policy: String,
    pub(crate) client_policy_source: Option<String>,
    pub(crate) local_status: String,
    pub(crate) local_detail: String,
    pub(crate) matched_rule: Option<String>,
    pub(crate) rule_source: Option<String>,
    pub(crate) rule_type: Option<String>,
    pub(crate) allowlist_rule: Option<String>,
    #[serde(default)]
    pub(crate) important_overrode: bool,
    pub(crate) upstreams: Vec<UpstreamDiagnosticResult>,
}

fn default_client_policy() -> String {
    "filter".to_string()
}

struct LocalDiagnostic {
    status: String,
    detail: String,
    client_policy: String,
    client_policy_source: Option<String>,
    matched_rule: Option<String>,
    rule_source: Option<String>,
    rule_type: Option<String>,
    allowlist_rule: Option<String>,
    important_overrode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UpstreamDiagnosticResult {
    pub(crate) upstream: String,
    pub(crate) success: bool,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) response_code: Option<u8>,
    pub(crate) authenticated_data: bool,
    pub(crate) answers: Vec<DnsResponseAnswer>,
    pub(crate) error: Option<String>,
}

pub(crate) fn run_dns_diagnostic(
    config: &AppConfig,
    filter: Option<&FilterRuntime>,
    protection_paused: bool,
    domain: &str,
    query_type: &str,
    client_ip: Option<&str>,
) -> Result<DnsDiagnosticReport, String> {
    let domain = normalize_hostname(domain)
        .ok_or_else(|| "请输入有效的域名，例如 example.com".to_string())?;
    let (query_type, qtype) = parse_query_type(query_type)?;
    let client_ip = parse_client_ip(client_ip)?;
    let query = build_query(&domain, qtype)?;
    let bootstrap = config.bootstrap_servers()?;
    let upstreams = build_runtime_upstreams_with_dnssec(
        config.upstream_servers()?,
        &bootstrap,
        config.dnssec_enabled,
    );
    let local = local_diagnostic(filter, protection_paused, &domain, qtype, client_ip);
    let results = test_upstreams(&query, upstreams);

    Ok(DnsDiagnosticReport {
        domain,
        query_type: query_type.to_string(),
        client_ip: client_ip.map(|ip| ip.to_string()),
        client_policy: local.client_policy,
        client_policy_source: local.client_policy_source,
        local_status: local.status,
        local_detail: local.detail,
        matched_rule: local.matched_rule,
        rule_source: local.rule_source,
        rule_type: local.rule_type,
        allowlist_rule: local.allowlist_rule,
        important_overrode: local.important_overrode,
        upstreams: results,
    })
}

fn local_diagnostic(
    filter: Option<&FilterRuntime>,
    protection_paused: bool,
    domain: &str,
    qtype: u16,
    client_ip: Option<IpAddr>,
) -> LocalDiagnostic {
    let empty = |status: &str, detail: String, client_policy: &str, source: Option<String>| {
        LocalDiagnostic {
            status: status.to_string(),
            detail,
            client_policy: client_policy.to_string(),
            client_policy_source: source,
            matched_rule: None,
            rule_source: None,
            rule_type: None,
            allowlist_rule: None,
            important_overrode: false,
        }
    };
    let Some(filter) = filter else {
        return empty("stopped", "DNS 服务当前未运行".to_string(), "filter", None);
    };
    let client_decision = client_ip.map(|ip| filter.client_filtering.decision(ip));
    let client_policy_source = client_decision
        .as_ref()
        .and_then(|decision| decision.source.map(str::to_string));
    let client_policy = if client_decision
        .as_ref()
        .is_some_and(|decision| decision.mode == super::client_policy::ClientFilteringMode::Bypass)
    {
        "bypass"
    } else {
        "filter"
    };
    if let Some(target) = filter.rewrites.lookup(domain) {
        let values = [
            target.ipv4.map(|ip| ip.to_string()),
            target.ipv6.map(|ip| ip.to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" / ");
        return empty(
            "rewrite",
            format!("将由本地重写返回 {values}"),
            client_policy,
            client_policy_source,
        );
    }
    if protection_paused {
        return empty(
            "paused",
            "过滤保护已暂停，本次查询会直接转发到上游".to_string(),
            client_policy,
            client_policy_source,
        );
    }
    if client_policy == "bypass" {
        let detail = client_policy_source.as_ref().map_or_else(
            || "该客户端已绕过过滤保护，本次查询会直接转发到上游".to_string(),
            |source| format!("客户端命中 {source} 的绕过策略；不会应用拦截规则和响应保护"),
        );
        return empty("bypassed", detail, client_policy, client_policy_source);
    }
    if let Some(rule_match) = filter.rules.blocking_match(domain, qtype) {
        return LocalDiagnostic {
            status: "blocked".to_string(),
            detail: format!("命中 {}：{}", rule_match.source, rule_match.rule),
            client_policy: client_policy.to_string(),
            client_policy_source,
            matched_rule: Some(rule_match.rule),
            rule_source: Some(rule_match.source),
            rule_type: Some(rule_match.rule_type),
            allowlist_rule: rule_match.allowlist_rule,
            important_overrode: rule_match.important_overrode,
        };
    }
    empty(
        "allowed",
        "未命中过滤规则，将转发到上游".to_string(),
        client_policy,
        client_policy_source,
    )
}

fn parse_client_ip(value: Option<&str>) -> Result<Option<IpAddr>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|_| "客户端地址必须是有效的 IPv4 或 IPv6 地址".to_string())
}

fn test_upstreams(query: &[u8], upstreams: Vec<RuntimeUpstream>) -> Vec<UpstreamDiagnosticResult> {
    let query = Arc::new(query.to_vec());
    thread_results(upstreams, |upstream| {
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        match forward_query(
            query.as_slice(),
            std::slice::from_ref(&upstream),
            &UpstreamMode::LoadBalance,
            &AtomicUsize::new(0),
            Instant::now() + DIAGNOSTIC_TIMEOUT,
            &stats,
        ) {
            Ok(result) => {
                let summary = summarize_response(&result.response);
                UpstreamDiagnosticResult {
                    upstream: result.upstream,
                    success: true,
                    latency_ms: Some(result.duration_ms),
                    response_code: summary.as_ref().map(|summary| summary.code),
                    authenticated_data: result
                        .response
                        .get(3)
                        .is_some_and(|flags| flags & 0x20 != 0),
                    answers: summary.map(|summary| summary.answers).unwrap_or_default(),
                    error: None,
                }
            }
            Err(error) => UpstreamDiagnosticResult {
                upstream: upstream.label().to_string(),
                success: false,
                latency_ms: None,
                response_code: None,
                authenticated_data: false,
                answers: Vec::new(),
                error: Some(error),
            },
        }
    })
}

fn thread_results<T, F>(items: Vec<RuntimeUpstream>, run: F) -> Vec<T>
where
    T: Send,
    F: Fn(RuntimeUpstream) -> T + Sync,
{
    std::thread::scope(|scope| {
        items
            .into_iter()
            .map(|item| scope.spawn(|| run(item)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().expect("DNS 诊断线程不应异常退出"))
            .collect()
    })
}

fn parse_query_type(value: &str) -> Result<(&'static str, u16), String> {
    match value.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(("A", 1)),
        "AAAA" => Ok(("AAAA", 28)),
        "TXT" => Ok(("TXT", 16)),
        "HTTPS" => Ok(("HTTPS", 65)),
        _ => Err("诊断仅支持 A、AAAA、TXT 或 HTTPS 查询".to_string()),
    }
}

fn build_query(domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(domain.len() + 18);
    query.extend_from_slice(
        &DIAGNOSTIC_QUERY_ID
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes(),
    );
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        let len = u8::try_from(label.len()).map_err(|_| "域名标签过长".to_string())?;
        query.push(len);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{filter_runtime::build_filter_runtime, protocol::parse_query};

    #[test]
    fn diagnostic_query_is_valid_dns_packet() {
        let query = build_query("example.com", 65).expect("应能构造查询");
        let parsed = parse_query(&query).expect("查询应可解析");
        assert_eq!(parsed.question.domain, "example.com");
        assert_eq!(parsed.question.qtype, 65);
    }

    #[test]
    fn client_ip_is_optional_but_must_be_valid() {
        assert_eq!(parse_client_ip(Some(" ")).unwrap(), None);
        assert_eq!(
            parse_client_ip(Some("192.168.1.20")).unwrap(),
            Some("192.168.1.20".parse().unwrap())
        );
        assert!(parse_client_ip(Some("not-an-ip")).is_err());
    }

    #[test]
    fn client_bypass_is_explained_before_rule_match() {
        let config = AppConfig {
            client_filtering_rules: "192.168.1.50 => bypass".into(),
            ..AppConfig::default()
        };
        let runtime = build_filter_runtime(&config, "||ads.example^");

        let bypassed = local_diagnostic(
            Some(&runtime),
            false,
            "ads.example",
            1,
            Some("192.168.1.50".parse().unwrap()),
        );
        assert_eq!(bypassed.status, "bypassed");
        assert_eq!(
            bypassed.client_policy_source.as_deref(),
            Some("192.168.1.50")
        );
        assert!(bypassed.matched_rule.is_none());

        let filtered = local_diagnostic(
            Some(&runtime),
            false,
            "ads.example",
            1,
            Some("192.168.1.51".parse().unwrap()),
        );
        assert_eq!(filtered.status, "blocked");
        assert_eq!(filtered.matched_rule.as_deref(), Some("||ads.example^"));
    }

    #[test]
    fn report_accepts_response_from_service_before_client_diagnostics() {
        let report: DnsDiagnosticReport = serde_json::from_value(serde_json::json!({
            "domain": "example.com",
            "query_type": "A",
            "local_status": "allowed",
            "local_detail": "本地过滤未命中",
            "upstreams": []
        }))
        .expect("旧服务诊断响应应保持可解析");

        assert_eq!(report.client_policy, "filter");
        assert!(report.client_ip.is_none());
        assert!(!report.important_overrode);
    }
}
