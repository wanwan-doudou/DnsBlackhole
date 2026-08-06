use std::{
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
    pub(crate) local_status: String,
    pub(crate) local_detail: String,
    pub(crate) upstreams: Vec<UpstreamDiagnosticResult>,
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
) -> Result<DnsDiagnosticReport, String> {
    let domain = normalize_hostname(domain)
        .ok_or_else(|| "请输入有效的域名，例如 example.com".to_string())?;
    let (query_type, qtype) = parse_query_type(query_type)?;
    let query = build_query(&domain, qtype)?;
    let bootstrap = config.bootstrap_servers()?;
    let upstreams = build_runtime_upstreams_with_dnssec(
        config.upstream_servers()?,
        &bootstrap,
        config.dnssec_enabled,
    );
    let local = local_diagnostic(filter, protection_paused, &domain, qtype);
    let results = test_upstreams(&query, upstreams);

    Ok(DnsDiagnosticReport {
        domain,
        query_type: query_type.to_string(),
        local_status: local.0,
        local_detail: local.1,
        upstreams: results,
    })
}

fn local_diagnostic(
    filter: Option<&FilterRuntime>,
    protection_paused: bool,
    domain: &str,
    qtype: u16,
) -> (String, String) {
    let Some(filter) = filter else {
        return ("stopped".to_string(), "DNS 服务当前未运行".to_string());
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
        return ("rewrite".to_string(), format!("将由本地重写返回 {values}"));
    }
    if protection_paused {
        return (
            "paused".to_string(),
            "过滤保护已暂停，本次查询会直接转发到上游".to_string(),
        );
    }
    if let Some(rule_match) = filter.rules.blocking_match(domain, qtype) {
        return (
            "blocked".to_string(),
            format!("命中 {}：{}", rule_match.source, rule_match.rule),
        );
    }
    (
        "allowed".to_string(),
        "未命中过滤规则，将转发到上游".to_string(),
    )
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
    use crate::dns::protocol::parse_query;

    #[test]
    fn diagnostic_query_is_valid_dns_packet() {
        let query = build_query("example.com", 65).expect("应能构造查询");
        let parsed = parse_query(&query).expect("查询应可解析");
        assert_eq!(parsed.question.domain, "example.com");
        assert_eq!(parsed.question.qtype, 65);
    }
}
