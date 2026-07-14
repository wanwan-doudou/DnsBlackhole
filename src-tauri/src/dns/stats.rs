use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::config::AppConfig;

use super::rules::RuleSummary;

const TRAFFIC_BUCKET_WINDOW_MINUTES: u64 = 90 * 24 * 60;

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStats {
    pub started_at: Option<u64>,
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub access_denied_total: u64,
    pub rate_limited_total: u64,
    pub refused_any_total: u64,
    pub dropped_udp_total: u64,
    pub last_query: Option<String>,
    pub last_blocked: Option<String>,
    pub last_error: Option<String>,
    pub query_domains: HashMap<String, u64>,
    pub blocked_domains: HashMap<String, u64>,
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficBucket {
    pub minute: u64,
    pub queries: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamRequestStat {
    pub upstream: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamLatencyStat {
    pub upstream: String,
    pub avg_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub running: bool,
    pub listen_addr: String,
    pub upstream_dns: String,
    pub summary: RuleSummary,
    pub stats: DnsStats,
    pub error: Option<String>,
}

pub fn empty_status(
    config: &AppConfig,
    running: bool,
    summary: RuleSummary,
    stats: DnsStats,
    error: Option<String>,
) -> RuntimeStatus {
    let listen_addr = config
        .listen_socket_addrs()
        .map(|addrs| {
            addrs
                .into_iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(" / ")
        })
        .unwrap_or_else(|_| format!("{}:{}", config.listen_host, config.listen_port));

    RuntimeStatus {
        running,
        listen_addr,
        upstream_dns: config.upstream_dns.clone(),
        summary,
        stats,
        error,
    }
}

pub(crate) fn reset_stats(stats: &Arc<Mutex<DnsStats>>) {
    if let Ok(mut current) = stats.lock() {
        *current = DnsStats {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs()),
            ..DnsStats::default()
        };
    }
}

pub(crate) fn record_query(
    stats: &Arc<Mutex<DnsStats>>,
    domain: &str,
    detailed_runtime_stats: bool,
) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.queries += 1;
        current.last_query = Some(domain.to_string());
        *current.query_domains.entry(domain.to_string()).or_default() += 1;
        record_traffic(&mut current, false);
    }
}

pub(crate) fn record_blocked_query(
    stats: &Arc<Mutex<DnsStats>>,
    domain: &str,
    detailed_runtime_stats: bool,
) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.queries += 1;
        current.blocked += 1;
        current.last_query = Some(domain.to_string());
        current.last_blocked = Some(domain.to_string());
        *current.query_domains.entry(domain.to_string()).or_default() += 1;
        *current
            .blocked_domains
            .entry(domain.to_string())
            .or_default() += 1;
        record_traffic(&mut current, false);
        record_traffic(&mut current, true);
    }
}

#[cfg(test)]
pub(crate) fn record_blocked(
    stats: &Arc<Mutex<DnsStats>>,
    domain: &str,
    detailed_runtime_stats: bool,
) {
    if let Ok(mut current) = stats.lock() {
        current.blocked += 1;
        current.last_blocked = Some(domain.to_string());
        if detailed_runtime_stats {
            *current
                .blocked_domains
                .entry(domain.to_string())
                .or_default() += 1;
            record_traffic(&mut current, true);
        }
    }
}

pub(crate) fn record_forwarded(stats: &Arc<Mutex<DnsStats>>, detailed_runtime_stats: bool) {
    if !detailed_runtime_stats {
        return;
    }

    if let Ok(mut current) = stats.lock() {
        current.forwarded += 1;
    }
}

pub(crate) fn record_error(stats: &Arc<Mutex<DnsStats>>, error: String) {
    if let Ok(mut current) = stats.lock() {
        current.failed += 1;
        current.last_error = Some(error);
    }
}

pub(crate) fn record_access_denied(stats: &Arc<Mutex<DnsStats>>, dropped_udp: bool) {
    if let Ok(mut current) = stats.lock() {
        current.access_denied_total += 1;
        if dropped_udp {
            current.dropped_udp_total += 1;
        }
    }
}

pub(crate) fn record_rate_limited(stats: &Arc<Mutex<DnsStats>>, dropped_udp: bool) {
    if let Ok(mut current) = stats.lock() {
        current.rate_limited_total += 1;
        if dropped_udp {
            current.dropped_udp_total += 1;
        }
    }
}

pub(crate) fn record_refused_any(stats: &Arc<Mutex<DnsStats>>) {
    if let Ok(mut current) = stats.lock() {
        current.refused_any_total += 1;
    }
}

fn record_traffic(stats: &mut DnsStats, blocked: bool) {
    let minute = current_minute();

    if let Some(bucket) = stats.traffic.last_mut()
        && bucket.minute == minute
    {
        increment_traffic_bucket(bucket, blocked);
        return;
    }

    if let Some(bucket) = stats
        .traffic
        .iter_mut()
        .find(|bucket| bucket.minute == minute)
    {
        increment_traffic_bucket(bucket, blocked);
        return;
    }

    let oldest_minute = minute.saturating_sub(TRAFFIC_BUCKET_WINDOW_MINUTES);
    stats
        .traffic
        .retain(|bucket| bucket.minute >= oldest_minute);
    stats.traffic.push(TrafficBucket {
        minute,
        ..TrafficBucket::default()
    });

    let bucket = stats
        .traffic
        .last_mut()
        .expect("traffic bucket should exist after push");
    increment_traffic_bucket(bucket, blocked);
}

fn increment_traffic_bucket(bucket: &mut TrafficBucket, blocked: bool) {
    if blocked {
        bucket.blocked += 1;
    } else {
        bucket.queries += 1;
    }
}

fn current_minute() -> u64 {
    current_second() / 60
}

pub(crate) fn current_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
