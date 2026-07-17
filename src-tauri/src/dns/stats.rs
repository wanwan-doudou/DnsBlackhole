use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;

use super::rules::RuleSummary;

const TRAFFIC_BUCKET_WINDOW_MINUTES: u64 = 90 * 24 * 60;
const SECURITY_EVENT_CAPACITY: usize = 200;
const SECURITY_EVENT_AGGREGATE_SECONDS: u64 = 10;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub security_events: VecDeque<SecurityEvent>,
    pub last_query: Option<String>,
    pub last_blocked: Option<String>,
    pub last_error: Option<String>,
    pub query_domains: HashMap<String, u64>,
    pub blocked_domains: HashMap<String, u64>,
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    AccessDenied,
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub protocol: DnsTransport,
    pub client_ip: String,
    pub reason: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficBucket {
    pub minute: u64,
    pub queries: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpstreamRequestStat {
    pub upstream: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpstreamLatencyStat {
    pub upstream: String,
    pub avg_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub(crate) fn record_access_denied(
    stats: &Arc<Mutex<DnsStats>>,
    client_ip: IpAddr,
    protocol: DnsTransport,
    reason: String,
) {
    if let Ok(mut current) = stats.lock() {
        current.access_denied_total += 1;
        if protocol == DnsTransport::Udp {
            current.dropped_udp_total += 1;
        }
        record_security_event(
            &mut current,
            SecurityEventType::AccessDenied,
            protocol,
            client_ip,
            reason,
        );
    }
}

pub(crate) fn record_rate_limited(
    stats: &Arc<Mutex<DnsStats>>,
    client_ip: IpAddr,
    protocol: DnsTransport,
    reason: String,
) {
    if let Ok(mut current) = stats.lock() {
        current.rate_limited_total += 1;
        if protocol == DnsTransport::Udp {
            current.dropped_udp_total += 1;
        }
        record_security_event(
            &mut current,
            SecurityEventType::RateLimited,
            protocol,
            client_ip,
            reason,
        );
    }
}

fn record_security_event(
    stats: &mut DnsStats,
    event_type: SecurityEventType,
    protocol: DnsTransport,
    client_ip: IpAddr,
    reason: String,
) {
    let now = current_second();
    let client_ip = client_ip.to_string();
    if let Some(last) = stats.security_events.back_mut()
        && last.event_type == event_type
        && last.protocol == protocol
        && last.client_ip == client_ip
        && last.reason == reason
        && now.saturating_sub(last.last_seen_at) <= SECURITY_EVENT_AGGREGATE_SECONDS
    {
        last.last_seen_at = now;
        last.count = last.count.saturating_add(1);
        return;
    }

    if stats.security_events.len() >= SECURITY_EVENT_CAPACITY {
        stats.security_events.pop_front();
    }
    stats.security_events.push_back(SecurityEvent {
        event_type,
        protocol,
        client_ip,
        reason,
        first_seen_at: now,
        last_seen_at: now,
        count: 1,
    });
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

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn aggregates_consecutive_security_events_and_counts_udp_drops() {
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let ip = "192.168.1.20".parse().unwrap();
        let reason = "客户端 192.168.1.20 不在允许列表中".to_string();

        record_access_denied(&stats, ip, DnsTransport::Udp, reason.clone());
        record_access_denied(&stats, ip, DnsTransport::Udp, reason);

        let current = stats.lock().unwrap();
        assert_eq!(current.access_denied_total, 2);
        assert_eq!(current.dropped_udp_total, 2);
        assert_eq!(current.security_events.len(), 1);
        assert_eq!(current.security_events[0].count, 2);
    }

    #[test]
    fn bounds_security_event_history() {
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        for index in 0..=SECURITY_EVENT_CAPACITY {
            let ip = IpAddr::V6(Ipv6Addr::from(index as u128));
            record_rate_limited(
                &stats,
                ip,
                DnsTransport::Tcp,
                format!("客户端 {ip} 触发限速"),
            );
        }

        let current = stats.lock().unwrap();
        assert_eq!(current.security_events.len(), SECURITY_EVENT_CAPACITY);
        assert_eq!(
            current.rate_limited_total,
            (SECURITY_EVENT_CAPACITY + 1) as u64
        );
    }
}
