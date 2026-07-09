mod access;
mod cache;
mod protocol;
mod rules;
mod server;
mod stats;
mod upstream;
mod worker;

pub use rules::{RuleSummary, summarize_rules};
pub use server::DnsServer;
pub use stats::{
    DnsStats, RuntimeStatus, TrafficBucket, UpstreamLatencyStat, UpstreamRequestStat, empty_status,
};

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use crate::config::UpstreamServer;

    use super::{
        cache::{DnsCache, DnsCacheConfig, QueryCacheKey, cache_ttl_seconds},
        protocol::{
            RCODE_NXDOMAIN, RCODE_REFUSED, TYPE_A, TYPE_ANY, TYPE_SOA, build_block_response,
            build_error_response, extract_response_ips, parse_question, prepare_cached_response,
            read_u16, response_is_truncated, response_min_record_ttl, validate_response_for_query,
        },
        rules::{compile_rules, summarize_rules},
        stats::{DnsStats, current_second, record_blocked, record_query},
        upstream::{
            RuntimeUpstream, is_upstream_temporarily_unhealthy, mark_upstream_available,
            mark_upstream_unhealthy,
        },
    };

    #[test]
    fn adguard_style_rule_blocks_domain_and_subdomain() {
        let rules = compile_rules("||example.org^");

        assert!(rules.is_blocked("example.org"));
        assert!(rules.is_blocked("ads.example.org"));
        assert!(!rules.is_blocked("badexample.org"));
    }

    #[test]
    fn allow_rule_overrides_block_rule() {
        let rules = compile_rules("||example.org^\n@@||safe.example.org^");

        assert!(rules.is_blocked("track.example.org"));
        assert!(!rules.is_blocked("safe.example.org"));
        assert!(!rules.is_blocked("cdn.safe.example.org"));
    }

    #[test]
    fn summarizes_ignored_rule_reasons() {
        let summary = summarize_rules(
            "! comment\n/ads[0-9]+\\.example/\n||example.org^$dnstype=A\nbad domain\n||valid.example^",
        );

        assert_eq!(summary.block_rules, 1);
        assert_eq!(summary.ignored_rules, 4);
        assert_eq!(summary.ignored_comment_rules, 1);
        assert_eq!(summary.ignored_regex_rules, 1);
        assert_eq!(summary.ignored_unsupported_rules, 1);
        assert_eq!(summary.ignored_invalid_rules, 1);
    }

    #[test]
    fn hosts_style_rule_blocks_exact_domain_only() {
        let rules = compile_rules("0.0.0.0 example.org");

        assert!(rules.is_blocked("example.org"));
        assert!(!rules.is_blocked("www.example.org"));
    }

    #[test]
    fn block_response_returns_zero_address_for_a_query() {
        let query = a_query("blocked.test");
        let question = parse_question(&query).expect("query should parse");
        let response = build_block_response(&query, &question);

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn refused_error_response_preserves_question() {
        let query = typed_query("example.org", TYPE_ANY);
        let response =
            build_error_response(&query, RCODE_REFUSED).expect("refused response should build");

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(response[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(read_u16(&response, 4), Some(1));
        assert_eq!(read_u16(&response, 6), Some(0));
    }

    #[test]
    fn validates_upstream_response_matches_original_query() {
        let query = a_query("example.org");
        let response = a_response("example.org", [1, 2, 3, 4]);

        validate_response_for_query(&query, &response).expect("response should match");

        let mut wrong_id = response.clone();
        wrong_id[0] = 0xab;
        assert!(validate_response_for_query(&query, &wrong_id).is_err());

        let wrong_question = a_response("other.example.org", [1, 2, 3, 4]);
        assert!(validate_response_for_query(&query, &wrong_question).is_err());
    }

    #[test]
    fn detects_truncated_dns_response() {
        let mut response = a_response("example.org", [1, 2, 3, 4]);

        assert!(!response_is_truncated(&response));
        response[2] |= 0b0000_0010;
        assert!(response_is_truncated(&response));
    }

    #[test]
    fn runtime_stats_record_domain_counts_and_traffic() {
        let stats = Arc::new(Mutex::new(DnsStats::default()));

        record_query(&stats, "ads.example.org", true);
        record_blocked(&stats, "ads.example.org", true);

        let current = stats.lock().expect("stats should lock");
        assert_eq!(current.queries, 1);
        assert_eq!(current.blocked, 1);
        assert_eq!(current.query_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.blocked_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.traffic.len(), 1);
        assert_eq!(current.traffic[0].queries, 1);
        assert_eq!(current.traffic[0].blocked, 1);
    }

    #[test]
    fn extracts_a_record_ips_from_dns_response() {
        let response = a_response("example.org", [1, 2, 3, 4]);

        assert_eq!(
            extract_response_ips(&response),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
    }

    #[test]
    fn dns_cache_rewrites_transaction_id_and_ttl() {
        let query = a_query("example.org");
        let question = parse_question(&query).expect("query should parse");
        let key = QueryCacheKey::from_question(&question);
        let config = DnsCacheConfig {
            enabled: true,
            max_size_bytes: 16 * 1024,
            min_ttl: 0,
            max_ttl: 60,
            optimistic: true,
        };
        let mut cache = DnsCache::from_config(config).expect("cache should build");

        cache.insert(key.clone(), a_response("example.org", [1, 2, 3, 4]), 100);
        let mut next_query = query.clone();
        next_query[0] = 0xab;
        next_query[1] = 0xcd;
        let raw_hit = cache.lookup(&key, 130).expect("cache should hit");
        let response = prepare_cached_response(&raw_hit.response, &next_query, raw_hit.ttl)
            .expect("cached response should prepare");

        assert!(!raw_hit.refresh);
        assert_eq!(&response[0..2], &[0xab, 0xcd]);
        assert_eq!(response_min_record_ttl(&response), Some(30));
    }

    #[test]
    fn dns_cache_stores_authoritative_nxdomain_response() {
        let query = a_query("missing.example.org");
        let question = parse_question(&query).expect("query should parse");
        let key = QueryCacheKey::from_question(&question);
        let response = nxdomain_response("missing.example.org", 300);
        let config = DnsCacheConfig {
            enabled: true,
            max_size_bytes: 16 * 1024,
            min_ttl: 0,
            max_ttl: 120,
            optimistic: true,
        };
        let mut cache = DnsCache::from_config(config.clone()).expect("cache should build");

        assert_eq!(cache_ttl_seconds(&response, &config), Some(120));
        cache.insert(key.clone(), response, 100);
        let mut next_query = query.clone();
        next_query[0] = 0xab;
        next_query[1] = 0xcd;
        let raw_hit = cache.lookup(&key, 130).expect("cache should hit");
        let response = prepare_cached_response(&raw_hit.response, &next_query, raw_hit.ttl)
            .expect("cached response should prepare");

        assert_eq!(&response[0..2], &[0xab, 0xcd]);
        assert_eq!(response[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(response_min_record_ttl(&response), Some(90));
    }

    #[test]
    fn upstream_failure_backoff_can_be_marked_and_cleared() {
        let upstream = RuntimeUpstream::new(UpstreamServer::Udp("127.0.0.1:53".parse().unwrap()))
            .expect("upstream should build");

        assert!(!is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
        mark_upstream_unhealthy(&upstream);
        assert!(is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
        mark_upstream_available(&upstream);
        assert!(!is_upstream_temporarily_unhealthy(
            &upstream,
            current_second()
        ));
    }

    fn a_query(domain: &str) -> Vec<u8> {
        typed_query(domain, TYPE_A)
    }

    fn typed_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn a_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&ip);
        packet
    }

    fn nxdomain_response(domain: &str, ttl: u32) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_SOA.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&24_u16.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&1_u32.to_be_bytes());
        packet.extend_from_slice(&3600_u32.to_be_bytes());
        packet.extend_from_slice(&600_u32.to_be_bytes());
        packet.extend_from_slice(&86400_u32.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet
    }
}
