mod access;
mod cache;
mod filter_runtime;
mod protocol;
mod rewrites;
mod rule_cache;
mod rules;
mod server;
mod stats;
mod task_pool;
mod upstream;
mod worker;

pub(crate) use filter_runtime::{build_filter_runtime_with_rules, replace_filter_runtime};
pub(crate) use protocol::{DnsResponseAnswer, DnsResponseSummary};
pub(crate) use rule_cache::{RuleLoadSource, clear_rule_cache, load_or_compile_rules};
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

    use crate::config::{AppConfig, BlockingMode};

    use super::{
        cache::{DnsCache, DnsCacheConfig, QueryCacheKey, cache_ttl_seconds},
        protocol::{
            BlockingPolicy, RCODE_NXDOMAIN, RCODE_REFUSED, TYPE_A, TYPE_ANY, TYPE_SOA,
            build_block_response, build_error_response, build_rewrite_response,
            extract_response_ips, parse_query, parse_question, prepare_cached_response, read_u16,
            response_is_truncated, response_min_record_ttl, summarize_response,
            truncate_response_for_udp, udp_payload_size, validate_response_for_query,
        },
        rewrites::compile_rewrites,
        rules::{compile_domain_set, compile_rules, summarize_rules},
        stats::{DnsStats, current_second, record_blocked, record_query},
        upstream::{
            RuntimeUpstream, is_upstream_temporarily_unhealthy, mark_upstream_available,
            mark_upstream_unhealthy,
        },
    };

    #[test]
    fn adguard_style_rule_blocks_domain_and_subdomain() {
        let rules = compile_rules("||example.org^");

        assert!(rules.is_blocked("example.org", TYPE_A));
        assert!(rules.is_blocked("ads.example.org", TYPE_A));
        assert!(!rules.is_blocked("badexample.org", TYPE_A));
    }

    #[test]
    fn allow_rule_overrides_block_rule() {
        let rules = compile_rules("||example.org^\n@@||safe.example.org^");

        assert!(rules.is_blocked("track.example.org", TYPE_A));
        assert!(!rules.is_blocked("safe.example.org", TYPE_A));
        assert!(!rules.is_blocked("cdn.safe.example.org", TYPE_A));
    }

    #[test]
    fn summarizes_ignored_rule_reasons() {
        let summary = summarize_rules(
            "! comment\n/ads[0-9]+\\.example/\n||example.org^$unknown\nbad domain\n||valid.example^",
        );

        assert_eq!(summary.block_rules, 1);
        assert_eq!(summary.ignored_rules, 4);
        assert_eq!(summary.ignored_comment_rules, 1);
        assert_eq!(summary.ignored_regex_rules, 1);
        assert_eq!(summary.ignored_unsupported_rules, 1);
        assert_eq!(summary.ignored_invalid_rules, 1);
    }

    #[test]
    fn important_rule_overrides_normal_exception() {
        let rules = compile_rules("||example.org^$important\n@@||example.org^");

        assert!(rules.is_blocked("example.org", TYPE_A));
        let matched = rules
            .blocking_match("example.org", TYPE_A)
            .expect("important block rule should match");
        assert_eq!(matched.rule, "||example.org^$important");
        assert_eq!(matched.rule_type, "suffix block");
        assert!(matched.important_overrode);
        assert_eq!(matched.allowlist_rule.as_deref(), Some("@@||example.org^"));

        let rules = compile_rules("||example.org^$important\n@@||example.org^$important");
        assert!(!rules.is_blocked("example.org", TYPE_A));
    }

    #[test]
    fn blocking_match_preserves_filter_source() {
        let rules = compile_rules("! dnsblackhole-source:\"AdGuard DNS filter\"\n||example.org^");

        let matched = rules
            .blocking_match("ads.example.org", TYPE_A)
            .expect("suffix rule should match");
        assert_eq!(matched.source, "AdGuard DNS filter");
        assert_eq!(matched.rule, "||example.org^");
    }

    #[test]
    fn dnstype_limits_matching_query_types() {
        let rules = compile_rules("||example.org^$dnstype=A|AAAA");

        assert!(rules.is_blocked("example.org", TYPE_A));
        assert!(rules.is_blocked("example.org", 28));
        assert!(!rules.is_blocked("example.org", 16));

        let rules = compile_rules("||example.net^$dnstype=~AAAA");
        assert!(rules.is_blocked("example.net", TYPE_A));
        assert!(!rules.is_blocked("example.net", 28));
    }

    #[test]
    fn denyallow_excludes_domain_branch() {
        let rules = compile_rules("||example.org^$denyallow=safe.example.org");

        assert!(rules.is_blocked("ads.example.org", TYPE_A));
        assert!(!rules.is_blocked("safe.example.org", TYPE_A));
        assert!(!rules.is_blocked("cdn.safe.example.org", TYPE_A));
    }

    #[test]
    fn badfilter_disables_matching_rule() {
        let rules = compile_rules("||example.org^$important\n||example.org^$important,badfilter");

        assert!(!rules.is_blocked("example.org", TYPE_A));
        let summary = summarize_rules("||example.org^$important");
        assert_eq!(summary.block_rules, 1);
        assert_eq!(summary.ignored_unsupported_rules, 0);
    }

    #[test]
    fn hosts_line_supports_multiple_domains() {
        let rules = compile_rules("0.0.0.0 ads.example.org tracker.example.org # comment");

        assert!(rules.is_blocked("ads.example.org", TYPE_A));
        assert!(rules.is_blocked("tracker.example.org", TYPE_A));
        assert_eq!(rules.summary().block_rules, 2);
    }

    #[test]
    fn hosts_style_rule_blocks_exact_domain_only() {
        let rules = compile_rules("0.0.0.0 example.org");

        assert!(rules.is_blocked("example.org", TYPE_A));
        assert!(!rules.is_blocked("www.example.org", TYPE_A));
    }

    #[test]
    fn duplicate_rule_across_lists_keeps_first_source() {
        let rules = compile_rules(
            "! dnsblackhole-source:\"清单A\"\n||example.org^\n! dnsblackhole-source:\"清单B\"\n||example.org^",
        );

        let matched = rules
            .blocking_match("ads.example.org", TYPE_A)
            .expect("duplicate rule should still match");
        assert_eq!(matched.source, "清单A");
        assert_eq!(matched.rule, "||example.org^");
    }

    #[test]
    fn non_canonical_rule_text_is_preserved() {
        let rules = compile_rules("*.example.org\n127.0.0.1  tracker.example.net");

        let wildcard = rules
            .blocking_match("sub.example.org", TYPE_A)
            .expect("wildcard rule should match");
        assert_eq!(wildcard.rule, "*.example.org");
        assert_eq!(wildcard.rule_type, "suffix block");

        // 行内多余空格无法由域名重建，必须原样保留
        let hosts = rules
            .blocking_match("tracker.example.net", TYPE_A)
            .expect("hosts rule should match");
        assert_eq!(hosts.rule, "127.0.0.1  tracker.example.net");
        assert_eq!(hosts.rule_type, "hosts block");
    }

    #[test]
    fn canonical_rule_text_is_reconstructed() {
        let rules = compile_rules("example.com\n0.0.0.0 example.org\n||example.net^");

        let plain = rules
            .blocking_match("example.com", TYPE_A)
            .expect("plain rule should match");
        assert_eq!(plain.rule, "example.com");
        assert_eq!(plain.rule_type, "exact block");

        let hosts = rules
            .blocking_match("example.org", TYPE_A)
            .expect("hosts rule should match");
        assert_eq!(hosts.rule, "0.0.0.0 example.org");
        assert_eq!(hosts.rule_type, "hosts block");

        let suffix = rules
            .blocking_match("cdn.example.net", TYPE_A)
            .expect("suffix rule should match");
        assert_eq!(suffix.rule, "||example.net^");
        assert_eq!(suffix.rule_type, "suffix block");
    }

    #[test]
    fn same_domain_rules_match_in_insertion_order() {
        // 带修饰符的规则在前：A 查询命中它，其余类型回落到通配规则
        let rules = compile_rules("||example.org^$dnstype=A\n||example.org^");
        let matched_a = rules
            .blocking_match("example.org", TYPE_A)
            .expect("A query should match");
        assert_eq!(matched_a.rule, "||example.org^$dnstype=A");
        let matched_txt = rules
            .blocking_match("example.org", 16)
            .expect("TXT query should match");
        assert_eq!(matched_txt.rule, "||example.org^");

        // 通配规则在前：所有查询都命中先插入的通配规则
        let rules = compile_rules("||example.org^\n||example.org^$dnstype=A");
        let matched_a = rules
            .blocking_match("example.org", TYPE_A)
            .expect("A query should match");
        assert_eq!(matched_a.rule, "||example.org^");
        let matched_txt = rules
            .blocking_match("example.org", 16)
            .expect("TXT query should match");
        assert_eq!(matched_txt.rule, "||example.org^");
    }

    #[test]
    fn block_response_returns_zero_address_for_a_query() {
        let query = a_query("blocked.test");
        let question = parse_question(&query).expect("query should parse");
        let response = build_block_response(&query, &question, &BlockingPolicy::default());

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn block_response_supports_nxdomain_and_custom_ip_modes() {
        let query = a_query("blocked.test");
        let question = parse_question(&query).expect("query should parse");

        let nxdomain_policy = BlockingPolicy::from_config(&AppConfig {
            blocking_mode: BlockingMode::Nxdomain,
            ..AppConfig::default()
        });
        let response = build_block_response(&query, &question, &nxdomain_policy);
        assert_eq!(response[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(read_u16(&response, 6), Some(0));

        let custom_policy = BlockingPolicy::from_config(&AppConfig {
            blocking_mode: BlockingMode::CustomIp,
            blocking_custom_ipv4: "10.0.0.1".into(),
            ..AppConfig::default()
        });
        let response = build_block_response(&query, &question, &custom_policy);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 1]);
    }

    #[test]
    fn rewrite_response_answers_matching_ip_family_only() {
        let rewrites = compile_rewrites("nas.lan 192.168.1.10");
        let target = rewrites.lookup("nas.lan").expect("rewrite should match");

        let query = a_query("nas.lan");
        let question = parse_question(&query).expect("query should parse");
        let response = build_rewrite_response(&query, &question, &target);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[192, 168, 1, 10]);

        let aaaa_query = typed_query("nas.lan", 28);
        let aaaa_question = parse_question(&aaaa_query).expect("query should parse");
        let aaaa_response = build_rewrite_response(&aaaa_query, &aaaa_question, &target);
        // 只有 IPv4 记录时，AAAA 查询应返回无答案的 NOERROR
        assert_eq!(aaaa_response[3] & 0x0f, 0);
        assert_eq!(read_u16(&aaaa_response, 6), Some(0));
    }

    #[test]
    fn domain_set_matches_domain_and_subdomains() {
        let set = compile_domain_set("example.com\n*.lan\n# comment\n");

        assert!(set.contains("example.com"));
        assert!(set.contains("www.example.com"));
        assert!(set.contains("nas.lan"));
        assert!(!set.contains("example.org"));
        assert!(!set.contains("badexample.com"));
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
    fn query_context_isolates_cache_and_bypasses_edns_options() {
        let query = a_query("example.org");
        let parsed = parse_query(&query).expect("query should parse");
        let base_key = QueryCacheKey::from_query(&parsed).expect("plain query should be cacheable");

        let mut cd_query = query.clone();
        cd_query[3] |= 0x10;
        let cd_key = QueryCacheKey::from_query(&parse_query(&cd_query).unwrap()).unwrap();
        assert_ne!(base_key, cd_key);

        let mut edns_query = query.clone();
        edns_query[11] = 1;
        edns_query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        let edns = parse_query(&edns_query).expect("EDNS query should parse");
        assert_eq!(edns.edns_udp_size, Some(1232));
        assert!(edns.dnssec_ok);
        assert_eq!(udp_payload_size(&edns_query), 1232);
        assert_ne!(base_key, QueryCacheKey::from_query(&edns).unwrap());

        let mut option_query = edns_query;
        let len = option_query.len();
        option_query[len - 2..].copy_from_slice(&4_u16.to_be_bytes());
        option_query.extend_from_slice(&[0, 8, 0, 0]);
        let with_option = parse_query(&option_query).expect("EDNS option query should parse");
        assert!(!with_option.cache_safe);
        assert!(QueryCacheKey::from_query(&with_option).is_none());
    }

    #[test]
    fn rejects_non_ascii_dns_labels() {
        let mut query = a_query("example.org");
        query[13] = 0xff;
        assert!(parse_question(&query).is_err());
    }

    #[test]
    fn cached_response_echoes_current_question_case() {
        let cached = a_response("example.org", [1, 2, 3, 4]);
        let query = a_query("EXAMPLE.org");
        let question = parse_question(&query).unwrap();
        let response = prepare_cached_response(&cached, &query, 30).unwrap();

        assert_eq!(
            &response[12..question.question_end],
            &query[12..question.question_end]
        );
    }

    #[test]
    fn oversized_udp_response_sets_tc_and_keeps_question() {
        let query = a_query("example.org");
        let mut response = a_response("example.org", [1, 2, 3, 4]);
        response.resize(700, 0);
        let truncated = truncate_response_for_udp(&query, &response, 512).unwrap();

        assert!(response_is_truncated(&truncated));
        assert_eq!(read_u16(&truncated, 6), Some(0));
        assert_eq!(read_u16(&truncated, 8), Some(0));
        assert_eq!(read_u16(&truncated, 10), Some(0));
        assert!(truncated.len() <= 512);
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
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        record_query(&stats, "ads.example.org", client, true);
        record_blocked(&stats, "ads.example.org", true);

        let current = stats.lock().expect("stats should lock");
        assert_eq!(current.queries, 1);
        assert_eq!(current.blocked, 1);
        assert_eq!(current.query_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.blocked_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.client_requests.get("192.168.1.20"), Some(&1));
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
    fn summarizes_dns_response_for_query_log() {
        let response = a_response("example.org", [1, 2, 3, 4]);
        let summary = summarize_response(&response).expect("response should summarize");

        assert_eq!(summary.code, 0);
        assert_eq!(summary.answer_count, 1);
        assert!(!summary.truncated);
        assert_eq!(summary.answers.len(), 1);
        assert_eq!(summary.answers[0].record_type, TYPE_A);
        assert_eq!(summary.answers[0].value, "1.2.3.4");
        assert_eq!(summary.answers[0].ttl, 60);

        let nxdomain = nxdomain_response("missing.example.org", 300);
        let summary = summarize_response(&nxdomain).expect("nxdomain should summarize");
        assert_eq!(summary.code, RCODE_NXDOMAIN);
        assert_eq!(summary.answer_count, 0);
        assert!(summary.answers.is_empty());
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
        let upstream =
            RuntimeUpstream::new(UpstreamServer::Udp("127.0.0.1:53".parse().unwrap()), &[]);

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
