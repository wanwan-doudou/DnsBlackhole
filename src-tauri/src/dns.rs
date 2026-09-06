mod access;
mod cache;
mod client_policy;
mod diagnostics;
mod filter_runtime;
mod ip_network;
mod local_reverse;
mod monitoring;
mod protocol;
mod rewrites;
mod rule_cache;
mod rules;
pub(crate) mod security_events;
mod server;
pub(crate) mod stats;
mod task_pool;
mod upstream;
mod upstream_routes;
mod worker;

pub(crate) use diagnostics::{DnsDiagnosticReport, run_dns_diagnostic};
pub(crate) use filter_runtime::{
    FilterRuntime, build_filter_runtime_with_rules, current_filter_runtime, replace_filter_runtime,
};
pub(crate) use protocol::{DnsResponseAnswer, DnsResponseSummary};
#[cfg(test)]
pub(crate) use rule_cache::{RULE_LOAD_TEST_GUARD, forget_active_rules};
pub(crate) use rule_cache::{RuleLoadSource, clear_rule_cache, load_or_compile_rules};
pub use rules::{RuleAnalysis, RuleSummary, analyze_rules, summarize_rules};
pub(crate) use security_events::flush_security_events;
pub use server::DnsServer;
pub(crate) use stats::apply_cache_stats;
pub use stats::{
    DnsStats, DnsTransport, RuntimeStatus, SecurityEvent, SecurityEventType, TrafficBucket,
    UpstreamLatencyStat, UpstreamRequestStat, empty_status,
};
pub(crate) use stats::{SECURITY_EVENT_CAPACITY, restore_security_events};

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use crate::config::UpstreamServer;

    use crate::config::{AppConfig, BlockingMode};

    use super::{
        analyze_rules,
        cache::{DnsCache, DnsCacheConfig, QueryCacheKey, cache_ttl_seconds},
        protocol::{
            BlockingPolicy, RCODE_NXDOMAIN, RCODE_REFUSED, TYPE_A, TYPE_ANY, TYPE_CNAME, TYPE_SOA,
            build_block_response, build_dnsrewrite_response, build_error_response,
            build_rewrite_response, extract_response_ips, normalize_cached_response, parse_query,
            parse_question, prepare_cached_response, read_u16, response_is_truncated,
            response_min_record_ttl, response_security_data, summarize_response,
            truncate_response_for_udp, udp_payload_size, validate_response_for_query,
        },
        rewrites::compile_rewrites,
        rules::{
            DnsRewriteAction, compile_domain_set, compile_rules, custom_rules_have_badfilter,
            summarize_rules,
        },
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

    fn rewrite_action(rule: &str, domain: &str, qtype: u16) -> Option<DnsRewriteAction> {
        compile_rules(rule)
            .blocking_match(domain, qtype)
            .and_then(|matched| matched.dnsrewrite)
    }

    #[test]
    fn dnsrewrite_short_forms_cover_ip_cname_and_rcode() {
        assert_eq!(
            rewrite_action("||a.example^$dnsrewrite=1.2.3.4", "a.example", TYPE_A),
            Some(DnsRewriteAction::Address("1.2.3.4".parse().expect("ipv4")))
        );
        assert_eq!(
            rewrite_action("||b.example^$dnsrewrite=2001:db8::1", "b.example", TYPE_A),
            Some(DnsRewriteAction::Address(
                "2001:db8::1".parse().expect("ipv6")
            ))
        );
        assert_eq!(
            rewrite_action(
                "||c.example^$dnsrewrite=target.example",
                "c.example",
                TYPE_A
            ),
            Some(DnsRewriteAction::Cname("target.example".into()))
        );
        assert_eq!(
            rewrite_action("||d.example^$dnsrewrite=REFUSED", "d.example", TYPE_A),
            Some(DnsRewriteAction::RCode(RCODE_REFUSED))
        );
        assert_eq!(
            rewrite_action("||e.example^$dnsrewrite=NXDOMAIN", "e.example", TYPE_A),
            Some(DnsRewriteAction::RCode(RCODE_NXDOMAIN))
        );
    }

    #[test]
    fn dnsrewrite_full_form_preserves_value_case_and_type() {
        assert_eq!(
            rewrite_action(
                "|txt.example^$dnsrewrite=NOERROR;TXT;Hello_World",
                "txt.example",
                16
            ),
            Some(DnsRewriteAction::Record {
                rtype: 16,
                value: "Hello_World".into()
            })
        );
        assert_eq!(
            rewrite_action(
                "||mx.example^$dnsrewrite=NOERROR;MX;10 mail.example.com",
                "mx.example",
                15
            ),
            Some(DnsRewriteAction::Record {
                rtype: 15,
                value: "10 mail.example.com".into()
            })
        );
        assert_eq!(
            rewrite_action(
                "||ip.example^$dnsrewrite=NOERROR;A;9.9.9.9",
                "ip.example",
                TYPE_A
            ),
            Some(DnsRewriteAction::Address("9.9.9.9".parse().expect("ipv4")))
        );
    }

    #[test]
    fn invalid_dnsrewrite_values_are_reported_as_unsupported() {
        // 非 NOERROR 不能带记录类型；不支持的记录类型宁可报不支持也不返回错误报文。
        for rule in [
            "||bad.example^$dnsrewrite=NXDOMAIN;A;1.2.3.4",
            "||bad.example^$dnsrewrite=NOERROR;CAA;0 issue \"ca.example\"",
            "||bad.example^$dnsrewrite=",
            "@@||bad.example^$dnsrewrite=1.2.3.4",
        ] {
            let analysis = analyze_rules(rule);
            assert_eq!(
                analysis.summary.ignored_unsupported_rules, 1,
                "规则应被判定为不支持：{rule}"
            );
            assert_eq!(analysis.summary.block_rules, 0, "规则不应生效：{rule}");
        }
    }

    #[test]
    fn dnsrewrite_modifier_combines_with_important_and_allowlist() {
        let rules = compile_rules(concat!(
            "@@||shop.example^
",
            "||shop.example^$important,dnsrewrite=127.0.0.1
",
        ));
        let matched = rules
            .blocking_match("shop.example", TYPE_A)
            .expect("important 规则应覆盖 allowlist");
        assert!(matched.important_overrode);
        assert_eq!(
            matched.dnsrewrite,
            Some(DnsRewriteAction::Address(
                "127.0.0.1".parse().expect("ipv4")
            ))
        );
    }

    #[test]
    fn dnsrewrite_response_returns_requested_record() {
        let policy = BlockingPolicy::default();
        let query = typed_query("txt.example", 16);
        let question = parse_question(&query).expect("question should parse");
        let response = build_dnsrewrite_response(
            &query,
            &question,
            &DnsRewriteAction::Record {
                rtype: 16,
                value: "hello".into(),
            },
            &policy,
        );
        assert_eq!(read_u16(&response, 6), Some(1), "应带 1 条 answer");
        assert!(
            response.windows(5).any(|window| window == b"hello"),
            "TXT 内容应出现在 rdata 中"
        );

        // 查询类型与重写类型不一致时只返回空 NOERROR，不返回类型错配的记录。
        let a_query = typed_query("txt.example", TYPE_A);
        let a_question = parse_question(&a_query).expect("question should parse");
        let a_response = build_dnsrewrite_response(
            &a_query,
            &a_question,
            &DnsRewriteAction::Record {
                rtype: 16,
                value: "hello".into(),
            },
            &policy,
        );
        assert_eq!(read_u16(&a_response, 6), Some(0), "类型不匹配应为空应答");
        assert_eq!(a_response[3] & 0x0f, 0, "应为 NOERROR");
    }

    #[test]
    fn dnsrewrite_rcode_and_address_responses_match_the_action() {
        let policy = BlockingPolicy::default();
        let query = typed_query("a.example", TYPE_A);
        let question = parse_question(&query).expect("question should parse");

        let refused = build_dnsrewrite_response(
            &query,
            &question,
            &DnsRewriteAction::RCode(RCODE_REFUSED),
            &policy,
        );
        assert_eq!(refused[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(read_u16(&refused, 6), Some(0));

        let nxdomain = build_dnsrewrite_response(
            &query,
            &question,
            &DnsRewriteAction::RCode(RCODE_NXDOMAIN),
            &policy,
        );
        assert_eq!(nxdomain[3] & 0x0f, RCODE_NXDOMAIN);
        // NXDOMAIN 复用负缓存 SOA 路径，authority 段必须带一条记录。
        assert_eq!(read_u16(&nxdomain, 8), Some(1));

        let address = build_dnsrewrite_response(
            &query,
            &question,
            &DnsRewriteAction::Address("9.9.9.9".parse().expect("ipv4")),
            &policy,
        );
        assert_eq!(read_u16(&address, 6), Some(1));
        assert!(address.ends_with(&[9, 9, 9, 9]));
    }

    #[test]
    fn dnsrewrite_combines_records_across_layers_and_beats_normal_rules() {
        let base = Arc::new(compile_rules(
            "||example.com^$important\n@@||www.example.com^$important\n||example.com^$dnsrewrite=1.2.3.4",
        ));
        let rules = super::rules::CompiledRules::with_custom_layer(
            base,
            "||www.example.com^$dnsrewrite=5.6.7.8\n||www.example.com^$dnsrewrite=2001:db8::1\n||www.example.com^$dnsrewrite=1.2.3.4",
        );
        for (qtype, expected) in [(1, 2), (28, 1), (16, 0), (255, 3)] {
            let query = typed_query("www.example.com", qtype);
            let question = parse_question(&query).unwrap();
            let matched = rules.blocking_match(&question.domain, qtype).unwrap();
            let response = build_dnsrewrite_response(
                &query,
                &question,
                matched.dnsrewrite.as_ref().unwrap(),
                &BlockingPolicy::default(),
            );
            assert_eq!(read_u16(&response, 6), Some(expected), "qtype={qtype}");
            assert_eq!(response[3] & 0xf, 0);
            assert!(summarize_response(&response).is_some());
        }
    }

    #[test]
    fn dnsrewrite_cache_roundtrip_and_custom_merge_preserve_matching() {
        let mut rules = compile_rules("||example.com^");
        rules.merge_custom_rules("||example.com^$dnsrewrite=1.2.3.4");
        let mut encoded = Vec::new();
        postcard::to_io(&rules, &mut encoded).unwrap();
        let restored: super::rules::CompiledRules = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(
            restored
                .blocking_match("example.com", 1)
                .unwrap()
                .dnsrewrite,
            Some(DnsRewriteAction::Address("1.2.3.4".parse().unwrap()))
        );
    }

    #[test]
    fn dnsrewrite_respects_constraints_and_whole_response_priority() {
        let rules = compile_rules(
            "||example.com^$dnsrewrite=1.2.3.4,dnstype=A,denyallow=skip.example.com\n||example.com^$dnsrewrite=2001:db8::1,dnstype=AAAA",
        );
        assert!(rules.blocking_match("skip.example.com", 1).is_none());
        assert!(matches!(
            rules
                .blocking_match("www.example.com", 28)
                .unwrap()
                .dnsrewrite,
            Some(DnsRewriteAction::Address(IpAddr::V6(_)))
        ));
        assert!(rules.blocking_match("www.example.com", 16).is_none());
        for prefix in ["NOERROR", "REFUSED", "target.example"] {
            let rules =
                format!("||example.com^$dnsrewrite=1.2.3.4\n||example.com^$dnsrewrite={prefix}");
            let action = rewrite_action(&rules, "example.com", 1).unwrap();
            assert!(!matches!(
                action,
                DnsRewriteAction::Address(_) | DnsRewriteAction::Multiple(_)
            ));
        }
    }

    #[test]
    fn dnsrewrite_rejects_invalid_record_data_before_serving() {
        for value in [
            "NOERROR;MX;not-a-priority mail.example",
            "NOERROR;SRV;1 2 70000 target.example",
            "NOERROR;PTR;a..example",
        ] {
            assert_eq!(
                analyze_rules(&format!("||example.com^$dnsrewrite={value}"))
                    .summary
                    .ignored_unsupported_rules,
                1
            );
        }
        let oversized = format!(
            "||example.com^$dnsrewrite=NOERROR;TXT;{}",
            "a".repeat(65_535)
        );
        assert_eq!(
            analyze_rules(&oversized).summary.ignored_unsupported_rules,
            1
        );
    }

    #[test]
    fn dnsrewrite_txt_wire_boundaries_never_wrap_lengths() {
        let query = typed_query("txt.example", 16);
        let question = parse_question(&query).unwrap();
        for size in [255, 256, 65_240, 65_279, 65_535] {
            let action = DnsRewriteAction::Record {
                rtype: 16,
                value: "a".repeat(size).into(),
            };
            let response =
                build_dnsrewrite_response(&query, &question, &action, &BlockingPolicy::default());
            assert!(response.len() <= usize::from(u16::MAX));
            let valid =
                size + size.div_ceil(255) + question.question_end + 12 <= usize::from(u16::MAX);
            assert_eq!(response[3] & 0xf, if valid { 0 } else { 2 }, "size={size}");
            if valid {
                let data_start = question.question_end + 12;
                assert_eq!(
                    usize::from(read_u16(&response, data_start - 2).unwrap()),
                    response.len() - data_start
                );
            } else {
                assert_eq!(read_u16(&response, 6), Some(0));
            }
        }
        let action = DnsRewriteAction::Multiple(
            vec![
                DnsRewriteAction::Record {
                    rtype: 16,
                    value: "a".repeat(40_000).into(),
                },
                DnsRewriteAction::Record {
                    rtype: 16,
                    value: "b".repeat(40_000).into(),
                },
            ]
            .into(),
        );
        let response =
            build_dnsrewrite_response(&query, &question, &action, &BlockingPolicy::default());
        assert_eq!(response[3] & 0xf, 2);
        assert_eq!(read_u16(&response, 6), Some(0));
    }

    #[test]
    fn rule_analysis_reports_exact_ignored_lines() {
        let analysis = analyze_rules(concat!(
            "||ads.example^\n",
            "/tracker\\d+/\n",
            "||valid.example^$third-party\n",
            "bad domain\n",
            "@@||safe.example^\n",
        ));

        assert_eq!(analysis.summary.block_rules, 1);
        assert_eq!(analysis.summary.allow_rules, 1);
        assert_eq!(analysis.diagnostics.len(), 3);
        assert_eq!(analysis.diagnostics[0].line, 2);
        assert_eq!(analysis.diagnostics[0].reason, "regex");
        assert_eq!(analysis.diagnostics[1].line, 3);
        assert_eq!(analysis.diagnostics[1].reason, "unsupported");
        assert_eq!(analysis.diagnostics[2].line, 4);
        assert_eq!(analysis.diagnostics[2].severity, "error");
    }

    /// 增量合并自定义规则必须和"清单+自定义"整体编译产生完全相同的判定与统计，
    /// 否则改动自定义规则会悄悄改变拦截行为。
    #[test]
    fn incremental_merge_matches_full_compilation() {
        let remote = concat!(
            "! dnsblackhole-source:\"清单A\"\n",
            "||ads.example^\n",
            "@@||safe.example^\n",
            "||dup.example^\n",
            "||typed.example^$dnstype=A\n",
            "||killed.example^$important,badfilter\n",
            "||parent.example^\n",
            "0.0.0.0 hostlist.example\n",
        );
        let custom = concat!(
            "||custom.example^\n",
            "@@||ads.example^\n",
            "||safe.example^$important\n",
            "||dup.example^\n",
            "||killed.example^$important\n",
            "0.0.0.0 customhost.example\n",
            "||branch.example^$denyallow=keep.branch.example\n",
            "||sub.parent.example^\n",
            "! 注释行\n",
            "/regex.not.supported/\n",
            "bad domain\n",
        );

        let full = compile_rules(&format!(
            "{remote}! dnsblackhole-source:\"自定义规则\"\n{custom}"
        ));
        let mut merged = compile_rules(remote);
        merged.merge_custom_rules(custom);
        let layered = super::rules::CompiledRules::with_custom_layer(
            std::sync::Arc::new(compile_rules(remote)),
            custom,
        );

        let probes = [
            ("ads.example", TYPE_A),
            ("sub.ads.example", TYPE_A),
            ("safe.example", TYPE_A),
            ("cdn.safe.example", TYPE_A),
            ("dup.example", TYPE_A),
            ("custom.example", TYPE_A),
            ("typed.example", TYPE_A),
            ("typed.example", 16),
            ("killed.example", TYPE_A),
            ("hostlist.example", TYPE_A),
            ("customhost.example", TYPE_A),
            ("branch.example", TYPE_A),
            ("keep.branch.example", TYPE_A),
            ("sub.parent.example", TYPE_A),
            ("unrelated.example", TYPE_A),
        ];
        for (implementation, actual_rules) in [("原地合并", &merged), ("分层共享", &layered)]
        {
            for (domain, qtype) in probes {
                match (
                    full.blocking_match(domain, qtype),
                    actual_rules.blocking_match(domain, qtype),
                ) {
                    (None, None) => {}
                    (Some(expected), Some(actual)) => {
                        assert_eq!(
                            expected.rule, actual.rule,
                            "{implementation}: {domain} 规则原文应一致"
                        );
                        assert_eq!(
                            expected.source, actual.source,
                            "{implementation}: {domain} 来源应一致"
                        );
                        assert_eq!(
                            expected.rule_type, actual.rule_type,
                            "{implementation}: {domain} 类型应一致"
                        );
                        assert_eq!(
                            expected.important_overrode, actual.important_overrode,
                            "{implementation}: {domain} important 覆盖标记应一致"
                        );
                        assert_eq!(
                            expected.allowlist_rule, actual.allowlist_rule,
                            "{implementation}: {domain} 放行规则应一致"
                        );
                    }
                    (expected, actual) => panic!(
                        "{implementation}: {domain} 判定不一致：整体编译命中={} / 增量命中={}",
                        expected.is_some(),
                        actual.is_some()
                    ),
                }
            }
        }

        let expected = full.summary();
        let actual = merged.summary();
        assert_eq!(expected.block_rules, actual.block_rules, "拦截条数应一致");
        assert_eq!(expected.allow_rules, actual.allow_rules, "放行条数应一致");
        assert_eq!(
            expected.ignored_rules, actual.ignored_rules,
            "忽略条数应一致"
        );
        assert_eq!(expected.ignored_comment_rules, actual.ignored_comment_rules);
        assert_eq!(expected.ignored_regex_rules, actual.ignored_regex_rules);
        assert_eq!(expected.ignored_invalid_rules, actual.ignored_invalid_rules);
        assert_eq!(expected, layered.summary(), "分层共享的摘要也应一致");
    }

    #[test]
    fn list_badfilter_still_disables_merged_custom_rule() {
        let remote = "! dnsblackhole-source:\"清单A\"\n||x.example^$important,badfilter";
        let custom = "||x.example^$important";

        let mut merged = compile_rules(remote);
        merged.merge_custom_rules(custom);

        // 清单里的 badfilter 必须继续压制自定义规则里的同一条
        assert!(!merged.is_blocked("x.example", TYPE_A));
        assert!(
            !compile_rules(&format!(
                "{remote}\n! dnsblackhole-source:\"自定义规则\"\n{custom}"
            ))
            .is_blocked("x.example", TYPE_A)
        );
    }

    #[test]
    fn detects_badfilter_in_custom_rules() {
        assert!(custom_rules_have_badfilter("||x.example^$badfilter"));
        assert!(custom_rules_have_badfilter(
            "||keep.example^\n||x.example^$important,badfilter"
        ));
        assert!(!custom_rules_have_badfilter("||x.example^$important"));
        assert!(!custom_rules_have_badfilter("! 注释\n||plain.example^"));
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
            blocking_response_ttl: 17,
            ..AppConfig::default()
        });
        let response = build_block_response(&query, &question, &nxdomain_policy);
        assert_eq!(response[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(read_u16(&response, 6), Some(0));
        assert_eq!(read_u16(&response, 8), Some(1));
        assert_eq!(response_min_record_ttl(&response), Some(17));
        assert_eq!(&response[response.len() - 4..], &17_u32.to_be_bytes());

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
    fn query_context_isolates_cache_and_bypasses_response_affecting_edns_options() {
        let query = a_query("example.org");
        let parsed = parse_query(&query).expect("query should parse");
        let base_key = QueryCacheKey::from_query(&parsed).expect("plain query should be cacheable");
        assert_ne!(
            base_key.clone().with_route(Some("filter")),
            base_key.clone().with_route(Some("filter-bypass")),
        );

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
    fn transport_only_edns_options_stay_cacheable() {
        let plain = edns_query("example.org", 1232, false, &[]);
        let plain_key = QueryCacheKey::from_query(&parse_query(&plain).unwrap())
            .expect("plain EDNS query should be cacheable");

        // Keepalive / Padding 可以在移除 OPT 后和无选项查询共用同一条缓存
        for options in [vec![0, 11, 0, 2, 0x00, 0x64], vec![0, 12, 0, 4, 0, 0, 0, 0]] {
            let query = edns_query("example.org", 1232, false, &options);
            let parsed = parse_query(&query).expect("query should parse");
            assert!(parsed.cache_safe, "选项 {options:?} 不应禁用缓存");
            assert_eq!(
                plain_key,
                QueryCacheKey::from_query(&parsed).expect("should be cacheable"),
                "选项 {options:?} 不应产生独立缓存键",
            );
        }

        // Cookie 响应必须由客户端校验，不能用无 Cookie 的缓存响应代替。
        let cookie =
            parse_query(&edns_query("example.org", 1232, false, &cookie_option())).unwrap();
        assert!(!cookie.cache_safe);
        assert!(QueryCacheKey::from_query(&cookie).is_none());

        // 混入 ECS（会改变应答内容）时仍然必须放弃缓存
        let mut mixed = vec![0, 12, 0, 4, 0, 0, 0, 0];
        mixed.extend_from_slice(&[0, 8, 0, 0]);
        let ecs = parse_query(&edns_query("example.org", 1232, false, &mixed)).unwrap();
        assert!(!ecs.cache_safe);

        // 截断的选项头必须按不可缓存处理，不能读越界
        let truncated = parse_query(&edns_query("example.org", 1232, false, &[0, 10, 0])).unwrap();
        assert!(!truncated.cache_safe);
        // 声明长度超过实际 rdata 的选项同样不可缓存
        let overflowing = parse_query(&edns_query(
            "example.org",
            1232,
            false,
            &[0, 10, 0, 9, 1, 2],
        ))
        .unwrap();
        assert!(!overflowing.cache_safe);
    }

    #[test]
    fn cookie_bearing_queries_bypass_cache() {
        let client_cookie = cookie_option();
        let client_query = edns_query("example.org", 1232, false, &client_cookie);
        assert!(QueryCacheKey::from_query(&parse_query(&client_query).unwrap()).is_none());

        // 已知 server cookie 的后续查询也必须直达上游，不能被旧缓存响应截获。
        let mut known_server_cookie = client_cookie;
        known_server_cookie[2..4].copy_from_slice(&16_u16.to_be_bytes());
        known_server_cookie.extend_from_slice(&[0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]);
        let retry_query = edns_query("example.org", 1232, false, &known_server_cookie);
        assert!(QueryCacheKey::from_query(&parse_query(&retry_query).unwrap()).is_none());
    }

    #[test]
    fn cache_key_ignores_client_udp_payload_size() {
        // 同一问题的应答与客户端声明的 UDP 大小无关，出站尺寸由 send_dns_response 单独截断。
        // 一旦入键，混合客户端的局域网会把同一域名拆成多份，每种客户端各吃一次冷 miss。
        let keys: Vec<_> = [512, 1232, 4096]
            .into_iter()
            .map(|size| {
                let query = edns_query("example.org", size, false, &[]);
                assert_eq!(udp_payload_size(&query), usize::from(size));
                QueryCacheKey::from_query(&parse_query(&query).unwrap()).unwrap()
            })
            .collect();
        assert_eq!(keys[0], keys[1]);
        assert_eq!(keys[1], keys[2]);

        // 但"是否使用 EDNS"必须继续分键：RFC 6891 §6.1.1 规定请求没有 OPT 时
        // 响应也不能带 OPT，两类客户端不能共用同一条缓存条目。
        let without_edns =
            QueryCacheKey::from_query(&parse_query(&a_query("example.org")).unwrap()).unwrap();
        assert_ne!(keys[1], without_edns);

        // DO 位真的会改变应答内容，必须继续分键
        let with_do = QueryCacheKey::from_query(
            &parse_query(&edns_query("example.org", 1232, true, &[])).unwrap(),
        )
        .unwrap();
        assert_ne!(keys[1], with_do);
    }

    #[test]
    fn cached_response_drops_opt_and_rebuilds_it_for_current_query() {
        let mut response = a_response("example.org", [1, 2, 3, 4]);
        response[11] = 1; // ARCOUNT
        response.push(0);
        response.extend_from_slice(&41_u16.to_be_bytes());
        response.extend_from_slice(&1232_u16.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        let cookie = cookie_option();
        response.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        response.extend_from_slice(&cookie);

        let original_len = response.len();
        assert!(normalize_cached_response(&mut response));
        assert_eq!(response.len(), original_len - cookie.len() - 11);
        assert_eq!(read_u16(&response, 10), Some(0), "缓存中不应保留 OPT");
        assert_eq!(response_min_record_ttl(&response), Some(60));
        assert!(
            !response
                .windows(8)
                .any(|w| w == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            "缓存条目里不能残留任何客户端 cookie",
        );

        let query = edns_query("example.org", 512, true, &[]);
        let prepared = prepare_cached_response(&response, &query, 30).unwrap();
        assert_eq!(read_u16(&prepared, 10), Some(1));
        assert_eq!(response_min_record_ttl(&prepared), Some(30));
        assert_eq!(
            &prepared[prepared.len() - 11..],
            &[0, 0, 41, 0x02, 0x00, 0, 0, 0x80, 0, 0, 0],
            "OPT 应使用当前请求的 UDP 大小和 DO 位重建",
        );

        // 没有 OPT 的响应无需改动，直接可缓存
        let mut plain = a_response("example.org", [1, 2, 3, 4]);
        let before = plain.clone();
        assert!(normalize_cached_response(&mut plain));
        assert_eq!(plain, before);
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
    fn extracts_cname_targets_and_private_addresses_from_response_sections() {
        let domain = "www.example.org";
        let target = "tracker.blocked.test";
        let mut response = typed_query(domain, TYPE_A);
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response[10..12].copy_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        let target_start = response.len();
        response.extend_from_slice(&0_u16.to_be_bytes());
        let data_start = response.len();
        append_dns_name(&mut response, target);
        let data_len = (response.len() - data_start) as u16;
        response[target_start..target_start + 2].copy_from_slice(&data_len.to_be_bytes());
        append_dns_name(&mut response, target);
        response.extend_from_slice(&TYPE_A.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[192, 168, 1, 20]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&65_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&11_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[10, 0, 0, 9]);

        let data = response_security_data(&response).expect("response should parse");
        assert_eq!(data.cname_targets, vec![target]);
        assert_eq!(
            data.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
            ]
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
            optimistic_max_stale_seconds: 12 * 3600,
            prefetch_enabled: false,
            prefetch_hit_threshold: 10,
        };
        let mut cache = DnsCache::from_config(config).expect("cache should build");

        cache.insert(key.clone(), a_response("example.org", [1, 2, 3, 4]), 100);
        let mut next_query = query.clone();
        next_query[0] = 0xab;
        next_query[1] = 0xcd;
        let raw_hit = cache.lookup(&key, 130).expect("cache should hit");
        let next_hit = cache.lookup(&key, 130).expect("cache should hit again");
        assert!(Arc::ptr_eq(&raw_hit.response, &next_hit.response));
        let response = prepare_cached_response(&raw_hit.response, &next_query, raw_hit.ttl)
            .expect("cached response should prepare");

        assert!(raw_hit.refresh_reason.is_none());
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
            optimistic_max_stale_seconds: 12 * 3600,
            prefetch_enabled: false,
            prefetch_hit_threshold: 10,
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
        let _probe_guard = super::upstream::HALF_OPEN_PROBE_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    /// 构造带 EDNS OPT 的查询。`options` 是 OPT rdata 的原始字节。
    fn edns_query(domain: &str, udp_size: u16, dnssec_ok: bool, options: &[u8]) -> Vec<u8> {
        let mut packet = a_query(domain);
        packet[11] = 1; // ARCOUNT
        packet.push(0); // OPT 的 owner 必须是根
        packet.extend_from_slice(&41_u16.to_be_bytes());
        packet.extend_from_slice(&udp_size.to_be_bytes());
        packet.extend_from_slice(&if dnssec_ok { 0x0000_8000_u32 } else { 0 }.to_be_bytes());
        packet.extend_from_slice(&(options.len() as u16).to_be_bytes());
        packet.extend_from_slice(options);
        packet
    }

    /// RFC 7873 的 8 字节 client cookie，dig / kdig / BIND / Unbound 默认都会带。
    fn cookie_option() -> Vec<u8> {
        let mut option = vec![0, 10, 0, 8];
        option.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        option
    }

    fn append_dns_name(packet: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
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

/// 基准测试用的内部访问层。只在 `bench` feature 下编译，正式产物不包含。
/// 这里不复制任何逻辑，只是把 `pub(crate)` 的热路径包一层给外部基准 crate 调用。
#[cfg(feature = "bench")]
pub mod bench_support {
    use std::sync::Arc;

    use crate::config::AppConfig;

    use super::{
        cache::{
            DnsCacheConfig, DnsCacheStore, QueryCacheKey, insert_cached_response,
            lookup_cached_response,
        },
        protocol::{BlockingPolicy, build_block_response as build_block, parse_query},
        rules::{CompiledRules, compile_rules as compile},
        stats::current_second,
    };

    pub struct BenchRules(CompiledRules);

    pub struct BenchCache {
        store: Option<Arc<DnsCacheStore>>,
        config: DnsCacheConfig,
    }

    pub fn compile_rules(raw: &str) -> BenchRules {
        BenchRules(compile(raw))
    }

    pub fn is_blocked(rules: &BenchRules, domain: &str, qtype: u16) -> bool {
        rules.0.blocking_match(domain, qtype).is_some()
    }

    pub fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
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

    pub fn parse_query_len(packet: &[u8]) -> Option<usize> {
        parse_query(packet)
            .ok()
            .map(|parsed| parsed.question.question_end)
    }

    pub fn build_block_response(packet: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_query(packet).ok()?;
        Some(build_block(
            packet,
            &parsed.question,
            &BlockingPolicy::default(),
        ))
    }

    pub fn build_cache(config: &AppConfig) -> Option<BenchCache> {
        let cache_config = DnsCacheConfig::from_config(config);
        let store = DnsCacheStore::from_config(cache_config.clone(), 64).map(Arc::new);
        store.is_some().then_some(BenchCache {
            store,
            config: cache_config,
        })
    }

    fn cache_key(packet: &[u8]) -> Option<QueryCacheKey> {
        QueryCacheKey::from_query(&parse_query(packet).ok()?)
    }

    pub fn cache_insert(cache: &BenchCache, packet: &[u8], response: Vec<u8>) {
        let Some(key) = cache_key(packet) else {
            return;
        };
        insert_cached_response(
            &cache.store,
            Some(&cache.config),
            key,
            response,
            current_second(),
        );
    }

    pub fn cache_lookup(cache: &BenchCache, packet: &[u8]) -> bool {
        let Some(key) = cache_key(packet) else {
            return false;
        };
        lookup_cached_response(&cache.store, &key, packet, current_second()).is_some()
    }
}
