use std::{collections::HashMap, net::IpAddr};

use chrono::{Datelike, Local, Timelike};

use crate::config::{AppConfig, ClientPolicyGroupSpec, ClientScheduleSpec};

use super::ip_network::IpNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientFilteringMode {
    Filter,
    Bypass,
}

#[derive(Clone)]
struct ClientPolicyProfile {
    name: String,
    mode: ClientFilteringMode,
    safe_search: bool,
    blocked_services: Vec<String>,
}

pub(crate) struct ClientFilteringDecision<'a> {
    pub(crate) mode: ClientFilteringMode,
    pub(crate) source: Option<&'a str>,
    pub(crate) profile: &'a str,
    profile_data: &'a ClientPolicyProfile,
}

impl ClientFilteringDecision<'_> {
    pub(crate) fn safe_search_target(&self, domain: &str) -> Option<&'static str> {
        self.profile_data
            .safe_search
            .then(|| safe_search_target(domain))
            .flatten()
    }

    pub(crate) fn blocked_service(&self, domain: &str) -> Option<&str> {
        self.profile_data
            .blocked_services
            .iter()
            .find(|service| {
                service_domains(service)
                    .iter()
                    .any(|base| domain_matches(domain, base))
            })
            .map(String::as_str)
    }
}

pub(crate) struct ClientFilteringPolicies {
    rules: Vec<ClientFilteringRule>,
    default_profile: ClientPolicyProfile,
}

struct ClientFilteringRule {
    network: IpNetwork,
    source: String,
    profile: ClientPolicyProfile,
    schedule: Option<ClientScheduleSpec>,
}

impl ClientFilteringPolicies {
    pub(crate) fn from_config(config: &AppConfig) -> Result<Self, String> {
        let mut profiles = config
            .client_policy_group_specs()?
            .into_iter()
            .map(profile_from_spec)
            .map(|profile| (profile.name.clone(), profile))
            .collect::<HashMap<_, _>>();
        profiles.insert(
            "family".into(),
            ClientPolicyProfile {
                name: "family".into(),
                mode: ClientFilteringMode::Filter,
                safe_search: config.family_safe_search,
                blocked_services: config.family_blocked_service_names()?,
            },
        );
        profiles.insert("filter".into(), default_filter_profile());
        profiles.insert(
            "bypass".into(),
            ClientPolicyProfile {
                name: "bypass".into(),
                mode: ClientFilteringMode::Bypass,
                safe_search: false,
                blocked_services: Vec::new(),
            },
        );

        let rules = config
            .client_filtering_rule_specs()?
            .into_iter()
            .map(|spec| {
                let profile = profiles
                    .get(&spec.profile)
                    .cloned()
                    .ok_or_else(|| format!("客户端策略组不存在：{}", spec.profile))?;
                Ok(ClientFilteringRule {
                    network: IpNetwork::parse(&spec.network, "客户端过滤策略")?,
                    source: spec.network,
                    profile,
                    schedule: spec.schedule,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            rules,
            default_profile: default_filter_profile(),
        })
    }

    pub(crate) fn decision(&self, client: IpAddr) -> ClientFilteringDecision<'_> {
        let now = Local::now();
        self.decision_at(
            client,
            now.weekday().num_days_from_monday() as usize,
            (now.hour() * 60 + now.minute()) as u16,
        )
    }

    fn decision_at(
        &self,
        client: IpAddr,
        weekday: usize,
        minute: u16,
    ) -> ClientFilteringDecision<'_> {
        let matched = self
            .rules
            .iter()
            .filter(|rule| {
                rule.network.contains(client)
                    && rule
                        .schedule
                        .is_none_or(|schedule| schedule_is_active(schedule, weekday, minute))
            })
            .max_by_key(|rule| rule.network.prefix_len());
        let profile = matched.map_or(&self.default_profile, |rule| &rule.profile);
        ClientFilteringDecision {
            mode: profile.mode,
            source: matched.map(|rule| rule.source.as_str()),
            profile: &profile.name,
            profile_data: profile,
        }
    }

    #[cfg(test)]
    pub(crate) fn filtering_enabled(&self, client: IpAddr) -> bool {
        self.decision(client).mode == ClientFilteringMode::Filter
    }
}

fn profile_from_spec(spec: ClientPolicyGroupSpec) -> ClientPolicyProfile {
    ClientPolicyProfile {
        name: spec.name,
        mode: if spec.bypass {
            ClientFilteringMode::Bypass
        } else {
            ClientFilteringMode::Filter
        },
        safe_search: spec.safe_search,
        blocked_services: spec.blocked_services,
    }
}

fn default_filter_profile() -> ClientPolicyProfile {
    ClientPolicyProfile {
        name: "filter".into(),
        mode: ClientFilteringMode::Filter,
        safe_search: false,
        blocked_services: Vec::new(),
    }
}

fn schedule_is_active(schedule: ClientScheduleSpec, weekday: usize, minute: u16) -> bool {
    if schedule.start_minute == schedule.end_minute {
        return schedule.weekdays[weekday];
    }
    if schedule.start_minute < schedule.end_minute {
        return schedule.weekdays[weekday]
            && minute >= schedule.start_minute
            && minute < schedule.end_minute;
    }
    if minute >= schedule.start_minute {
        schedule.weekdays[weekday]
    } else if minute < schedule.end_minute {
        schedule.weekdays[(weekday + 6) % 7]
    } else {
        false
    }
}

fn safe_search_target(domain: &str) -> Option<&'static str> {
    const SAFE_SEARCH_TARGETS: &[(&[&str], &str)] = &[
        (
            &[
                "google.com",
                "www.google.com",
                "google.com.hk",
                "www.google.com.hk",
            ],
            "forcesafesearch.google.com",
        ),
        (&["bing.com", "www.bing.com"], "strict.bing.com"),
        (
            &["duckduckgo.com", "www.duckduckgo.com"],
            "safe.duckduckgo.com",
        ),
        (
            &[
                "youtube.com",
                "www.youtube.com",
                "m.youtube.com",
                "youtubei.googleapis.com",
                "youtube.googleapis.com",
                "youtube-nocookie.com",
                "www.youtube-nocookie.com",
            ],
            "restrictmoderate.youtube.com",
        ),
    ];
    SAFE_SEARCH_TARGETS
        .iter()
        .find(|(domains, target)| {
            !domain.eq_ignore_ascii_case(target)
                && domains
                    .iter()
                    .any(|candidate| domain.eq_ignore_ascii_case(candidate))
        })
        .map(|(_, target)| *target)
}

fn service_domains(service: &str) -> &'static [&'static str] {
    match service {
        "youtube" => &[
            "youtube.com",
            "youtu.be",
            "youtube-nocookie.com",
            "googlevideo.com",
            "ytimg.com",
            "youtubei.googleapis.com",
        ],
        "tiktok" => &["tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly"],
        "instagram" => &["instagram.com", "cdninstagram.com"],
        "facebook" => &[
            "facebook.com",
            "facebook.net",
            "fb.com",
            "fbcdn.net",
            "messenger.com",
        ],
        "x" => &["x.com", "twitter.com", "t.co", "twimg.com"],
        "reddit" => &[
            "reddit.com",
            "redd.it",
            "redditmedia.com",
            "redditstatic.com",
        ],
        "twitch" => &["twitch.tv", "twitchcdn.net"],
        "discord" => &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
        ],
        "steam" => &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
        ],
        "epic" => &["epicgames.com", "epicgames.dev"],
        "roblox" => &["roblox.com", "rbxcdn.com"],
        _ => &[],
    }
}

fn domain_matches(domain: &str, base: &str) -> bool {
    domain.eq_ignore_ascii_case(base)
        || domain
            .strip_suffix(base)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_policy_wins() {
        let config = AppConfig {
            client_filtering_rules: concat!(
                "192.168.0.0/16 => bypass\n",
                "192.168.1.0/24 => filter\n",
                "fd00::/8 => bypass"
            )
            .into(),
            ..AppConfig::default()
        };
        let policies = ClientFilteringPolicies::from_config(&config).unwrap();

        assert!(policies.filtering_enabled("192.168.1.42".parse().unwrap()));
        assert!(!policies.filtering_enabled("192.168.2.42".parse().unwrap()));
        assert!(!policies.filtering_enabled("fd12::1".parse().unwrap()));
        assert!(policies.filtering_enabled("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn named_family_policy_and_overnight_schedule_are_applied() {
        let config = AppConfig {
            family_blocked_services: "tiktok,reddit".into(),
            client_filtering_rules: "192.168.1.20 => family @ mon-fri 20:00-07:00".into(),
            ..AppConfig::default()
        };
        let policies = ClientFilteringPolicies::from_config(&config).unwrap();
        let client = "192.168.1.20".parse().unwrap();

        let monday_evening = policies.decision_at(client, 0, 21 * 60);
        assert_eq!(monday_evening.profile, "family");
        assert_eq!(
            monday_evening.blocked_service("www.tiktok.com"),
            Some("tiktok")
        );
        assert_eq!(
            monday_evening.safe_search_target("www.google.com"),
            Some("forcesafesearch.google.com")
        );

        let tuesday_morning = policies.decision_at(client, 1, 6 * 60);
        assert_eq!(tuesday_morning.profile, "family");
        let sunday_morning = policies.decision_at(client, 6, 6 * 60);
        assert_eq!(sunday_morning.profile, "filter");
    }

    #[test]
    fn custom_group_can_block_selected_services() {
        let config = AppConfig {
            client_policy_groups: "study => filter, safe_search, block:youtube|tiktok".into(),
            client_filtering_rules: "10.0.0.8 => study".into(),
            ..AppConfig::default()
        };
        let policies = ClientFilteringPolicies::from_config(&config).unwrap();
        let decision = policies.decision_at("10.0.0.8".parse().unwrap(), 2, 12 * 60);
        assert_eq!(decision.profile, "study");
        assert_eq!(decision.blocked_service("cdn.youtube.com"), Some("youtube"));
        assert_eq!(decision.blocked_service("example.com"), None);
    }
}
