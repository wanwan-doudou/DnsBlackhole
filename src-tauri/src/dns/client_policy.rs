use std::net::IpAddr;

use crate::config::AppConfig;

use super::ip_network::IpNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientFilteringMode {
    Filter,
    Bypass,
}

pub(crate) struct ClientFilteringDecision<'a> {
    pub(crate) mode: ClientFilteringMode,
    pub(crate) source: Option<&'a str>,
}

pub(crate) struct ClientFilteringPolicies {
    rules: Vec<ClientFilteringRule>,
}

struct ClientFilteringRule {
    network: IpNetwork,
    source: String,
    mode: ClientFilteringMode,
}

impl ClientFilteringPolicies {
    pub(crate) fn from_config(config: &AppConfig) -> Result<Self, String> {
        let rules = config
            .client_filtering_rule_specs()?
            .into_iter()
            .map(|spec| {
                Ok(ClientFilteringRule {
                    network: IpNetwork::parse(&spec.network, "客户端过滤策略")?,
                    source: spec.network,
                    mode: if spec.bypass {
                        ClientFilteringMode::Bypass
                    } else {
                        ClientFilteringMode::Filter
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { rules })
    }

    pub(crate) fn decision(&self, client: IpAddr) -> ClientFilteringDecision<'_> {
        let matched = self
            .rules
            .iter()
            .filter(|rule| rule.network.contains(client))
            .max_by_key(|rule| rule.network.prefix_len());
        ClientFilteringDecision {
            mode: matched.map_or(ClientFilteringMode::Filter, |rule| rule.mode),
            source: matched.map(|rule| rule.source.as_str()),
        }
    }

    pub(crate) fn filtering_enabled(&self, client: IpAddr) -> bool {
        self.decision(client).mode == ClientFilteringMode::Filter
    }
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
}
