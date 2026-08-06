use std::{
    net::IpAddr,
    sync::{Arc, atomic::AtomicUsize},
};

use crate::config::{AppConfig, ClientUpstreamRuleSpec, DomainUpstreamRuleSpec};

use super::upstream::{RuntimeUpstream, build_runtime_upstreams_with_dnssec};

pub(crate) struct RouteUpstreamPool {
    key: String,
    pub(crate) upstreams: Vec<RuntimeUpstream>,
    pub(crate) next_upstream: AtomicUsize,
}

pub(crate) struct UpstreamRoutes {
    domains: Vec<DomainRoute>,
    clients: Vec<ClientRoute>,
}

struct DomainRoute {
    pattern: String,
    include_subdomains: bool,
    pool: Arc<RouteUpstreamPool>,
}

struct ClientRoute {
    network: IpNetwork,
    pool: Arc<RouteUpstreamPool>,
}

#[derive(Clone, Copy)]
struct IpNetwork {
    family: IpFamily,
    network: u128,
    prefix_len: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl UpstreamRoutes {
    pub(crate) fn from_config(config: &AppConfig) -> Result<Self, String> {
        let bootstrap = config.bootstrap_servers()?;
        let domains = config
            .domain_upstream_rule_specs()?
            .into_iter()
            .map(|spec| build_domain_route(spec, &bootstrap, config.dnssec_enabled))
            .collect();
        let clients = config
            .client_upstream_rule_specs()?
            .into_iter()
            .map(|spec| build_client_route(spec, &bootstrap, config.dnssec_enabled))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { domains, clients })
    }

    pub(crate) fn select(&self, domain: &str, client: IpAddr) -> Option<Arc<RouteUpstreamPool>> {
        let client_route = self
            .clients
            .iter()
            .filter(|route| route.network.contains(client))
            .max_by_key(|route| route.network.prefix_len);
        if let Some(route) = client_route {
            return Some(Arc::clone(&route.pool));
        }

        self.domains
            .iter()
            .filter(|route| route.matches(domain))
            .max_by_key(|route| (route.pattern.len(), !route.include_subdomains))
            .map(|route| Arc::clone(&route.pool))
    }
}

impl RouteUpstreamPool {
    pub(crate) fn key(&self) -> &str {
        &self.key
    }
}

impl DomainRoute {
    fn matches(&self, domain: &str) -> bool {
        domain == self.pattern
            || (self.include_subdomains
                && domain
                    .strip_suffix(&self.pattern)
                    .is_some_and(|prefix| prefix.ends_with('.')))
    }
}

impl IpNetwork {
    fn parse(value: &str) -> Result<Self, String> {
        let (ip, prefix_len) = if let Some((ip, prefix_len)) = value.split_once('/') {
            (
                ip.parse::<IpAddr>()
                    .map_err(|_| format!("客户端上游策略 IP 无效：{ip}"))?,
                prefix_len
                    .parse::<u8>()
                    .map_err(|_| format!("客户端上游策略前缀无效：{prefix_len}"))?,
            )
        } else {
            let ip = value
                .parse::<IpAddr>()
                .map_err(|_| format!("客户端上游策略 IP 无效：{value}"))?;
            let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
            (ip, prefix_len)
        };
        let (family, bits, raw) = ip_parts(ip);
        if prefix_len > bits {
            return Err(format!("客户端上游策略前缀长度无效：{value}"));
        }
        Ok(Self {
            family,
            network: prefix_network(raw, bits, prefix_len),
            prefix_len,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let (family, bits, raw) = ip_parts(ip);
        family == self.family && prefix_network(raw, bits, self.prefix_len) == self.network
    }
}

fn build_domain_route(
    spec: DomainUpstreamRuleSpec,
    bootstrap: &[std::net::SocketAddr],
    dnssec_enabled: bool,
) -> DomainRoute {
    let key = format!(
        "domain:{}{}",
        if spec.include_subdomains { "*." } else { "" },
        spec.pattern
    );
    DomainRoute {
        pattern: spec.pattern,
        include_subdomains: spec.include_subdomains,
        pool: Arc::new(RouteUpstreamPool {
            key,
            upstreams: build_runtime_upstreams_with_dnssec(
                spec.upstreams,
                bootstrap,
                dnssec_enabled,
            ),
            next_upstream: AtomicUsize::new(0),
        }),
    }
}

fn build_client_route(
    spec: ClientUpstreamRuleSpec,
    bootstrap: &[std::net::SocketAddr],
    dnssec_enabled: bool,
) -> Result<ClientRoute, String> {
    Ok(ClientRoute {
        network: IpNetwork::parse(&spec.network)?,
        pool: Arc::new(RouteUpstreamPool {
            key: format!("client:{}", spec.network),
            upstreams: build_runtime_upstreams_with_dnssec(
                spec.upstreams,
                bootstrap,
                dnssec_enabled,
            ),
            next_upstream: AtomicUsize::new(0),
        }),
    })
}

fn ip_parts(ip: IpAddr) -> (IpFamily, u8, u128) {
    match ip {
        IpAddr::V4(ip) => (IpFamily::V4, 32, u32::from(ip) as u128),
        IpAddr::V6(ip) => (IpFamily::V6, 128, u128::from(ip)),
    }
}

fn prefix_network(value: u128, bits: u8, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    let shift = u32::from(bits - prefix_len);
    (value >> shift) << shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_routes_take_priority_and_use_longest_prefix() {
        let config = AppConfig {
            domain_upstream_rules: "*.example.com => 1.1.1.1".into(),
            client_upstream_rules: "192.168.0.0/16 => 8.8.8.8\n192.168.1.0/24 => 9.9.9.9".into(),
            ..AppConfig::default()
        };
        let routes = UpstreamRoutes::from_config(&config).expect("分流配置应有效");
        let route = routes
            .select("www.example.com", "192.168.1.8".parse().unwrap())
            .expect("应命中客户端规则");
        assert_eq!(route.key(), "client:192.168.1.0/24");
    }

    #[test]
    fn wildcard_domain_route_matches_base_and_subdomains() {
        let config = AppConfig {
            domain_upstream_rules: "*.example.com => 1.1.1.1".into(),
            ..AppConfig::default()
        };
        let routes = UpstreamRoutes::from_config(&config).expect("分流配置应有效");
        let client = "127.0.0.1".parse().unwrap();
        assert!(routes.select("example.com", client).is_some());
        assert!(routes.select("a.example.com", client).is_some());
        assert!(routes.select("badexample.com", client).is_none());
    }
}
