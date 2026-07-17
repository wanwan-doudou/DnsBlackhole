use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Mutex,
};

use crate::config::AppConfig;

const RATE_LIMITER_CLIENT_TTL_SECONDS: u64 = 120;
const RATE_LIMITER_PRUNE_INTERVAL_SECONDS: u64 = 60;
const RATE_LIMITER_MAX_CLIENTS: usize = 4096;
const RATE_LIMITER_BURST_SECONDS: u64 = 10;

pub(crate) enum ClientAccessDecision {
    Allow,
    Deny(String),
    RateLimited(String),
}

pub(crate) struct ClientAccess {
    allowed: ClientMatcher,
    blocked: ClientMatcher,
    rate_limiter: Option<Mutex<ClientRateLimiter>>,
}

#[derive(Default)]
struct ClientMatcher {
    exact: HashSet<IpAddr>,
    prefixes: Vec<IpPrefix>,
}

struct IpPrefix {
    family: IpFamily,
    network: u128,
    prefix_len: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

struct ClientRateLimiter {
    limit_per_second: u32,
    clients: HashMap<IpAddr, RateBucket>,
    last_prune_at: u64,
}

struct RateBucket {
    tokens: u64,
    last_refill: u64,
    last_seen: u64,
}

impl ClientAccess {
    pub(crate) fn from_config(config: &AppConfig) -> Result<Self, String> {
        let allowed = ClientMatcher::parse(&config.allowed_clients, "允许客户端")?;
        let blocked = ClientMatcher::parse(&config.blocked_clients, "拒绝客户端")?;
        let rate_limiter = (config.rate_limit_per_second > 0)
            .then(|| Mutex::new(ClientRateLimiter::new(config.rate_limit_per_second)));

        Ok(Self {
            allowed,
            blocked,
            rate_limiter,
        })
    }

    pub(crate) fn check(&self, ip: IpAddr, now: u64) -> ClientAccessDecision {
        if self.blocked.matches(ip) {
            return ClientAccessDecision::Deny(format!("客户端 {ip} 在拒绝列表中"));
        }

        if self.allowed.has_rules() && !self.allowed.matches(ip) {
            return ClientAccessDecision::Deny(format!("客户端 {ip} 不在允许列表中"));
        }

        if let Some(rate_limiter) = &self.rate_limiter
            && let Ok(mut rate_limiter) = rate_limiter.lock()
            && !rate_limiter.allow(ip, now)
        {
            return ClientAccessDecision::RateLimited(format!(
                "客户端 {ip} 触发每秒 {} 次持续查询限速（已用完 {} 秒突发容量）",
                rate_limiter.limit_per_second, RATE_LIMITER_BURST_SECONDS
            ));
        }

        ClientAccessDecision::Allow
    }
}

impl ClientMatcher {
    fn parse(value: &str, label: &str) -> Result<Self, String> {
        let mut matcher = Self::default();
        for (index, line) in value.lines().enumerate() {
            let item = line.split_whitespace().next().unwrap_or_default().trim();
            if item.is_empty() || item.starts_with('#') || item.starts_with('!') {
                continue;
            }

            if let Ok(ip) = item.parse::<IpAddr>() {
                matcher.exact.insert(ip);
                continue;
            }

            let prefix = IpPrefix::parse(item).map_err(|_| {
                format!(
                    "{label}第 {} 行必须是 IP 地址或 CIDR 网段：{item}",
                    index + 1
                )
            })?;
            matcher.prefixes.push(prefix);
        }

        Ok(matcher)
    }

    fn has_rules(&self) -> bool {
        !self.exact.is_empty() || !self.prefixes.is_empty()
    }

    fn matches(&self, ip: IpAddr) -> bool {
        self.exact.contains(&ip) || self.prefixes.iter().any(|prefix| prefix.contains(ip))
    }
}

impl IpPrefix {
    fn parse(value: &str) -> Result<Self, ()> {
        let (ip, prefix_len) = value.split_once('/').ok_or(())?;
        let ip = ip.parse::<IpAddr>().map_err(|_| ())?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| ())?;
        Self::new(ip, prefix_len)
    }

    fn new(ip: IpAddr, prefix_len: u8) -> Result<Self, ()> {
        let (family, bits, value) = ip_parts(ip);
        if prefix_len > bits {
            return Err(());
        }

        Ok(Self {
            family,
            network: prefix_network(value, bits, prefix_len),
            prefix_len,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let (family, bits, value) = ip_parts(ip);
        family == self.family && prefix_network(value, bits, self.prefix_len) == self.network
    }
}

fn ip_parts(ip: IpAddr) -> (IpFamily, u8, u128) {
    match ip {
        IpAddr::V4(addr) => (IpFamily::V4, 32, u32::from(addr) as u128),
        IpAddr::V6(addr) => (IpFamily::V6, 128, u128::from(addr)),
    }
}

fn prefix_network(value: u128, bits: u8, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }

    let shift = u32::from(bits.saturating_sub(prefix_len));
    (value >> shift) << shift
}

impl ClientRateLimiter {
    fn new(limit_per_second: u32) -> Self {
        Self {
            limit_per_second,
            clients: HashMap::new(),
            last_prune_at: 0,
        }
    }

    fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        if now.saturating_sub(self.last_prune_at) >= RATE_LIMITER_PRUNE_INTERVAL_SECONDS {
            self.prune(now);
        }

        if !self.clients.contains_key(&ip) && self.clients.len() >= RATE_LIMITER_MAX_CLIENTS {
            return false;
        }

        let capacity = u64::from(self.limit_per_second).saturating_mul(RATE_LIMITER_BURST_SECONDS);
        let bucket = self.clients.entry(ip).or_insert(RateBucket {
            tokens: capacity,
            last_refill: now,
            last_seen: now,
        });

        if now < bucket.last_refill {
            // 系统时间被向后校准时重置桶，避免客户端长时间无法恢复额度。
            bucket.tokens = capacity;
            bucket.last_refill = now;
        } else {
            let elapsed = now.saturating_sub(bucket.last_refill);
            if elapsed > 0 {
                bucket.tokens = bucket
                    .tokens
                    .saturating_add(elapsed.saturating_mul(u64::from(self.limit_per_second)))
                    .min(capacity);
                bucket.last_refill = now;
            }
        }
        bucket.last_seen = now;

        if bucket.tokens == 0 {
            return false;
        }

        bucket.tokens -= 1;
        true
    }

    fn prune(&mut self, now: u64) {
        let oldest = now.saturating_sub(RATE_LIMITER_CLIENT_TTL_SECONDS);
        self.clients.retain(|_, bucket| bucket.last_seen >= oldest);
        self.last_prune_at = now;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::config::AppConfig;

    use super::{
        ClientAccess, ClientAccessDecision, ClientRateLimiter, RATE_LIMITER_BURST_SECONDS,
        RATE_LIMITER_MAX_CLIENTS,
    };

    #[test]
    fn access_allowlist_allows_private_default_clients() {
        let access = ClientAccess::from_config(&AppConfig::default()).expect("access should build");

        assert!(matches!(
            access.check(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 100),
            ClientAccessDecision::Allow
        ));
        assert!(matches!(
            access.check(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 100),
            ClientAccessDecision::Deny(_)
        ));
    }

    #[test]
    fn blocked_clients_override_allowed_clients() {
        let config = AppConfig {
            allowed_clients: "192.168.0.0/16".into(),
            blocked_clients: "192.168.1.2".into(),
            ..AppConfig::default()
        };
        let access = ClientAccess::from_config(&config).expect("access should build");

        assert!(matches!(
            access.check(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 100),
            ClientAccessDecision::Deny(_)
        ));
    }

    #[test]
    fn client_rate_limit_allows_burst_and_enforces_sustained_rate() {
        let config = AppConfig {
            allowed_clients: "127.0.0.1".into(),
            rate_limit_per_second: 2,
            ..AppConfig::default()
        };
        let access = ClientAccess::from_config(&config).expect("access should build");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let burst_capacity = 2 * RATE_LIMITER_BURST_SECONDS;

        for _ in 0..burst_capacity {
            assert!(matches!(access.check(ip, 100), ClientAccessDecision::Allow));
        }
        assert!(matches!(
            access.check(ip, 100),
            ClientAccessDecision::RateLimited(_)
        ));
        assert!(matches!(access.check(ip, 101), ClientAccessDecision::Allow));
        assert!(matches!(access.check(ip, 101), ClientAccessDecision::Allow));
        assert!(matches!(
            access.check(ip, 101),
            ClientAccessDecision::RateLimited(_)
        ));
    }

    #[test]
    fn default_rate_limit_accepts_normal_reconnect_burst() {
        let access = ClientAccess::from_config(&AppConfig::default()).expect("access should build");
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        for _ in 0..500 {
            assert!(matches!(access.check(ip, 100), ClientAccessDecision::Allow));
        }
    }

    #[test]
    fn rate_limiter_never_exceeds_client_capacity() {
        let mut limiter = ClientRateLimiter::new(10);
        for index in 0..RATE_LIMITER_MAX_CLIENTS {
            assert!(limiter.allow(IpAddr::V6(Ipv6Addr::from(index as u128 + 1)), 100));
        }

        assert!(!limiter.allow(
            IpAddr::V6(Ipv6Addr::from(RATE_LIMITER_MAX_CLIENTS as u128 + 1)),
            100
        ));
        assert_eq!(limiter.clients.len(), RATE_LIMITER_MAX_CLIENTS);
    }
}
