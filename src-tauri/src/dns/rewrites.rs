use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// 本地 DNS 重写表。`*.domain` 会同时匹配域名本身和所有子域名，与规则语法保持一致。
#[derive(Clone, Default)]
pub(crate) struct CompiledRewrites {
    exact: HashMap<String, RewriteTarget>,
    wildcard: HashMap<String, RewriteTarget>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RewriteTarget {
    pub(crate) ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
}

impl CompiledRewrites {
    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub(crate) fn lookup(&self, domain: &str) -> Option<RewriteTarget> {
        if let Some(target) = self.exact.get(domain) {
            return Some(*target);
        }
        if let Some(target) = self.wildcard.get(domain) {
            return Some(*target);
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if let Some(target) = self.wildcard.get(&domain[offset..]) {
                return Some(*target);
            }
        }

        None
    }
}

pub(crate) fn compile_rewrites(raw: &str) -> CompiledRewrites {
    let mut rewrites = CompiledRewrites::default();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let (Some(pattern), Some(ip)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(ip) = ip.parse::<IpAddr>() else {
            continue;
        };

        let (domain, wildcard) = match pattern.strip_prefix("*.") {
            Some(rest) => (rest, true),
            None => (pattern, false),
        };
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }

        let table = if wildcard {
            &mut rewrites.wildcard
        } else {
            &mut rewrites.exact
        };
        let target = table.entry(domain).or_default();
        match ip {
            IpAddr::V4(addr) => target.ipv4 = Some(addr),
            IpAddr::V6(addr) => target.ipv6 = Some(addr),
        }
    }

    rewrites
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_exact_and_wildcard_rewrites() {
        let rewrites = compile_rewrites(
            "# 注释\nnas.lan 192.168.1.10\nnas.lan ::1\n*.home.lan 192.168.1.1\nbad-line\n",
        );

        let nas = rewrites.lookup("nas.lan").expect("nas.lan should match");
        assert_eq!(nas.ipv4, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(nas.ipv6, Some(Ipv6Addr::LOCALHOST));

        let base = rewrites.lookup("home.lan").expect("home.lan should match");
        assert_eq!(base.ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        let sub = rewrites
            .lookup("tv.home.lan")
            .expect("tv.home.lan should match");
        assert_eq!(sub.ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));

        assert!(rewrites.lookup("other.lan").is_none());
        assert!(rewrites.lookup("nas.lan.evil.com").is_none());
    }
}
