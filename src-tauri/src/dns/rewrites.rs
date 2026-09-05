use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
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

/// 系统 hosts 文件路径。Windows 上位置由 %SystemRoot% 决定，不写死盘符。
pub(crate) fn system_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// 读取系统 hosts 文件。读不到（权限、文件缺失）时返回 None，由调用方决定是否告警；
/// 这不该阻止 DNS 服务启动。
pub(crate) fn read_system_hosts() -> Option<String> {
    let path = system_hosts_path();
    match std::fs::read(&path) {
        // hosts 文件通常是 ASCII，但可能混入非 UTF-8 字节，按有损转换处理。
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(error) => {
            eprintln!("读取系统 hosts 文件 {} 失败：{error}", path.display());
            None
        }
    }
}

/// 把系统 hosts 文件合并进重写表。格式是 `IP 主机名 [主机名...]`，与配置里的
/// `域名 IP` 正好相反，且一行可以映射多个名字。
///
/// 已有的用户重写优先：这里只填补空缺的 IPv4/IPv6 槽位，不覆盖用户显式配置的记录。
pub(crate) fn merge_hosts_file(rewrites: &mut CompiledRewrites, contents: &str) {
    for line in contents.lines() {
        // hosts 只用 `#` 作注释，行内注释同样需要截断。
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(Ok(ip)) = parts.next().map(str::parse::<IpAddr>) else {
            continue;
        };
        for host in parts {
            // IPv6 链路本地地址常带 `%zone`，作为域名没有意义，直接跳过。
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() || !is_valid_hostname(&host) {
                continue;
            }
            let inherited = rewrites.lookup(&host).unwrap_or_default();
            let target = rewrites.exact.entry(host).or_insert(inherited);
            match ip {
                IpAddr::V4(addr) => {
                    target.ipv4.get_or_insert(addr);
                }
                IpAddr::V6(addr) => {
                    target.ipv6.get_or_insert(addr);
                }
            }
        }
    }
}

fn is_valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_hosts_preserves_wildcard_addresses_and_fills_missing_family() {
        let mut rewrites = compile_rewrites("*.example 192.168.1.10\n*.sub.example 192.168.1.20");
        merge_hosts_file(
            &mut rewrites,
            "192.168.1.99 test.example\nfd00::1 test.example\n192.168.1.99 test.sub.example",
        );
        let target = rewrites.lookup("test.example").unwrap();
        assert_eq!(target.ipv4, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(target.ipv6, Some("fd00::1".parse().unwrap()));
        assert_eq!(
            rewrites.lookup("test.sub.example").unwrap().ipv4,
            Some(Ipv4Addr::new(192, 168, 1, 20))
        );
        assert_eq!(rewrites.lookup("other.example").unwrap().ipv6, None);
    }

    #[test]
    fn hosts_file_entries_fill_gaps_without_overriding_user_rewrites() {
        let mut rewrites = compile_rewrites("nas.lan 192.168.1.10");
        merge_hosts_file(
            &mut rewrites,
            concat!(
                "# 系统 hosts
",
                "127.0.0.1       localhost
",
                "::1             localhost
",
                "192.168.1.99    nas.lan          # 用户已配置，IPv4 不应被覆盖
",
                "fd00::2         nas.lan
",
                "0.0.0.0         ads.example tracker.example
",
                "not-an-ip       broken.example
",
                "10.0.0.1
",
            ),
        );

        let nas = rewrites.lookup("nas.lan").expect("nas.lan should match");
        assert_eq!(
            nas.ipv4,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            "用户重写优先于 hosts"
        );
        assert_eq!(
            nas.ipv6,
            Some("fd00::2".parse::<Ipv6Addr>().expect("ipv6")),
            "空缺的 IPv6 槽位应由 hosts 补齐"
        );

        let localhost = rewrites
            .lookup("localhost")
            .expect("localhost should match");
        assert_eq!(localhost.ipv4, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(localhost.ipv6, Some(Ipv6Addr::LOCALHOST));

        // 一行多个主机名都要生效。
        assert_eq!(
            rewrites
                .lookup("tracker.example")
                .expect("tracker.example should match")
                .ipv4,
            Some(Ipv4Addr::UNSPECIFIED)
        );
        assert!(rewrites.lookup("broken.example").is_none());
    }

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
