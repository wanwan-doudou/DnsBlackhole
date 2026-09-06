//! 私有地址反查的本地应答。
//!
//! `192.168.1.50.in-addr.arpa` 这类查询会把内网网段逐个暴露给公共上游。实测中私有地址
//! 反查的延迟（30~80ms）与公网反查基线（28.5ms）同量级，且响应里带上游 SOA，说明确实
//! 出网了；连 `127.0.0.1` 与 `169.254.x` 的反查也一样。Windows 资源管理器和各类网络
//! 工具会持续发这类查询，等于把内网拓扑长期外送。
//!
//! 这里在转发前把落在"只在本地有意义"的地址空间里的反查拦下，由本地生成带 SOA 的
//! NXDOMAIN，让客户端按 RFC 2308 负缓存，绝不出网。
//!
//! 部分区域名（`168.192.in-addr.arpa`）同样拦截：它虽然只泄漏网段而不是具体主机，
//! 但同样没有必要出网。只有当标签构成的整个网段都在私有空间内时才拦，
//! 因此 `192.in-addr.arpa`（192.0.0.0/8 含公网地址）仍会正常转发。

/// 只在本地有意义的 IPv4 地址空间，格式为（网络地址, 前缀长度）。
const LOCAL_V4_NETWORKS: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8    "this network"
    (0x0A00_0000, 8),  // 10.0.0.0/8
    (0x6440_0000, 10), // 100.64.0.0/10 RFC 6598 CGNAT
    (0x7F00_0000, 8),  // 127.0.0.0/8  回环
    (0xA9FE_0000, 16), // 169.254.0.0/16 链路本地
    (0xAC10_0000, 12), // 172.16.0.0/12
    (0xC0A8_0000, 16), // 192.168.0.0/16
    (0xE000_0000, 4),  // 224.0.0.0/4  组播
    (0xF000_0000, 4),  // 240.0.0.0/4  保留
];

/// 只在本地有意义的 IPv6 地址空间。
const LOCAL_V6_NETWORKS: &[(u128, u8)] = &[
    (0, 128),            // ::/128 未指定
    (1, 128),            // ::1/128 回环
    (0xfc00 << 112, 7),  // fc00::/7  ULA
    (0xfe80 << 112, 10), // fe80::/10 链路本地
    (0xff00 << 112, 8),  // ff00::/8  组播
];

/// 反查域名是否落在只在本地有意义的地址空间里。
///
/// 传入的域名必须已经小写（`parse_question` 保证了这一点）。
pub(crate) fn is_local_reverse_name(domain: &str) -> bool {
    if let Some(prefix) = domain.strip_suffix(".in-addr.arpa") {
        return parse_v4_reverse_prefix(prefix)
            .is_some_and(|(network, prefix_len)| network_is_local_v4(network, prefix_len));
    }
    if let Some(prefix) = domain.strip_suffix(".ip6.arpa") {
        return parse_v6_reverse_prefix(prefix)
            .is_some_and(|(network, prefix_len)| network_is_local_v6(network, prefix_len));
    }
    false
}

/// 反查名是倒序的：`1.2.3.4.in-addr.arpa` 对应 4.3.2.1。
/// 标签数不足 4 个时得到的是一个网段而不是主机地址。
fn parse_v4_reverse_prefix(prefix: &str) -> Option<(u32, u8)> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for label in prefix.split('.') {
        if count == 4 {
            return None;
        }
        // 反查名里的十进制标签不允许带前导零或正号，按原样拒绝，避免同一网段有多种写法
        if label.is_empty() || (label.len() > 1 && label.starts_with('0')) {
            return None;
        }
        octets[count] = label.parse::<u8>().ok()?;
        count += 1;
    }
    if count == 0 {
        return None;
    }

    let mut network = 0u32;
    // 倒序还原：最靠前的标签是地址最低位的字节
    for (index, octet) in octets.iter().enumerate().take(count) {
        network |= u32::from(*octet) << (8 * index as u32);
    }
    Some((network << (8 * (4 - count) as u32), (8 * count) as u8))
}

/// `ip6.arpa` 的每个标签是一个十六进制 nibble，同样倒序。
fn parse_v6_reverse_prefix(prefix: &str) -> Option<(u128, u8)> {
    let mut nibbles = [0u8; 32];
    let mut count = 0usize;
    for label in prefix.split('.') {
        if count == 32 {
            return None;
        }
        let mut chars = label.chars();
        let nibble = chars.next()?.to_digit(16)?;
        if chars.next().is_some() {
            return None;
        }
        nibbles[count] = nibble as u8;
        count += 1;
    }
    if count == 0 {
        return None;
    }

    let mut network = 0u128;
    for (index, nibble) in nibbles.iter().enumerate().take(count) {
        network |= u128::from(*nibble) << (4 * index as u32);
    }
    Some((network << (4 * (32 - count) as u32), (4 * count) as u8))
}

fn network_is_local_v4(network: u32, prefix_len: u8) -> bool {
    LOCAL_V4_NETWORKS.iter().any(|&(local, local_len)| {
        // 只有查询网段完整落在私有网段内才算：前缀更短说明它还覆盖了公网地址
        prefix_len >= local_len && mask_u32(network, local_len) == local
    })
}

fn network_is_local_v6(network: u128, prefix_len: u8) -> bool {
    LOCAL_V6_NETWORKS.iter().any(|&(local, local_len)| {
        prefix_len >= local_len && mask_u128(network, local_len) == local
    })
}

fn mask_u32(value: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    value & (u32::MAX << (32 - u32::from(prefix_len)))
}

fn mask_u128(value: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    value & (u128::MAX << (128 - u32::from(prefix_len)))
}

#[cfg(test)]
mod tests {
    use super::is_local_reverse_name;

    #[test]
    fn intercepts_private_host_reverse_names() {
        for domain in [
            "17.1.168.192.in-addr.arpa",
            "231.5.168.192.in-addr.arpa",
            "44.99.16.172.in-addr.arpa",
            "7.3.0.10.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "5.4.254.169.in-addr.arpa",
            "1.100.64.100.in-addr.arpa",
        ] {
            assert!(is_local_reverse_name(domain), "{domain} 应被本地拦下");
        }
    }

    #[test]
    fn forwards_public_reverse_names() {
        for domain in [
            "8.8.8.8.in-addr.arpa",
            "1.1.1.1.in-addr.arpa",
            "5.5.5.223.in-addr.arpa",
            "example.org",
            "in-addr.arpa",
            "arpa",
        ] {
            assert!(!is_local_reverse_name(domain), "{domain} 应正常转发");
        }
    }

    #[test]
    fn intercepts_private_zone_names_but_not_mixed_prefixes() {
        // 整段都在私有空间内 => 拦
        assert!(is_local_reverse_name("1.168.192.in-addr.arpa")); // 192.168.1.0/24
        assert!(is_local_reverse_name("168.192.in-addr.arpa")); // 192.168.0.0/16
        assert!(is_local_reverse_name("10.in-addr.arpa")); // 10.0.0.0/8
        assert!(is_local_reverse_name("127.in-addr.arpa")); // 127.0.0.0/8
        assert!(is_local_reverse_name("16.172.in-addr.arpa")); // 172.16.0.0/12

        // 192.0.0.0/8 和 172.0.0.0/8 都含公网地址，前缀太短，不能拦
        assert!(!is_local_reverse_name("192.in-addr.arpa"));
        assert!(!is_local_reverse_name("172.in-addr.arpa"));
        // 172.32.0.0/16 在 172.16.0.0/12 之外
        assert!(!is_local_reverse_name("32.172.in-addr.arpa"));
    }

    #[test]
    fn handles_ipv6_reverse_names() {
        // fd00::1 的完整反查名：32 个 nibble 倒序 => 1 + 29 个 0 + d + f
        let mut labels = vec!["1"];
        labels.extend(vec!["0"; 29]);
        labels.push("d");
        labels.push("f");
        let name = format!("{}.ip6.arpa", labels.join("."));
        assert_eq!(labels.len(), 32, "ip6.arpa 完整名必须是 32 个标签");
        assert!(is_local_reverse_name(&name), "ULA 反查应被拦下：{name}");

        // fe80::/10 链路本地区域名
        assert!(is_local_reverse_name("8.e.f.ip6.arpa"));
        // ::1 回环
        let loopback = format!("1.{}.ip6.arpa", vec!["0"; 31].join("."));
        assert!(is_local_reverse_name(&loopback));

        // 2001:db8:: 是文档地址但不属于本地空间，应转发
        assert!(!is_local_reverse_name("8.b.d.0.1.0.0.2.ip6.arpa"));
        // f.ip6.arpa 覆盖 f000::/4，包含公网地址，前缀太短
        assert!(!is_local_reverse_name("f.ip6.arpa"));
    }

    #[test]
    fn rejects_malformed_reverse_names() {
        for domain in [
            "256.1.168.192.in-addr.arpa",
            "1.1.1.1.1.in-addr.arpa",
            "01.168.192.in-addr.arpa",
            "..168.192.in-addr.arpa",
            "-1.168.192.in-addr.arpa",
            "zz.ip6.arpa",
            "1a.ip6.arpa",
        ] {
            assert!(
                !is_local_reverse_name(domain),
                "{domain} 不应被识别为本地反查"
            );
        }
    }
}
