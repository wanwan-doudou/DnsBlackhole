use std::net::IpAddr;

#[derive(Clone, Copy)]
pub(crate) struct IpNetwork {
    family: IpFamily,
    network: u128,
    prefix_len: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpNetwork {
    pub(crate) fn parse(value: &str, label: &str) -> Result<Self, String> {
        let (ip, prefix_len) = if let Some((ip, prefix_len)) = value.split_once('/') {
            (
                ip.parse::<IpAddr>()
                    .map_err(|_| format!("{label} IP 无效：{ip}"))?,
                prefix_len
                    .parse::<u8>()
                    .map_err(|_| format!("{label}前缀无效：{prefix_len}"))?,
            )
        } else {
            let ip = value
                .parse::<IpAddr>()
                .map_err(|_| format!("{label} IP 无效：{value}"))?;
            let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
            (ip, prefix_len)
        };
        let (family, bits, raw) = ip_parts(ip);
        if prefix_len > bits {
            return Err(format!("{label}前缀长度无效：{value}"));
        }
        Ok(Self {
            family,
            network: prefix_network(raw, bits, prefix_len),
            prefix_len,
        })
    }

    pub(crate) fn contains(self, ip: IpAddr) -> bool {
        let (family, bits, raw) = ip_parts(ip);
        family == self.family && prefix_network(raw, bits, self.prefix_len) == self.network
    }

    pub(crate) fn prefix_len(self) -> u8 {
        self.prefix_len
    }
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
    fn matches_ipv4_and_ipv6_networks() {
        let ipv4 = IpNetwork::parse("192.168.1.0/24", "测试网络").unwrap();
        assert!(ipv4.contains("192.168.1.42".parse().unwrap()));
        assert!(!ipv4.contains("192.168.2.42".parse().unwrap()));

        let ipv6 = IpNetwork::parse("fd00::/8", "测试网络").unwrap();
        assert!(ipv6.contains("fd12::1".parse().unwrap()));
        assert!(!ipv6.contains("2001:db8::1".parse().unwrap()));
    }
}
