use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{AppConfig, BlockingMode};

use super::rewrites::RewriteTarget;

pub(crate) const DNS_HEADER_LEN: usize = 12;
pub(crate) const MAX_DNS_PACKET_SIZE: usize = u16::MAX as usize;
const MAX_UDP_DNS_PAYLOAD: usize = 65_507;
const BLOCK_RESPONSE_TTL: u32 = 60;
const REWRITE_RESPONSE_TTL: u32 = 300;
pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_NS: u16 = 2;
pub(crate) const TYPE_SOA: u16 = 6;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const TYPE_ANY: u16 = 255;
pub(crate) const RCODE_NOERROR: u8 = 0;
pub(crate) const RCODE_REFUSED: u8 = 5;
pub(crate) const RCODE_NXDOMAIN: u8 = 3;

pub(crate) struct Question {
    pub(crate) domain: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
    pub(crate) question_end: usize,
}

pub(crate) struct ParsedQuery {
    pub(crate) question: Question,
    pub(crate) recursion_desired: bool,
    pub(crate) authentic_data: bool,
    pub(crate) checking_disabled: bool,
    pub(crate) dnssec_ok: bool,
    pub(crate) edns_udp_size: Option<u16>,
    pub(crate) cache_safe: bool,
}

pub(crate) fn parse_query(packet: &[u8]) -> Result<ParsedQuery, String> {
    if packet.len() < DNS_HEADER_LEN {
        return Err("DNS 请求长度不足".into());
    }

    let flags = read_u16(packet, 2).ok_or("DNS flags 读取失败")?;
    if flags & 0x8000 != 0 {
        return Err("DNS 请求的 QR 标志无效".into());
    }
    if flags & 0x7800 != 0 {
        return Err("暂不支持非标准 DNS opcode".into());
    }
    if flags & 0x0040 != 0 {
        return Err("DNS 请求设置了保留标志位".into());
    }

    let question = parse_question(packet)?;
    let answer_count = read_u16(packet, 6).unwrap_or(0);
    let authority_count = read_u16(packet, 8).unwrap_or(0);
    let additional_count = read_u16(packet, 10).unwrap_or(0);
    let mut offset = question.question_end;
    let mut cache_safe = answer_count == 0 && authority_count == 0;

    for _ in 0..answer_count.saturating_add(authority_count) {
        let record = read_dns_record(packet, offset).ok_or("DNS 请求资源记录格式无效")?;
        offset = record.next_offset;
    }

    let mut edns_udp_size = None;
    let mut dnssec_ok = false;
    for _ in 0..additional_count {
        let owner_is_root = packet.get(offset).is_some_and(|value| *value == 0);
        let record = read_dns_record(packet, offset).ok_or("DNS 请求附加记录格式无效")?;
        if record.record_type == TYPE_OPT && edns_udp_size.is_none() && owner_is_root {
            edns_udp_size = Some(record.record_class.max(512));
            dnssec_ok = record.ttl & 0x0000_8000 != 0;
            if record.data_len != 0 || record.ttl & 0xffff_7fff != 0 {
                // ECS、Cookie 等 EDNS 选项会影响响应，不参与缓存或重复请求合并。
                cache_safe = false;
            }
        } else {
            cache_safe = false;
        }
        offset = record.next_offset;
    }

    if offset != packet.len() {
        return Err("DNS 请求包含未解析的尾部数据".into());
    }

    Ok(ParsedQuery {
        question,
        recursion_desired: flags & 0x0100 != 0,
        authentic_data: flags & 0x0020 != 0,
        checking_disabled: flags & 0x0010 != 0,
        dnssec_ok,
        edns_udp_size,
        cache_safe,
    })
}

pub(crate) fn parse_question(packet: &[u8]) -> Result<Question, String> {
    if packet.len() < DNS_HEADER_LEN {
        return Err("DNS 请求长度不足".into());
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    if question_count != 1 {
        return Err("DNS 请求必须且只能包含 1 个 question".into());
    }

    let mut offset = DNS_HEADER_LEN;
    let mut domain = String::with_capacity(packet.len().saturating_sub(DNS_HEADER_LEN).min(253));

    loop {
        if offset >= packet.len() {
            return Err("DNS 域名解析越界".into());
        }

        let label_len = packet[offset] as usize;
        offset += 1;

        if label_len == 0 {
            break;
        }

        if label_len > 63 {
            return Err("DNS label 长度超过 63 字节".into());
        }

        if label_len & 0b1100_0000 != 0 {
            return Err("暂不支持压缩格式的 DNS question".into());
        }

        if offset + label_len > packet.len() {
            return Err("DNS label 长度越界".into());
        }

        if !domain.is_empty() {
            domain.push('.');
        }
        push_ascii_lowercase(&mut domain, &packet[offset..offset + label_len])?;
        offset += label_len;
    }

    if offset + 4 > packet.len() {
        return Err("DNS question 缺少类型或类别".into());
    }

    let qtype = read_u16(packet, offset).ok_or("DNS qtype 读取失败")?;
    let qclass = read_u16(packet, offset + 2).ok_or("DNS qclass 读取失败")?;
    let question_end = offset + 4;

    Ok(Question {
        domain,
        qtype,
        qclass,
        question_end,
    })
}

fn push_ascii_lowercase(target: &mut String, bytes: &[u8]) -> Result<(), String> {
    if !bytes.is_ascii() {
        return Err("DNS label 必须使用 ASCII/Punycode 编码".into());
    }
    for byte in bytes {
        target.push(char::from(byte.to_ascii_lowercase()));
    }
    Ok(())
}

pub(crate) fn build_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let question = parse_question(query).ok()?;
    let mut response = Vec::with_capacity(question.question_end);

    response.extend_from_slice(query.get(0..2)?);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80 | (rcode & 0x0f));
    write_u16(&mut response, 1);
    write_u16(&mut response, 0);
    write_u16(&mut response, 0);
    write_u16(&mut response, 0);
    response.extend_from_slice(query.get(DNS_HEADER_LEN..question.question_end)?);

    Some(response)
}

/// 拦截响应策略，由配置编译而来，可随过滤状态热替换。
#[derive(Clone)]
pub(crate) struct BlockingPolicy {
    mode: BlockingMode,
    custom_ipv4: Option<Ipv4Addr>,
    custom_ipv6: Option<Ipv6Addr>,
}

impl Default for BlockingPolicy {
    fn default() -> Self {
        Self {
            mode: BlockingMode::NullIp,
            custom_ipv4: None,
            custom_ipv6: None,
        }
    }
}

impl BlockingPolicy {
    pub(crate) fn from_config(config: &AppConfig) -> Self {
        Self {
            mode: config.blocking_mode.clone(),
            custom_ipv4: config.blocking_custom_ipv4.trim().parse().ok(),
            custom_ipv6: config.blocking_custom_ipv6.trim().parse().ok(),
        }
    }
}

pub(crate) fn build_block_response(
    query: &[u8],
    question: &Question,
    policy: &BlockingPolicy,
) -> Vec<u8> {
    match policy.mode {
        BlockingMode::NullIp => build_ip_response(
            query,
            question,
            RCODE_NOERROR,
            Some(Ipv4Addr::UNSPECIFIED),
            Some(Ipv6Addr::UNSPECIFIED),
            BLOCK_RESPONSE_TTL,
        ),
        BlockingMode::CustomIp => build_ip_response(
            query,
            question,
            RCODE_NOERROR,
            policy.custom_ipv4,
            policy.custom_ipv6,
            BLOCK_RESPONSE_TTL,
        ),
        BlockingMode::Nxdomain => build_ip_response(query, question, RCODE_NXDOMAIN, None, None, 0),
        BlockingMode::Refused => build_ip_response(query, question, RCODE_REFUSED, None, None, 0),
    }
}

pub(crate) fn build_rewrite_response(
    query: &[u8],
    question: &Question,
    target: &RewriteTarget,
) -> Vec<u8> {
    build_ip_response(
        query,
        question,
        RCODE_NOERROR,
        target.ipv4,
        target.ipv6,
        REWRITE_RESPONSE_TTL,
    )
}

fn build_ip_response(
    query: &[u8],
    question: &Question,
    rcode: u8,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    ttl: u32,
) -> Vec<u8> {
    let answer_ip = if rcode == RCODE_NOERROR {
        match question.qtype {
            TYPE_A => ipv4.map(|addr| addr.octets().to_vec()),
            TYPE_AAAA => ipv6.map(|addr| addr.octets().to_vec()),
            _ => None,
        }
    } else {
        None
    };
    let answer_count = if answer_ip.is_some() { 1_u16 } else { 0_u16 };
    let mut response = Vec::with_capacity(question.question_end + 32);

    response.extend_from_slice(&query[0..2]);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80 | (rcode & 0x0f));
    write_u16(&mut response, 1);
    write_u16(&mut response, answer_count);
    write_u16(&mut response, 0);
    write_u16(&mut response, 0);
    response.extend_from_slice(&query[DNS_HEADER_LEN..question.question_end]);

    if let Some(ip_bytes) = answer_ip {
        response.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut response, question.qtype);
        write_u16(&mut response, question.qclass);
        response.extend_from_slice(&ttl.to_be_bytes());
        write_u16(&mut response, ip_bytes.len() as u16);
        response.extend_from_slice(&ip_bytes);
    }

    response
}

pub(crate) fn validate_response_for_query(query: &[u8], response: &[u8]) -> Result<(), String> {
    if query.len() < DNS_HEADER_LEN || response.len() < DNS_HEADER_LEN {
        return Err("DNS 响应长度不足".into());
    }
    if query[0..2] != response[0..2] {
        return Err("DNS 响应 transaction ID 与请求不匹配".into());
    }
    if response[2] & 0x80 == 0 {
        return Err("上游返回的 DNS 包不是响应".into());
    }

    let query_question = parse_question(query)?;
    let response_question = parse_question(response)?;
    if query_question.domain != response_question.domain
        || query_question.qtype != response_question.qtype
        || query_question.qclass != response_question.qclass
    {
        return Err("DNS 响应 question 与请求不匹配".into());
    }

    Ok(())
}

pub(crate) fn response_is_truncated(packet: &[u8]) -> bool {
    packet.get(2).is_some_and(|flags| flags & 0b0000_0010 != 0)
}

pub(crate) fn extract_response_ips(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < DNS_HEADER_LEN {
        return Vec::new();
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    let answer_count = read_u16(packet, 6).unwrap_or(0);
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        let Some(next_offset) = skip_dns_name(packet, offset) else {
            return Vec::new();
        };
        offset = next_offset.saturating_add(4);
        if offset > packet.len() {
            return Vec::new();
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        let Some(next_offset) = skip_dns_name(packet, offset) else {
            break;
        };
        offset = next_offset;
        if offset + 10 > packet.len() {
            break;
        }

        let record_type = read_u16(packet, offset).unwrap_or_default();
        let record_class = read_u16(packet, offset + 2).unwrap_or_default();
        let data_len = read_u16(packet, offset + 8).unwrap_or_default() as usize;
        let data_offset = offset + 10;
        let data_end = data_offset.saturating_add(data_len);
        if data_end > packet.len() {
            break;
        }

        if record_class == 1 && record_type == TYPE_A && data_len == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(
                packet[data_offset],
                packet[data_offset + 1],
                packet[data_offset + 2],
                packet[data_offset + 3],
            )));
        }

        if record_class == 1 && record_type == TYPE_AAAA && data_len == 16 {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[data_offset..data_end]);
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }

        offset = data_end;
    }

    ips
}

pub(crate) fn response_cache_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let rcode = packet[3] & 0x0f;
    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        return None;
    }
    let answer_count = read_u16(packet, 6)?;
    let authority_count = read_u16(packet, 8)?;
    let additional_count = read_u16(packet, 10)?;

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        let next_offset = skip_dns_name(packet, offset)?;
        if next_offset + 4 > packet.len() {
            return None;
        }
        offset = next_offset;
    }
    let question_type = read_u16(packet, offset)?;
    offset = offset.checked_add(4)?;
    if offset > packet.len() {
        return None;
    }

    let mut min_ttl = None;
    let mut has_answer = false;
    let mut has_ip_answer = false;
    for _ in 0..answer_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            has_answer = true;
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        if record.record_class == 1 && matches!(record.record_type, TYPE_A | TYPE_AAAA) {
            has_ip_answer = true;
        }
        offset = record.next_offset;
    }

    let mut has_soa_authority = false;
    let mut has_ns_authority = false;
    for _ in 0..authority_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        match record.record_type {
            TYPE_SOA => has_soa_authority = true,
            TYPE_NS => has_ns_authority = true,
            _ => {}
        }
        offset = record.next_offset;
    }

    for _ in 0..additional_count {
        let record = read_dns_record(packet, offset)?;
        if record.record_type != TYPE_OPT {
            min_ttl = Some(min_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
        offset = record.next_offset;
    }

    let authoritative_negative = has_soa_authority && !has_ns_authority;
    let cacheable = match rcode {
        RCODE_NOERROR => {
            if has_answer {
                !matches!(question_type, TYPE_A | TYPE_AAAA) || has_ip_answer
            } else {
                authoritative_negative
            }
        }
        RCODE_NXDOMAIN => authoritative_negative,
        _ => false,
    };
    if !cacheable {
        return None;
    }

    min_ttl
}

struct DnsRecordHeader {
    record_type: u16,
    record_class: u16,
    ttl: u32,
    data_len: usize,
    next_offset: usize,
}

fn read_dns_record(packet: &[u8], offset: usize) -> Option<DnsRecordHeader> {
    let header_offset = skip_dns_name(packet, offset)?;
    if header_offset + 10 > packet.len() {
        return None;
    }

    let record_type = read_u16(packet, header_offset)?;
    let record_class = read_u16(packet, header_offset + 2)?;
    let ttl = read_u32(packet, header_offset + 4)?;
    let data_len = read_u16(packet, header_offset + 8)? as usize;
    let next_offset = header_offset.checked_add(10)?.checked_add(data_len)?;
    if next_offset > packet.len() {
        return None;
    }

    Some(DnsRecordHeader {
        record_type,
        record_class,
        ttl,
        data_len,
        next_offset,
    })
}

#[cfg(test)]
pub(crate) fn response_min_record_ttl(packet: &[u8]) -> Option<u32> {
    response_cache_ttl(packet)
}

pub(crate) fn prepare_cached_response(
    cached_response: &[u8],
    query: &[u8],
    ttl: u32,
) -> Option<Vec<u8>> {
    let mut response = prepare_response_for_query(cached_response, query)?;
    rewrite_response_ttls(&mut response, ttl)?;
    Some(response)
}

pub(crate) fn prepare_response_for_query(response: &[u8], query: &[u8]) -> Option<Vec<u8>> {
    let response_question = parse_question(response).ok()?;
    let query_question = parse_question(query).ok()?;
    if response_question.domain != query_question.domain
        || response_question.qtype != query_question.qtype
        || response_question.qclass != query_question.qclass
        || response_question.question_end != query_question.question_end
    {
        return None;
    }

    let mut prepared = response.to_vec();
    prepared[0..2].copy_from_slice(&query[0..2]);
    prepared[DNS_HEADER_LEN..response_question.question_end]
        .copy_from_slice(&query[DNS_HEADER_LEN..query_question.question_end]);
    Some(prepared)
}

pub(crate) fn udp_payload_size(query: &[u8]) -> usize {
    parse_query(query)
        .ok()
        .and_then(|parsed| parsed.edns_udp_size)
        .map_or(512, usize::from)
        .clamp(512, MAX_UDP_DNS_PAYLOAD)
}

pub(crate) fn truncate_response_for_udp(
    query: &[u8],
    response: &[u8],
    max_size: usize,
) -> Option<Vec<u8>> {
    if response.len() <= max_size {
        return Some(response.to_vec());
    }
    if response.len() < DNS_HEADER_LEN {
        return None;
    }

    let question = parse_question(query).ok()?;
    let mut truncated = Vec::with_capacity(question.question_end);
    truncated.extend_from_slice(query.get(0..2)?);
    truncated.push(response[2] | 0x02);
    truncated.push(response[3]);
    write_u16(&mut truncated, 1);
    write_u16(&mut truncated, 0);
    write_u16(&mut truncated, 0);
    write_u16(&mut truncated, 0);
    truncated.extend_from_slice(query.get(DNS_HEADER_LEN..question.question_end)?);
    (truncated.len() <= max_size).then_some(truncated)
}

fn rewrite_response_ttls(packet: &mut [u8], ttl: u32) -> Option<()> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    let answer_count = read_u16(packet, 6).unwrap_or(0);
    let authority_count = read_u16(packet, 8).unwrap_or(0);
    let additional_count = read_u16(packet, 10).unwrap_or(0);
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        let next_offset = skip_dns_name(packet, offset)?;
        offset = next_offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    for _ in 0..answer_count
        .saturating_add(authority_count)
        .saturating_add(additional_count)
    {
        let next_offset = skip_dns_name(packet, offset)?;
        offset = next_offset;
        if offset + 10 > packet.len() {
            return None;
        }

        let record_type = read_u16(packet, offset)?;
        if record_type != TYPE_OPT {
            write_u32_at(packet, offset + 4, ttl)?;
        }
        let data_len = read_u16(packet, offset + 8)? as usize;
        offset = offset.checked_add(10)?.checked_add(data_len)?;
        if offset > packet.len() {
            return None;
        }
    }

    Some(())
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)? as usize;
        offset += 1;

        if length == 0 {
            return Some(offset);
        }

        if length & 0b1100_0000 == 0b1100_0000 {
            packet.get(offset)?;
            return Some(offset + 1);
        }

        if length & 0b1100_0000 != 0 {
            return None;
        }

        offset = offset.checked_add(length)?;
        if offset > packet.len() {
            return None;
        }
    }
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([first, second]))
}

fn write_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    let third = *bytes.get(offset + 2)?;
    let fourth = *bytes.get(offset + 3)?;
    Some(u32::from_be_bytes([first, second, third, fourth]))
}

fn write_u32_at(target: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let bytes = value.to_be_bytes();
    target.get_mut(offset..offset + 4)?.copy_from_slice(&bytes);
    Some(())
}
