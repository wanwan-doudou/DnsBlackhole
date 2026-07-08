use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    sync::mpsc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    config::{AppConfig, UpstreamMode, UpstreamServer},
    database::{Database, QueryLogEntry},
};

const DNS_HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TRAFFIC_BUCKET_WINDOW_MINUTES: u64 = 90 * 24 * 60;
const FASTEST_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_millis(350);

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleSummary {
    pub block_rules: usize,
    pub allow_rules: usize,
    pub ignored_rules: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStats {
    pub started_at: Option<u64>,
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub last_query: Option<String>,
    pub last_blocked: Option<String>,
    pub last_error: Option<String>,
    pub query_domains: HashMap<String, u64>,
    pub blocked_domains: HashMap<String, u64>,
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficBucket {
    pub minute: u64,
    pub queries: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamRequestStat {
    pub upstream: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamLatencyStat {
    pub upstream: String,
    pub avg_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub running: bool,
    pub listen_addr: String,
    pub upstream_dns: String,
    pub summary: RuleSummary,
    pub stats: DnsStats,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct CompiledRules {
    blocks: Vec<Rule>,
    allows: Vec<Rule>,
    summary: RuleSummary,
}

#[derive(Clone)]
struct Rule {
    domain: String,
    include_subdomains: bool,
}

struct UpstreamForwardResponse {
    response: Vec<u8>,
    upstream: String,
    duration_ms: u64,
}

pub struct DnsServer {
    listen_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DnsServer {
    pub fn start(
        config: AppConfig,
        rules_text: String,
        stats: Arc<Mutex<DnsStats>>,
        database: Arc<Database>,
    ) -> Result<Self, String> {
        config.validate()?;

        let listen_addr = config.listen_socket_addr()?;
        let upstream_servers = config.upstream_servers()?;
        let upstream_mode = config.upstream_mode.clone();
        let query_log_enabled = config.query_log_enabled;
        let anonymize_client_ip = config.anonymize_client_ip;
        let rules = compile_rules(&rules_text);
        let socket =
            UdpSocket::bind(listen_addr).map_err(|e| format!("监听 {listen_addr} 失败：{e}"))?;
        configure_udp_listener_socket(&socket)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| format!("设置 DNS 读取超时失败：{e}"))?;

        reset_stats(&stats);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_stats = Arc::clone(&stats);
        let thread = thread::spawn(move || {
            serve_udp(
                socket,
                upstream_servers,
                upstream_mode,
                rules,
                worker_stats,
                database,
                query_log_enabled,
                anonymize_client_ip,
                worker_stop,
            );
        });

        Ok(Self {
            listen_addr,
            stop,
            thread: Some(thread),
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
fn configure_udp_listener_socket(socket: &UdpSocket) -> Result<(), String> {
    use std::{ffi::c_void, io, os::windows::io::AsRawSocket, ptr};

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            _: usize,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: *mut u32,
            _: *mut c_void,
            _: *mut c_void,
        ) -> i32;
    }

    // Windows 默认会把 UDP ICMP reset 映射成下一次 recv_from 的 WSAECONNRESET。
    // DNS 监听端不应因为客户端端口关闭而中断接收循环，所以关闭该通知。
    let mut behavior = 0_u32;
    let mut bytes_returned = 0_u32;
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&mut behavior as *mut u32).cast::<c_void>(),
            std::mem::size_of_val(&behavior) as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "关闭 Windows UDP reset 通知失败：{}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(not(windows))]
fn configure_udp_listener_socket(_socket: &UdpSocket) -> Result<(), String> {
    Ok(())
}

pub fn summarize_rules(raw: &str) -> RuleSummary {
    compile_rules(raw).summary
}

pub fn compile_rules(raw: &str) -> CompiledRules {
    let mut blocks = Vec::new();
    let mut allows = Vec::new();
    let mut ignored_rules = 0;

    for line in raw.lines() {
        match parse_rule(line) {
            ParsedRule::Block(rule) => blocks.push(rule),
            ParsedRule::Allow(rule) => allows.push(rule),
            ParsedRule::Ignored => ignored_rules += 1,
        }
    }

    let summary = RuleSummary {
        block_rules: blocks.len(),
        allow_rules: allows.len(),
        ignored_rules,
    };

    CompiledRules {
        blocks,
        allows,
        summary,
    }
}

pub fn empty_status(
    config: &AppConfig,
    running: bool,
    summary: RuleSummary,
    stats: DnsStats,
    error: Option<String>,
) -> RuntimeStatus {
    let listen_addr = config
        .listen_socket_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| format!("{}:{}", config.listen_host, config.listen_port));

    RuntimeStatus {
        running,
        listen_addr,
        upstream_dns: config.upstream_dns.clone(),
        summary,
        stats,
        error,
    }
}

fn reset_stats(stats: &Arc<Mutex<DnsStats>>) {
    if let Ok(mut current) = stats.lock() {
        *current = DnsStats {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs()),
            ..DnsStats::default()
        };
    }
}

fn serve_udp(
    socket: UdpSocket,
    upstream_servers: Vec<UpstreamServer>,
    upstream_mode: UpstreamMode,
    rules: CompiledRules,
    stats: Arc<Mutex<DnsStats>>,
    database: Arc<Database>,
    query_log_enabled: bool,
    anonymize_client_ip: bool,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; 4096];
    let mut next_upstream = 0_usize;

    while !stop.load(Ordering::Relaxed) {
        let (len, client_addr) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                record_error(&stats, format!("接收 DNS 请求失败：{error}"));
                continue;
            }
        };

        if len == 0 {
            continue;
        }

        let query = &buffer[..len];
        let question = match parse_question(query) {
            Ok(question) => question,
            Err(error) => {
                record_error(&stats, error);
                continue;
            }
        };

        record_query(&stats, &question.domain);

        if rules.is_blocked(&question.domain) {
            let response = build_block_response(query, &question);
            if let Err(error) = socket.send_to(&response, client_addr) {
                let message = format!("返回黑名单响应失败：{error}");
                record_error(&stats, message.clone());
                write_query_log(
                    &database,
                    query_log_enabled,
                    anonymize_client_ip,
                    &question.domain,
                    client_addr,
                    true,
                    false,
                    true,
                    None,
                    None,
                    Some(message),
                );
                continue;
            }
            record_blocked(&stats, &question.domain);
            write_query_log(
                &database,
                query_log_enabled,
                anonymize_client_ip,
                &question.domain,
                client_addr,
                true,
                false,
                false,
                None,
                None,
                None,
            );
            continue;
        }

        match forward_query(query, &upstream_servers, &upstream_mode, &mut next_upstream) {
            Ok(forwarded) => {
                if let Err(error) = socket.send_to(&forwarded.response, client_addr) {
                    let message = format!("转发响应给客户端失败：{error}");
                    record_error(&stats, message.clone());
                    write_query_log(
                        &database,
                        query_log_enabled,
                        anonymize_client_ip,
                        &question.domain,
                        client_addr,
                        false,
                        true,
                        true,
                        Some(&forwarded.upstream),
                        Some(forwarded.duration_ms),
                        Some(message),
                    );
                } else {
                    record_forwarded(&stats);
                    write_query_log(
                        &database,
                        query_log_enabled,
                        anonymize_client_ip,
                        &question.domain,
                        client_addr,
                        false,
                        true,
                        false,
                        Some(&forwarded.upstream),
                        Some(forwarded.duration_ms),
                        None,
                    );
                }
            }
            Err(error) => {
                record_error(&stats, error.clone());
                write_query_log(
                    &database,
                    query_log_enabled,
                    anonymize_client_ip,
                    &question.domain,
                    client_addr,
                    false,
                    false,
                    true,
                    None,
                    None,
                    Some(error),
                );
            }
        }
    }
}

fn forward_query(
    query: &[u8],
    upstream_servers: &[UpstreamServer],
    mode: &UpstreamMode,
    next_upstream: &mut usize,
) -> Result<UpstreamForwardResponse, String> {
    match mode {
        UpstreamMode::LoadBalance => forward_load_balanced(query, upstream_servers, next_upstream),
        UpstreamMode::ParallelRequests => forward_parallel(query, upstream_servers),
        UpstreamMode::FastestAddr => forward_fastest_addr(query, upstream_servers),
    }
}

fn forward_load_balanced(
    query: &[u8],
    upstream_servers: &[UpstreamServer],
    next_upstream: &mut usize,
) -> Result<UpstreamForwardResponse, String> {
    let mut last_error = None;
    let server_count = upstream_servers.len();

    if server_count == 0 {
        return Err("没有可用的上游 DNS".into());
    }

    let start = *next_upstream % server_count;
    *next_upstream = (*next_upstream).wrapping_add(1);

    for offset in 0..server_count {
        let upstream = &upstream_servers[(start + offset) % server_count];
        let result = forward_to_upstream(query, upstream);

        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_parallel(
    query: &[u8],
    upstream_servers: &[UpstreamServer],
) -> Result<UpstreamForwardResponse, String> {
    if upstream_servers.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    for upstream in upstream_servers.iter().cloned() {
        let sender = sender.clone();
        let query = query.to_vec();
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(&query, &upstream));
        });
    }
    drop(sender);

    let mut last_error = None;
    for result in receiver.iter().take(upstream_servers.len()) {
        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_fastest_addr(
    query: &[u8],
    upstream_servers: &[UpstreamServer],
) -> Result<UpstreamForwardResponse, String> {
    if upstream_servers.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    for upstream in upstream_servers.iter().cloned() {
        let sender = sender.clone();
        let query = query.to_vec();
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(&query, &upstream));
        });
    }
    drop(sender);

    let mut responses = Vec::new();
    let mut last_error = None;
    for result in receiver.iter().take(upstream_servers.len()) {
        match result {
            Ok(response) => responses.push(response),
            Err(error) => last_error = Some(error),
        }
    }

    if responses.is_empty() {
        return Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()));
    }

    if let Some(index) = fastest_response_index(&responses) {
        return Ok(responses.swap_remove(index));
    }

    Ok(responses.remove(0))
}

fn fastest_response_index(responses: &[UpstreamForwardResponse]) -> Option<usize> {
    let mut best = None;

    for (index, response) in responses.iter().enumerate() {
        for ip in extract_response_ips(&response.response)
            .into_iter()
            .take(16)
        {
            let Some(duration) = measure_ip_latency(ip) else {
                continue;
            };
            let should_replace = match best {
                Some((_, best_duration)) => duration < best_duration,
                None => true,
            };
            if should_replace {
                best = Some((index, duration));
            }
        }
    }

    best.map(|(index, _)| index)
}

fn measure_ip_latency(ip: IpAddr) -> Option<Duration> {
    [443, 80]
        .into_iter()
        .filter_map(|port| {
            let addr = SocketAddr::new(ip, port);
            let start = Instant::now();
            TcpStream::connect_timeout(&addr, FASTEST_ADDR_CONNECT_TIMEOUT)
                .ok()
                .map(|_| start.elapsed())
        })
        .min()
}

fn forward_to_upstream(
    query: &[u8],
    upstream: &UpstreamServer,
) -> Result<UpstreamForwardResponse, String> {
    let started = Instant::now();
    let response = match upstream {
        UpstreamServer::Udp(addr) => forward_udp(query, *addr),
        UpstreamServer::Doh(url) => forward_doh(query, url),
    }?;
    Ok(UpstreamForwardResponse {
        response,
        upstream: format_upstream(upstream),
        duration_ms: duration_ms(started.elapsed()),
    })
}

fn format_upstream(upstream: &UpstreamServer) -> String {
    match upstream {
        UpstreamServer::Udp(addr) => addr.to_string(),
        UpstreamServer::Doh(url) => normalize_doh_upstream_label(url),
    }
}

fn normalize_doh_upstream_label(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return url.to_string(),
    };
    let slash_index = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash_index];
    if authority.contains(':') {
        return url.to_string();
    }
    format!(
        "{scheme}://{authority}:{default_port}{}",
        &rest[slash_index..]
    )
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn forward_udp(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, String> {
    let bind_addr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("创建上游 DNS UDP 连接失败：{e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("设置上游 DNS 超时失败：{e}"))?;
    socket
        .send_to(query, upstream_addr)
        .map_err(|e| format!("请求上游 DNS 失败：{e}"))?;

    let mut response = vec![0_u8; 4096];
    let len = socket
        .recv(&mut response)
        .map_err(|e| format!("读取上游 DNS 响应失败：{e}"))?;
    response.truncate(len);
    Ok(response)
}

fn forward_doh(query: &[u8], url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("DnsBlackhole/0.1")
        .build()
        .map_err(|e| format!("创建 DoH 客户端失败：{e}"))?;

    let response = client
        .post(url)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .body(query.to_vec())
        .send()
        .map_err(|e| format!("请求 DoH 上游失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("DoH 上游返回错误：{e}"))?;

    response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("读取 DoH 响应失败：{e}"))
}

impl CompiledRules {
    fn is_blocked(&self, domain: &str) -> bool {
        if self.allows.iter().any(|rule| rule.matches(domain)) {
            return false;
        }
        self.blocks.iter().any(|rule| rule.matches(domain))
    }
}

impl Rule {
    fn matches(&self, domain: &str) -> bool {
        if domain == self.domain {
            return true;
        }
        self.include_subdomains && domain.ends_with(&format!(".{}", self.domain))
    }
}

enum ParsedRule {
    Block(Rule),
    Allow(Rule),
    Ignored,
}

fn parse_rule(line: &str) -> ParsedRule {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedRule::Ignored;
    }

    if let Some(rule) = parse_hosts_rule(trimmed) {
        return ParsedRule::Block(rule);
    }

    parse_filter_rule(trimmed)
}

fn parse_hosts_rule(line: &str) -> Option<Rule> {
    let mut parts = line.split_whitespace();
    let ip = parts.next()?;
    let domain = parts.next()?;
    let is_block_ip = matches!(ip, "0.0.0.0" | "127.0.0.1" | "::" | "::1");
    if !is_block_ip {
        return None;
    }

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains: false,
    })
}

fn parse_filter_rule(line: &str) -> ParsedRule {
    let (is_allow, rest) = if let Some(value) = line.strip_prefix("@@") {
        (true, value)
    } else {
        (false, line)
    };

    let pattern = rest.split('$').next().unwrap_or(rest).trim();
    let Some(rule) = parse_pattern(pattern) else {
        return ParsedRule::Ignored;
    };

    if is_allow {
        ParsedRule::Allow(rule)
    } else {
        ParsedRule::Block(rule)
    }
}

fn parse_pattern(pattern: &str) -> Option<Rule> {
    if pattern.starts_with('/') && pattern.ends_with('/') {
        return None;
    }

    if let Some(rest) = pattern.strip_prefix("||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('|');
        return normalize_domain(domain).map(|domain| Rule {
            domain,
            include_subdomains: true,
        });
    }

    let domain = pattern
        .trim_matches('|')
        .trim_end_matches('^')
        .strip_prefix("*.")
        .unwrap_or_else(|| pattern.trim_matches('|').trim_end_matches('^'));
    let include_subdomains = pattern.starts_with("*.");

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains,
    })
}

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty() {
        return None;
    }
    if domain.contains('/') || domain.contains('*') || domain.contains(' ') {
        return None;
    }
    if !domain
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }

    Some(domain)
}

struct Question {
    domain: String,
    qtype: u16,
    question_end: usize,
}

fn parse_question(packet: &[u8]) -> Result<Question, String> {
    if packet.len() < DNS_HEADER_LEN {
        return Err("DNS 请求长度不足".into());
    }

    let question_count = read_u16(packet, 4).unwrap_or(0);
    if question_count == 0 {
        return Err("DNS 请求没有 question".into());
    }

    let mut offset = DNS_HEADER_LEN;
    let mut labels = Vec::new();

    loop {
        if offset >= packet.len() {
            return Err("DNS 域名解析越界".into());
        }

        let label_len = packet[offset] as usize;
        offset += 1;

        if label_len == 0 {
            break;
        }

        if label_len & 0b1100_0000 != 0 {
            return Err("暂不支持压缩格式的 DNS question".into());
        }

        if offset + label_len > packet.len() {
            return Err("DNS label 长度越界".into());
        }

        labels.push(String::from_utf8_lossy(&packet[offset..offset + label_len]).to_string());
        offset += label_len;
    }

    if offset + 4 > packet.len() {
        return Err("DNS question 缺少类型或类别".into());
    }

    let qtype = read_u16(packet, offset).ok_or("DNS qtype 读取失败")?;
    let question_end = offset + 4;
    let domain = labels.join(".").to_ascii_lowercase();

    Ok(Question {
        domain,
        qtype,
        question_end,
    })
}

fn build_block_response(query: &[u8], question: &Question) -> Vec<u8> {
    let answer_count = if matches!(question.qtype, TYPE_A | TYPE_AAAA) {
        1_u16
    } else {
        0_u16
    };
    let mut response = Vec::with_capacity(question.question_end + 32);

    response.extend_from_slice(&query[0..2]);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80);
    write_u16(&mut response, 1);
    write_u16(&mut response, answer_count);
    write_u16(&mut response, 0);
    write_u16(&mut response, 0);
    response.extend_from_slice(&query[DNS_HEADER_LEN..question.question_end]);

    if answer_count == 1 {
        response.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut response, question.qtype);
        write_u16(&mut response, 1);
        response.extend_from_slice(&60_u32.to_be_bytes());
        if question.qtype == TYPE_A {
            write_u16(&mut response, 4);
            response.extend_from_slice(&[0, 0, 0, 0]);
        } else {
            write_u16(&mut response, 16);
            response.extend_from_slice(&[0; 16]);
        }
    }

    response
}

fn extract_response_ips(packet: &[u8]) -> Vec<IpAddr> {
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

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let first = *bytes.get(offset)?;
    let second = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([first, second]))
}

fn write_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn record_query(stats: &Arc<Mutex<DnsStats>>, domain: &str) {
    if let Ok(mut current) = stats.lock() {
        current.queries += 1;
        current.last_query = Some(domain.to_string());
        *current.query_domains.entry(domain.to_string()).or_default() += 1;
        record_traffic(&mut current, false);
    }
}

fn record_blocked(stats: &Arc<Mutex<DnsStats>>, domain: &str) {
    if let Ok(mut current) = stats.lock() {
        current.blocked += 1;
        current.last_blocked = Some(domain.to_string());
        *current
            .blocked_domains
            .entry(domain.to_string())
            .or_default() += 1;
        record_traffic(&mut current, true);
    }
}

fn record_forwarded(stats: &Arc<Mutex<DnsStats>>) {
    if let Ok(mut current) = stats.lock() {
        current.forwarded += 1;
    }
}

fn record_error(stats: &Arc<Mutex<DnsStats>>, error: String) {
    if let Ok(mut current) = stats.lock() {
        current.failed += 1;
        current.last_error = Some(error);
    }
}

fn write_query_log(
    database: &Arc<Database>,
    enabled: bool,
    anonymize_client_ip: bool,
    domain: &str,
    client_addr: SocketAddr,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
) {
    if !enabled {
        return;
    }

    let entry = QueryLogEntry {
        domain: domain.to_string(),
        client_ip: Some(client_addr.ip().to_string()),
        blocked,
        forwarded,
        failed,
        upstream_server: upstream_server.map(str::to_string),
        upstream_duration_ms,
        error,
    };

    if let Err(error) = database.insert_query_log(&entry, anonymize_client_ip) {
        eprintln!("{error}");
    }
}

fn record_traffic(stats: &mut DnsStats, blocked: bool) {
    let minute = current_minute();
    let oldest_minute = minute.saturating_sub(TRAFFIC_BUCKET_WINDOW_MINUTES);
    stats
        .traffic
        .retain(|bucket| bucket.minute >= oldest_minute);

    let bucket = if let Some(bucket) = stats
        .traffic
        .iter_mut()
        .find(|bucket| bucket.minute == minute)
    {
        bucket
    } else {
        stats.traffic.push(TrafficBucket {
            minute,
            ..TrafficBucket::default()
        });
        stats
            .traffic
            .last_mut()
            .expect("traffic bucket should exist after push")
    };

    if blocked {
        bucket.blocked += 1;
    } else {
        bucket.queries += 1;
    }
}

fn current_minute() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 60)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adguard_style_rule_blocks_domain_and_subdomain() {
        let rules = compile_rules("||example.org^");

        assert!(rules.is_blocked("example.org"));
        assert!(rules.is_blocked("ads.example.org"));
        assert!(!rules.is_blocked("badexample.org"));
    }

    #[test]
    fn allow_rule_overrides_block_rule() {
        let rules = compile_rules("||example.org^\n@@||safe.example.org^");

        assert!(rules.is_blocked("track.example.org"));
        assert!(!rules.is_blocked("safe.example.org"));
        assert!(!rules.is_blocked("cdn.safe.example.org"));
    }

    #[test]
    fn hosts_style_rule_blocks_exact_domain_only() {
        let rules = compile_rules("0.0.0.0 example.org");

        assert!(rules.is_blocked("example.org"));
        assert!(!rules.is_blocked("www.example.org"));
    }

    #[test]
    fn block_response_returns_zero_address_for_a_query() {
        let query = a_query("blocked.test");
        let question = parse_question(&query).expect("query should parse");
        let response = build_block_response(&query, &question);

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn runtime_stats_record_domain_counts_and_traffic() {
        let stats = Arc::new(Mutex::new(DnsStats::default()));

        record_query(&stats, "ads.example.org");
        record_blocked(&stats, "ads.example.org");

        let current = stats.lock().expect("stats should lock");
        assert_eq!(current.queries, 1);
        assert_eq!(current.blocked, 1);
        assert_eq!(current.query_domains.get("ads.example.org"), Some(&1));
        assert_eq!(current.blocked_domains.get("ads.example.org"), Some(&1));
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

    fn a_query(domain: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
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
}
