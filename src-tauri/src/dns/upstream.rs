use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::config::{UpstreamMode, UpstreamServer};

use super::{
    protocol::{extract_response_ips, response_is_truncated, validate_response_for_query},
    stats::current_second,
};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_FAILURE_BACKOFF_SECONDS: u64 = 30;
const DOH_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FASTEST_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_millis(180);
const FASTEST_ADDR_MAX_IPS_PER_RESPONSE: usize = 8;
const FASTEST_ADDR_MAX_PROBES: usize = 32;
const MAX_PARALLEL_UPSTREAMS_PER_QUERY: usize = 8;
const DNSBLACKHOLE_USER_AGENT: &str = "DnsBlackhole/0.1";

#[derive(Clone)]
pub(crate) struct RuntimeUpstream {
    server: UpstreamServer,
    label: String,
    doh_client: Option<reqwest::blocking::Client>,
    unhealthy_until: Arc<AtomicU64>,
}

#[derive(Clone)]
pub(crate) struct UpstreamForwardResponse {
    pub(crate) response: Vec<u8>,
    pub(crate) upstream: String,
    pub(crate) duration_ms: u64,
}

struct IpLatencyProbe {
    response_index: usize,
    duration: Duration,
}

pub(crate) fn build_runtime_upstreams(
    upstream_servers: Vec<UpstreamServer>,
) -> Result<Vec<RuntimeUpstream>, String> {
    upstream_servers
        .into_iter()
        .map(RuntimeUpstream::new)
        .collect()
}

impl RuntimeUpstream {
    pub(crate) fn new(server: UpstreamServer) -> Result<Self, String> {
        let label = format_upstream_server(&server);
        let doh_client = match &server {
            UpstreamServer::Udp(_) => None,
            UpstreamServer::Doh(_) => Some(build_doh_client()?),
        };

        Ok(Self {
            server,
            label,
            doh_client,
            unhealthy_until: Arc::new(AtomicU64::new(0)),
        })
    }
}

fn build_doh_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .connect_timeout(UPSTREAM_TIMEOUT)
        .pool_idle_timeout(Some(DOH_CLIENT_POOL_IDLE_TIMEOUT))
        .pool_max_idle_per_host(2)
        .user_agent(DNSBLACKHOLE_USER_AGENT)
        .build()
        .map_err(|e| format!("创建 DoH 客户端失败：{e}"))
}

pub(crate) fn forward_query(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
) -> Result<UpstreamForwardResponse, String> {
    match mode {
        UpstreamMode::LoadBalance => forward_load_balanced(query, upstream_servers, next_upstream),
        UpstreamMode::ParallelRequests => forward_parallel(query, upstream_servers),
        UpstreamMode::FastestAddr => forward_fastest_addr(query, upstream_servers),
    }
}

fn forward_load_balanced(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    next_upstream: &AtomicUsize,
) -> Result<UpstreamForwardResponse, String> {
    let mut last_error = None;
    let server_count = upstream_servers.len();

    if server_count == 0 {
        return Err("没有可用的上游 DNS".into());
    }

    let start = next_upstream.fetch_add(1, Ordering::Relaxed) % server_count;
    let now = current_second();
    let mut skipped_unhealthy = false;

    for pass in 0..2 {
        for offset in 0..server_count {
            let upstream = &upstream_servers[(start + offset) % server_count];
            let unhealthy = is_upstream_temporarily_unhealthy(upstream, now);
            if pass == 0 && unhealthy {
                skipped_unhealthy = true;
                continue;
            }
            if pass == 1 && !unhealthy {
                continue;
            }

            match forward_to_upstream(query, upstream) {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
        }

        if !skipped_unhealthy {
            break;
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_parallel(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
) -> Result<UpstreamForwardResponse, String> {
    let selected_upstreams = select_parallel_upstreams(upstream_servers);
    if selected_upstreams.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    for upstream in &selected_upstreams {
        let upstream = upstream.clone();
        let sender = sender.clone();
        let query = Arc::clone(&query);
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(query.as_ref().as_slice(), &upstream));
        });
    }
    drop(sender);

    let mut last_error = None;
    for result in receiver.iter().take(selected_upstreams.len()) {
        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| "没有可用的上游 DNS".into()))
}

fn forward_fastest_addr(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
) -> Result<UpstreamForwardResponse, String> {
    let selected_upstreams = select_parallel_upstreams(upstream_servers);
    if selected_upstreams.is_empty() {
        return Err("没有可用的上游 DNS".into());
    }

    let (sender, receiver) = mpsc::channel();
    let query = Arc::new(query.to_vec());
    for upstream in &selected_upstreams {
        let upstream = upstream.clone();
        let sender = sender.clone();
        let query = Arc::clone(&query);
        thread::spawn(move || {
            let _ = sender.send(forward_to_upstream(query.as_ref().as_slice(), &upstream));
        });
    }
    drop(sender);

    let mut responses = Vec::new();
    let mut last_error = None;
    for result in receiver.iter().take(selected_upstreams.len()) {
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

fn select_parallel_upstreams(upstream_servers: &[RuntimeUpstream]) -> Vec<RuntimeUpstream> {
    let now = current_second();
    let mut selected = upstream_servers
        .iter()
        .filter(|upstream| !is_upstream_temporarily_unhealthy(upstream, now))
        .take(MAX_PARALLEL_UPSTREAMS_PER_QUERY)
        .cloned()
        .collect::<Vec<_>>();

    if selected.is_empty() {
        selected = upstream_servers
            .iter()
            .take(MAX_PARALLEL_UPSTREAMS_PER_QUERY)
            .cloned()
            .collect();
    }

    selected
}

fn fastest_response_index(responses: &[UpstreamForwardResponse]) -> Option<usize> {
    let candidates = responses
        .iter()
        .enumerate()
        .flat_map(|(index, response)| {
            extract_response_ips(&response.response)
                .into_iter()
                .take(FASTEST_ADDR_MAX_IPS_PER_RESPONSE)
                .map(move |ip| (index, ip))
        })
        .take(FASTEST_ADDR_MAX_PROBES)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return None;
    }

    let (sender, receiver) = mpsc::channel();
    for (response_index, ip) in candidates {
        let sender = sender.clone();
        thread::spawn(move || {
            if let Some(duration) = measure_ip_latency(ip) {
                let _ = sender.send(IpLatencyProbe {
                    response_index,
                    duration,
                });
            }
        });
    }
    drop(sender);

    receiver
        .into_iter()
        .min_by_key(|probe| probe.duration)
        .map(|probe| probe.response_index)
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
    upstream: &RuntimeUpstream,
) -> Result<UpstreamForwardResponse, String> {
    let started = Instant::now();
    let response = match &upstream.server {
        UpstreamServer::Udp(addr) => forward_udp(query, *addr),
        UpstreamServer::Doh(url) => {
            let client = upstream
                .doh_client
                .as_ref()
                .ok_or_else(|| "DoH 客户端未初始化".to_string())?;
            forward_doh(query, url, client)
        }
    };
    let response = match response {
        Ok(response) => {
            if let Err(error) = validate_response_for_query(query, &response) {
                mark_upstream_unhealthy(upstream);
                return Err(format!("上游 {} 响应无效：{error}", upstream.label));
            }
            mark_upstream_available(upstream);
            response
        }
        Err(error) => {
            mark_upstream_unhealthy(upstream);
            return Err(error);
        }
    };
    Ok(UpstreamForwardResponse {
        response,
        upstream: format_upstream(upstream),
        duration_ms: duration_ms(started.elapsed()),
    })
}

pub(crate) fn is_upstream_temporarily_unhealthy(upstream: &RuntimeUpstream, now: u64) -> bool {
    upstream.unhealthy_until.load(Ordering::Relaxed) > now
}

pub(crate) fn mark_upstream_available(upstream: &RuntimeUpstream) {
    upstream.unhealthy_until.store(0, Ordering::Relaxed);
}

pub(crate) fn mark_upstream_unhealthy(upstream: &RuntimeUpstream) {
    upstream.unhealthy_until.store(
        current_second().saturating_add(UPSTREAM_FAILURE_BACKOFF_SECONDS),
        Ordering::Relaxed,
    );
}

fn format_upstream(upstream: &RuntimeUpstream) -> String {
    upstream.label.clone()
}

fn format_upstream_server(server: &UpstreamServer) -> String {
    match server {
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
        .set_read_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS 超时失败：{e}"))?;
    socket
        .connect(upstream_addr)
        .map_err(|e| format!("连接上游 DNS 失败：{e}"))?;
    socket
        .send(query)
        .map_err(|e| format!("请求上游 DNS 失败：{e}"))?;

    let mut response = vec![0_u8; 4096];
    let len = socket
        .recv(&mut response)
        .map_err(|e| format!("读取上游 DNS 响应失败：{e}"))?;
    response.truncate(len);
    if response_is_truncated(&response) {
        return forward_tcp(query, upstream_addr);
    }

    Ok(response)
}

fn forward_tcp(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, String> {
    let query_len =
        u16::try_from(query.len()).map_err(|_| "DNS TCP 请求长度超过 65535 字节".to_string())?;
    let mut stream = TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT)
        .map_err(|e| format!("创建上游 DNS TCP 连接失败：{e}"))?;
    stream
        .set_read_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS TCP 读取超时失败：{e}"))?;
    stream
        .set_write_timeout(Some(UPSTREAM_TIMEOUT))
        .map_err(|e| format!("设置上游 DNS TCP 写入超时失败：{e}"))?;

    stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|_| stream.write_all(query))
        .map_err(|e| format!("请求上游 DNS TCP 失败：{e}"))?;

    let mut len_buf = [0_u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("读取上游 DNS TCP 响应长度失败：{e}"))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len == 0 {
        return Err("上游 DNS TCP 返回空响应".to_string());
    }

    let mut response = vec![0_u8; response_len];
    stream
        .read_exact(&mut response)
        .map_err(|e| format!("读取上游 DNS TCP 响应失败：{e}"))?;
    Ok(response)
}

fn forward_doh(
    query: &[u8],
    url: &str,
    client: &reqwest::blocking::Client,
) -> Result<Vec<u8>, String> {
    let mut request_body = query.to_vec();
    if request_body.len() >= 2 {
        request_body[0] = 0;
        request_body[1] = 0;
    }

    let response = client
        .post(url)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .body(request_body)
        .send()
        .map_err(|e| format!("请求 DoH 上游失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("DoH 上游返回错误：{e}"))?;

    response
        .bytes()
        .map(|bytes| {
            let mut response = bytes.to_vec();
            if response.len() >= 2 && query.len() >= 2 {
                response[0..2].copy_from_slice(&query[0..2]);
            }
            response
        })
        .map_err(|e| format!("读取 DoH 响应失败：{e}"))
}
