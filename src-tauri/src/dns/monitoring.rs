use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::json;

use crate::config::AppConfig;

use super::stats::DnsStats;

const MAX_REQUEST_BYTES: usize = 8192;

pub(crate) struct PreparedMonitoringListener {
    listener: TcpListener,
    token: String,
}

pub(crate) fn prepare(config: &AppConfig) -> Result<Option<PreparedMonitoringListener>, String> {
    if !config.monitoring_api_enabled {
        return Ok(None);
    }
    let addr = config.monitoring_api_socket_addr()?;
    let listener =
        TcpListener::bind(addr).map_err(|error| format!("启动监控接口 {addr} 失败：{error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("设置监控接口为非阻塞模式失败：{error}"))?;
    Ok(Some(PreparedMonitoringListener {
        listener,
        token: config.monitoring_api_token.trim().to_string(),
    }))
}

pub(crate) fn spawn(
    prepared: PreparedMonitoringListener,
    stats: Arc<Mutex<DnsStats>>,
    protection_paused_until: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match prepared.listener.accept() {
                Ok((stream, _)) => {
                    handle_connection(stream, &prepared.token, &stats, &protection_paused_until)
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
    })
}

fn handle_connection(
    mut stream: TcpStream,
    token: &str,
    stats: &Arc<Mutex<DnsStats>>,
    protection_paused_until: &Arc<AtomicU64>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0_u8; MAX_REQUEST_BYTES];
    let Ok(length) = stream.read(&mut buffer) else {
        return;
    };
    let Ok(request) = std::str::from_utf8(&buffer[..length]) else {
        write_response(
            &mut stream,
            400,
            "text/plain; charset=utf-8",
            "请求编码无效\n",
        );
        return;
    };
    let Some(first_line) = request.lines().next() else {
        write_response(&mut stream, 400, "text/plain; charset=utf-8", "请求为空\n");
        return;
    };
    let mut request_parts = first_line.split_whitespace();
    if request_parts.next() != Some("GET") {
        write_response(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            "仅支持 GET\n",
        );
        return;
    }
    let path = request_parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    if !token.is_empty() && !request_is_authorized(request, token) {
        write_response(
            &mut stream,
            401,
            "application/json; charset=utf-8",
            "{\"error\":\"unauthorized\"}\n",
        );
        return;
    }

    let snapshot = stats
        .lock()
        .map(|current| current.clone())
        .unwrap_or_default();
    match path {
        "/health" => write_response(
            &mut stream,
            200,
            "application/json; charset=utf-8",
            "{\"status\":\"ok\"}\n",
        ),
        "/api/v1/status" => {
            let now = super::stats::current_second();
            let paused_until = protection_paused_until.load(Ordering::Acquire);
            let body = json!({
                "running": true,
                "protection_paused": paused_until > now,
                "protection_paused_until": (paused_until > now).then_some(paused_until),
                "started_at": snapshot.started_at,
                "queries": snapshot.queries,
                "blocked": snapshot.blocked,
                "forwarded": snapshot.forwarded,
                "failed": snapshot.failed,
                "cache_hits": snapshot.cache_hits,
                "cache_misses": snapshot.cache_misses,
            })
            .to_string();
            write_response(
                &mut stream,
                200,
                "application/json; charset=utf-8",
                &(body + "\n"),
            );
        }
        "/metrics" => write_response(
            &mut stream,
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            &prometheus_metrics(&snapshot),
        ),
        _ => write_response(
            &mut stream,
            404,
            "application/json; charset=utf-8",
            "{\"error\":\"not_found\"}\n",
        ),
    }
}

fn request_is_authorized(request: &str, token: &str) -> bool {
    request.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        let value = value.trim();
        (name.eq_ignore_ascii_case("authorization")
            && value
                .strip_prefix("Bearer ")
                .is_some_and(|value| secure_eq(value, token)))
            || (name.eq_ignore_ascii_case("x-api-token") && secure_eq(value, token))
    })
}

fn secure_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn prometheus_metrics(stats: &DnsStats) -> String {
    format!(
        concat!(
            "# HELP dnsblackhole_queries_total Total DNS queries processed.\n",
            "# TYPE dnsblackhole_queries_total counter\n",
            "dnsblackhole_queries_total {}\n",
            "# HELP dnsblackhole_blocked_total Total DNS queries blocked.\n",
            "# TYPE dnsblackhole_blocked_total counter\n",
            "dnsblackhole_blocked_total {}\n",
            "# HELP dnsblackhole_forwarded_total Total DNS queries forwarded upstream.\n",
            "# TYPE dnsblackhole_forwarded_total counter\n",
            "dnsblackhole_forwarded_total {}\n",
            "# HELP dnsblackhole_failed_total Total failed DNS operations.\n",
            "# TYPE dnsblackhole_failed_total counter\n",
            "dnsblackhole_failed_total {}\n",
            "# TYPE dnsblackhole_cache_hits_total counter\n",
            "dnsblackhole_cache_hits_total {}\n",
            "# TYPE dnsblackhole_cache_misses_total counter\n",
            "dnsblackhole_cache_misses_total {}\n",
            "# TYPE dnsblackhole_access_denied_total counter\n",
            "dnsblackhole_access_denied_total {}\n",
            "# TYPE dnsblackhole_rate_limited_total counter\n",
            "dnsblackhole_rate_limited_total {}\n",
            "# TYPE dnsblackhole_cache_entries gauge\n",
            "dnsblackhole_cache_entries {}\n",
            "# TYPE dnsblackhole_cache_bytes gauge\n",
            "dnsblackhole_cache_bytes {}\n"
        ),
        stats.queries,
        stats.blocked,
        stats.forwarded,
        stats.failed,
        stats.cache_hits,
        stats.cache_misses,
        stats.access_denied_total,
        stats.rate_limited_total,
        stats.cache_entries,
        stats.cache_bytes,
    )
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_headers_are_validated() {
        assert!(request_is_authorized(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer secret-token-1234\r\n\r\n",
            "secret-token-1234"
        ));
        assert!(request_is_authorized(
            "GET /metrics HTTP/1.1\r\nX-API-Token: secret-token-1234\r\n\r\n",
            "secret-token-1234"
        ));
        assert!(!request_is_authorized(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
            "secret-token-1234"
        ));
    }

    #[test]
    fn metrics_do_not_expose_domains_or_clients() {
        let stats = DnsStats {
            queries: 12,
            blocked: 3,
            last_query: Some("private.example".into()),
            ..DnsStats::default()
        };
        let metrics = prometheus_metrics(&stats);
        assert!(metrics.contains("dnsblackhole_queries_total 12"));
        assert!(!metrics.contains("private.example"));
    }
}
