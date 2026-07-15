use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use crate::{config::UpstreamMode, database::QueryLogEntry};

use super::{
    access::{ClientAccess, ClientAccessDecision},
    cache::{
        DnsCacheConfig, DnsCacheStore, QueryCacheKey, insert_cached_response,
        lookup_cached_response,
    },
    filter_runtime::{FilterRuntime, SharedFilterRuntime, current_filter_runtime},
    protocol::{
        RCODE_REFUSED, TYPE_ANY, build_block_response, build_error_response,
        build_rewrite_response, parse_question,
    },
    stats::{
        DnsStats, DnsTransport, current_second, record_access_denied, record_blocked_query,
        record_error, record_forwarded, record_query, record_rate_limited, record_refused_any,
    },
    task_pool,
    upstream::{RuntimeUpstream, UpstreamForwardResponse, forward_query},
};

const WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(200);
const PENDING_QUERY_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const PENDING_QUERY_SHARDS: usize = 64;

pub(crate) struct DnsWorkItem {
    pub(crate) query: Vec<u8>,
    pub(crate) client_addr: SocketAddr,
    pub(crate) response_target: DnsResponseTarget,
}

pub(crate) enum DnsResponseTarget {
    Udp {
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
    },
    Tcp(mpsc::SyncSender<Option<Vec<u8>>>),
}

pub(crate) struct DnsWorkerContext {
    pub(crate) upstream_servers: Arc<Vec<RuntimeUpstream>>,
    pub(crate) fallback_upstream_servers: Arc<Vec<RuntimeUpstream>>,
    pub(crate) upstream_mode: UpstreamMode,
    pub(crate) next_upstream: AtomicUsize,
    pub(crate) fallback_next_upstream: AtomicUsize,
    pub(crate) access: Arc<ClientAccess>,
    pub(crate) refuse_any: bool,
    pub(crate) filter_runtime: SharedFilterRuntime,
    pub(crate) stats: Arc<Mutex<DnsStats>>,
    pub(crate) dns_cache: Option<Arc<DnsCacheStore>>,
    pub(crate) dns_cache_config: Option<DnsCacheConfig>,
    pub(crate) pending_queries: Arc<PendingQueries>,
    pub(crate) query_log_sender: Option<mpsc::SyncSender<QueryLogMessage>>,
    pub(crate) anonymize_client_ip: bool,
    pub(crate) detailed_runtime_stats: bool,
}

pub(crate) struct QueryLogMessage {
    pub(crate) entry: QueryLogEntry,
    pub(crate) anonymize_client_ip: bool,
}

type PendingQuery = Arc<PendingQueryState>;

struct PendingQueryState {
    result: Mutex<Option<Result<UpstreamForwardResponse, String>>>,
    ready: Condvar,
}

enum PendingQueryRole {
    Leader(PendingQuery),
    Follower(PendingQuery),
}

pub(crate) struct PendingQueries {
    shards: Vec<Mutex<HashMap<QueryCacheKey, PendingQuery>>>,
}

impl PendingQueries {
    pub(crate) fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Mutex::new(HashMap::new()));
        }

        Self { shards }
    }

    fn begin(&self, cache_key: &QueryCacheKey) -> PendingQueryRole {
        let shard_index = self.shard_index(cache_key);
        if let Some(shard) = self.shards.get(shard_index)
            && let Ok(mut pending_queries) = shard.lock()
        {
            if let Some(pending_query) = pending_queries.get(cache_key) {
                return PendingQueryRole::Follower(Arc::clone(pending_query));
            }

            let pending_query = new_pending_query();
            pending_queries.insert(cache_key.clone(), Arc::clone(&pending_query));
            return PendingQueryRole::Leader(pending_query);
        }

        PendingQueryRole::Leader(new_pending_query())
    }

    fn finish(&self, cache_key: &QueryCacheKey, pending_query: &PendingQuery) {
        let shard_index = self.shard_index(cache_key);
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let Ok(mut pending_queries) = shard.lock() else {
            return;
        };

        let should_remove = pending_queries
            .get(cache_key)
            .is_some_and(|current| Arc::ptr_eq(current, pending_query));
        if should_remove {
            pending_queries.remove(cache_key);
        }
    }

    fn shard_index(&self, cache_key: &QueryCacheKey) -> usize {
        query_cache_key_shard_index(cache_key, self.shards.len())
    }
}

fn query_cache_key_shard_index(cache_key: &QueryCacheKey, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    (hasher.finish() % shard_count.max(1) as u64) as usize
}

fn new_pending_query() -> PendingQuery {
    Arc::new(PendingQueryState {
        result: Mutex::new(None),
        ready: Condvar::new(),
    })
}

pub(crate) fn dns_worker_loop(
    receiver: mpsc::Receiver<DnsWorkItem>,
    context: Arc<DnsWorkerContext>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let work_item = match receiver.recv_timeout(WORKER_RECV_TIMEOUT) {
            Ok(work_item) => work_item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        handle_dns_query(&context, work_item);
    }
}

fn handle_dns_query(context: &DnsWorkerContext, work_item: DnsWorkItem) {
    let query = work_item.query.as_slice();
    let client_addr = work_item.client_addr;
    let response_target = &work_item.response_target;

    match context.access.check(client_addr.ip(), current_second()) {
        ClientAccessDecision::Allow => {}
        ClientAccessDecision::Deny(message) => {
            record_access_denied(
                &context.stats,
                client_addr.ip(),
                response_transport(response_target),
                message.clone(),
            );
            send_refused_or_drop(context, response_target, query, message);
            return;
        }
        ClientAccessDecision::RateLimited(message) => {
            record_rate_limited(
                &context.stats,
                client_addr.ip(),
                response_transport(response_target),
                message.clone(),
            );
            send_refused_or_drop(context, response_target, query, message);
            return;
        }
    }

    let question = match parse_question(query) {
        Ok(question) => question,
        Err(error) => {
            record_error(&context.stats, error);
            send_no_response(response_target);
            return;
        }
    };

    // 整包读取当前过滤状态，一次查询内保持一致；规则热替换只影响后续查询
    let filter = current_filter_runtime(&context.filter_runtime);

    if context.refuse_any && question.qtype == TYPE_ANY {
        record_query(
            &context.stats,
            &question.domain,
            context.detailed_runtime_stats,
        );
        let message = format!("已拒绝 ANY 查询：{}", question.domain);
        let response = build_error_response(query, RCODE_REFUSED);
        match response {
            Some(response) => {
                if let Err(error) = send_dns_response(response_target, &response) {
                    let message = format!("返回 ANY 拒绝响应失败：{error}");
                    record_error(&context.stats, message.clone());
                    queue_query_log(
                        context,
                        &filter,
                        &question.domain,
                        client_addr,
                        false,
                        false,
                        true,
                        None,
                        None,
                        Some(message),
                    );
                    return;
                }
            }
            None => send_no_response(response_target),
        }
        record_refused_any(&context.stats);
        queue_query_log(
            context,
            &filter,
            &question.domain,
            client_addr,
            false,
            false,
            false,
            None,
            None,
            Some(message),
        );
        return;
    }

    // 本地 DNS 重写优先于黑名单，保证局域网自定义记录不被清单误拦
    if !filter.rewrites.is_empty()
        && let Some(target) = filter.rewrites.lookup(&question.domain)
    {
        record_query(
            &context.stats,
            &question.domain,
            context.detailed_runtime_stats,
        );
        let response = build_rewrite_response(query, &question, &target);
        if let Err(error) = send_dns_response(response_target, &response) {
            let message = format!("返回 DNS 重写响应失败：{error}");
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &filter,
                &question.domain,
                client_addr,
                false,
                false,
                true,
                None,
                None,
                Some(message),
            );
        } else {
            queue_query_log(
                context,
                &filter,
                &question.domain,
                client_addr,
                false,
                false,
                false,
                None,
                None,
                None,
            );
        }
        return;
    }

    if let Some(rule_match) = filter
        .rules
        .blocking_match(&question.domain, question.qtype)
    {
        let response = build_block_response(query, &question, &filter.blocking);
        if let Err(error) = send_dns_response(response_target, &response) {
            let message = format!("返回黑名单响应失败：{error}");
            record_query(
                &context.stats,
                &question.domain,
                context.detailed_runtime_stats,
            );
            record_error(&context.stats, message.clone());
            queue_blocked_query_log(
                context,
                &filter,
                &question.domain,
                client_addr,
                true,
                Some(message),
                &rule_match,
            );
            return;
        }
        record_blocked_query(
            &context.stats,
            &question.domain,
            context.detailed_runtime_stats,
        );
        queue_blocked_query_log(
            context,
            &filter,
            &question.domain,
            client_addr,
            false,
            None,
            &rule_match,
        );
        return;
    }

    record_query(
        &context.stats,
        &question.domain,
        context.detailed_runtime_stats,
    );

    let cache_key = QueryCacheKey::from_question(&question);
    if let Some(cache_hit) =
        lookup_cached_response(&context.dns_cache, &cache_key, query, current_second())
    {
        if let Err(error) = send_dns_response(response_target, &cache_hit.response) {
            let message = format!("返回 DNS 缓存响应失败：{error}");
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &filter,
                &question.domain,
                client_addr,
                false,
                false,
                true,
                None,
                None,
                Some(message),
            );
        } else {
            queue_query_log(
                context,
                &filter,
                &question.domain,
                client_addr,
                false,
                false,
                false,
                None,
                Some(0),
                None,
            );
            if cache_hit.refresh {
                refresh_expired_cache_async(
                    work_item.query,
                    cache_key,
                    Arc::clone(&context.upstream_servers),
                    Arc::clone(&context.fallback_upstream_servers),
                    context.upstream_mode.clone(),
                    context.dns_cache.clone(),
                    context.dns_cache_config.clone(),
                );
            }
        }
        return;
    }

    let pending_query = match begin_pending_query(context, &cache_key) {
        PendingQueryRole::Leader(pending_query) => pending_query,
        PendingQueryRole::Follower(pending_query) => {
            match wait_pending_query(&pending_query) {
                Ok(forwarded) => {
                    let response = prepare_forwarded_response(&forwarded.response, query);
                    if let Err(error) = send_dns_response(response_target, &response) {
                        let message = format!("转发复用响应给客户端失败：{error}");
                        record_error(&context.stats, message.clone());
                        queue_query_log(
                            context,
                            &filter,
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
                        queue_query_log(
                            context,
                            &filter,
                            &question.domain,
                            client_addr,
                            false,
                            false,
                            false,
                            Some(&forwarded.upstream),
                            Some(forwarded.duration_ms),
                            None,
                        );
                    }
                }
                Err(error) => {
                    record_error(&context.stats, error.clone());
                    send_no_response(response_target);
                    queue_query_log(
                        context,
                        &filter,
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
            return;
        }
    };

    let forward_result = forward_query_with_fallback(
        query,
        context.upstream_servers.as_ref(),
        context.fallback_upstream_servers.as_ref(),
        &context.upstream_mode,
        &context.next_upstream,
        &context.fallback_next_upstream,
    );
    finish_pending_query(context, &cache_key, &pending_query, forward_result.clone());

    match forward_result {
        Ok(forwarded) => {
            insert_cached_response(
                &context.dns_cache,
                context.dns_cache_config.as_ref(),
                cache_key,
                forwarded.response.clone(),
                current_second(),
            );
            if let Err(error) = send_dns_response(response_target, &forwarded.response) {
                let message = format!("转发响应给客户端失败：{error}");
                record_error(&context.stats, message.clone());
                queue_query_log(
                    context,
                    &filter,
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
                record_forwarded(&context.stats, context.detailed_runtime_stats);
                queue_query_log(
                    context,
                    &filter,
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
            record_error(&context.stats, error.clone());
            send_no_response(response_target);
            queue_query_log(
                context,
                &filter,
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

fn response_transport(response_target: &DnsResponseTarget) -> DnsTransport {
    match response_target {
        DnsResponseTarget::Udp { .. } => DnsTransport::Udp,
        DnsResponseTarget::Tcp(_) => DnsTransport::Tcp,
    }
}

fn send_refused_or_drop(
    context: &DnsWorkerContext,
    response_target: &DnsResponseTarget,
    query: &[u8],
    message: String,
) {
    match response_target {
        DnsResponseTarget::Udp { .. } => {}
        DnsResponseTarget::Tcp(_) => {
            let Some(response) = build_error_response(query, RCODE_REFUSED) else {
                send_no_response(response_target);
                return;
            };
            if let Err(error) = send_dns_response(response_target, &response) {
                record_error(
                    &context.stats,
                    format!("{message}；返回拒绝响应失败：{error}"),
                );
            }
        }
    }
}

fn send_dns_response(response_target: &DnsResponseTarget, response: &[u8]) -> Result<(), String> {
    match response_target {
        DnsResponseTarget::Udp {
            socket,
            client_addr,
        } => socket
            .send_to(response, *client_addr)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        DnsResponseTarget::Tcp(sender) => sender
            .try_send(Some(response.to_vec()))
            .map_err(|error| error.to_string()),
    }
}

fn send_no_response(response_target: &DnsResponseTarget) {
    if let DnsResponseTarget::Tcp(sender) = response_target {
        let _ = sender.try_send(None);
    }
}

fn begin_pending_query(context: &DnsWorkerContext, cache_key: &QueryCacheKey) -> PendingQueryRole {
    context.pending_queries.begin(cache_key)
}

fn finish_pending_query(
    context: &DnsWorkerContext,
    cache_key: &QueryCacheKey,
    pending_query: &PendingQuery,
    result: Result<UpstreamForwardResponse, String>,
) {
    if let Ok(mut current) = pending_query.result.lock() {
        *current = Some(result);
        pending_query.ready.notify_all();
    }

    context.pending_queries.finish(cache_key, pending_query);
}

fn wait_pending_query(pending_query: &PendingQuery) -> Result<UpstreamForwardResponse, String> {
    let result = pending_query
        .result
        .lock()
        .map_err(|_| "等待重复 DNS 请求结果失败".to_string())?;
    let (result, timeout) = pending_query
        .ready
        .wait_timeout_while(result, PENDING_QUERY_WAIT_TIMEOUT, |result| {
            result.is_none()
        })
        .map_err(|_| "等待重复 DNS 请求结果失败".to_string())?;

    if timeout.timed_out() && result.is_none() {
        return Err("等待重复 DNS 请求结果超时".to_string());
    }

    result
        .as_ref()
        .cloned()
        .unwrap_or_else(|| Err("重复 DNS 请求没有可用结果".to_string()))
}

fn forward_query_with_fallback(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    fallback_upstream_servers: &[RuntimeUpstream],
    upstream_mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
    fallback_next_upstream: &AtomicUsize,
) -> Result<UpstreamForwardResponse, String> {
    match forward_query(query, upstream_servers, upstream_mode, next_upstream) {
        Ok(response) => Ok(response),
        Err(primary_error) => {
            if fallback_upstream_servers.is_empty() {
                return Err(primary_error);
            }

            forward_query(
                query,
                fallback_upstream_servers,
                upstream_mode,
                fallback_next_upstream,
            )
            .map_err(|fallback_error| {
                format!("主上游失败：{primary_error}；fallback 上游也失败：{fallback_error}")
            })
        }
    }
}

pub(crate) fn prepare_forwarded_response(response: &[u8], query: &[u8]) -> Vec<u8> {
    let mut response = response.to_vec();
    if response.len() >= 2 && query.len() >= 2 {
        response[0..2].copy_from_slice(&query[0..2]);
    }
    response
}

fn refresh_expired_cache_async(
    query: Vec<u8>,
    cache_key: QueryCacheKey,
    upstream_servers: Arc<Vec<RuntimeUpstream>>,
    fallback_upstream_servers: Arc<Vec<RuntimeUpstream>>,
    upstream_mode: UpstreamMode,
    dns_cache: Option<Arc<DnsCacheStore>>,
    dns_cache_config: Option<DnsCacheConfig>,
) {
    let Some(cache) = dns_cache else {
        return;
    };
    let Some(cache_config) = dns_cache_config else {
        return;
    };

    task_pool::spawn_task(move || {
        let next_upstream = AtomicUsize::new(0);
        let fallback_next_upstream = AtomicUsize::new(0);
        match forward_query_with_fallback(
            &query,
            upstream_servers.as_ref(),
            fallback_upstream_servers.as_ref(),
            &upstream_mode,
            &next_upstream,
            &fallback_next_upstream,
        ) {
            Ok(forwarded) => {
                let cache_for_insert = Some(Arc::clone(&cache));
                insert_cached_response(
                    &cache_for_insert,
                    Some(&cache_config),
                    cache_key,
                    forwarded.response,
                    current_second(),
                );
            }
            Err(_) => {
                cache.finish_refresh(&cache_key);
            }
        }
    });
}

fn queue_query_log(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    domain: &str,
    client_addr: SocketAddr,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
) {
    queue_query_log_with_match(
        context,
        filter,
        domain,
        client_addr,
        blocked,
        forwarded,
        failed,
        upstream_server,
        upstream_duration_ms,
        error,
        None,
    );
}

fn queue_blocked_query_log(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    domain: &str,
    client_addr: SocketAddr,
    failed: bool,
    error: Option<String>,
    rule_match: &super::rules::BlockMatch,
) {
    queue_query_log_with_match(
        context,
        filter,
        domain,
        client_addr,
        true,
        false,
        failed,
        None,
        None,
        error,
        Some(rule_match),
    );
}

#[allow(clippy::too_many_arguments)]
fn queue_query_log_with_match(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    domain: &str,
    client_addr: SocketAddr,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
    rule_match: Option<&super::rules::BlockMatch>,
) {
    if filter.log_ignore.contains(domain) {
        return;
    }
    let Some(sender) = &context.query_log_sender else {
        return;
    };

    let entry = QueryLogEntry {
        domain: domain.to_string(),
        client_ip: Some(client_addr.ip().to_string()),
        blocked,
        forwarded,
        failed,
        upstream_server: upstream_server.map(str::to_string),
        upstream_duration_ms,
        error,
        matched_rule: rule_match.map(|matched| matched.rule.clone()),
        rule_source: rule_match.map(|matched| matched.source.clone()),
        rule_type: rule_match.map(|matched| matched.rule_type.clone()),
        important_overrode: rule_match.is_some_and(|matched| matched.important_overrode),
        allowlist_rule: rule_match.and_then(|matched| matched.allowlist_rule.clone()),
    };

    let message = QueryLogMessage {
        entry,
        anonymize_client_ip: context.anonymize_client_ip,
    };
    match sender.try_send(message) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            record_error(&context.stats, "查询日志队列已满，已丢弃日志".to_string());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            record_error(&context.stats, "查询日志写入队列已关闭".to_string());
        }
    }
}
