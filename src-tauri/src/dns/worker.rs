use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use crate::{
    config::UpstreamMode,
    database::{QueryLogEntry, QueryPersistenceEntry},
};

use super::{
    access::{ClientAccess, ClientAccessDecision},
    cache::{
        CacheRefreshReason, DnsCacheConfig, DnsCacheStore, QueryCacheKey, insert_cached_response,
        lookup_cached_response,
    },
    filter_runtime::{FilterRuntime, SharedFilterRuntime, current_filter_runtime},
    protocol::{
        Question, RCODE_REFUSED, TYPE_ANY, build_block_response, build_error_response,
        build_rewrite_response, parse_query, prepare_response_for_query, response_security_data,
        summarize_response, truncate_response_for_udp, udp_payload_size,
    },
    stats::{
        DnsStats, DnsTransport, ResponseProtectionKind, current_second, record_access_denied,
        record_blocked_query, record_error, record_forwarded, record_persistence_queue_drop,
        record_query, record_rate_limited, record_refused_any, record_response_blocked,
    },
    task_pool,
    upstream::{RuntimeUpstream, UpstreamForwardResponse, forward_query},
    upstream_routes::{RouteUpstreamPool, UpstreamRoutes},
};

const WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(200);
const OPTIMISTIC_REFRESH_MAX_QUEUE_WAIT: Duration = Duration::from_secs(2);
const FORWARD_QUERY_TOTAL_TIMEOUT: Duration = Duration::from_secs(6);
// Windows 刚连上或自动恢复 Wi-Fi 时，路由表和既有 UDP socket 可能暂时不可用。
// connect 会返回 WSAENETUNREACH/WSAEHOSTUNREACH，复用 socket 的 send 可能返回 WSAEINVAL；
// 短暂等待后重试，避免首个 NCSI 探测直接收到失败。
const NETWORK_UNAVAILABLE_RETRY_DELAYS: [Duration; 5] = [
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1_200),
    Duration::from_millis(1_600),
];
#[cfg(windows)]
const WINDOWS_UDP_NO_BUFFER_SPACE: i32 = 10055;
#[cfg(windows)]
const WINDOWS_UDP_SEND_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(1), Duration::from_millis(2)];
pub(crate) const PENDING_QUERY_SHARDS: usize = 64;
// 单个域名的等待者上限，避免故障域名被反复重试时无限堆积待投递的响应目标。
const MAX_PENDING_FOLLOWERS: usize = 512;

pub(crate) struct DnsWorkItem {
    pub(crate) query: Vec<u8>,
    pub(crate) client_addr: SocketAddr,
    pub(crate) response_target: DnsResponseTarget,
    pub(crate) queued_at: Instant,
}

#[derive(Clone)]
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
    pub(crate) upstream_routes: Arc<UpstreamRoutes>,
    pub(crate) upstream_mode: UpstreamMode,
    pub(crate) next_upstream: AtomicUsize,
    pub(crate) fallback_next_upstream: AtomicUsize,
    pub(crate) access: Arc<ClientAccess>,
    pub(crate) refuse_any: bool,
    pub(crate) protection_paused_until: Arc<AtomicU64>,
    pub(crate) filter_runtime: SharedFilterRuntime,
    pub(crate) stats: Arc<Mutex<DnsStats>>,
    pub(crate) dns_cache: Option<Arc<DnsCacheStore>>,
    pub(crate) dns_cache_config: Option<DnsCacheConfig>,
    pub(crate) pending_queries: Arc<PendingQueries>,
    pub(crate) persistence_sender: Option<mpsc::SyncSender<QueryPersistenceEntry>>,
    pub(crate) query_log_enabled: bool,
    pub(crate) statistics_enabled: bool,
    pub(crate) anonymize_client_ip: bool,
    pub(crate) detailed_runtime_stats: bool,
}

type PendingQuery = Arc<PendingQueryState>;

struct PendingQueryState {
    /// 已登记、等待 leader 结果的重复查询。leader 完成时 `take` 成 `None`，
    /// 此后到达的重复查询会看到 `None` 并退化成自己转发。
    followers: Mutex<Option<Vec<PendingFollower>>>,
}

/// 重复查询投递响应所需的全部上下文。leader 拿到上游结果后代替 follower 投递，
/// follower 因此不必占用 worker 线程阻塞等待。
struct PendingFollower {
    query: Vec<u8>,
    client_addr: SocketAddr,
    response_target: DnsResponseTarget,
    domain: String,
    query_type: u16,
    query_class: u16,
    transport: &'static str,
    processing_started: Instant,
}

enum PendingQueryRole {
    Leader(PendingQuery),
    Follower(PendingQuery),
}

struct QueryLogMetadata<'a> {
    domain: &'a str,
    query_type: u16,
    query_class: u16,
    transport: &'static str,
    processing_started: Instant,
}

struct ResponseProtectionBlock {
    kind: ResponseProtectionKind,
    rule_match: super::rules::BlockMatch,
}

impl<'a> QueryLogMetadata<'a> {
    fn new(
        question: &'a Question,
        response_target: &DnsResponseTarget,
        processing_started: Instant,
    ) -> Self {
        let transport = match response_target {
            DnsResponseTarget::Udp { .. } => "udp",
            DnsResponseTarget::Tcp(_) => "tcp",
        };
        Self {
            domain: &question.domain,
            query_type: question.qtype,
            query_class: question.qclass,
            transport,
            processing_started,
        }
    }
}

#[derive(Clone, Copy)]
enum QueryResponseSource {
    Upstream,
    Cache,
    Rewrite,
    Blocked,
    Refused,
}

impl QueryResponseSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Cache => "cache",
            Self::Rewrite => "rewrite",
            Self::Blocked => "blocked",
            Self::Refused => "refused",
        }
    }
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
        followers: Mutex::new(Some(Vec::new())),
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
    // 从监听线程入队时开始计时，确保持久化的处理耗时包含内部工作队列等待。
    let processing_started = work_item.queued_at;
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

    let parsed_query = match parse_query(query) {
        Ok(query) => query,
        Err(error) => {
            record_error(&context.stats, error);
            send_no_response(response_target);
            return;
        }
    };
    let question = &parsed_query.question;
    let log_metadata = QueryLogMetadata::new(question, response_target, processing_started);

    // 整包读取当前过滤状态，一次查询内保持一致；规则热替换只影响后续查询
    let filter = current_filter_runtime(&context.filter_runtime);

    if context.refuse_any && question.qtype == TYPE_ANY {
        record_query(
            &context.stats,
            &question.domain,
            client_addr.ip(),
            context.detailed_runtime_stats,
        );
        let message = format!("已拒绝 ANY 查询：{}", question.domain);
        let response = build_error_response(query, RCODE_REFUSED);
        match response.as_deref() {
            Some(response) => {
                if let Err(error) = send_dns_response(response_target, query, response) {
                    let message = format!("返回 ANY 拒绝响应失败：{error}");
                    record_error(&context.stats, message.clone());
                    queue_query_log(
                        context,
                        &filter,
                        &log_metadata,
                        client_addr,
                        QueryResponseSource::Refused,
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
        queue_query_log_with_response(
            context,
            &filter,
            &log_metadata,
            client_addr,
            QueryResponseSource::Refused,
            false,
            false,
            false,
            None,
            None,
            Some(message),
            response.as_deref(),
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
            client_addr.ip(),
            context.detailed_runtime_stats,
        );
        let response = build_rewrite_response(query, question, &target);
        if let Err(error) = send_dns_response(response_target, query, &response) {
            let message = format!("返回 DNS 重写响应失败：{error}");
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Rewrite,
                false,
                false,
                true,
                None,
                None,
                Some(message),
            );
        } else {
            queue_query_log_with_response(
                context,
                &filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Rewrite,
                false,
                false,
                false,
                None,
                None,
                None,
                Some(&response),
            );
        }
        return;
    }

    let client_filtering_enabled = filter.client_filtering.filtering_enabled(client_addr.ip());
    let filtering_active =
        client_filtering_enabled && !protection_is_paused(&context.protection_paused_until);

    if filtering_active
        && let Some(rule_match) = filter
            .rules
            .blocking_match(&question.domain, question.qtype)
    {
        let response = build_block_response(query, question, &filter.blocking);
        if let Err(error) = send_dns_response(response_target, query, &response) {
            let message = format!("返回黑名单响应失败：{error}");
            record_query(
                &context.stats,
                &question.domain,
                client_addr.ip(),
                context.detailed_runtime_stats,
            );
            record_error(&context.stats, message.clone());
            queue_blocked_query_log(
                context,
                &filter,
                &log_metadata,
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
            client_addr.ip(),
            &rule_match.source,
            context.detailed_runtime_stats,
        );
        queue_blocked_query_log_with_response(
            context,
            &filter,
            &log_metadata,
            client_addr,
            false,
            None,
            Some(&response),
            &rule_match,
        );
        return;
    }

    record_query(
        &context.stats,
        &question.domain,
        client_addr.ip(),
        context.detailed_runtime_stats,
    );

    let routed_upstream = context
        .upstream_routes
        .select(&question.domain, client_addr.ip());
    let route_key = routed_upstream.as_deref().map(RouteUpstreamPool::key);
    let cache_scope = if client_filtering_enabled {
        route_key.map(str::to_string)
    } else {
        Some(match route_key {
            Some(route) => format!("{route}:filter-bypass"),
            None => "filter-bypass".to_string(),
        })
    };
    let cache_key =
        QueryCacheKey::from_query(&parsed_query).map(|key| key.with_route(cache_scope.as_deref()));
    if let Some(cache_key) = cache_key.as_ref()
        && let Some(cache_hit) =
            lookup_cached_response(&context.dns_cache, cache_key, query, current_second())
    {
        if filtering_active
            && let Some(block) = response_protection_block(
                &filter,
                question,
                &cache_hit.response,
                routed_upstream.is_some(),
            )
        {
            if cache_hit.refresh_reason.is_some()
                && let Some(cache) = context.dns_cache.as_deref()
            {
                cache.finish_refresh(cache_key);
            }
            deliver_response_protection_block(
                context,
                &filter,
                &log_metadata,
                client_addr,
                response_target,
                query,
                question,
                &block,
                None,
                None,
            );
            return;
        }
        if let Err(error) = send_dns_response(response_target, query, &cache_hit.response) {
            if cache_hit.refresh_reason.is_some()
                && let Some(cache) = context.dns_cache.as_deref()
            {
                cache.finish_refresh(cache_key);
            }
            let message = format!("返回 DNS 缓存响应失败：{error}");
            record_error(&context.stats, message.clone());
            queue_query_log(
                context,
                &filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Cache,
                false,
                false,
                true,
                None,
                None,
                Some(message),
            );
        } else {
            queue_query_log_with_response(
                context,
                &filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Cache,
                false,
                false,
                false,
                None,
                None,
                None,
                Some(&cache_hit.response),
            );
            if let Some(refresh_reason) = cache_hit.refresh_reason {
                refresh_cache_async(
                    work_item.query,
                    cache_key.clone(),
                    refresh_reason,
                    Arc::clone(&context.upstream_servers),
                    Arc::clone(&context.fallback_upstream_servers),
                    routed_upstream.clone(),
                    context.upstream_mode.clone(),
                    Arc::clone(&context.stats),
                    context.dns_cache.clone(),
                    context.dns_cache_config.clone(),
                    Arc::clone(&context.filter_runtime),
                    filtering_active,
                );
            }
        }
        return;
    }

    let pending_query = if let Some(cache_key) = cache_key.as_ref() {
        match begin_pending_query(context, cache_key) {
            PendingQueryRole::Leader(pending_query) => Some(pending_query),
            PendingQueryRole::Follower(pending_query) => {
                // 登记响应目标后立刻让出 worker 线程，由 leader 代为投递。
                // 阻塞等待会让同一域名的重复查询吃满 worker，上游抖动时连缓存命中都被拖住。
                let follower = PendingFollower {
                    query: work_item.query.clone(),
                    client_addr,
                    response_target: response_target.clone(),
                    domain: question.domain.clone(),
                    query_type: question.qtype,
                    query_class: question.qclass,
                    transport: log_metadata.transport,
                    processing_started,
                };
                if register_pending_follower(&pending_query, follower) {
                    return;
                }
                // leader 已经完成或等待者过多，退化成自己转发。
                None
            }
        }
    } else {
        None
    };

    let forward_result = forward_query_with_route(
        query,
        routed_upstream.as_deref(),
        context.upstream_servers.as_ref(),
        context.fallback_upstream_servers.as_ref(),
        &context.upstream_mode,
        &context.next_upstream,
        &context.fallback_next_upstream,
        &context.stats,
    );
    if filtering_active
        && let Ok(forwarded) = &forward_result
        && let Some(block) = response_protection_block(
            &filter,
            question,
            &forwarded.response,
            routed_upstream.is_some(),
        )
    {
        if let (Some(cache_key), Some(pending_query)) = (cache_key.as_ref(), pending_query.as_ref())
        {
            finish_pending_protection_block(
                context,
                &filter,
                cache_key,
                pending_query,
                &block,
                Some(&forwarded.upstream),
                Some(forwarded.duration_ms),
            );
        }
        deliver_response_protection_block(
            context,
            &filter,
            &log_metadata,
            client_addr,
            response_target,
            query,
            question,
            &block,
            Some(&forwarded.upstream),
            Some(forwarded.duration_ms),
        );
        return;
    }
    if let (Some(cache_key), Some(pending_query)) = (cache_key.as_ref(), pending_query.as_ref()) {
        finish_pending_query(context, &filter, cache_key, pending_query, &forward_result);
    }

    match forward_result {
        Ok(forwarded) => {
            if let Some(cache_key) = cache_key {
                insert_cached_response(
                    &context.dns_cache,
                    context.dns_cache_config.as_ref(),
                    cache_key,
                    forwarded.response.clone(),
                    current_second(),
                );
            }
            if let Err(error) = send_dns_response(response_target, query, &forwarded.response) {
                let message = format!("转发响应给客户端失败：{error}");
                record_error(&context.stats, message.clone());
                queue_query_log(
                    context,
                    &filter,
                    &log_metadata,
                    client_addr,
                    QueryResponseSource::Upstream,
                    false,
                    true,
                    true,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    Some(message),
                );
            } else {
                record_forwarded(&context.stats, context.detailed_runtime_stats);
                queue_query_log_with_response(
                    context,
                    &filter,
                    &log_metadata,
                    client_addr,
                    QueryResponseSource::Upstream,
                    false,
                    true,
                    false,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    None,
                    Some(&forwarded.response),
                );
            }
        }
        Err(error) => {
            record_error(&context.stats, error.clone());
            send_no_response(response_target);
            queue_query_log(
                context,
                &filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Upstream,
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

fn protection_is_paused(deadline: &AtomicU64) -> bool {
    deadline.load(Ordering::Acquire) > current_second()
}

fn response_protection_block(
    filter: &FilterRuntime,
    question: &Question,
    response: &[u8],
    uses_routed_upstream: bool,
) -> Option<ResponseProtectionBlock> {
    let check_cname = filter.cname_cloaking_enabled;
    let check_rebinding = filter.rebinding_protection_enabled
        && !uses_routed_upstream
        && !filter.rebinding_allowed_domains.contains(&question.domain);
    if !check_cname && !check_rebinding {
        return None;
    }
    let data = response_security_data(response)?;

    if check_cname {
        for target in data.cname_targets {
            if let Some(rule_match) = filter.rules.blocking_match(&target, question.qtype) {
                return Some(ResponseProtectionBlock {
                    kind: ResponseProtectionKind::CnameCloaking,
                    rule_match,
                });
            }
        }
    }

    if check_rebinding
        && let Some(address) = data
            .addresses
            .into_iter()
            .find(|ip| is_rebinding_address(*ip))
    {
        return Some(ResponseProtectionBlock {
            kind: ResponseProtectionKind::Rebinding,
            rule_match: super::rules::BlockMatch {
                rule: format!("private-address:{address}"),
                source: "DNS Rebinding Protection".into(),
                rule_type: "response protection".into(),
                important_overrode: false,
                allowlist_rule: None,
            },
        });
    }

    None
}

fn is_rebinding_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || octets[0] >= 240
        }
        IpAddr::V6(address) => {
            address
                .to_ipv4_mapped()
                .is_some_and(|address| is_rebinding_address(IpAddr::V4(address)))
                || address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn deliver_response_protection_block(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    response_target: &DnsResponseTarget,
    query: &[u8],
    question: &Question,
    block: &ResponseProtectionBlock,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
) {
    record_response_blocked(
        &context.stats,
        metadata.domain,
        client_addr.ip(),
        &block.rule_match.source,
        block.kind,
        context.detailed_runtime_stats,
    );
    let response = build_block_response(query, question, &filter.blocking);
    let error = send_dns_response(response_target, query, &response)
        .err()
        .map(|error| format!("返回响应安全拦截结果失败：{error}"));
    if let Some(message) = &error {
        record_error(&context.stats, message.clone());
    }
    queue_query_log_with_match(
        context,
        filter,
        metadata,
        client_addr,
        QueryResponseSource::Blocked,
        true,
        false,
        error.is_some(),
        upstream_server,
        upstream_duration_ms,
        error,
        Some(&response),
        Some(&block.rule_match),
    );
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
            if let Err(error) = send_dns_response(response_target, query, &response) {
                record_error(
                    &context.stats,
                    format!("{message}；返回拒绝响应失败：{error}"),
                );
            }
        }
    }
}

fn send_dns_response(
    response_target: &DnsResponseTarget,
    query: &[u8],
    response: &[u8],
) -> Result<(), String> {
    match response_target {
        DnsResponseTarget::Udp {
            socket,
            client_addr,
        } => {
            let max_size = udp_payload_size(query);
            if response.len() <= max_size {
                return send_udp_response(socket, response, *client_addr)
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            }
            let response = truncate_response_for_udp(query, response, max_size)
                .ok_or_else(|| "无法构造符合客户端 UDP 大小限制的 DNS 响应".to_string())?;
            send_udp_response(socket, &response, *client_addr)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        DnsResponseTarget::Tcp(sender) => sender
            .try_send(Some(response.to_vec()))
            .map_err(|error| error.to_string()),
    }
}

#[cfg(windows)]
fn send_udp_response(
    socket: &UdpSocket,
    response: &[u8],
    client_addr: SocketAddr,
) -> io::Result<usize> {
    retry_windows_udp_send(|| socket.send_to(response, client_addr))
}

#[cfg(windows)]
fn retry_windows_udp_send<T>(mut send: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut retry_index = 0;
    loop {
        match send() {
            // WSAENOBUFS 通常是短暂的系统发送队列背压，只在该错误上做有限重试。
            Err(error)
                if error.raw_os_error() == Some(WINDOWS_UDP_NO_BUFFER_SPACE)
                    && retry_index < WINDOWS_UDP_SEND_RETRY_DELAYS.len() =>
            {
                std::thread::sleep(WINDOWS_UDP_SEND_RETRY_DELAYS[retry_index]);
                retry_index += 1;
            }
            result => return result,
        }
    }
}

#[cfg(not(windows))]
fn send_udp_response(
    socket: &UdpSocket,
    response: &[u8],
    client_addr: SocketAddr,
) -> io::Result<usize> {
    socket.send_to(response, client_addr)
}

fn send_no_response(response_target: &DnsResponseTarget) {
    match response_target {
        DnsResponseTarget::Tcp(sender) => {
            let _ = sender.try_send(None);
        }
        DnsResponseTarget::Udp { .. } => {}
    }
}

fn begin_pending_query(context: &DnsWorkerContext, cache_key: &QueryCacheKey) -> PendingQueryRole {
    context.pending_queries.begin(cache_key)
}

/// 登记成功返回 true，此时 worker 可以立即处理下一个请求。
/// leader 已经完成（或等待者过多）时返回 false，调用方应退化成自己转发。
fn register_pending_follower(pending_query: &PendingQuery, follower: PendingFollower) -> bool {
    let Ok(mut followers) = pending_query.followers.lock() else {
        return false;
    };
    match followers.as_mut() {
        Some(followers) if followers.len() < MAX_PENDING_FOLLOWERS => {
            followers.push(follower);
            true
        }
        _ => false,
    }
}

fn finish_pending_query(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    cache_key: &QueryCacheKey,
    pending_query: &PendingQuery,
    result: &Result<UpstreamForwardResponse, String>,
) {
    // 先摘掉共享入口，随后到达的重复查询会另起一个 leader，不会等待已完成的结果。
    context.pending_queries.finish(cache_key, pending_query);

    let followers = pending_query
        .followers
        .lock()
        .ok()
        .and_then(|mut followers| followers.take())
        .unwrap_or_default();
    for follower in followers {
        deliver_pending_follower(context, filter, follower, result);
    }
}

fn deliver_pending_follower(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    follower: PendingFollower,
    result: &Result<UpstreamForwardResponse, String>,
) {
    let log_metadata = QueryLogMetadata {
        domain: &follower.domain,
        query_type: follower.query_type,
        query_class: follower.query_class,
        transport: follower.transport,
        processing_started: follower.processing_started,
    };
    let query = follower.query.as_slice();
    let response_target = &follower.response_target;
    let client_addr = follower.client_addr;

    match result {
        Ok(forwarded) => {
            let response = prepare_forwarded_response(&forwarded.response, query);
            if let Err(error) = send_dns_response(response_target, query, &response) {
                let message = format!("转发复用响应给客户端失败：{error}");
                record_error(&context.stats, message.clone());
                queue_query_log(
                    context,
                    filter,
                    &log_metadata,
                    client_addr,
                    QueryResponseSource::Upstream,
                    false,
                    true,
                    true,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    Some(message),
                );
            } else {
                queue_query_log_with_response(
                    context,
                    filter,
                    &log_metadata,
                    client_addr,
                    QueryResponseSource::Upstream,
                    false,
                    false,
                    false,
                    Some(&forwarded.upstream),
                    Some(forwarded.duration_ms),
                    None,
                    Some(&response),
                );
            }
        }
        Err(error) => {
            record_error(&context.stats, error.clone());
            send_no_response(response_target);
            queue_query_log(
                context,
                filter,
                &log_metadata,
                client_addr,
                QueryResponseSource::Upstream,
                false,
                false,
                true,
                None,
                None,
                Some(error.clone()),
            );
        }
    }
}

fn forward_query_with_fallback(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    fallback_upstream_servers: &[RuntimeUpstream],
    upstream_mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
    fallback_next_upstream: &AtomicUsize,
    stats: &Arc<Mutex<DnsStats>>,
) -> Result<UpstreamForwardResponse, String> {
    let deadline = Instant::now() + FORWARD_QUERY_TOTAL_TIMEOUT;
    let mut result = forward_query_once_with_fallback(
        query,
        upstream_servers,
        fallback_upstream_servers,
        upstream_mode,
        next_upstream,
        fallback_next_upstream,
        deadline,
        stats,
    );
    for delay in NETWORK_UNAVAILABLE_RETRY_DELAYS {
        if !result
            .as_ref()
            .is_err_and(|error| is_network_temporarily_unavailable(error))
        {
            break;
        }
        if deadline
            .checked_duration_since(Instant::now())
            .is_none_or(|remaining| remaining <= delay)
        {
            break;
        }
        std::thread::sleep(delay);
        result = forward_query_once_with_fallback(
            query,
            upstream_servers,
            fallback_upstream_servers,
            upstream_mode,
            next_upstream,
            fallback_next_upstream,
            deadline,
            stats,
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn forward_query_with_route(
    query: &[u8],
    route: Option<&RouteUpstreamPool>,
    upstream_servers: &[RuntimeUpstream],
    fallback_upstream_servers: &[RuntimeUpstream],
    upstream_mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
    fallback_next_upstream: &AtomicUsize,
    stats: &Arc<Mutex<DnsStats>>,
) -> Result<UpstreamForwardResponse, String> {
    if let Some(route) = route {
        return forward_query_with_fallback(
            query,
            &route.upstreams,
            &[],
            upstream_mode,
            &route.next_upstream,
            fallback_next_upstream,
            stats,
        );
    }
    forward_query_with_fallback(
        query,
        upstream_servers,
        fallback_upstream_servers,
        upstream_mode,
        next_upstream,
        fallback_next_upstream,
        stats,
    )
}

#[allow(clippy::too_many_arguments)]
fn forward_query_once_with_fallback(
    query: &[u8],
    upstream_servers: &[RuntimeUpstream],
    fallback_upstream_servers: &[RuntimeUpstream],
    upstream_mode: &UpstreamMode,
    next_upstream: &AtomicUsize,
    fallback_next_upstream: &AtomicUsize,
    deadline: Instant,
    stats: &Arc<Mutex<DnsStats>>,
) -> Result<UpstreamForwardResponse, String> {
    match forward_query(
        query,
        upstream_servers,
        upstream_mode,
        next_upstream,
        deadline,
        stats,
    ) {
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
                deadline,
                stats,
            )
            .map_err(|fallback_error| {
                format!("主上游失败：{primary_error}；fallback 上游也失败：{fallback_error}")
            })
        }
    }
}

fn is_network_temporarily_unavailable(error: &str) -> bool {
    // io::Error 的展示文本会本地化，但 Windows raw OS error 始终保留在末尾。
    error.contains("(os error 10051)")
        || error.contains("(os error 10065)")
        || (error.contains("请求上游 DNS 失败") && error.contains("(os error 10022)"))
}

pub(crate) fn prepare_forwarded_response(response: &[u8], query: &[u8]) -> Vec<u8> {
    prepare_response_for_query(response, query).unwrap_or_else(|| {
        let mut response = response.to_vec();
        if response.len() >= 2 && query.len() >= 2 {
            response[0..2].copy_from_slice(&query[0..2]);
        }
        response
    })
}

#[allow(clippy::too_many_arguments)]
fn refresh_cache_async(
    query: Vec<u8>,
    cache_key: QueryCacheKey,
    refresh_reason: CacheRefreshReason,
    upstream_servers: Arc<Vec<RuntimeUpstream>>,
    fallback_upstream_servers: Arc<Vec<RuntimeUpstream>>,
    routed_upstream: Option<Arc<RouteUpstreamPool>>,
    upstream_mode: UpstreamMode,
    stats: Arc<Mutex<DnsStats>>,
    dns_cache: Option<Arc<DnsCacheStore>>,
    dns_cache_config: Option<DnsCacheConfig>,
    filter_runtime: SharedFilterRuntime,
    filtering_active: bool,
) {
    let Some(cache) = dns_cache else {
        return;
    };
    let Some(cache_config) = dns_cache_config else {
        cache.finish_refresh(&cache_key);
        return;
    };
    cache.record_refresh_started(refresh_reason);

    let cache_on_reject = Arc::clone(&cache);
    let cache_key_on_reject = cache_key.clone();
    let queued_at = Instant::now();
    if !task_pool::spawn_coordination_task(move || {
        if queued_at.elapsed() > OPTIMISTIC_REFRESH_MAX_QUEUE_WAIT {
            cache.finish_refresh(&cache_key);
            cache.record_refresh_failed(refresh_reason);
            return;
        }
        let next_upstream = AtomicUsize::new(0);
        let fallback_next_upstream = AtomicUsize::new(0);
        match forward_query_with_route(
            &query,
            routed_upstream.as_deref(),
            upstream_servers.as_ref(),
            fallback_upstream_servers.as_ref(),
            &upstream_mode,
            &next_upstream,
            &fallback_next_upstream,
            &stats,
        ) {
            Ok(forwarded) => {
                let blocked = filtering_active
                    && parse_query(&query).ok().is_some_and(|parsed| {
                        let filter = current_filter_runtime(&filter_runtime);
                        response_protection_block(
                            &filter,
                            &parsed.question,
                            &forwarded.response,
                            routed_upstream.is_some(),
                        )
                        .is_some()
                    });
                if blocked {
                    cache.finish_refresh(&cache_key);
                    cache.record_refresh_failed(refresh_reason);
                    return;
                }
                let cache_for_insert = Some(Arc::clone(&cache));
                let refresh_key = cache_key.clone();
                if insert_cached_response(
                    &cache_for_insert,
                    Some(&cache_config),
                    cache_key,
                    forwarded.response,
                    current_second(),
                ) {
                    cache.record_refresh_completed(refresh_reason);
                } else {
                    cache.finish_refresh(&refresh_key);
                    cache.record_refresh_failed(refresh_reason);
                }
            }
            Err(_) => {
                cache.finish_refresh(&cache_key);
                cache.record_refresh_failed(refresh_reason);
            }
        }
    }) {
        cache_on_reject.finish_refresh(&cache_key_on_reject);
        cache_on_reject.record_refresh_failed(refresh_reason);
    }
}

fn finish_pending_protection_block(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    cache_key: &QueryCacheKey,
    pending_query: &PendingQuery,
    block: &ResponseProtectionBlock,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
) {
    context.pending_queries.finish(cache_key, pending_query);
    let followers = pending_query
        .followers
        .lock()
        .ok()
        .and_then(|mut followers| followers.take())
        .unwrap_or_default();
    for follower in followers {
        let Ok(parsed) = parse_query(&follower.query) else {
            send_no_response(&follower.response_target);
            continue;
        };
        let metadata = QueryLogMetadata {
            domain: &follower.domain,
            query_type: follower.query_type,
            query_class: follower.query_class,
            transport: follower.transport,
            processing_started: follower.processing_started,
        };
        deliver_response_protection_block(
            context,
            filter,
            &metadata,
            follower.client_addr,
            &follower.response_target,
            &follower.query,
            &parsed.question,
            block,
            upstream_server,
            upstream_duration_ms,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn queue_query_log(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    response_source: QueryResponseSource,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
) {
    queue_query_log_with_response(
        context,
        filter,
        metadata,
        client_addr,
        response_source,
        blocked,
        forwarded,
        failed,
        upstream_server,
        upstream_duration_ms,
        error,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn queue_query_log_with_response(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    response_source: QueryResponseSource,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
    response: Option<&[u8]>,
) {
    queue_query_log_with_match(
        context,
        filter,
        metadata,
        client_addr,
        response_source,
        blocked,
        forwarded,
        failed,
        upstream_server,
        upstream_duration_ms,
        error,
        response,
        None,
    );
}

fn queue_blocked_query_log(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    failed: bool,
    error: Option<String>,
    rule_match: &super::rules::BlockMatch,
) {
    queue_blocked_query_log_with_response(
        context,
        filter,
        metadata,
        client_addr,
        failed,
        error,
        None,
        rule_match,
    );
}

#[allow(clippy::too_many_arguments)]
fn queue_blocked_query_log_with_response(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    failed: bool,
    error: Option<String>,
    response: Option<&[u8]>,
    rule_match: &super::rules::BlockMatch,
) {
    queue_query_log_with_match(
        context,
        filter,
        metadata,
        client_addr,
        QueryResponseSource::Blocked,
        true,
        false,
        failed,
        None,
        None,
        error,
        response,
        Some(rule_match),
    );
}

#[allow(clippy::too_many_arguments)]
fn queue_query_log_with_match(
    context: &DnsWorkerContext,
    filter: &FilterRuntime,
    metadata: &QueryLogMetadata<'_>,
    client_addr: SocketAddr,
    response_source: QueryResponseSource,
    blocked: bool,
    forwarded: bool,
    failed: bool,
    upstream_server: Option<&str>,
    upstream_duration_ms: Option<u64>,
    error: Option<String>,
    response: Option<&[u8]>,
    rule_match: Option<&super::rules::BlockMatch>,
) {
    let Some(sender) = &context.persistence_sender else {
        return;
    };
    let persist_log = context.query_log_enabled && !filter.log_ignore.contains(metadata.domain);
    let persist_statistics =
        context.statistics_enabled && !filter.statistics_ignore.contains(metadata.domain);
    if !persist_log && !persist_statistics {
        return;
    }

    let entry = QueryLogEntry {
        domain: metadata.domain.to_string(),
        query_type: metadata.query_type,
        query_class: metadata.query_class,
        transport: metadata.transport.to_string(),
        response_source: response_source.as_str().to_string(),
        response: response.and_then(summarize_response),
        client_ip: Some(client_addr.ip().to_string()),
        blocked,
        forwarded,
        failed,
        upstream_server: upstream_server.map(str::to_string),
        upstream_duration_ms,
        processing_duration_ms: duration_ms(metadata.processing_started.elapsed()),
        error,
        matched_rule: rule_match.map(|matched| matched.rule.clone()),
        rule_source: rule_match.map(|matched| matched.source.clone()),
        rule_type: rule_match.map(|matched| matched.rule_type.clone()),
        important_overrode: rule_match.is_some_and(|matched| matched.important_overrode),
        allowlist_rule: rule_match.and_then(|matched| matched.allowlist_rule.clone()),
    };

    let message = QueryPersistenceEntry {
        entry,
        anonymize_client_ip: context.anonymize_client_ip,
        persist_log,
        persist_statistics,
    };
    match sender.try_send(message) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            record_persistence_queue_drop(
                &context.stats,
                "查询数据队列已满，已丢弃持久化事件".to_string(),
            );
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            record_persistence_queue_drop(&context.stats, "查询数据写入队列已关闭".to_string());
        }
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod pending_query_tests {
    use std::{net::IpAddr, sync::mpsc, time::Instant};

    use super::{
        DnsResponseTarget, MAX_PENDING_FOLLOWERS, PENDING_QUERY_SHARDS, PendingFollower,
        PendingQueries, PendingQueryRole, is_rebinding_address, new_pending_query,
        register_pending_follower, response_protection_block,
    };
    use crate::{
        config::AppConfig,
        dns::{
            cache::QueryCacheKey,
            filter_runtime::build_filter_runtime,
            protocol::{Question, TYPE_A, TYPE_CNAME},
            stats::ResponseProtectionKind,
        },
    };

    fn test_cache_key() -> QueryCacheKey {
        QueryCacheKey::from_question(&Question {
            domain: "example.com".into(),
            qtype: 28,
            qclass: 1,
            question_end: 0,
        })
    }

    fn test_follower() -> PendingFollower {
        // 这些用例只验证登记行为，不投递响应，接收端无需保留
        let (sender, _) = mpsc::sync_channel(1);
        PendingFollower {
            query: vec![0x12, 0x34],
            client_addr: "127.0.0.1:1000".parse().unwrap(),
            response_target: DnsResponseTarget::Tcp(sender),
            domain: "example.com".into(),
            query_type: 28,
            query_class: 1,
            transport: "udp",
            processing_started: Instant::now(),
        }
    }

    #[test]
    fn duplicate_query_registers_instead_of_blocking_worker() {
        let pending_queries = PendingQueries::new(PENDING_QUERY_SHARDS);
        let cache_key = test_cache_key();

        let leader = match pending_queries.begin(&cache_key) {
            PendingQueryRole::Leader(leader) => leader,
            PendingQueryRole::Follower(_) => panic!("首个查询应成为 leader"),
        };
        let follower_pending = match pending_queries.begin(&cache_key) {
            PendingQueryRole::Follower(pending) => pending,
            PendingQueryRole::Leader(_) => panic!("重复查询应成为 follower"),
        };

        // 登记立即返回，worker 不会阻塞在上游结果上
        assert!(register_pending_follower(
            &follower_pending,
            test_follower()
        ));
        assert_eq!(
            leader.followers.lock().unwrap().as_ref().map(Vec::len),
            Some(1),
            "follower 应登记到 leader 的待投递列表"
        );
    }

    #[test]
    fn follower_registration_fails_after_leader_finished() {
        let pending = new_pending_query();
        // 模拟 leader 完成时摘掉待投递列表
        let taken = pending.followers.lock().unwrap().take();
        assert!(taken.is_some_and(|followers| followers.is_empty()));

        assert!(
            !register_pending_follower(&pending, test_follower()),
            "leader 已完成后不应再登记，调用方需退化成自己转发"
        );
    }

    #[test]
    fn follower_registration_is_bounded() {
        let pending = new_pending_query();
        for _ in 0..MAX_PENDING_FOLLOWERS {
            assert!(register_pending_follower(&pending, test_follower()));
        }

        assert!(
            !register_pending_follower(&pending, test_follower()),
            "等待者数量必须有上限，避免故障域名无限堆积"
        );
    }

    #[test]
    fn finished_leader_lets_next_duplicate_start_a_new_leader() {
        let pending_queries = PendingQueries::new(PENDING_QUERY_SHARDS);
        let cache_key = test_cache_key();

        let leader = match pending_queries.begin(&cache_key) {
            PendingQueryRole::Leader(leader) => leader,
            PendingQueryRole::Follower(_) => panic!("首个查询应成为 leader"),
        };
        pending_queries.finish(&cache_key, &leader);

        assert!(
            matches!(
                pending_queries.begin(&cache_key),
                PendingQueryRole::Leader(_)
            ),
            "leader 完成并摘除共享入口后，下一个查询应另起 leader"
        );
    }

    #[test]
    fn rebinding_address_detection_covers_local_ranges_only() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(
                is_rebinding_address(address.parse::<IpAddr>().unwrap()),
                "{address} should be protected"
            );
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                !is_rebinding_address(address.parse::<IpAddr>().unwrap()),
                "{address} should remain public"
            );
        }
    }

    #[test]
    fn response_protection_honors_cname_rules_trusted_domains_and_routes() {
        let filter = build_filter_runtime(&AppConfig::default(), "||tracker.example^");
        let question = Question {
            domain: "www.example".into(),
            qtype: TYPE_A,
            qclass: 1,
            question_end: 0,
        };
        let cname_response = cname_response("www.example", "tracker.example", [1, 1, 1, 1]);
        let blocked = response_protection_block(&filter, &question, &cname_response, false)
            .expect("blocked CNAME target should be detected");
        assert_eq!(blocked.kind, ResponseProtectionKind::CnameCloaking);
        assert_eq!(blocked.rule_match.source, "自定义规则");

        let private_response = a_response("www.example", [192, 168, 1, 10]);
        let blocked = response_protection_block(&filter, &question, &private_response, false)
            .expect("private response should be detected");
        assert_eq!(blocked.kind, ResponseProtectionKind::Rebinding);
        assert!(response_protection_block(&filter, &question, &private_response, true).is_none());

        let trusted_question = Question {
            domain: "nas.home.arpa".into(),
            ..question
        };
        assert!(
            response_protection_block(&filter, &trusted_question, &private_response, false)
                .is_none()
        );
    }

    fn a_response(domain: &str, address: [u8; 4]) -> Vec<u8> {
        let mut response = response_question(domain, 1);
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        append_record_tail(&mut response, TYPE_A, 4);
        response.extend_from_slice(&address);
        response
    }

    fn cname_response(domain: &str, target: &str, address: [u8; 4]) -> Vec<u8> {
        let mut response = response_question(domain, 1);
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response[10..12].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        let data_len_offset = response.len();
        response.extend_from_slice(&0_u16.to_be_bytes());
        let data_offset = response.len();
        append_name(&mut response, target);
        let data_len = (response.len() - data_offset) as u16;
        response[data_len_offset..data_len_offset + 2].copy_from_slice(&data_len.to_be_bytes());
        append_name(&mut response, target);
        append_record_tail(&mut response, TYPE_A, 4);
        response.extend_from_slice(&address);
        response
    }

    fn response_question(domain: &str, qtype: u16) -> Vec<u8> {
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        append_name(&mut response, domain);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response
    }

    fn append_name(packet: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
    }

    fn append_record_tail(packet: &mut Vec<u8>, record_type: u16, data_len: u16) {
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&data_len.to_be_bytes());
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::io;

    use super::{
        WINDOWS_UDP_NO_BUFFER_SPACE, is_network_temporarily_unavailable, retry_windows_udp_send,
    };

    #[test]
    fn identifies_windows_network_transition_errors() {
        assert!(is_network_temporarily_unavailable(
            "连接上游 DNS 失败：套接字操作尝试一个无法连接的主机。 (os error 10065)"
        ));
        assert!(is_network_temporarily_unavailable(
            "连接上游 DNS 失败：网络不可达。 (os error 10051)"
        ));
        assert!(is_network_temporarily_unavailable(
            "请求上游 DNS 失败：提供了一个无效的参数。 (os error 10022)"
        ));
        assert!(!is_network_temporarily_unavailable(
            "解析监听地址失败：提供了一个无效的参数。 (os error 10022)"
        ));
        assert!(!is_network_temporarily_unavailable("读取上游 DNS 响应超时"));
    }

    #[test]
    fn retries_transient_windows_udp_buffer_pressure() {
        let mut attempts = 0;
        let sent = retry_windows_udp_send(|| {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(WINDOWS_UDP_NO_BUFFER_SPACE))
            } else {
                Ok(42)
            }
        })
        .expect("短暂缓冲区压力恢复后应发送成功");

        assert_eq!(sent, 42);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn stops_after_windows_udp_buffer_retries_are_exhausted() {
        let mut attempts = 0;
        let error = retry_windows_udp_send(|| {
            attempts += 1;
            Err::<usize, _>(io::Error::from_raw_os_error(WINDOWS_UDP_NO_BUFFER_SPACE))
        })
        .expect_err("持续缓冲区压力应在有限重试后返回错误");

        assert_eq!(attempts, 3);
        assert_eq!(error.raw_os_error(), Some(WINDOWS_UDP_NO_BUFFER_SPACE));
    }

    #[test]
    fn does_not_retry_other_windows_udp_errors() {
        let mut attempts = 0;
        let error = retry_windows_udp_send(|| {
            attempts += 1;
            Err::<usize, _>(io::Error::from_raw_os_error(10054))
        })
        .expect_err("非缓冲区错误应直接返回");

        assert_eq!(attempts, 1);
        assert_eq!(error.raw_os_error(), Some(10054));
    }
}
