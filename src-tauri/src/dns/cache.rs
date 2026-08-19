use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
};

use crate::config::AppConfig;

#[cfg(test)]
use super::protocol::Question;
use super::protocol::{ParsedQuery, prepare_cached_response, response_cache_ttl};

const DNS_CACHE_ENTRY_OVERHEAD_BYTES: usize = 96;
// 淘汰时从迭代起点抽样对比 last_used，避免全表扫描找最旧条目
const DNS_CACHE_EVICT_SAMPLE: usize = 16;
// 缓存满载后若工作集持续换入，不能让每次插入都在写锁内扫描整个 shard。
const DNS_CACHE_EXPIRED_SCAN_INTERVAL_SECONDS: u64 = 30;

#[derive(Debug, Clone)]
pub(crate) struct DnsCacheConfig {
    pub(crate) enabled: bool,
    pub(crate) max_size_bytes: usize,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
    pub(crate) optimistic: bool,
    pub(crate) prefetch_enabled: bool,
    pub(crate) prefetch_hit_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QueryCacheKey {
    domain: String,
    qtype: u16,
    qclass: u16,
    recursion_desired: bool,
    authentic_data: bool,
    checking_disabled: bool,
    dnssec_ok: bool,
    edns_udp_size: Option<u16>,
    route: Option<String>,
}

struct CachedDnsResponse {
    // 命中后仍要复制并改写 ID/TTL；共享原始包可避免查找阶段先完整复制一次。
    response: Arc<[u8]>,
    expires_at: u64,
    prefetch_at: u64,
    size: usize,
    // 原子字段让读路径只需要 shard 读锁，多个 worker 可以并行命中缓存
    last_used: AtomicU64,
    refreshing: AtomicBool,
    hit_count: AtomicU32,
}

pub(crate) struct CacheHit {
    pub(crate) response: Vec<u8>,
    pub(crate) refresh_reason: Option<CacheRefreshReason>,
}

pub(crate) struct RawCacheHit {
    pub(crate) response: Arc<[u8]>,
    pub(crate) ttl: u32,
    pub(crate) stale: bool,
    pub(crate) refresh_reason: Option<CacheRefreshReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheRefreshReason {
    Expired,
    Prefetch,
}

pub(crate) struct DnsCache {
    config: DnsCacheConfig,
    entries: HashMap<QueryCacheKey, CachedDnsResponse>,
    total_size: usize,
    access_counter: AtomicU64,
    last_expired_scan_at: u64,
}

pub(crate) struct DnsCacheStore {
    shards: Vec<RwLock<DnsCache>>,
    metrics: CacheMetrics,
}

#[derive(Default)]
struct CacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
    stale_hits: AtomicU64,
    refresh_started: AtomicU64,
    refresh_completed: AtomicU64,
    refresh_failed: AtomicU64,
    prefetch_started: AtomicU64,
    prefetch_completed: AtomicU64,
    prefetch_failed: AtomicU64,
    insertions: AtomicU64,
    evictions: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DnsCacheStatsSnapshot {
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) stale_hits: u64,
    pub(crate) refresh_started: u64,
    pub(crate) refresh_completed: u64,
    pub(crate) refresh_failed: u64,
    pub(crate) prefetch_started: u64,
    pub(crate) prefetch_completed: u64,
    pub(crate) prefetch_failed: u64,
    pub(crate) insertions: u64,
    pub(crate) evictions: u64,
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

impl DnsCacheConfig {
    pub(crate) fn from_config(config: &AppConfig) -> Self {
        Self {
            enabled: config.dns_cache_enabled,
            max_size_bytes: config.dns_cache_size,
            min_ttl: config.dns_cache_min_ttl,
            max_ttl: config.dns_cache_max_ttl,
            optimistic: config.dns_cache_optimistic,
            prefetch_enabled: config.dns_cache_prefetch_enabled,
            prefetch_hit_threshold: config.dns_cache_prefetch_hit_threshold,
        }
    }
}

impl QueryCacheKey {
    pub(crate) fn from_query(query: &ParsedQuery) -> Option<Self> {
        query.cache_safe.then(|| Self {
            domain: query.question.domain.clone(),
            qtype: query.question.qtype,
            qclass: query.question.qclass,
            recursion_desired: query.recursion_desired,
            authentic_data: query.authentic_data,
            checking_disabled: query.checking_disabled,
            dnssec_ok: query.dnssec_ok,
            edns_udp_size: query.edns_udp_size,
            route: None,
        })
    }

    pub(crate) fn with_route(mut self, route: Option<&str>) -> Self {
        self.route = route.map(str::to_string);
        self
    }

    #[cfg(test)]
    pub(crate) fn from_question(question: &Question) -> Self {
        Self {
            domain: question.domain.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
            recursion_desired: true,
            authentic_data: false,
            checking_disabled: false,
            dnssec_ok: false,
            edns_udp_size: None,
            route: None,
        }
    }
}

impl DnsCacheStore {
    pub(crate) fn from_config(config: DnsCacheConfig, shard_count: usize) -> Option<Self> {
        if !config.enabled || config.max_size_bytes == 0 {
            return None;
        }

        let shard_count = shard_count
            .max(1)
            .min((config.max_size_bytes / 4096).max(1));
        let shard_size = (config.max_size_bytes / shard_count).max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            let mut shard_config = config.clone();
            shard_config.max_size_bytes = shard_size;
            if let Some(cache) = DnsCache::from_config(shard_config) {
                shards.push(RwLock::new(cache));
            }
        }

        if shards.is_empty() {
            None
        } else {
            Some(Self {
                shards,
                metrics: CacheMetrics::default(),
            })
        }
    }

    pub(crate) fn lookup(&self, cache_key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        let result = self
            .shard(cache_key)
            .and_then(|shard| shard.read().ok()?.lookup(cache_key, now));
        match result.as_ref() {
            Some(hit) => {
                self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                if hit.stale {
                    self.metrics.stale_hits.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    pub(crate) fn insert_with_ttl(
        &self,
        cache_key: QueryCacheKey,
        response: Vec<u8>,
        now: u64,
        ttl: u32,
    ) -> bool {
        let Some(shard) = self.shard(&cache_key) else {
            return false;
        };
        if let Ok(mut cache) = shard.write() {
            let outcome = cache.insert_with_ttl(cache_key, response, now, ttl);
            if outcome.inserted {
                self.metrics.insertions.fetch_add(1, Ordering::Relaxed);
            }
            self.metrics
                .evictions
                .fetch_add(outcome.evicted, Ordering::Relaxed);
            outcome.inserted
        } else {
            false
        }
    }

    pub(crate) fn finish_refresh(&self, cache_key: &QueryCacheKey) {
        let Some(shard) = self.shard(cache_key) else {
            return;
        };
        if let Ok(cache) = shard.read() {
            cache.finish_refresh(cache_key);
        }
    }

    pub(crate) fn record_refresh_completed(&self, reason: CacheRefreshReason) {
        self.metrics
            .refresh_completed
            .fetch_add(1, Ordering::Relaxed);
        if reason == CacheRefreshReason::Prefetch {
            self.metrics
                .prefetch_completed
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_refresh_started(&self, reason: CacheRefreshReason) {
        self.metrics.refresh_started.fetch_add(1, Ordering::Relaxed);
        if reason == CacheRefreshReason::Prefetch {
            self.metrics
                .prefetch_started
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_refresh_failed(&self, reason: CacheRefreshReason) {
        self.metrics.refresh_failed.fetch_add(1, Ordering::Relaxed);
        if reason == CacheRefreshReason::Prefetch {
            self.metrics.prefetch_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn stats_snapshot(&self) -> DnsCacheStatsSnapshot {
        let (entries, bytes) = self.shards.iter().fold((0_u64, 0_u64), |current, shard| {
            let Ok(cache) = shard.read() else {
                return current;
            };
            (
                current.0.saturating_add(cache.entries.len() as u64),
                current.1.saturating_add(cache.total_size as u64),
            )
        });
        DnsCacheStatsSnapshot {
            hits: self.metrics.hits.load(Ordering::Relaxed),
            misses: self.metrics.misses.load(Ordering::Relaxed),
            stale_hits: self.metrics.stale_hits.load(Ordering::Relaxed),
            refresh_started: self.metrics.refresh_started.load(Ordering::Relaxed),
            refresh_completed: self.metrics.refresh_completed.load(Ordering::Relaxed),
            refresh_failed: self.metrics.refresh_failed.load(Ordering::Relaxed),
            prefetch_started: self.metrics.prefetch_started.load(Ordering::Relaxed),
            prefetch_completed: self.metrics.prefetch_completed.load(Ordering::Relaxed),
            prefetch_failed: self.metrics.prefetch_failed.load(Ordering::Relaxed),
            insertions: self.metrics.insertions.load(Ordering::Relaxed),
            evictions: self.metrics.evictions.load(Ordering::Relaxed),
            entries,
            bytes,
        }
    }

    pub(crate) fn clear(&self) {
        for shard in &self.shards {
            if let Ok(mut cache) = shard.write() {
                cache.clear();
            }
        }
        self.metrics.reset();
    }

    fn shard(&self, cache_key: &QueryCacheKey) -> Option<&RwLock<DnsCache>> {
        self.shards
            .get(query_cache_key_shard_index(cache_key, self.shards.len()))
    }
}

fn query_cache_key_shard_index(cache_key: &QueryCacheKey, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    (hasher.finish() % shard_count.max(1) as u64) as usize
}

impl DnsCache {
    pub(crate) fn from_config(config: DnsCacheConfig) -> Option<Self> {
        if !config.enabled || config.max_size_bytes == 0 {
            return None;
        }

        Some(Self {
            config,
            entries: HashMap::new(),
            total_size: 0,
            access_counter: AtomicU64::new(0),
            last_expired_scan_at: 0,
        })
    }

    pub(crate) fn lookup(&self, key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        let access = self.access_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = self.entries.get(key)?;

        let fresh = entry.expires_at > now;
        if !fresh && !self.config.optimistic {
            // 过期条目留给淘汰或下次插入清理，读路径保持只读
            return None;
        }

        entry.last_used.store(access, Ordering::Relaxed);
        let previous_hit_count = entry.hit_count.fetch_add(1, Ordering::Relaxed);
        let refresh_reason = if !fresh {
            entry
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(CacheRefreshReason::Expired)
        } else if self.config.prefetch_enabled
            && previous_hit_count >= self.config.prefetch_hit_threshold.saturating_sub(1)
            && now >= entry.prefetch_at
        {
            entry
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(CacheRefreshReason::Prefetch)
        } else {
            None
        };
        let ttl = if fresh {
            u32::try_from(entry.expires_at.saturating_sub(now))
                .unwrap_or(u32::MAX)
                .max(1)
        } else {
            1
        };
        Some(RawCacheHit {
            response: entry.response.clone(),
            ttl,
            stale: !fresh,
            refresh_reason,
        })
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, key: QueryCacheKey, response: Vec<u8>, now: u64) {
        let Some(ttl) = cache_ttl_seconds(&response, &self.config) else {
            return;
        };
        if ttl == 0 {
            return;
        }

        self.insert_with_ttl(key, response, now, ttl);
    }

    fn insert_with_ttl(
        &mut self,
        key: QueryCacheKey,
        response: Vec<u8>,
        now: u64,
        ttl: u32,
    ) -> CacheInsertOutcome {
        if ttl == 0 {
            return CacheInsertOutcome::default();
        }

        let access = self.access_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let size = response
            .len()
            .saturating_add(key.domain.len())
            .saturating_add(DNS_CACHE_ENTRY_OVERHEAD_BYTES);
        if size > self.config.max_size_bytes {
            return CacheInsertOutcome::default();
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.total_size = self.total_size.saturating_sub(previous.size);
        }

        self.total_size = self.total_size.saturating_add(size);
        self.entries.insert(
            key,
            CachedDnsResponse {
                response: response.into(),
                expires_at: now.saturating_add(u64::from(ttl)),
                prefetch_at: now
                    .saturating_add(u64::from(ttl))
                    .saturating_sub(u64::from((ttl / 10).max(1))),
                size,
                last_used: AtomicU64::new(access),
                refreshing: AtomicBool::new(false),
                hit_count: AtomicU32::new(0),
            },
        );
        CacheInsertOutcome {
            inserted: true,
            evicted: self.evict_over_limit(now),
        }
    }

    fn finish_refresh(&self, key: &QueryCacheKey) {
        if let Some(entry) = self.entries.get(key) {
            entry.refreshing.store(false, Ordering::Release);
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.total_size = 0;
        self.last_expired_scan_at = 0;
    }

    fn evict_over_limit(&mut self, now: u64) -> u64 {
        let mut evicted = 0_u64;
        if self.total_size > self.config.max_size_bytes && self.should_scan_expired(now) {
            evicted = evicted.saturating_add(self.evict_expired(now));
            self.last_expired_scan_at = now;
        }

        while self.total_size > self.config.max_size_bytes {
            // 近似 LRU：只取样少量条目挑最旧的淘汰，避免每次淘汰都全表扫描
            let Some(key) = self
                .entries
                .iter()
                .take(DNS_CACHE_EVICT_SAMPLE)
                .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone())
            else {
                self.total_size = 0;
                return evicted;
            };

            if let Some(entry) = self.entries.remove(&key) {
                self.total_size = self.total_size.saturating_sub(entry.size);
                evicted = evicted.saturating_add(1);
            }
        }
        evicted
    }

    fn evict_expired(&mut self, now: u64) -> u64 {
        let mut removed_size = 0_usize;
        let mut removed_count = 0_u64;
        self.entries.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed_size = removed_size.saturating_add(entry.size);
                removed_count = removed_count.saturating_add(1);
            }
            keep
        });
        self.total_size = self.total_size.saturating_sub(removed_size);
        removed_count
    }

    fn should_scan_expired(&self, now: u64) -> bool {
        self.last_expired_scan_at == 0
            || now.saturating_sub(self.last_expired_scan_at)
                >= DNS_CACHE_EXPIRED_SCAN_INTERVAL_SECONDS
    }
}

#[derive(Default)]
struct CacheInsertOutcome {
    inserted: bool,
    evicted: u64,
}

impl CacheMetrics {
    fn reset(&self) {
        for counter in [
            &self.hits,
            &self.misses,
            &self.stale_hits,
            &self.refresh_started,
            &self.refresh_completed,
            &self.refresh_failed,
            &self.prefetch_started,
            &self.prefetch_completed,
            &self.prefetch_failed,
            &self.insertions,
            &self.evictions,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

pub(crate) fn lookup_cached_response(
    dns_cache: &Option<Arc<DnsCacheStore>>,
    cache_key: &QueryCacheKey,
    query: &[u8],
    now: u64,
) -> Option<CacheHit> {
    let cache = dns_cache.as_ref()?;
    let raw_hit = cache.lookup(cache_key, now)?;
    let response = prepare_cached_response(&raw_hit.response, query, raw_hit.ttl)?;
    Some(CacheHit {
        response,
        refresh_reason: raw_hit.refresh_reason,
    })
}

pub(crate) fn insert_cached_response(
    dns_cache: &Option<Arc<DnsCacheStore>>,
    cache_config: Option<&DnsCacheConfig>,
    cache_key: QueryCacheKey,
    response: Vec<u8>,
    now: u64,
) -> bool {
    let Some(cache) = dns_cache else {
        return false;
    };
    let Some(config) = cache_config else {
        return false;
    };
    let Some(ttl) = cache_ttl_seconds(&response, config) else {
        return false;
    };
    cache.insert_with_ttl(cache_key, response, now, ttl)
}

pub(crate) fn cache_ttl_seconds(packet: &[u8], config: &DnsCacheConfig) -> Option<u32> {
    let ttl = response_cache_ttl(packet)?;
    if ttl == 0 {
        return None;
    }

    let mut ttl = ttl;
    if config.min_ttl > 0 {
        ttl = ttl.max(config.min_ttl);
    }
    if config.max_ttl > 0 {
        ttl = ttl.min(config.max_ttl);
    }
    Some(ttl)
}

#[cfg(test)]
mod tests {
    use super::{
        CacheRefreshReason, DNS_CACHE_EXPIRED_SCAN_INTERVAL_SECONDS, DnsCache, DnsCacheConfig,
        DnsCacheStore, QueryCacheKey,
    };
    use crate::dns::protocol::Question;

    #[test]
    fn throttles_full_expired_entry_scans() {
        let mut cache = DnsCache::from_config(DnsCacheConfig {
            enabled: true,
            max_size_bytes: 1024,
            min_ttl: 0,
            max_ttl: 60,
            optimistic: true,
            prefetch_enabled: true,
            prefetch_hit_threshold: 10,
        })
        .expect("cache should build");

        assert!(cache.should_scan_expired(100));
        cache.last_expired_scan_at = 100;
        assert!(!cache.should_scan_expired(100));
        assert!(!cache.should_scan_expired(100 + DNS_CACHE_EXPIRED_SCAN_INTERVAL_SECONDS - 1));
        assert!(cache.should_scan_expired(100 + DNS_CACHE_EXPIRED_SCAN_INTERVAL_SECONDS));
    }

    #[test]
    fn prefetches_only_hot_entries_near_expiration_and_tracks_metrics() {
        let store = DnsCacheStore::from_config(
            DnsCacheConfig {
                enabled: true,
                max_size_bytes: 16 * 1024,
                min_ttl: 0,
                max_ttl: 300,
                optimistic: true,
                prefetch_enabled: true,
                prefetch_hit_threshold: 2,
            },
            1,
        )
        .expect("cache store should build");
        let key = QueryCacheKey::from_question(&Question {
            domain: "hot.example".into(),
            qtype: 1,
            qclass: 1,
            question_end: 0,
        });
        store.insert_with_ttl(key.clone(), vec![0; 64], 100, 100);

        assert_eq!(store.lookup(&key, 180).unwrap().refresh_reason, None);
        let refresh_reason = store.lookup(&key, 190).unwrap().refresh_reason;
        assert_eq!(refresh_reason, Some(CacheRefreshReason::Prefetch));
        store.record_refresh_started(refresh_reason.unwrap());
        assert_eq!(store.lookup(&key, 191).unwrap().refresh_reason, None);

        let missing = QueryCacheKey::from_question(&Question {
            domain: "missing.example".into(),
            qtype: 1,
            qclass: 1,
            question_end: 0,
        });
        assert!(store.lookup(&missing, 191).is_none());
        let stats = store.stats_snapshot();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.prefetch_started, 1);
        assert_eq!(stats.entries, 1);
        assert!(stats.bytes >= 64);

        store.clear();
        let stats = store.stats_snapshot();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.entries, 0);
    }
}
