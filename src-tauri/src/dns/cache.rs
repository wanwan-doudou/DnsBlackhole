use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
};

use crate::config::AppConfig;

use super::protocol::{Question, prepare_cached_response, response_cache_ttl};

const DNS_CACHE_ENTRY_OVERHEAD_BYTES: usize = 96;

#[derive(Debug, Clone)]
pub(crate) struct DnsCacheConfig {
    pub(crate) enabled: bool,
    pub(crate) max_size_bytes: usize,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
    pub(crate) optimistic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QueryCacheKey {
    domain: String,
    qtype: u16,
    qclass: u16,
}

struct CachedDnsResponse {
    response: Vec<u8>,
    expires_at: u64,
    size: usize,
    last_used: u64,
    refreshing: bool,
}

pub(crate) struct CacheHit {
    pub(crate) response: Vec<u8>,
    pub(crate) refresh: bool,
}

pub(crate) struct RawCacheHit {
    pub(crate) response: Vec<u8>,
    pub(crate) ttl: u32,
    pub(crate) refresh: bool,
}

pub(crate) struct DnsCache {
    config: DnsCacheConfig,
    entries: HashMap<QueryCacheKey, CachedDnsResponse>,
    total_size: usize,
    access_counter: u64,
}

pub(crate) struct DnsCacheStore {
    shards: Vec<Mutex<DnsCache>>,
}

impl DnsCacheConfig {
    pub(crate) fn from_config(config: &AppConfig) -> Self {
        Self {
            enabled: config.dns_cache_enabled,
            max_size_bytes: config.dns_cache_size,
            min_ttl: config.dns_cache_min_ttl,
            max_ttl: config.dns_cache_max_ttl,
            optimistic: config.dns_cache_optimistic,
        }
    }
}

impl QueryCacheKey {
    pub(crate) fn from_question(question: &Question) -> Self {
        Self {
            domain: question.domain.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
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
                shards.push(Mutex::new(cache));
            }
        }

        if shards.is_empty() {
            None
        } else {
            Some(Self { shards })
        }
    }

    pub(crate) fn lookup(&self, cache_key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        let shard = self.shard(cache_key)?;
        shard.lock().ok()?.lookup(cache_key, now)
    }

    pub(crate) fn insert_with_ttl(
        &self,
        cache_key: QueryCacheKey,
        response: Vec<u8>,
        now: u64,
        ttl: u32,
    ) {
        let Some(shard) = self.shard(&cache_key) else {
            return;
        };
        if let Ok(mut cache) = shard.lock() {
            cache.insert_with_ttl(cache_key, response, now, ttl);
        }
    }

    pub(crate) fn finish_refresh(&self, cache_key: &QueryCacheKey) {
        let Some(shard) = self.shard(cache_key) else {
            return;
        };
        if let Ok(mut cache) = shard.lock() {
            cache.finish_refresh(cache_key);
        }
    }

    pub(crate) fn clear(&self) {
        for shard in &self.shards {
            if let Ok(mut cache) = shard.lock() {
                cache.clear();
            }
        }
    }

    fn shard(&self, cache_key: &QueryCacheKey) -> Option<&Mutex<DnsCache>> {
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
            access_counter: 0,
        })
    }

    pub(crate) fn lookup(&mut self, key: &QueryCacheKey, now: u64) -> Option<RawCacheHit> {
        self.access_counter = self.access_counter.wrapping_add(1);
        let access = self.access_counter;
        let entry = self.entries.get_mut(key)?;

        let fresh = entry.expires_at > now;
        if !fresh && !self.config.optimistic {
            let size = entry.size;
            self.total_size = self.total_size.saturating_sub(size);
            self.entries.remove(key);
            return None;
        }

        entry.last_used = access;
        let refresh = !fresh && !entry.refreshing;
        if refresh {
            entry.refreshing = true;
        }
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
            refresh,
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

    fn insert_with_ttl(&mut self, key: QueryCacheKey, response: Vec<u8>, now: u64, ttl: u32) {
        if ttl == 0 {
            return;
        }

        self.access_counter = self.access_counter.wrapping_add(1);
        let size = response
            .len()
            .saturating_add(key.domain.len())
            .saturating_add(DNS_CACHE_ENTRY_OVERHEAD_BYTES);
        if size > self.config.max_size_bytes {
            return;
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.total_size = self.total_size.saturating_sub(previous.size);
        }

        self.total_size = self.total_size.saturating_add(size);
        self.entries.insert(
            key,
            CachedDnsResponse {
                response,
                expires_at: now.saturating_add(u64::from(ttl)),
                size,
                last_used: self.access_counter,
                refreshing: false,
            },
        );
        self.evict_over_limit(now);
    }

    fn finish_refresh(&mut self, key: &QueryCacheKey) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.refreshing = false;
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.total_size = 0;
    }

    fn evict_over_limit(&mut self, now: u64) {
        if self.total_size > self.config.max_size_bytes {
            self.evict_expired(now);
        }

        while self.total_size > self.config.max_size_bytes {
            let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                self.total_size = 0;
                return;
            };

            if let Some(entry) = self.entries.remove(&key) {
                self.total_size = self.total_size.saturating_sub(entry.size);
            }
        }
    }

    fn evict_expired(&mut self, now: u64) {
        let mut removed_size = 0_usize;
        self.entries.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed_size = removed_size.saturating_add(entry.size);
            }
            keep
        });
        self.total_size = self.total_size.saturating_sub(removed_size);
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
        refresh: raw_hit.refresh,
    })
}

pub(crate) fn insert_cached_response(
    dns_cache: &Option<Arc<DnsCacheStore>>,
    cache_config: Option<&DnsCacheConfig>,
    cache_key: QueryCacheKey,
    response: Vec<u8>,
    now: u64,
) {
    let Some(cache) = dns_cache else {
        return;
    };
    let Some(config) = cache_config else {
        return;
    };
    let Some(ttl) = cache_ttl_seconds(&response, config) else {
        return;
    };
    cache.insert_with_ttl(cache_key, response, now, ttl);
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
