use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(not(test))]
use std::thread;

use serde::{Deserialize, Serialize};

use crate::{config, config::AppConfig, storage};

use super::rules::{CompiledRules, compile_rules};

const RULE_CACHE_FORMAT_VERSION: u32 = 1;
const RULE_CACHE_FILE: &str = ".compiled-rules-v1.postcard";
const FINGERPRINT_BUFFER_SIZE: usize = 256 * 1024;
const DESERIALIZE_BUFFER_SIZE: usize = 1024 * 1024;
static LATEST_CACHE_FINGERPRINT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleLoadSource {
    Cache,
    Compiled,
}

pub(crate) struct LoadedRules {
    pub(crate) rules: Arc<CompiledRules>,
    pub(crate) source: RuleLoadSource,
}

#[derive(Serialize)]
struct RuleCacheRef<'a> {
    format_version: u32,
    fingerprint: u64,
    rules: &'a CompiledRules,
}

#[derive(Deserialize)]
struct RuleCacheOwned {
    format_version: u32,
    fingerprint: u64,
    rules: CompiledRules,
}

pub(crate) fn load_or_compile_rules(data_dir: &Path, app_config: &AppConfig) -> LoadedRules {
    let fingerprint = effective_rules_fingerprint(data_dir, app_config);
    LATEST_CACHE_FINGERPRINT.store(fingerprint, Ordering::Release);
    let cache_path = rule_cache_path(data_dir);
    if let Ok(rules) = load_rule_cache(&cache_path, fingerprint) {
        return LoadedRules {
            rules: Arc::new(rules),
            source: RuleLoadSource::Cache,
        };
    }

    let rules_text = config::build_effective_rules(data_dir, app_config);
    let rules = Arc::new(compile_rules(&rules_text));
    persist_rule_cache(cache_path, fingerprint, Arc::clone(&rules));
    LoadedRules {
        rules,
        source: RuleLoadSource::Compiled,
    }
}

#[cfg(not(test))]
fn persist_rule_cache(path: PathBuf, fingerprint: u64, rules: Arc<CompiledRules>) {
    thread::spawn(move || {
        if let Err(error) = save_rule_cache(&path, fingerprint, &rules, true) {
            eprintln!("写入规则编译缓存失败：{error}");
        }
    });
}

#[cfg(test)]
fn persist_rule_cache(path: PathBuf, fingerprint: u64, rules: Arc<CompiledRules>) {
    save_rule_cache(&path, fingerprint, &rules, false).expect("规则编译缓存应能写入");
}

fn rule_cache_path(data_dir: &Path) -> PathBuf {
    storage::filters_dir(data_dir).join(RULE_CACHE_FILE)
}

fn effective_rules_fingerprint(data_dir: &Path, app_config: &AppConfig) -> u64 {
    let mut fingerprint = Fnv1a64::new();
    fingerprint.write(&RULE_CACHE_FORMAT_VERSION.to_le_bytes());
    fingerprint.write(env!("CARGO_PKG_VERSION").as_bytes());
    fingerprint.write(&[u8::from(app_config.use_filters)]);
    if !app_config.use_filters {
        return fingerprint.finish();
    }

    let mut has_rules = false;
    for filter in app_config.filters.iter().filter(|filter| filter.enabled) {
        let path = storage::filters_dir(data_dir).join(format!("{}.txt", filter.id));
        let Ok(mut file) = File::open(path) else {
            fingerprint.write(b"missing-filter");
            fingerprint.write(filter.id.as_bytes());
            continue;
        };
        if has_rules {
            fingerprint.write(b"\n");
        }
        let source = serde_json::to_string(&filter.name).unwrap_or_else(|_| "\"未知清单\"".into());
        fingerprint.write(b"! dnsblackhole-source:");
        fingerprint.write(source.as_bytes());
        fingerprint.write(b"\n");
        hash_reader(&mut fingerprint, &mut file);
        has_rules = true;
    }

    if !app_config.blacklist.trim().is_empty() {
        if has_rules {
            fingerprint.write(b"\n");
        }
        fingerprint.write("! dnsblackhole-source:\"自定义规则\"\n".as_bytes());
        fingerprint.write(app_config.blacklist.as_bytes());
    }
    fingerprint.finish()
}

fn hash_reader(fingerprint: &mut Fnv1a64, reader: &mut impl Read) {
    let mut buffer = vec![0_u8; FINGERPRINT_BUFFER_SIZE];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => fingerprint.write(&buffer[..read]),
        }
    }
}

fn load_rule_cache(path: &Path, fingerprint: u64) -> Result<CompiledRules, String> {
    let file = File::open(path).map_err(|error| format!("打开缓存失败：{error}"))?;
    let reader = BufReader::new(file);
    let mut scratch = vec![0_u8; DESERIALIZE_BUFFER_SIZE];
    let (cache, _) = postcard::from_io::<RuleCacheOwned, _>((reader, scratch.as_mut_slice()))
        .map_err(|error| format!("解析缓存失败：{error}"))?;
    if cache.format_version != RULE_CACHE_FORMAT_VERSION || cache.fingerprint != fingerprint {
        return Err("规则缓存已过期".to_string());
    }
    Ok(cache.rules)
}

fn save_rule_cache(
    path: &Path,
    fingerprint: u64,
    rules: &CompiledRules,
    require_latest: bool,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "规则缓存路径缺少父目录".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建缓存目录失败：{error}"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = path.with_file_name(format!(
        "{RULE_CACHE_FILE}.{}.{}.tmp",
        std::process::id(),
        nonce
    ));
    let result = (|| {
        let file = File::create(&temporary).map_err(|error| format!("创建缓存失败：{error}"))?;
        let mut writer = BufWriter::new(file);
        postcard::to_io(
            &RuleCacheRef {
                format_version: RULE_CACHE_FORMAT_VERSION,
                fingerprint,
                rules,
            },
            &mut writer,
        )
        .map_err(|error| format!("序列化缓存失败：{error}"))?;
        writer
            .flush()
            .map_err(|error| format!("刷新缓存失败：{error}"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("同步缓存失败：{error}"))?;
        drop(writer);
        if require_latest && LATEST_CACHE_FINGERPRINT.load(Ordering::Acquire) != fingerprint {
            let _ = fs::remove_file(&temporary);
            return Ok(());
        }
        if path.exists() {
            fs::remove_file(path).map_err(|error| format!("替换旧缓存失败：{error}"))?;
        }
        fs::rename(&temporary, path).map_err(|error| format!("启用缓存失败：{error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct Fnv1a64(u64);

impl Fnv1a64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    fn new() -> Self {
        Self(Self::OFFSET)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dnsblackhole-rule-cache-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos()
        ))
    }

    #[test]
    fn cache_round_trip_preserves_rule_matching() {
        let dir = temporary_directory("round-trip");
        let path = dir.join("rules.cache");
        let rules = compile_rules("||example.org^\n@@||safe.example.org^");
        save_rule_cache(&path, 42, &rules, false).expect("cache should save");

        let loaded = load_rule_cache(&path, 42).expect("cache should load");
        assert!(loaded.is_blocked("ads.example.org", 1));
        assert!(!loaded.is_blocked("safe.example.org", 1));
        assert!(load_rule_cache(&path, 43).is_err());

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    #[test]
    fn effective_content_change_invalidates_cache() {
        let dir = temporary_directory("invalidate");
        let filters_dir = storage::filters_dir(&dir);
        fs::create_dir_all(&filters_dir).expect("filters directory should create");
        fs::write(filters_dir.join("sample.txt"), "||first.example^").expect("filter should write");
        let config = AppConfig {
            filters: vec![crate::config::FilterSubscription {
                id: "sample".to_string(),
                name: "测试清单".to_string(),
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        let first = load_or_compile_rules(&dir, &config);
        assert_eq!(first.source, RuleLoadSource::Compiled);
        let second = load_or_compile_rules(&dir, &config);
        assert_eq!(second.source, RuleLoadSource::Cache);

        fs::write(filters_dir.join("sample.txt"), "||second.example^")
            .expect("filter should update");
        let changed = load_or_compile_rules(&dir, &config);
        assert_eq!(changed.source, RuleLoadSource::Compiled);
        assert!(changed.rules.is_blocked("second.example", 1));

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }
}
