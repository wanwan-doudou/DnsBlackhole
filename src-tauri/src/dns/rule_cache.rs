use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(not(test))]
use std::thread;

use serde::{Deserialize, Serialize};

use crate::{config, config::AppConfig, storage};

use super::rules::{CompiledRules, compile_rules, custom_rules_have_badfilter};

const RULE_CACHE_FORMAT_VERSION: u32 = 3;
const RULE_CACHE_MAGIC: [u8; 8] = *b"DNSBRC03";
const RULE_CACHE_FILE: &str = ".compiled-rules-v3.postcard";
const LEGACY_RULE_CACHE_FILES: [&str; 2] =
    [".compiled-rules-v1.postcard", ".compiled-rules-v2.postcard"];
const FINGERPRINT_BUFFER_SIZE: usize = 256 * 1024;
const DESERIALIZE_BUFFER_SIZE: usize = 1024 * 1024;
static LATEST_CACHE_FINGERPRINT: AtomicU64 = AtomicU64::new(0);
/// 当前仍在生效的编译结果。指纹一致时直接复用，省掉一次数十 MiB 的缓存反序列化。
/// 只持有 Weak：运行实例释放规则后记录自然失效，不会留下常驻内存。
static ACTIVE_RULES: Mutex<Option<(u64, Weak<CompiledRules>)>> = Mutex::new(None);
/// 当前生效结果里的纯远程清单层。只改自定义规则时直接复用，不再反序列化整份缓存。
static ACTIVE_REMOTE_RULES: Mutex<Option<(u64, Weak<CompiledRules>)>> = Mutex::new(None);
/// 同一进程内文件元数据未变化时复用内容指纹，避免每次保存配置都重读数十 MiB 清单。
static REMOTE_FINGERPRINT_CACHE: Mutex<Option<CachedRemoteFingerprint>> = Mutex::new(None);

#[derive(Clone, Copy)]
struct CachedRemoteFingerprint {
    manifest: u64,
    fingerprint: u64,
}

/// 规则加载依赖 ACTIVE_RULES 这一进程级单例，测试需要串行执行才能断言复用行为。
#[cfg(test)]
pub(crate) static RULE_LOAD_TEST_GUARD: Mutex<()> = Mutex::new(());
#[cfg(test)]
static FINGERPRINT_HASHED_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleLoadSource {
    Memory,
    Cache,
    Compiled,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RuleCacheClearStats {
    pub(crate) removed_files: usize,
    pub(crate) removed_bytes: u64,
}

pub(crate) struct LoadedRules {
    pub(crate) rules: Arc<CompiledRules>,
    pub(crate) source: RuleLoadSource,
}

#[derive(Serialize)]
struct RuleCacheRef<'a> {
    rules: &'a CompiledRules,
}

#[derive(Deserialize)]
struct RuleCacheOwned {
    rules: CompiledRules,
}

pub(crate) fn load_or_compile_rules(data_dir: &Path, app_config: &AppConfig) -> LoadedRules {
    let total_started = Instant::now();
    let fingerprint_started = Instant::now();
    let remote_fingerprint = remote_rules_fingerprint(data_dir, app_config);
    let fingerprint = effective_rules_fingerprint(remote_fingerprint, app_config);
    crate::performance::log_service("规则加载", "规则指纹计算", fingerprint_started);
    LATEST_CACHE_FINGERPRINT.store(remote_fingerprint, Ordering::Release);

    // 指纹一致说明规则完全没有变化，正在生效的编译结果可以直接复用，
    // 不必再从磁盘反序列化一份一模一样的出来。
    if let Some(rules) = reuse_active_rules(fingerprint) {
        crate::performance::log_service("规则加载", "总计（复用内存）", total_started);
        return LoadedRules {
            rules,
            source: RuleLoadSource::Memory,
        };
    }

    let has_custom = app_config.use_filters && !app_config.blacklist.trim().is_empty();
    // 自定义 badfilter 要回溯禁用清单里已编译的规则，增量合并做不到；这种结果混了
    // 自定义规则，也不能当作"纯清单"缓存写回，只能整体编译且不落盘。
    if has_custom && custom_rules_have_badfilter(&app_config.blacklist) {
        let compile_started = Instant::now();
        let rules_text = config::build_effective_rules(data_dir, app_config);
        let rules = Arc::new(compile_rules(&rules_text));
        crate::performance::log_service(
            "规则加载",
            "规则编译（自定义 badfilter）",
            compile_started,
        );
        remember_active_rules(fingerprint, &rules);
        crate::performance::log_service("规则加载", "总计（重新编译）", total_started);
        return LoadedRules {
            rules,
            source: RuleLoadSource::Compiled,
        };
    }

    let cache_path = rule_cache_path(data_dir);
    let (remote, source) = if let Some(remote) = reuse_remote_rules(remote_fingerprint) {
        (remote, RuleLoadSource::Memory)
    } else {
        let cache_started = Instant::now();
        if let Ok(remote) = load_rule_cache(&cache_path, remote_fingerprint) {
            crate::performance::log_service("规则加载", "编译缓存反序列化", cache_started);
            let remote = Arc::new(remote);
            remember_remote_rules(remote_fingerprint, &remote);
            (remote, RuleLoadSource::Cache)
        } else {
            crate::performance::log_service("规则加载", "缓存检查（未命中）", cache_started);
            let rules_text_started = Instant::now();
            let remote_text = config::build_remote_rules(data_dir, app_config);
            crate::performance::log_service("规则加载", "规则文本合并", rules_text_started);
            let compile_started = Instant::now();
            let remote = Arc::new(compile_rules(&remote_text));
            crate::performance::log_service("规则加载", "规则编译", compile_started);
            remember_remote_rules(remote_fingerprint, &remote);
            persist_rule_cache(cache_path, remote_fingerprint, Arc::clone(&remote));
            (remote, RuleLoadSource::Compiled)
        }
    };

    let rules = if has_custom {
        Arc::new(CompiledRules::with_custom_layer(
            Arc::clone(&remote),
            &app_config.blacklist,
        ))
    } else {
        remote
    };
    remember_active_rules(fingerprint, &rules);
    crate::performance::log_service("规则加载", "总计", total_started);
    LoadedRules { rules, source }
}

/// 取回仍在生效且指纹匹配的编译结果；已被释放或指纹不符时返回 None，
/// 由调用方回落到磁盘缓存或重新编译。
fn reuse_active_rules(fingerprint: u64) -> Option<Arc<CompiledRules>> {
    let active = ACTIVE_RULES.lock().ok()?;
    let (active_fingerprint, rules) = active.as_ref()?;
    if *active_fingerprint != fingerprint {
        return None;
    }
    rules.upgrade()
}

fn remember_active_rules(fingerprint: u64, rules: &Arc<CompiledRules>) {
    if let Ok(mut active) = ACTIVE_RULES.lock() {
        *active = Some((fingerprint, Arc::downgrade(rules)));
    }
}

fn reuse_remote_rules(fingerprint: u64) -> Option<Arc<CompiledRules>> {
    let active = ACTIVE_REMOTE_RULES.lock().ok()?;
    let (active_fingerprint, rules) = active.as_ref()?;
    (*active_fingerprint == fingerprint)
        .then(|| rules.upgrade())
        .flatten()
}

fn remember_remote_rules(fingerprint: u64, rules: &Arc<CompiledRules>) {
    if let Ok(mut active) = ACTIVE_REMOTE_RULES.lock() {
        *active = Some((fingerprint, Arc::downgrade(rules)));
    }
}

pub(crate) fn forget_active_rules() {
    if let Ok(mut active) = ACTIVE_RULES.lock() {
        *active = None;
    }
    if let Ok(mut active) = ACTIVE_REMOTE_RULES.lock() {
        *active = None;
    }
    if let Ok(mut cached) = REMOTE_FINGERPRINT_CACHE.lock() {
        *cached = None;
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

pub(crate) fn clear_rule_cache(data_dir: &Path) -> Result<RuleCacheClearStats, String> {
    // 让尚未完成的后台写入任务放弃启用旧缓存，避免清理后又立即写回。
    LATEST_CACHE_FINGERPRINT.store(0, Ordering::Release);
    // 清理缓存意味着下次要完整重走一遍编译，内存中的复用记录也一并作废。
    forget_active_rules();
    let dir = storage::filters_dir(data_dir);
    if !dir.exists() {
        return Ok(RuleCacheClearStats::default());
    }

    let mut stats = RuleCacheClearStats::default();
    let entries = fs::read_dir(&dir)
        .map_err(|error| format!("读取规则编译缓存目录失败（{}）：{error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("读取规则编译缓存文件失败：{error}"))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_rule_cache_file(file_name) {
            continue;
        }

        let metadata = entry.metadata().map_err(|error| {
            format!(
                "读取规则编译缓存文件信息失败（{}）：{error}",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            continue;
        }

        fs::remove_file(&path)
            .map_err(|error| format!("删除规则编译缓存失败（{}）：{error}", path.display()))?;
        stats.removed_files += 1;
        stats.removed_bytes += metadata.len();
    }
    Ok(stats)
}

fn is_rule_cache_file(file_name: &str) -> bool {
    std::iter::once(RULE_CACHE_FILE)
        .chain(LEGACY_RULE_CACHE_FILES)
        .any(|cache_file| {
            file_name == cache_file
                || (file_name.starts_with(&format!("{cache_file}.")) && file_name.ends_with(".tmp"))
        })
}

/// 只覆盖远程清单的指纹，用来索引磁盘编译缓存：改动自定义规则时清单部分没变，
/// 缓存依然有效，不必重编译数百万条清单规则。
fn remote_rules_fingerprint(data_dir: &Path, app_config: &AppConfig) -> u64 {
    let manifest = remote_rules_manifest(data_dir, app_config);
    if let Ok(cache) = REMOTE_FINGERPRINT_CACHE.lock()
        && let Some(cached) = *cache
        && cached.manifest == manifest
    {
        return cached.fingerprint;
    }

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

    let fingerprint = fingerprint.finish();
    if let Ok(mut cache) = REMOTE_FINGERPRINT_CACHE.lock() {
        *cache = Some(CachedRemoteFingerprint {
            manifest,
            fingerprint,
        });
    }
    fingerprint
}

fn remote_rules_manifest(data_dir: &Path, app_config: &AppConfig) -> u64 {
    let mut manifest = Fnv1a64::new();
    manifest.write(&RULE_CACHE_FORMAT_VERSION.to_le_bytes());
    manifest.write(env!("CARGO_PKG_VERSION").as_bytes());
    manifest.write(&[u8::from(app_config.use_filters)]);
    write_manifest_segment(&mut manifest, data_dir.to_string_lossy().as_bytes());
    if !app_config.use_filters {
        return manifest.finish();
    }

    for filter in app_config.filters.iter().filter(|filter| filter.enabled) {
        write_manifest_segment(&mut manifest, filter.id.as_bytes());
        write_manifest_segment(&mut manifest, filter.name.as_bytes());
        let path = storage::filters_dir(data_dir).join(format!("{}.txt", filter.id));
        match fs::metadata(path) {
            Ok(metadata) => {
                manifest.write(&metadata.len().to_le_bytes());
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_nanos())
                    .unwrap_or_default();
                manifest.write(&modified.to_le_bytes());
            }
            Err(_) => manifest.write(b"missing-filter"),
        }
    }
    manifest.finish()
}

fn write_manifest_segment(manifest: &mut Fnv1a64, value: &[u8]) {
    manifest.write(&(value.len() as u64).to_le_bytes());
    manifest.write(value);
}

/// 覆盖全部生效规则（清单 + 自定义）的指纹，用来判断内存里那份编译结果能否复用。
fn effective_rules_fingerprint(remote: u64, app_config: &AppConfig) -> u64 {
    if !app_config.use_filters || app_config.blacklist.trim().is_empty() {
        return remote;
    }
    let mut fingerprint = Fnv1a64(remote);
    fingerprint.write("\n! dnsblackhole-source:\"自定义规则\"\n".as_bytes());
    fingerprint.write(app_config.blacklist.as_bytes());
    fingerprint.finish()
}

fn hash_reader(fingerprint: &mut Fnv1a64, reader: &mut impl Read) {
    let mut buffer = vec![0_u8; FINGERPRINT_BUFFER_SIZE];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                #[cfg(test)]
                FINGERPRINT_HASHED_BYTES.fetch_add(read as u64, Ordering::Relaxed);
                fingerprint.write(&buffer[..read]);
            }
        }
    }
}

fn load_rule_cache(path: &Path, fingerprint: u64) -> Result<CompiledRules, String> {
    let file = File::open(path).map_err(|error| format!("打开缓存失败：{error}"))?;
    let mut reader = BufReader::new(file);
    let (format_version, cached_fingerprint) = read_rule_cache_header(&mut reader)?;
    if format_version != RULE_CACHE_FORMAT_VERSION || cached_fingerprint != fingerprint {
        return Err("规则缓存已过期".to_string());
    }
    let mut scratch = vec![0_u8; DESERIALIZE_BUFFER_SIZE];
    let (cache, _) = postcard::from_io::<RuleCacheOwned, _>((reader, scratch.as_mut_slice()))
        .map_err(|error| format!("解析缓存失败：{error}"))?;
    Ok(cache.rules)
}

fn read_rule_cache_header(reader: &mut impl Read) -> Result<(u32, u64), String> {
    let mut magic = [0_u8; RULE_CACHE_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("读取缓存头失败：{error}"))?;
    if magic != RULE_CACHE_MAGIC {
        return Err("规则缓存格式不受支持".to_string());
    }

    let mut version = [0_u8; std::mem::size_of::<u32>()];
    let mut fingerprint = [0_u8; std::mem::size_of::<u64>()];
    reader
        .read_exact(&mut version)
        .and_then(|_| reader.read_exact(&mut fingerprint))
        .map_err(|error| format!("读取缓存头失败：{error}"))?;
    Ok((u32::from_le_bytes(version), u64::from_le_bytes(fingerprint)))
}

fn write_rule_cache_header(writer: &mut impl Write, fingerprint: u64) -> Result<(), String> {
    writer
        .write_all(&RULE_CACHE_MAGIC)
        .and_then(|_| writer.write_all(&RULE_CACHE_FORMAT_VERSION.to_le_bytes()))
        .and_then(|_| writer.write_all(&fingerprint.to_le_bytes()))
        .map_err(|error| format!("写入缓存头失败：{error}"))
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
        write_rule_cache_header(&mut writer, fingerprint)?;
        postcard::to_io(&RuleCacheRef { rules }, &mut writer)
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
        fs::rename(&temporary, path).map_err(|error| format!("启用缓存失败：{error}"))?;
        for legacy in LEGACY_RULE_CACHE_FILES {
            let _ = fs::remove_file(parent.join(legacy));
        }
        Ok(())
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

    /// 复用记录是进程级单例，触碰它的测试必须串行，否则会互相覆盖指纹。
    fn lock_rule_load() -> std::sync::MutexGuard<'static, ()> {
        RULE_LOAD_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let _guard = lock_rule_load();
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
        // 释放编译结果，让下一次加载落到磁盘缓存而不是内存复用
        drop(first);
        let second = load_or_compile_rules(&dir, &config);
        assert_eq!(second.source, RuleLoadSource::Cache);

        fs::write(filters_dir.join("sample.txt"), "||second.example^")
            .expect("filter should update");
        let changed = load_or_compile_rules(&dir, &config);
        assert_eq!(changed.source, RuleLoadSource::Compiled);
        assert!(changed.rules.is_blocked("second.example", 1));

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    #[test]
    fn unchanged_filter_metadata_reuses_content_fingerprint() {
        let _guard = lock_rule_load();
        let dir = temporary_directory("fingerprint-metadata");
        let filters_dir = storage::filters_dir(&dir);
        fs::create_dir_all(&filters_dir).expect("filters directory should create");
        let content = "||first.example^\n".repeat(1024);
        fs::write(filters_dir.join("sample.txt"), &content).expect("filter should write");
        let config = sample_config("");
        forget_active_rules();

        FINGERPRINT_HASHED_BYTES.store(0, Ordering::Relaxed);
        let first = remote_rules_fingerprint(&dir, &config);
        assert!(FINGERPRINT_HASHED_BYTES.load(Ordering::Relaxed) > 0);

        FINGERPRINT_HASHED_BYTES.store(0, Ordering::Relaxed);
        let reused = remote_rules_fingerprint(&dir, &config);
        assert_eq!(first, reused);
        assert_eq!(
            FINGERPRINT_HASHED_BYTES.load(Ordering::Relaxed),
            0,
            "元数据未变时不应重新读取清单正文"
        );

        fs::write(
            filters_dir.join("sample.txt"),
            format!("{content}||changed.example^\n"),
        )
        .expect("filter should update");
        FINGERPRINT_HASHED_BYTES.store(0, Ordering::Relaxed);
        let changed = remote_rules_fingerprint(&dir, &config);
        assert_ne!(changed, first);
        assert!(FINGERPRINT_HASHED_BYTES.load(Ordering::Relaxed) > 0);

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    #[test]
    fn unchanged_rules_reuse_active_compilation() {
        let _guard = lock_rule_load();
        let dir = temporary_directory("reuse-active");
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

        // 指纹未变且编译结果仍在生效，应复用同一份而不再读盘
        let reused = load_or_compile_rules(&dir, &config);
        assert_eq!(reused.source, RuleLoadSource::Memory);
        assert!(Arc::ptr_eq(&first.rules, &reused.rules));

        // 删掉磁盘缓存后依然能复用，说明这条路径确实没有触碰磁盘
        fs::remove_file(filters_dir.join(RULE_CACHE_FILE)).expect("cache should remove");
        let without_cache = load_or_compile_rules(&dir, &config);
        assert_eq!(without_cache.source, RuleLoadSource::Memory);
        assert!(without_cache.rules.is_blocked("first.example", 1));

        // 编译结果全部释放后回落到重新编译
        drop((first, reused, without_cache));
        let after_release = load_or_compile_rules(&dir, &config);
        assert_eq!(after_release.source, RuleLoadSource::Compiled);

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    #[test]
    fn fingerprint_mismatch_is_rejected_before_payload_deserialization() {
        let dir = temporary_directory("header-mismatch");
        fs::create_dir_all(&dir).expect("temporary directory should create");
        let path = dir.join("rules.cache");
        let mut file = File::create(&path).expect("cache should create");
        write_rule_cache_header(&mut file, 42).expect("cache header should write");
        file.write_all(b"invalid postcard payload")
            .expect("invalid payload should write");
        drop(file);

        let mismatch = match load_rule_cache(&path, 43) {
            Ok(_) => panic!("fingerprint should mismatch"),
            Err(error) => error,
        };
        assert_eq!(mismatch, "规则缓存已过期");
        assert!(load_rule_cache(&path, 42).is_err());

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    fn sample_config(blacklist: &str) -> AppConfig {
        AppConfig {
            filters: vec![crate::config::FilterSubscription {
                id: "sample".to_string(),
                name: "测试清单".to_string(),
                enabled: true,
                ..Default::default()
            }],
            blacklist: blacklist.to_string(),
            ..Default::default()
        }
    }

    /// 本次优化的核心行为：只改自定义规则时，清单指纹没变，
    /// 应该复用磁盘上的清单编译缓存，而不是重编译整份清单。
    #[test]
    fn custom_rule_change_reuses_list_cache() {
        let _guard = lock_rule_load();
        let dir = temporary_directory("custom-cache");
        let filters_dir = storage::filters_dir(&dir);
        fs::create_dir_all(&filters_dir).expect("filters directory should create");
        fs::write(filters_dir.join("sample.txt"), "||list.example^").expect("filter should write");

        let mut config = sample_config("||first-custom.example^");
        let first = load_or_compile_rules(&dir, &config);
        assert_eq!(first.source, RuleLoadSource::Compiled);
        assert!(first.rules.is_blocked("list.example", 1));
        assert!(first.rules.is_blocked("first-custom.example", 1));

        // 只改自定义规则：直接共享当前远程清单层，不再反序列化整份缓存。
        config.blacklist = "||second-custom.example^".to_string();
        let second = load_or_compile_rules(&dir, &config);
        assert_eq!(second.source, RuleLoadSource::Memory);
        assert!(second.rules.is_blocked("list.example", 1));
        assert!(second.rules.is_blocked("second-custom.example", 1));
        assert!(
            !second.rules.is_blocked("first-custom.example", 1),
            "上一版自定义规则不应残留"
        );

        // 清空自定义规则同样命中清单缓存
        config.blacklist = String::new();
        let cleared = load_or_compile_rules(&dir, &config);
        assert_eq!(cleared.source, RuleLoadSource::Memory);
        assert!(cleared.rules.is_blocked("list.example", 1));
        assert!(!cleared.rules.is_blocked("second-custom.example", 1));

        // 清单内容变化才需要重新编译
        fs::write(filters_dir.join("sample.txt"), "||changed.example^")
            .expect("filter should update");
        let changed = load_or_compile_rules(&dir, &config);
        assert_eq!(changed.source, RuleLoadSource::Compiled);
        assert!(changed.rules.is_blocked("changed.example", 1));

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    /// 自定义 badfilter 要回溯禁用清单规则，增量合并做不到，必须整体编译。
    #[test]
    fn custom_badfilter_falls_back_to_full_compilation() {
        let _guard = lock_rule_load();
        let dir = temporary_directory("custom-badfilter");
        let filters_dir = storage::filters_dir(&dir);
        fs::create_dir_all(&filters_dir).expect("filters directory should create");
        fs::write(
            filters_dir.join("sample.txt"),
            "||list.example^\n||keep.example^",
        )
        .expect("filter should write");

        let config = sample_config("||list.example^$badfilter");
        let loaded = load_or_compile_rules(&dir, &config);
        assert_eq!(loaded.source, RuleLoadSource::Compiled);
        assert!(
            !loaded.rules.is_blocked("list.example", 1),
            "自定义 badfilter 应禁用清单里的同一条规则"
        );
        assert!(loaded.rules.is_blocked("keep.example", 1));

        // 混入自定义规则的结果不能作为纯清单缓存写回，
        // 否则之后不带 badfilter 的加载会拿到被污染的清单。
        let clean = load_or_compile_rules(&dir, &sample_config(""));
        assert_eq!(clean.source, RuleLoadSource::Compiled);
        assert!(clean.rules.is_blocked("list.example", 1));

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }

    /// 用真实规模的清单实测三条加载路径的耗时差异。默认跳过，手动执行：
    ///   $env:DNSBLACKHOLE_BENCH_DIR="<含 filters 子目录的数据目录>"
    ///   cargo test --release --lib measures_real_scale -- --ignored --nocapture
    #[test]
    #[ignore]
    fn measures_real_scale_rule_load_paths() {
        let _guard = lock_rule_load();
        let dir = PathBuf::from(
            std::env::var("DNSBLACKHOLE_BENCH_DIR")
                .expect("需要设置 DNSBLACKHOLE_BENCH_DIR 指向含 filters 子目录的数据目录"),
        );
        let filters_dir = storage::filters_dir(&dir);

        let mut filters: Vec<_> = fs::read_dir(&filters_dir)
            .expect("filters 目录应可读")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
                    return None;
                }
                let id = path.file_stem()?.to_string_lossy().into_owned();
                Some(crate::config::FilterSubscription {
                    name: id.clone(),
                    id,
                    enabled: true,
                    ..Default::default()
                })
            })
            .collect();
        filters.sort_by(|left, right| left.id.cmp(&right.id));
        assert!(!filters.is_empty(), "filters 目录里没有 .txt 清单");
        let total_bytes: u64 = filters
            .iter()
            .filter_map(|filter| fs::metadata(filters_dir.join(format!("{}.txt", filter.id))).ok())
            .map(|meta| meta.len())
            .sum();
        let no_custom = AppConfig {
            filters,
            blacklist: String::new(),
            ..Default::default()
        };

        const ROUNDS: usize = 3;

        // 冷启动：既无内存记录也无磁盘缓存，走全量编译清单
        let mut summary = None;
        let compile_runs = measure(ROUNDS, |_| {
            forget_active_rules();
            let _ = fs::remove_file(rule_cache_path(&dir));
            let started = Instant::now();
            let loaded = load_or_compile_rules(&dir, &no_custom);
            let elapsed = started.elapsed().as_millis();
            assert_eq!(loaded.source, RuleLoadSource::Compiled);
            summary = Some(loaded.rules.summary());
            elapsed
        });

        // 清单缓存命中、无自定义规则：优化点 1 之前每次保存都要付这一笔
        let cache_runs = measure(ROUNDS, |_| {
            forget_active_rules();
            let started = Instant::now();
            let loaded = load_or_compile_rules(&dir, &no_custom);
            let elapsed = started.elapsed().as_millis();
            assert_eq!(loaded.source, RuleLoadSource::Cache);
            elapsed
        });

        // 优化点 1：指纹未变直接复用内存中的编译结果（held 保证编译结果仍在生效）
        let held = load_or_compile_rules(&dir, &no_custom);
        let reuse_runs = measure(ROUNDS, |_| {
            let started = Instant::now();
            let loaded = load_or_compile_rules(&dir, &no_custom);
            let elapsed = started.elapsed().as_millis();
            assert_eq!(loaded.source, RuleLoadSource::Memory);
            assert!(Arc::ptr_eq(&held.rules, &loaded.rules));
            elapsed
        });

        // 优化点 2：改自定义规则时共享纯清单层，只编译几条自定义规则。
        // 每轮换一条不同规则，确保不是整份生效结果的指纹复用。
        let custom_runs = measure(ROUNDS, |round| {
            let domain = format!("custom-{round}.example");
            let config = AppConfig {
                blacklist: format!("||{domain}^"),
                ..no_custom.clone()
            };
            let started = Instant::now();
            let loaded = load_or_compile_rules(&dir, &config);
            let elapsed = started.elapsed().as_millis();
            assert_eq!(loaded.source, RuleLoadSource::Memory);
            assert!(loaded.rules.is_blocked(&domain, 1));
            elapsed
        });

        let fingerprint_runs = measure(ROUNDS, |_| {
            let started = Instant::now();
            let _ = remote_rules_fingerprint(&dir, &no_custom);
            started.elapsed().as_millis()
        });

        const LOOKUPS: usize = 100_000;
        let lookup_domain = "custom-benchmark.deep.example";
        let overlay = CompiledRules::with_custom_layer(
            Arc::clone(&held.rules),
            &format!("||{lookup_domain}^"),
        );
        let overlay_started = Instant::now();
        for _ in 0..LOOKUPS {
            std::hint::black_box(overlay.blocking_match(lookup_domain, 1));
        }
        let overlay_lookup_ms = overlay_started.elapsed().as_millis();

        let mut merged = load_rule_cache(
            &rule_cache_path(&dir),
            remote_rules_fingerprint(&dir, &no_custom),
        )
        .expect("清单缓存应可用于查询对照");
        merged.merge_custom_rules(&format!("||{lookup_domain}^"));
        let merged_started = Instant::now();
        for _ in 0..LOOKUPS {
            std::hint::black_box(merged.blocking_match(lookup_domain, 1));
        }
        let merged_lookup_ms = merged_started.elapsed().as_millis();

        let summary = summary.expect("编译摘要应已记录");
        let compile_ms = median(&compile_runs);
        let custom_ms = median(&custom_runs);
        println!("\n===== 真实规模规则加载实测（{ROUNDS} 轮取中位）=====");
        println!(
            "清单 {} 份，源文件 {:.1} MiB，拦截规则 {} 条，放行规则 {} 条",
            no_custom.filters.len(),
            total_bytes as f64 / (1024.0 * 1024.0),
            summary.block_rules,
            summary.allow_rules
        );
        println!(
            "  元数据未变的指纹复用：      {:>6} ms   {fingerprint_runs:?}",
            median(&fingerprint_runs)
        );
        println!("  全量编译清单：              {compile_ms:>6} ms   {compile_runs:?}");
        println!(
            "  反序列化清单缓存：          {:>6} ms   {cache_runs:?}",
            median(&cache_runs)
        );
        println!(
            "  复用内存（优化点 1）：      {:>6} ms   {reuse_runs:?}",
            median(&reuse_runs)
        );
        println!("  改自定义规则（优化点 2）：  {custom_ms:>6} ms   {custom_runs:?}");
        println!(
            "  自定义命中查询 {LOOKUPS} 次：分层 {overlay_lookup_ms} ms / 原地合并 {merged_lookup_ms} ms"
        );
        println!(
            "\n  改自定义规则净收益：{} ms（优化前 {compile_ms} -> 优化后 {custom_ms}）",
            compile_ms.saturating_sub(custom_ms)
        );
    }

    fn measure(rounds: usize, mut run: impl FnMut(usize) -> u128) -> Vec<u128> {
        (0..rounds).map(&mut run).collect()
    }

    fn median(values: &[u128]) -> u128 {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    #[test]
    fn clearing_rule_cache_preserves_downloaded_filter_sources() {
        let _guard = lock_rule_load();
        let dir = temporary_directory("safe-clear");
        let filters_dir = storage::filters_dir(&dir);
        fs::create_dir_all(filters_dir.join("nested")).expect("filters directory should create");
        fs::write(filters_dir.join("sample.txt"), "||example.org^")
            .expect("filter source should write");
        fs::write(filters_dir.join(RULE_CACHE_FILE), "cache").expect("compiled cache should write");
        fs::write(filters_dir.join(LEGACY_RULE_CACHE_FILES[0]), "old")
            .expect("legacy cache should write");
        let temporary_cache = filters_dir.join(format!("{RULE_CACHE_FILE}.1.2.tmp"));
        fs::write(&temporary_cache, "tmp").expect("temporary cache should write");
        fs::write(filters_dir.join("nested").join("keep.txt"), "keep")
            .expect("nested file should write");

        let stats = clear_rule_cache(&dir).expect("compiled cache should clear");

        assert_eq!(stats.removed_files, 3);
        assert_eq!(stats.removed_bytes, 11);
        assert!(filters_dir.join("sample.txt").exists());
        assert!(filters_dir.join("nested").join("keep.txt").exists());
        assert!(!filters_dir.join(RULE_CACHE_FILE).exists());
        assert!(!filters_dir.join(LEGACY_RULE_CACHE_FILES[0]).exists());
        assert!(!temporary_cache.exists());

        fs::remove_dir_all(dir).expect("temporary directory should remove");
    }
}
