use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, backup::Backup};
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "macos"))]
use tauri::{AppHandle, Manager};

const DATABASE_FILE: &str = "dnsblackhole.sqlite3";
const FILTERS_DIR: &str = "filters";
const LOCATOR_FILE: &str = "storage.json";

#[derive(Debug, Clone)]
pub struct StorageBootstrap {
    pub default_dir: PathBuf,
    pub data_dir: PathBuf,
    pub migration_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub current_path: String,
    pub default_path: String,
    pub pending_path: Option<String>,
    pub migration_error: Option<String>,
    pub is_default: bool,
    pub database_bytes: u64,
    pub filter_cache_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct StorageLocator {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_data_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup_data_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_migration_error: Option<String>,
}

#[cfg(not(target_os = "macos"))]
pub fn initialize(app: &AppHandle) -> Result<StorageBootstrap, String> {
    let default_dir = default_data_dir(app)?;
    initialize_at(default_dir)
}

pub(crate) fn initialize_at(default_dir: PathBuf) -> Result<StorageBootstrap, String> {
    fs::create_dir_all(&default_dir)
        .map_err(|error| format!("创建默认数据目录失败（{}）：{error}", default_dir.display()))?;
    let mut locator = read_locator(&default_dir)?;
    let mut data_dir = locator
        .data_dir
        .clone()
        .unwrap_or_else(|| default_dir.clone());
    let mut migration_error = None;

    if locator.data_dir.is_some() && !database_path(&data_dir).exists() {
        return Err(format!(
            "自定义数据目录不可用或数据库不存在：{}",
            data_dir.display()
        ));
    }

    if let Some(pending_dir) = locator.pending_data_dir.take() {
        if same_directory(&data_dir, &pending_dir) {
            locator.data_dir = custom_data_dir(&default_dir, &pending_dir);
        } else {
            match migrate_data(&data_dir, &pending_dir) {
                Ok(()) => {
                    locator.data_dir = custom_data_dir(&default_dir, &pending_dir);
                    locator.cleanup_data_dir = Some(data_dir.clone());
                    data_dir = pending_dir;
                    locator.last_migration_error = None;
                }
                Err(error) => {
                    let error = format!("数据目录迁移失败，已继续使用原目录：{error}");
                    locator.last_migration_error = Some(error.clone());
                    migration_error = Some(error);
                }
            }
        }
        write_locator(&default_dir, &locator)?;
    }

    fs::create_dir_all(&data_dir)
        .map_err(|error| format!("创建数据目录失败（{}）：{error}", data_dir.display()))?;
    Ok(StorageBootstrap {
        default_dir,
        data_dir,
        migration_error,
    })
}

pub fn finish_pending_cleanup(default_dir: &Path, current_data_dir: &Path) -> Result<(), String> {
    let mut locator = read_locator(default_dir)?;
    let Some(cleanup_dir) = locator.cleanup_data_dir.clone() else {
        return Ok(());
    };
    if same_directory(&cleanup_dir, current_data_dir) {
        locator.cleanup_data_dir = None;
        return write_locator(default_dir, &locator);
    }

    remove_managed_data(&cleanup_dir)?;
    locator.cleanup_data_dir = None;
    write_locator(default_dir, &locator)
}

pub fn storage_info(default_dir: &Path, current_data_dir: &Path) -> Result<StorageInfo, String> {
    let locator = read_locator(default_dir)?;
    let database_bytes = database_files_size(current_data_dir)?;
    let filter_cache_bytes = directory_size(&current_data_dir.join(FILTERS_DIR))?;
    Ok(StorageInfo {
        current_path: path_for_display(current_data_dir),
        default_path: path_for_display(default_dir),
        pending_path: locator.pending_data_dir.map(|path| path_for_display(&path)),
        migration_error: locator.last_migration_error,
        is_default: same_directory(default_dir, current_data_dir),
        database_bytes,
        filter_cache_bytes,
        total_bytes: database_bytes.saturating_add(filter_cache_bytes),
    })
}

pub fn request_migration(
    default_dir: &Path,
    current_data_dir: &Path,
    selected_dir: &Path,
) -> Result<StorageInfo, String> {
    let selected_dir = validate_target_directory(current_data_dir, selected_dir)?;
    let mut locator = read_locator(default_dir)?;
    locator.last_migration_error = None;
    if same_directory(current_data_dir, &selected_dir) {
        locator.pending_data_dir = None;
    } else {
        locator.pending_data_dir = Some(selected_dir);
    }
    write_locator(default_dir, &locator)?;
    storage_info(default_dir, current_data_dir)
}

pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DATABASE_FILE)
}

pub fn filters_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(FILTERS_DIR)
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map_err(|_| "无法获取默认数据目录".to_string())
}

fn locator_path(default_dir: &Path) -> PathBuf {
    default_dir.join(LOCATOR_FILE)
}

fn read_locator(default_dir: &Path) -> Result<StorageLocator, String> {
    let path = locator_path(default_dir);
    if !path.exists() {
        return Ok(StorageLocator::default());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("读取数据目录配置失败（{}）：{error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("解析数据目录配置失败（{}）：{error}", path.display()))
}

fn write_locator(default_dir: &Path, locator: &StorageLocator) -> Result<(), String> {
    fs::create_dir_all(default_dir).map_err(|error| {
        format!(
            "创建数据目录配置位置失败（{}）：{error}",
            default_dir.display()
        )
    })?;
    let path = locator_path(default_dir);
    let temporary = default_dir.join(format!("{LOCATOR_FILE}.{}.tmp", std::process::id()));
    let raw = serde_json::to_vec_pretty(locator)
        .map_err(|error| format!("序列化数据目录配置失败：{error}"))?;
    let result = (|| {
        let mut file = File::create(&temporary).map_err(|error| {
            format!(
                "创建数据目录临时配置失败（{}）：{error}",
                temporary.display()
            )
        })?;
        file.write_all(&raw).map_err(|error| {
            format!(
                "写入数据目录临时配置失败（{}）：{error}",
                temporary.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "同步数据目录临时配置失败（{}）：{error}",
                temporary.display()
            )
        })?;
        drop(file);
        replace_file(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_target_directory(
    current_data_dir: &Path,
    selected_dir: &Path,
) -> Result<PathBuf, String> {
    if !selected_dir.is_absolute() {
        return Err("数据存储路径必须是绝对路径".to_string());
    }
    #[cfg(windows)]
    if is_windows_network_path(selected_dir) {
        return Err("数据存储路径不支持网络共享目录".to_string());
    }
    fs::create_dir_all(selected_dir).map_err(|error| {
        format!(
            "创建目标数据目录失败（{}）：{error}",
            selected_dir.display()
        )
    })?;
    let selected_dir = selected_dir.canonicalize().map_err(|error| {
        format!(
            "解析目标数据目录失败（{}）：{error}",
            selected_dir.display()
        )
    })?;
    // SQLite WAL 在网络卷和云同步目录上可能损坏，与 Windows 拒绝 UNC 的策略对等
    #[cfg(target_os = "macos")]
    {
        if is_macos_network_volume(&selected_dir) {
            return Err("数据存储路径不支持网络卷，请选择本机磁盘目录".to_string());
        }
        if is_macos_cloud_synced_dir(&selected_dir) {
            return Err("数据存储路径不支持 iCloud 云同步目录，请选择本机磁盘目录".to_string());
        }
    }
    let current = current_data_dir
        .canonicalize()
        .unwrap_or_else(|_| current_data_dir.to_path_buf());
    if selected_dir != current
        && (selected_dir.starts_with(&current) || current.starts_with(&selected_dir))
    {
        return Err("新旧数据目录不能互相嵌套".to_string());
    }
    if selected_dir != current {
        ensure_target_available(&selected_dir)?;
        verify_writable(&selected_dir)?;
    }
    Ok(selected_dir)
}

#[cfg(windows)]
fn is_windows_network_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..))
    )
}

#[cfg(target_os = "macos")]
fn is_macos_network_volume(path: &Path) -> bool {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(c_path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        // 无法判断卷类型时不拦截，后续的写入测试仍会兜底
        return false;
    }
    let stats = unsafe { stats.assume_init() };
    stats.f_flags & (libc::MNT_LOCAL as u32) == 0
}

// iCloud Drive 实际落盘在 ~/Library/Mobile Documents，同步冲突会破坏 SQLite
#[cfg(target_os = "macos")]
fn is_macos_cloud_synced_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "Mobile Documents")
}

fn ensure_target_available(target_dir: &Path) -> Result<(), String> {
    let conflicts = [
        target_dir.join(DATABASE_FILE),
        target_dir.join(format!("{DATABASE_FILE}-wal")),
        target_dir.join(format!("{DATABASE_FILE}-shm")),
        target_dir.join(FILTERS_DIR),
    ];
    if conflicts.iter().any(|path| path.exists()) {
        return Err("目标目录中已经存在 DnsBlackhole 数据，请选择其他目录".to_string());
    }
    Ok(())
}

fn verify_writable(target_dir: &Path) -> Result<(), String> {
    let probe = target_dir.join(format!(".dnsblackhole-write-test-{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|error| format!("目标数据目录不可写（{}）：{error}", target_dir.display()))?;
    fs::remove_file(&probe).map_err(|error| format!("清理目标目录写入测试文件失败：{error}"))?;
    Ok(())
}

fn migrate_data(source_dir: &Path, target_dir: &Path) -> Result<(), String> {
    let target_dir = validate_target_directory(source_dir, target_dir)?;
    let source_database = database_path(source_dir);
    if !source_database.exists() {
        return Err(format!(
            "原数据库不存在或存储目录不可用：{}",
            source_database.display()
        ));
    }
    let target_database = database_path(&target_dir);
    let temporary_database = target_dir.join(format!("{DATABASE_FILE}.migration.tmp"));
    let temporary_filters =
        target_dir.join(format!("{FILTERS_DIR}.migration-{}", std::process::id()));
    let result = (|| {
        backup_database(&source_database, &temporary_database)?;
        verify_database(&temporary_database)?;
        let source_filters = filters_dir(source_dir);
        if source_filters.exists() {
            copy_directory(&source_filters, &temporary_filters)?;
        }
        if temporary_database.exists() {
            fs::rename(&temporary_database, &target_database).map_err(|error| {
                format!(
                    "启用迁移后的数据库失败（{}）：{error}",
                    target_database.display()
                )
            })?;
        }
        if temporary_filters.exists() {
            fs::rename(&temporary_filters, filters_dir(&target_dir))
                .map_err(|error| format!("启用迁移后的过滤器缓存失败：{error}"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_database);
        let _ = fs::remove_file(&target_database);
        let _ = fs::remove_dir_all(&temporary_filters);
        let _ = fs::remove_dir_all(filters_dir(&target_dir));
    }
    result
}

fn backup_database(source_path: &Path, target_path: &Path) -> Result<(), String> {
    let source = Connection::open_with_flags(
        source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("打开原数据库失败（{}）：{error}", source_path.display()))?;
    let mut target = Connection::open(target_path)
        .map_err(|error| format!("创建目标数据库失败（{}）：{error}", target_path.display()))?;
    let backup = Backup::new(&source, &mut target)
        .map_err(|error| format!("创建数据库迁移任务失败：{error}"))?;
    backup
        .run_to_completion(256, Duration::from_millis(5), None)
        .map_err(|error| format!("迁移数据库失败：{error}"))
}

fn verify_database(path: &Path) -> Result<(), String> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("打开迁移后的数据库失败（{}）：{error}", path.display()))?;
    let result = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|error| format!("校验迁移后的数据库失败：{error}"))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(format!("迁移后的数据库完整性校验未通过：{result}"))
    }
}

fn copy_directory(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| format!("创建过滤器缓存目标目录失败：{error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("读取过滤器缓存目录失败（{}）：{error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("读取过滤器缓存文件失败：{error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("读取过滤器缓存文件类型失败：{error}"))?;
        let target_path = target.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(format!(
                "过滤器缓存中不支持符号链接：{}",
                entry.path().display()
            ));
        }
        if file_type.is_dir() {
            copy_directory(&entry.path(), &target_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target_path)
                .map_err(|error| format!("复制过滤器缓存失败：{error}"))?;
        }
    }
    Ok(())
}

fn remove_managed_data(data_dir: &Path) -> Result<(), String> {
    for suffix in ["", "-wal", "-shm"] {
        let path = data_dir.join(format!("{DATABASE_FILE}{suffix}"));
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("清理原数据库文件失败（{}）：{error}", path.display()))?;
        }
    }
    let filters = filters_dir(data_dir);
    if filters.exists() {
        fs::remove_dir_all(&filters)
            .map_err(|error| format!("清理原过滤器缓存失败（{}）：{error}", filters.display()))?;
    }
    let _ = fs::remove_dir(data_dir);
    Ok(())
}

fn database_files_size(data_dir: &Path) -> Result<u64, String> {
    let mut total = 0_u64;
    for suffix in ["", "-wal", "-shm"] {
        let path = data_dir.join(format!("{DATABASE_FILE}{suffix}"));
        if path.exists() {
            total = total.saturating_add(
                fs::metadata(&path)
                    .map_err(|error| format!("读取数据库文件大小失败：{error}"))?
                    .len(),
            );
        }
    }
    Ok(total)
}

fn directory_size(path: &Path) -> Result<u64, String> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(path)
        .map_err(|error| format!("读取目录大小失败（{}）：{error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("读取目录项失败：{error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("读取目录项类型失败：{error}"))?;
        if file_type.is_dir() {
            total = total.saturating_add(directory_size(&entry.path())?);
        } else if file_type.is_file() {
            total = total.saturating_add(
                entry
                    .metadata()
                    .map_err(|error| format!("读取文件大小失败：{error}"))?
                    .len(),
            );
        }
    }
    Ok(total)
}

fn custom_data_dir(default_dir: &Path, data_dir: &Path) -> Option<PathBuf> {
    (!same_directory(default_dir, data_dir)).then(|| data_dir.to_path_buf())
}

fn same_directory(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left == right
}

fn path_for_display(path: &Path) -> String {
    let value = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(network_path) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{network_path}");
        }
        if let Some(local_path) = value.strip_prefix(r"\\?\") {
            return local_path.to_string();
        }
    }
    value.into_owned()
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }
    let from = wide(from.as_os_str());
    let to = wide(to.as_os_str());
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(format!(
            "更新数据目录配置失败：{}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|error| format!("更新数据目录配置失败：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "dnsblackhole-storage-{name}-{}-{}",
            std::process::id(),
            timestamp
        ));
        fs::create_dir_all(&path).expect("temporary directory should create");
        path
    }

    #[test]
    fn migrates_database_and_filter_cache() {
        let root = temporary_directory("migration");
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir_all(filters_dir(&source)).expect("source filters should create");
        fs::create_dir_all(&target).expect("target should create");
        let database = Connection::open(database_path(&source)).expect("database should create");
        database
            .execute_batch("CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('ok');")
            .expect("sample data should insert");
        drop(database);
        fs::write(filters_dir(&source).join("sample.txt"), "||example.org^")
            .expect("filter should write");

        migrate_data(&source, &target).expect("data should migrate");

        let migrated = Connection::open(database_path(&target)).expect("database should open");
        let value: String = migrated
            .query_row("SELECT value FROM sample", [], |row| row.get(0))
            .expect("sample data should read");
        assert_eq!(value, "ok");
        assert_eq!(
            fs::read_to_string(filters_dir(&target).join("sample.txt"))
                .expect("filter should read"),
            "||example.org^"
        );
        drop(migrated);
        fs::remove_dir_all(root).expect("temporary directory should remove");
    }

    #[test]
    fn rejects_target_with_existing_application_data() {
        let root = temporary_directory("conflict");
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir_all(&source).expect("source should create");
        fs::create_dir_all(&target).expect("target should create");
        fs::write(database_path(&target), "occupied").expect("conflict should write");

        let error = validate_target_directory(&source, &target)
            .expect_err("existing application data should be rejected");
        assert!(error.contains("已经存在 DnsBlackhole 数据"));
        fs::remove_dir_all(root).expect("temporary directory should remove");
    }

    #[test]
    fn rejects_migration_when_source_database_is_missing() {
        let root = temporary_directory("missing-source");
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir_all(&source).expect("source should create");
        fs::create_dir_all(&target).expect("target should create");

        let error = migrate_data(&source, &target)
            .expect_err("missing source database should reject migration");

        assert!(error.contains("原数据库不存在"));
        assert!(!database_path(&target).exists());
        assert!(!filters_dir(&target).exists());
        fs::remove_dir_all(root).expect("temporary directory should remove");
    }

    #[cfg(windows)]
    #[test]
    fn distinguishes_local_verbatim_paths_from_network_paths() {
        assert!(!is_windows_network_path(Path::new(r"D:\DnsBlackhole")));
        assert!(!is_windows_network_path(Path::new(r"\\?\D:\DnsBlackhole")));
        assert!(is_windows_network_path(Path::new(
            r"\\server\share\DnsBlackhole"
        )));
        assert!(is_windows_network_path(Path::new(
            r"\\?\UNC\server\share\DnsBlackhole"
        )));
    }

    #[cfg(windows)]
    #[test]
    fn hides_windows_verbatim_prefixes_from_display_paths() {
        assert_eq!(
            path_for_display(Path::new(r"\\?\D:\DnsBlackhole\data")),
            r"D:\DnsBlackhole\data"
        );
        assert_eq!(
            path_for_display(Path::new(r"\\?\UNC\server\share\data")),
            r"\\server\share\data"
        );
        assert_eq!(
            path_for_display(Path::new(r"D:\DnsBlackhole\data")),
            r"D:\DnsBlackhole\data"
        );
    }
}
