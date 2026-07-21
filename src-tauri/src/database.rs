use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, named_params, params};
use serde::{Deserialize, Serialize};
#[cfg(not(any(target_os = "macos", windows)))]
use tauri::AppHandle;

use crate::{
    config::{self, AppConfig},
    dns::{
        DnsResponseAnswer, DnsResponseSummary, TrafficBucket, UpstreamLatencyStat,
        UpstreamRequestStat,
    },
};

const INSERT_QUERY_LOG_SQL: &str = "
    INSERT INTO query_logs
        (
            timestamp,
            domain,
            client_ip,
            blocked,
            forwarded,
            failed,
            upstream_server,
            upstream_duration_ms,
            processing_duration_ms,
            error,
            matched_rule,
            rule_source,
            rule_type,
            important_overrode,
            allowlist_rule,
            query_type,
            query_class,
            transport,
            response_source,
            response_code,
            response_answer_count,
            response_answers,
            response_truncated
        )
     VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
     )";

const UPSERT_DASHBOARD_DAILY_STATS_SQL: &str = "
    INSERT INTO dashboard_summary_stats
        (scope, dimension, value, queries, blocked, forwarded, failed, first_seen_at, last_seen_at)
    VALUES (
        strftime('%Y-%m-%d', ?1, 'unixepoch', 'localtime'),
        'total',
        '',
        1,
        ?2,
        ?3,
        ?4,
        ?1,
        ?1
    )
    ON CONFLICT(scope, dimension, value) DO UPDATE SET
        queries = queries + 1,
        blocked = blocked + excluded.blocked,
        forwarded = forwarded + excluded.forwarded,
        failed = failed + excluded.failed,
        first_seen_at = MIN(first_seen_at, excluded.first_seen_at),
        last_seen_at = MAX(last_seen_at, excluded.last_seen_at)";

const UPSERT_DASHBOARD_LIFETIME_STATS_SQL: &str = "
    INSERT INTO dashboard_summary_stats
        (
            scope,
            dimension,
            value,
            queries,
            blocked,
            forwarded,
            failed,
            requests,
            latency_total_ms,
            latency_samples,
            first_seen_at,
            last_seen_at
        )
    VALUES ('all', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
    ON CONFLICT(scope, dimension, value) DO UPDATE SET
        queries = queries + excluded.queries,
        blocked = blocked + excluded.blocked,
        forwarded = forwarded + excluded.forwarded,
        failed = failed + excluded.failed,
        requests = requests + excluded.requests,
        latency_total_ms = latency_total_ms + excluded.latency_total_ms,
        latency_samples = latency_samples + excluded.latency_samples,
        first_seen_at = MIN(first_seen_at, excluded.first_seen_at),
        last_seen_at = MAX(last_seen_at, excluded.last_seen_at)";
const READ_CONNECTION_POOL_SIZE: usize = 4;
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const WAL_MAINTENANCE_INTERVAL_SECONDS: u64 = 5 * 60;
const WAL_TRUNCATE_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;
const WAL_JOURNAL_SIZE_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
type DomainRankings = (HashMap<String, u64>, HashMap<String, u64>);
type DashboardTotals = (u64, u64, u64, u64, Option<u64>, Option<u64>);

struct DashboardStatsStatements<'connection> {
    dashboard_daily: rusqlite::Statement<'connection>,
    dashboard_lifetime: rusqlite::Statement<'connection>,
}

pub struct Database {
    conn: Mutex<Connection>,
    // WAL 模式下读写可并行；仪表盘/日志查询走独立只读连接，
    // 避免和批量日志写入互相阻塞。内存库（测试）没有独立连接，回退主连接。
    read_conns: Vec<Mutex<Connection>>,
    wal_path: Option<PathBuf>,
    last_wal_maintenance_at: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct QueryLogEntry {
    pub domain: String,
    pub query_type: u16,
    pub query_class: u16,
    pub transport: String,
    pub response_source: String,
    pub response: Option<DnsResponseSummary>,
    pub client_ip: Option<String>,
    pub blocked: bool,
    pub forwarded: bool,
    pub failed: bool,
    pub upstream_server: Option<String>,
    pub upstream_duration_ms: Option<u64>,
    pub processing_duration_ms: f64,
    pub error: Option<String>,
    pub matched_rule: Option<String>,
    pub rule_source: Option<String>,
    pub rule_type: Option<String>,
    pub important_overrode: bool,
    pub allowlist_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogRecord {
    pub id: i64,
    pub timestamp: u64,
    pub domain: String,
    pub query_type: Option<u16>,
    pub query_class: Option<u16>,
    pub transport: Option<String>,
    pub response_source: Option<String>,
    pub response: Option<DnsResponseSummary>,
    pub client_ip: Option<String>,
    pub blocked: bool,
    pub forwarded: bool,
    pub failed: bool,
    pub upstream_server: Option<String>,
    pub upstream_duration_ms: Option<u64>,
    pub processing_duration_ms: Option<f64>,
    pub error: Option<String>,
    pub matched_rule: Option<String>,
    pub rule_source: Option<String>,
    pub rule_type: Option<String>,
    pub important_overrode: bool,
    pub allowlist_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogPage {
    pub records: Vec<QueryLogRecord>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct LogStats {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub query_domains: HashMap<String, u64>,
    pub blocked_domains: HashMap<String, u64>,
    pub client_requests: HashMap<String, u64>,
    pub blocklist_hits: HashMap<String, u64>,
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
    pub dashboard_started_at: Option<u64>,
    pub dashboard_ended_at: Option<u64>,
}

impl Database {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let total_started = Instant::now();
        let path = crate::storage::database_path(data_dir);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("创建数据库目录失败：{e}"))?;
        }
        let connection_started = Instant::now();
        let conn = Connection::open(&path).map_err(|e| format!("打开数据库失败：{e}"))?;
        crate::performance::log_service("数据库启动", "主连接打开", connection_started);
        let schema_started = Instant::now();
        let mut database = Self::from_connection(conn)?;
        database.wal_path = Some(wal_path_for_database(&path));
        database.truncate_oversized_wal_at_startup();
        crate::performance::log_service("数据库启动", "连接配置与结构检查", schema_started);
        // 主连接完成建表和 WAL 设置后再打开只读连接
        let read_pool_started = Instant::now();
        database.read_conns = (0..READ_CONNECTION_POOL_SIZE)
            .filter_map(|_| open_read_connection(&path))
            .collect();
        crate::performance::log_service("数据库启动", "只读连接池", read_pool_started);
        crate::performance::log_service("数据库启动", "总计", total_started);
        Ok(database)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("打开内存数据库失败：{e}"))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, String> {
        conn.busy_timeout(DATABASE_BUSY_TIMEOUT)
            .map_err(|e| format!("设置数据库等待超时失败：{e}"))?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            read_conns: Vec::new(),
            wal_path: None,
            last_wal_maintenance_at: AtomicU64::new(unix_now()),
        })
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    pub fn load_or_migrate_config(&self, app: &AppHandle) -> Result<AppConfig, String> {
        if let Some(config) = self.load_config()? {
            return Ok(config);
        }

        let config = config::load(app).unwrap_or_default();
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn load_or_default_config(&self) -> Result<AppConfig, String> {
        if let Some(config) = self.load_config()? {
            return Ok(config);
        }

        let config = AppConfig::default();
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn load_config(&self) -> Result<Option<AppConfig>, String> {
        let conn = self.lock()?;
        let raw = conn
            .query_row("SELECT value FROM app_config WHERE id = 1", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|e| format!("读取数据库配置失败：{e}"))?;

        raw.map(|value| {
            let mut config: AppConfig =
                serde_json::from_str(&value).map_err(|e| format!("解析数据库配置失败：{e}"))?;
            config::migrate_legacy_defaults(&mut config);
            config.validate()?;
            Ok(config)
        })
        .transpose()
    }

    pub fn save_config(&self, config: &AppConfig) -> Result<(), String> {
        config.validate()?;
        let raw = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
        let now = u64_to_db_i64(unix_now(), "配置更新时间")?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO app_config (id, value, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![raw, now],
        )
        .map_err(|e| format!("保存数据库配置失败：{e}"))?;
        Ok(())
    }

    pub fn insert_query_logs(&self, entries: &[(QueryLogEntry, bool)]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("创建查询日志批量写入事务失败：{e}"))?;
        {
            let mut insert_stmt = tx
                .prepare(INSERT_QUERY_LOG_SQL)
                .map_err(|e| format!("准备批量写入查询日志失败：{e}"))?;
            let mut stats_statements = DashboardStatsStatements {
                dashboard_daily: tx
                    .prepare(UPSERT_DASHBOARD_DAILY_STATS_SQL)
                    .map_err(|e| format!("准备写入仪表盘每日统计失败：{e}"))?,
                dashboard_lifetime: tx
                    .prepare(UPSERT_DASHBOARD_LIFETIME_STATS_SQL)
                    .map_err(|e| format!("准备写入仪表盘累计统计失败：{e}"))?,
            };
            for (entry, anonymize_client_ip) in entries {
                let timestamp = unix_now();
                execute_query_log_insert(&mut insert_stmt, entry, *anonymize_client_ip, timestamp)?;
                upsert_dashboard_stats(
                    &mut stats_statements,
                    entry,
                    *anonymize_client_ip,
                    timestamp,
                )?;
            }
        }
        tx.commit()
            .map_err(|e| format!("提交查询日志批量写入失败：{e}"))?;
        self.maintain_wal_if_due(&conn);
        Ok(())
    }

    pub fn prune_query_logs(&self, retention_hours: u32) -> Result<(), String> {
        let since_raw = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let since = u64_to_db_i64(since_raw, "日志清理时间戳")?;
        let since_minute = u64_to_db_i64(since_raw / 60, "日志统计清理分钟")?;
        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("创建查询日志清理事务失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_logs WHERE timestamp < ?1",
            params![since],
        )
        .map_err(|e| format!("清理查询日志失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_log_minute_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理分钟统计失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_log_domain_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理域名统计失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_log_upstream_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理上游统计失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_log_client_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理客户端统计失败：{e}"))?;
        tx.execute(
            "DELETE FROM query_log_blocklist_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理黑名单统计失败：{e}"))?;
        tx.commit()
            .map_err(|e| format!("提交查询日志清理失败：{e}"))?;
        self.truncate_oversized_wal(&conn);
        Ok(())
    }

    pub fn log_stats(&self, _retention_hours: u32) -> Result<LogStats, String> {
        if self.read_conns.len() >= READ_CONNECTION_POOL_SIZE {
            return parallel_log_stats(&self.read_conns);
        }
        let conn = self.lock_read()?;
        log_stats_with_connection(&conn)
    }

    pub fn query_logs(
        &self,
        retention_hours: u32,
        filter: &str,
        search: &str,
        page: u32,
        page_size: u32,
    ) -> Result<QueryLogPage, String> {
        let since = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let since_param = u64_to_db_i64(since, "查询日志起始时间戳")?;
        let filter_sql = match filter {
            "blocked" => " AND blocked = 1",
            "processed" => " AND blocked = 0 AND failed = 0",
            "failed" => " AND failed = 1",
            _ => "",
        };
        let search = search.trim();
        let search_sql = if search.is_empty() {
            ""
        } else {
            " AND (
                domain LIKE :search
                OR COALESCE(client_ip, '') LIKE :search
                OR COALESCE(upstream_server, '') LIKE :search
                OR COALESCE(error, '') LIKE :search
             )"
        };
        let where_sql = format!("timestamp >= :since{search_sql}{filter_sql}");
        let sql = format!(
            "SELECT
                id,
                timestamp,
                domain,
                client_ip,
                blocked,
                forwarded,
                failed,
                upstream_server,
                upstream_duration_ms,
                processing_duration_ms,
                error,
                matched_rule,
                rule_source,
                rule_type,
                important_overrode,
                allowlist_rule,
                query_type,
                query_class,
                transport,
                response_source,
                response_code,
                response_answer_count,
                response_answers,
                response_truncated
             FROM query_logs
             WHERE {where_sql}
             ORDER BY timestamp DESC, id DESC
             LIMIT :limit OFFSET :offset"
        );
        let search_pattern = format!("%{search}%");
        let page = page.max(1);
        let page_size = page_size.clamp(20, 200);
        let limit = i64::from(page_size);
        let offset = i64::from(page.saturating_sub(1)) * i64::from(page_size);
        let conn = self.lock_read()?;
        let total_sql = format!("SELECT COUNT(*) FROM query_logs WHERE {where_sql}");
        let total = if search.is_empty() {
            conn.query_row(
                &total_sql,
                named_params! {
                    ":since": since_param,
                },
                |row| read_u64(row, 0),
            )
        } else {
            conn.query_row(
                &total_sql,
                named_params! {
                    ":since": since_param,
                    ":search": search_pattern,
                },
                |row| read_u64(row, 0),
            )
        }
        .map_err(|e| format!("统计查询日志失败：{e}"))?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("准备查询日志失败：{e}"))?;
        let mut rows = if search.is_empty() {
            stmt.query(named_params! {
                ":since": since_param,
                ":limit": limit,
                ":offset": offset,
            })
        } else {
            stmt.query(named_params! {
                ":since": since_param,
                ":search": search_pattern,
                ":limit": limit,
                ":offset": offset,
            })
        }
        .map_err(|e| format!("读取查询日志失败：{e}"))?;

        let mut records = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("读取查询日志行失败：{e}"))?
        {
            records.push(read_query_log_record(row).map_err(|e| format!("解析查询日志失败：{e}"))?);
        }
        Ok(QueryLogPage {
            records,
            total,
            page,
            page_size,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn.lock().map_err(|_| "数据库连接已损坏".into())
    }

    fn lock_read(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        if let Some(read_conn) = self.read_conns.first() {
            return read_conn.lock().map_err(|_| "数据库只读连接已损坏".into());
        }
        self.lock()
    }

    fn truncate_oversized_wal_at_startup(&self) {
        let started = Instant::now();
        let Ok(conn) = self.lock() else {
            return;
        };
        if self.truncate_oversized_wal(&conn) {
            crate::performance::log_service("数据库启动", "WAL 空间回收", started);
        }
    }

    fn maintain_wal_if_due(&self, conn: &Connection) {
        let now = unix_now();
        let previous = self.last_wal_maintenance_at.load(Ordering::Relaxed);
        if now.saturating_sub(previous) < WAL_MAINTENANCE_INTERVAL_SECONDS
            || self
                .last_wal_maintenance_at
                .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        self.truncate_oversized_wal(conn);
    }

    fn truncate_oversized_wal(&self, conn: &Connection) -> bool {
        let Some(wal_path) = self.wal_path.as_ref() else {
            return false;
        };
        let Ok(metadata) = fs::metadata(wal_path) else {
            return false;
        };
        if metadata.len() <= WAL_TRUNCATE_THRESHOLD_BYTES {
            return false;
        }

        match checkpoint_and_truncate_wal(conn) {
            Ok(true) => true,
            Ok(false) => false,
            Err(error) => {
                eprintln!("回收数据库 WAL 空间失败：{error}");
                false
            }
        }
    }
}

fn wal_path_for_database(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push("-wal");
    path.into()
}

fn checkpoint_and_truncate_wal(conn: &Connection) -> Result<bool, String> {
    conn.busy_timeout(Duration::ZERO)
        .map_err(|e| format!("设置 WAL 回收等待策略失败：{e}"))?;
    let checkpoint_result = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|busy| busy == 0)
        .map_err(|e| format!("执行 WAL 检查点失败：{e}"));
    let restore_result = conn
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(|e| format!("恢复数据库等待超时失败：{e}"));

    match (checkpoint_result, restore_result) {
        (Ok(truncated), Ok(())) => Ok(truncated),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn log_stats_with_connection(conn: &Connection) -> Result<LogStats, String> {
    let (queries, blocked, forwarded, failed, dashboard_started_at, dashboard_ended_at) =
        total_log_counts(conn)?;
    let (query_domains, blocked_domains) = grouped_domain_counts(conn)?;
    Ok(LogStats {
        queries,
        blocked,
        forwarded,
        failed,
        query_domains,
        blocked_domains,
        client_requests: client_request_counts(conn)?,
        blocklist_hits: blocklist_hit_counts(conn)?,
        traffic: traffic_buckets(conn)?,
        upstream_requests: upstream_request_counts(conn)?,
        upstream_avg_latency: upstream_avg_latency(conn)?,
        dashboard_started_at,
        dashboard_ended_at,
    })
}

fn parallel_log_stats(read_conns: &[Mutex<Connection>]) -> Result<LogStats, String> {
    std::thread::scope(|scope| {
        let totals_conn = &read_conns[0];
        let domains_conn = &read_conns[1];
        let clients_conn = &read_conns[2];
        let upstreams_conn = &read_conns[3];

        let totals = scope.spawn(move || {
            let conn = totals_conn
                .lock()
                .map_err(|_| "数据库统计连接已损坏".to_string())?;
            Ok::<_, String>((total_log_counts(&conn)?, traffic_buckets(&conn)?))
        });
        let domains = scope.spawn(move || {
            let conn = domains_conn
                .lock()
                .map_err(|_| "数据库域名排行连接已损坏".to_string())?;
            grouped_domain_counts(&conn)
        });
        let clients = scope.spawn(move || {
            let conn = clients_conn
                .lock()
                .map_err(|_| "数据库客户端排行连接已损坏".to_string())?;
            Ok::<_, String>((client_request_counts(&conn)?, blocklist_hit_counts(&conn)?))
        });
        let upstreams = scope.spawn(move || {
            let conn = upstreams_conn
                .lock()
                .map_err(|_| "数据库上游排行连接已损坏".to_string())?;
            Ok::<_, String>((
                upstream_request_counts(&conn)?,
                upstream_avg_latency(&conn)?,
            ))
        });

        let (
            (queries, blocked, forwarded, failed, dashboard_started_at, dashboard_ended_at),
            traffic,
        ) = totals
            .join()
            .map_err(|_| "数据库统计线程异常".to_string())??;
        let (query_domains, blocked_domains) = domains
            .join()
            .map_err(|_| "数据库域名排行线程异常".to_string())??;
        let (client_requests, blocklist_hits) = clients
            .join()
            .map_err(|_| "数据库客户端排行线程异常".to_string())??;
        let (upstream_requests, upstream_avg_latency) = upstreams
            .join()
            .map_err(|_| "数据库上游排行线程异常".to_string())??;

        Ok(LogStats {
            queries,
            blocked,
            forwarded,
            failed,
            query_domains,
            blocked_domains,
            client_requests,
            blocklist_hits,
            traffic,
            upstream_requests,
            upstream_avg_latency,
            dashboard_started_at,
            dashboard_ended_at,
        })
    })
}

fn total_log_counts(conn: &Connection) -> Result<DashboardTotals, String> {
    conn.query_row(
        "SELECT
            queries,
            blocked,
            forwarded,
            failed,
            first_seen_at,
            last_seen_at
         FROM dashboard_summary_stats
         WHERE scope = 'all' AND dimension = 'total' AND value = ''",
        [],
        |row| {
            Ok((
                read_u64(row, 0)?,
                read_u64(row, 1)?,
                read_u64(row, 2)?,
                read_u64(row, 3)?,
                Some(read_u64(row, 4)?),
                Some(read_u64(row, 5)?),
            ))
        },
    )
    .optional()
    .map(|row| row.unwrap_or_default())
    .map_err(|e| format!("读取仪表盘累计统计失败：{e}"))
}

fn open_read_connection(path: &std::path::Path) -> Option<Mutex<Connection>> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    if conn.busy_timeout(Duration::from_secs(2)).is_err() {
        return None;
    }
    let _ = conn.execute_batch(
        "
        PRAGMA temp_store = MEMORY;
        PRAGMA cache_size = -8192;
        ",
    );
    Some(Mutex::new(conn))
}

fn execute_query_log_insert(
    stmt: &mut rusqlite::Statement<'_>,
    entry: &QueryLogEntry,
    anonymize_client_ip: bool,
    timestamp: u64,
) -> Result<(), String> {
    let timestamp = u64_to_db_i64(timestamp, "查询日志时间戳")?;
    let upstream_duration_ms = optional_u64_to_db_i64(entry.upstream_duration_ms, "上游响应时间")?;
    let client_ip = stored_client_ip(entry, anonymize_client_ip);
    let response_answers = entry
        .response
        .as_ref()
        .map(|response| serde_json::to_string(&response.answers))
        .transpose()
        .map_err(|e| format!("序列化 DNS 响应记录失败：{e}"))?;

    stmt.execute(params![
        timestamp,
        entry.domain.as_str(),
        client_ip.as_deref(),
        bool_to_i64(entry.blocked),
        bool_to_i64(entry.forwarded),
        bool_to_i64(entry.failed),
        entry.upstream_server.as_deref(),
        upstream_duration_ms,
        entry.processing_duration_ms,
        entry.error.as_deref(),
        entry.matched_rule.as_deref(),
        entry.rule_source.as_deref(),
        entry.rule_type.as_deref(),
        bool_to_i64(entry.important_overrode),
        entry.allowlist_rule.as_deref(),
        i64::from(entry.query_type),
        i64::from(entry.query_class),
        entry.transport.as_str(),
        entry.response_source.as_str(),
        entry
            .response
            .as_ref()
            .map(|response| i64::from(response.code)),
        entry
            .response
            .as_ref()
            .map(|response| i64::from(response.answer_count)),
        response_answers.as_deref(),
        entry
            .response
            .as_ref()
            .map(|response| bool_to_i64(response.truncated)),
    ])
    .map_err(|e| format!("写入查询日志失败：{e}"))?;
    Ok(())
}

fn upsert_dashboard_stats(
    statements: &mut DashboardStatsStatements<'_>,
    entry: &QueryLogEntry,
    anonymize_client_ip: bool,
    timestamp: u64,
) -> Result<(), String> {
    let dashboard_timestamp = u64_to_db_i64(timestamp, "仪表盘统计时间戳")?;
    let blocked = bool_to_i64(entry.blocked);
    let forwarded = bool_to_i64(entry.forwarded);
    let failed = bool_to_i64(entry.failed);
    statements
        .dashboard_daily
        .execute(params![dashboard_timestamp, blocked, forwarded, failed])
        .map_err(|e| format!("写入仪表盘每日统计失败：{e}"))?;
    upsert_dashboard_lifetime(
        &mut statements.dashboard_lifetime,
        "total",
        "",
        1,
        blocked,
        forwarded,
        failed,
        0,
        0,
        0,
        dashboard_timestamp,
    )?;
    upsert_dashboard_lifetime(
        &mut statements.dashboard_lifetime,
        "domain",
        entry.domain.as_str(),
        1,
        blocked,
        0,
        0,
        0,
        0,
        0,
        dashboard_timestamp,
    )?;
    if entry.forwarded
        && let Some(upstream_server) = entry.upstream_server.as_deref()
    {
        let latency_total =
            optional_u64_to_db_i64(entry.upstream_duration_ms, "上游响应时间")?.unwrap_or_default();
        let latency_samples = if entry.upstream_duration_ms.is_some() {
            1_i64
        } else {
            0_i64
        };
        upsert_dashboard_lifetime(
            &mut statements.dashboard_lifetime,
            "upstream",
            upstream_server,
            0,
            0,
            0,
            0,
            1,
            latency_total,
            latency_samples,
            dashboard_timestamp,
        )?;
    }

    if let Some(client_ip) = stored_client_ip(entry, anonymize_client_ip)
        && !client_ip.is_empty()
    {
        upsert_dashboard_lifetime(
            &mut statements.dashboard_lifetime,
            "client",
            &client_ip,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            dashboard_timestamp,
        )?;
    }

    if entry.blocked {
        let rule_source = entry
            .rule_source
            .as_deref()
            .filter(|source| !source.is_empty())
            .unwrap_or("未知来源");
        upsert_dashboard_lifetime(
            &mut statements.dashboard_lifetime,
            "blocklist",
            rule_source,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            dashboard_timestamp,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_dashboard_lifetime(
    statement: &mut rusqlite::Statement<'_>,
    dimension: &str,
    value: &str,
    queries: i64,
    blocked: i64,
    forwarded: i64,
    failed: i64,
    requests: i64,
    latency_total_ms: i64,
    latency_samples: i64,
    timestamp: i64,
) -> Result<(), String> {
    statement
        .execute(params![
            dimension,
            value,
            queries,
            blocked,
            forwarded,
            failed,
            requests,
            latency_total_ms,
            latency_samples,
            timestamp,
        ])
        .map_err(|e| format!("写入仪表盘累计统计失败：{e}"))?;
    Ok(())
}

fn stored_client_ip(entry: &QueryLogEntry, anonymize_client_ip: bool) -> Option<String> {
    entry.client_ip.as_deref().map(|ip| {
        if anonymize_client_ip {
            anonymize_ip(ip)
        } else {
            ip.to_string()
        }
    })
}

fn read_query_log_record(row: &Row<'_>) -> rusqlite::Result<QueryLogRecord> {
    let response_code = row.get::<_, Option<u8>>(20)?;
    let response_answer_count = row.get::<_, Option<u16>>(21)?.unwrap_or_default();
    let response_answers = row
        .get::<_, Option<String>>(22)?
        .and_then(|value| serde_json::from_str::<Vec<DnsResponseAnswer>>(&value).ok())
        .unwrap_or_default();
    let response_truncated = row.get::<_, Option<i64>>(23)?.unwrap_or_default() != 0;
    let response = response_code.map(|code| DnsResponseSummary {
        code,
        answer_count: response_answer_count,
        answers: response_answers,
        truncated: response_truncated,
    });

    Ok(QueryLogRecord {
        id: row.get(0)?,
        timestamp: read_u64(row, 1)?,
        domain: row.get(2)?,
        client_ip: row.get(3)?,
        blocked: row.get::<_, i64>(4)? != 0,
        forwarded: row.get::<_, i64>(5)? != 0,
        failed: row.get::<_, i64>(6)? != 0,
        upstream_server: row.get(7)?,
        upstream_duration_ms: read_optional_u64(row, 8)?,
        processing_duration_ms: row.get(9)?,
        error: row.get(10)?,
        matched_rule: row.get(11)?,
        rule_source: row.get(12)?,
        rule_type: row.get(13)?,
        important_overrode: row.get::<_, i64>(14)? != 0,
        allowlist_rule: row.get(15)?,
        query_type: row.get(16)?,
        query_class: row.get(17)?,
        transport: row.get(18)?,
        response_source: row.get(19)?,
        response,
    })
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            domain TEXT NOT NULL,
            client_ip TEXT,
            blocked INTEGER NOT NULL DEFAULT 0,
            forwarded INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            upstream_server TEXT,
            upstream_duration_ms INTEGER,
            processing_duration_ms REAL,
            error TEXT,
            matched_rule TEXT,
            rule_source TEXT,
            rule_type TEXT,
            important_overrode INTEGER NOT NULL DEFAULT 0,
            allowlist_rule TEXT,
            query_type INTEGER,
            query_class INTEGER,
            transport TEXT,
            response_source TEXT,
            response_code INTEGER,
            response_answer_count INTEGER,
            response_answers TEXT,
            response_truncated INTEGER
        );

        CREATE TABLE IF NOT EXISTS query_log_minute_stats (
            minute INTEGER PRIMARY KEY,
            queries INTEGER NOT NULL DEFAULT 0,
            blocked INTEGER NOT NULL DEFAULT 0,
            forwarded INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS query_log_domain_stats (
            minute INTEGER NOT NULL,
            domain TEXT NOT NULL,
            queries INTEGER NOT NULL DEFAULT 0,
            blocked INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (minute, domain)
        );

        CREATE TABLE IF NOT EXISTS query_log_upstream_stats (
            minute INTEGER NOT NULL,
            upstream_server TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            latency_total_ms INTEGER NOT NULL DEFAULT 0,
            latency_samples INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (minute, upstream_server)
        );

        CREATE TABLE IF NOT EXISTS query_log_client_stats (
            minute INTEGER NOT NULL,
            client_ip TEXT NOT NULL,
            queries INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (minute, client_ip)
        );

        CREATE TABLE IF NOT EXISTS query_log_blocklist_stats (
            minute INTEGER NOT NULL,
            rule_source TEXT NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (minute, rule_source)
        );

        CREATE TABLE IF NOT EXISTS dashboard_summary_stats (
            scope TEXT NOT NULL,
            dimension TEXT NOT NULL,
            value TEXT NOT NULL,
            queries INTEGER NOT NULL DEFAULT 0,
            blocked INTEGER NOT NULL DEFAULT 0,
            forwarded INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            requests INTEGER NOT NULL DEFAULT 0,
            latency_total_ms INTEGER NOT NULL DEFAULT 0,
            latency_samples INTEGER NOT NULL DEFAULT 0,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            PRIMARY KEY (scope, dimension, value)
        ) WITHOUT ROWID;
        ",
    )
    .map_err(|e| format!("初始化数据库失败：{e}"))?;
    add_column_if_missing(conn, "query_logs", "upstream_server", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "upstream_duration_ms", "INTEGER")?;
    add_column_if_missing(conn, "query_logs", "processing_duration_ms", "REAL")?;
    add_column_if_missing(conn, "query_logs", "matched_rule", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "rule_source", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "rule_type", "TEXT")?;
    add_column_if_missing(
        conn,
        "query_logs",
        "important_overrode",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(conn, "query_logs", "allowlist_rule", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "query_type", "INTEGER")?;
    add_column_if_missing(conn, "query_logs", "query_class", "INTEGER")?;
    add_column_if_missing(conn, "query_logs", "transport", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "response_source", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "response_code", "INTEGER")?;
    add_column_if_missing(conn, "query_logs", "response_answer_count", "INTEGER")?;
    add_column_if_missing(conn, "query_logs", "response_answers", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "response_truncated", "INTEGER")?;
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp
            ON query_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_query_logs_domain
            ON query_logs(domain);
        CREATE INDEX IF NOT EXISTS idx_query_logs_blocked_domain
            ON query_logs(blocked, domain);
        CREATE INDEX IF NOT EXISTS idx_query_logs_upstream_server
            ON query_logs(upstream_server);
        CREATE INDEX IF NOT EXISTS idx_query_log_domain_stats_domain
            ON query_log_domain_stats(domain);
        CREATE INDEX IF NOT EXISTS idx_query_log_upstream_stats_upstream
            ON query_log_upstream_stats(upstream_server);
        CREATE INDEX IF NOT EXISTS idx_query_log_client_stats_client
            ON query_log_client_stats(client_ip);
        CREATE INDEX IF NOT EXISTS idx_query_log_blocklist_stats_source
            ON query_log_blocklist_stats(rule_source);
        CREATE INDEX IF NOT EXISTS idx_dashboard_summary_queries
            ON dashboard_summary_stats(scope, dimension, queries DESC, value);
        CREATE INDEX IF NOT EXISTS idx_dashboard_summary_blocked
            ON dashboard_summary_stats(scope, dimension, blocked DESC, value);
        CREATE INDEX IF NOT EXISTS idx_dashboard_summary_requests
            ON dashboard_summary_stats(scope, dimension, requests DESC, value);
        ",
    )
    .map_err(|e| format!("初始化数据库索引失败：{e}"))?;
    if !table_has_rows(conn, "dashboard_summary_stats")
        .map_err(|e| format!("检查仪表盘汇总数据失败：{e}"))?
    {
        backfill_query_log_stats_if_empty(conn)?;
        backfill_dashboard_summary_if_empty(conn)?;
    }
    Ok(())
}

fn configure_connection(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA cache_size = -8192;
        PRAGMA wal_autocheckpoint = 1000;
        ",
    )
    .map_err(|e| format!("配置数据库连接失败：{e}"))?;
    conn.pragma_update(
        None,
        "journal_size_limit",
        WAL_JOURNAL_SIZE_LIMIT_BYTES as i64,
    )
    .map_err(|e| format!("配置 WAL 文件大小限制失败：{e}"))?;
    Ok(())
}

fn backfill_query_log_stats_if_empty(conn: &Connection) -> Result<(), String> {
    if !table_has_rows(conn, "query_logs").map_err(|e| format!("检查查询日志回填数据失败：{e}"))?
    {
        return Ok(());
    }

    backfill_stats_table_if_empty(
        conn,
        "query_log_minute_stats",
        "
        INSERT INTO query_log_minute_stats (minute, queries, blocked, forwarded, failed)
        SELECT
            timestamp / 60,
            COUNT(*),
            COALESCE(SUM(blocked), 0),
            COALESCE(SUM(forwarded), 0),
            COALESCE(SUM(failed), 0)
        FROM query_logs
        GROUP BY timestamp / 60;
        ",
    )?;
    backfill_stats_table_if_empty(
        conn,
        "query_log_domain_stats",
        "
        INSERT INTO query_log_domain_stats (minute, domain, queries, blocked)
        SELECT
            timestamp / 60,
            domain,
            COUNT(*),
            COALESCE(SUM(blocked), 0)
        FROM query_logs
        GROUP BY timestamp / 60, domain;
        ",
    )?;
    backfill_stats_table_if_empty(
        conn,
        "query_log_upstream_stats",
        "
        INSERT INTO query_log_upstream_stats (
            minute,
            upstream_server,
            requests,
            latency_total_ms,
            latency_samples
        )
        SELECT
            timestamp / 60,
            upstream_server,
            COUNT(*),
            COALESCE(SUM(COALESCE(upstream_duration_ms, 0)), 0),
            COUNT(upstream_duration_ms)
        FROM query_logs
        WHERE forwarded = 1 AND upstream_server IS NOT NULL
        GROUP BY timestamp / 60, upstream_server;
        ",
    )?;
    backfill_stats_table_if_empty(
        conn,
        "query_log_client_stats",
        "
        INSERT INTO query_log_client_stats (minute, client_ip, queries)
        SELECT timestamp / 60, client_ip, COUNT(*)
        FROM query_logs
        WHERE client_ip IS NOT NULL AND client_ip != ''
        GROUP BY timestamp / 60, client_ip;
        ",
    )?;
    backfill_stats_table_if_empty(
        conn,
        "query_log_blocklist_stats",
        "
        INSERT INTO query_log_blocklist_stats (minute, rule_source, hits)
        SELECT
            timestamp / 60,
            COALESCE(NULLIF(rule_source, ''), '未知来源'),
            COUNT(*)
        FROM query_logs
        WHERE blocked = 1
        GROUP BY timestamp / 60, COALESCE(NULLIF(rule_source, ''), '未知来源');
        ",
    )?;
    Ok(())
}

fn backfill_dashboard_summary_if_empty(conn: &Connection) -> Result<(), String> {
    if table_has_rows(conn, "dashboard_summary_stats")
        .map_err(|e| format!("检查仪表盘汇总数据失败：{e}"))?
    {
        return Ok(());
    }
    if !table_has_rows(conn, "query_log_minute_stats")
        .map_err(|e| format!("检查旧统计数据失败：{e}"))?
    {
        return Ok(());
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("创建仪表盘汇总回填事务失败：{e}"))?;
    tx.execute_batch(
        "
        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, queries, blocked, forwarded, failed,
            first_seen_at, last_seen_at
        )
        SELECT
            strftime('%Y-%m-%d', minute * 60, 'unixepoch', 'localtime'),
            'total',
            '',
            SUM(queries),
            SUM(blocked),
            SUM(forwarded),
            SUM(failed),
            MIN(minute) * 60,
            MAX(minute) * 60
        FROM query_log_minute_stats
        GROUP BY strftime('%Y-%m-%d', minute * 60, 'unixepoch', 'localtime');

        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, queries, blocked, forwarded, failed,
            first_seen_at, last_seen_at
        )
        SELECT
            'all', 'total', '', SUM(queries), SUM(blocked), SUM(forwarded), SUM(failed),
            MIN(minute) * 60, MAX(minute) * 60
        FROM query_log_minute_stats;

        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, queries, blocked, first_seen_at, last_seen_at
        )
        SELECT
            'all', 'domain', domain, SUM(queries), SUM(blocked),
            MIN(minute) * 60, MAX(minute) * 60
        FROM query_log_domain_stats
        GROUP BY domain;

        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, queries, first_seen_at, last_seen_at
        )
        SELECT
            'all', 'client', client_ip, SUM(queries),
            MIN(minute) * 60, MAX(minute) * 60
        FROM query_log_client_stats
        GROUP BY client_ip;

        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, blocked, first_seen_at, last_seen_at
        )
        SELECT
            'all', 'blocklist', rule_source, SUM(hits),
            MIN(minute) * 60, MAX(minute) * 60
        FROM query_log_blocklist_stats
        GROUP BY rule_source;

        INSERT INTO dashboard_summary_stats (
            scope, dimension, value, requests, latency_total_ms, latency_samples,
            first_seen_at, last_seen_at
        )
        SELECT
            'all', 'upstream', upstream_server, SUM(requests),
            SUM(latency_total_ms), SUM(latency_samples),
            MIN(minute) * 60, MAX(minute) * 60
        FROM query_log_upstream_stats
        GROUP BY upstream_server;
        ",
    )
    .map_err(|e| format!("回填仪表盘汇总数据失败：{e}"))?;
    tx.commit()
        .map_err(|e| format!("提交仪表盘汇总回填失败：{e}"))
}

fn backfill_stats_table_if_empty(
    conn: &Connection,
    table: &str,
    backfill_sql: &str,
) -> Result<(), String> {
    if table_has_rows(conn, table).map_err(|e| format!("检查 {table} 统计失败：{e}"))? {
        return Ok(());
    }
    conn.execute_batch(backfill_sql)
        .map_err(|e| format!("回填 {table} 统计失败：{e}"))
}

fn table_has_rows(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)"),
        [],
        |row| row.get(0),
    )
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("读取数据库表结构失败：{e}"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("读取数据库字段失败：{e}"))?;

    for current in columns {
        if current.map_err(|e| format!("解析数据库字段失败：{e}"))? == column {
            return Ok(());
        }
    }

    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(|e| format!("迁移数据库字段失败：{e}"))?;
    Ok(())
}

fn grouped_domain_counts(conn: &Connection) -> Result<DomainRankings, String> {
    let mut stmt = conn
        .prepare(
            "SELECT 0 AS ranking, value, queries AS count
             FROM (
                 SELECT value, queries
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'domain' AND queries > 0
                 ORDER BY queries DESC, value ASC
                 LIMIT 200
             )
             UNION ALL
             SELECT 1 AS ranking, value, blocked AS count
             FROM (
                 SELECT value, blocked
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'domain' AND blocked > 0
                 ORDER BY blocked DESC, value ASC
                 LIMIT 200
             )
             ",
        )
        .map_err(|e| format!("准备域名排行查询失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                read_u64(row, 2)?,
            ))
        })
        .map_err(|e| format!("读取域名排行失败：{e}"))?;

    let mut query_counts = HashMap::new();
    let mut blocked_counts = HashMap::new();
    for row in rows {
        let (ranking, domain, count) = row.map_err(|e| format!("解析域名排行失败：{e}"))?;
        match ranking {
            0 => {
                query_counts.insert(domain, count);
            }
            1 => {
                blocked_counts.insert(domain, count);
            }
            _ => return Err("域名排行类型无效".into()),
        }
    }
    Ok((query_counts, blocked_counts))
}

fn client_request_counts(conn: &Connection) -> Result<HashMap<String, u64>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT value, queries
             FROM dashboard_summary_stats
             WHERE scope = 'all' AND dimension = 'client' AND queries > 0
             ORDER BY queries DESC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备客户端排行查询失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, read_u64(row, 1)?)))
        .map_err(|e| format!("读取客户端排行失败：{e}"))?;

    let mut counts = HashMap::new();
    for row in rows {
        let (client, count) = row.map_err(|e| format!("解析客户端排行失败：{e}"))?;
        counts.insert(client, count);
    }
    Ok(counts)
}

fn blocklist_hit_counts(conn: &Connection) -> Result<HashMap<String, u64>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT value, blocked
             FROM dashboard_summary_stats
             WHERE scope = 'all' AND dimension = 'blocklist' AND blocked > 0
             ORDER BY blocked DESC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备黑名单排行查询失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, read_u64(row, 1)?)))
        .map_err(|e| format!("读取黑名单排行失败：{e}"))?;

    let mut counts = HashMap::new();
    for row in rows {
        let (source, count) = row.map_err(|e| format!("解析黑名单排行失败：{e}"))?;
        counts.insert(source, count);
    }
    Ok(counts)
}

fn traffic_buckets(conn: &Connection) -> Result<Vec<TrafficBucket>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT
                CAST(strftime('%s', scope || ' 00:00:00', 'utc') AS INTEGER) / 60,
                queries,
                blocked
             FROM dashboard_summary_stats
             WHERE dimension = 'total'
               AND value = ''
               AND scope >= date('now', 'localtime', '-29 days')
               AND scope <= date('now', 'localtime')
             ORDER BY scope",
        )
        .map_err(|e| format!("准备趋势查询失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TrafficBucket {
                minute: read_u64(row, 0)?,
                queries: read_u64(row, 1)?,
                blocked: read_u64(row, 2)?,
            })
        })
        .map_err(|e| format!("读取趋势数据失败：{e}"))?;

    let mut buckets = Vec::new();
    for row in rows {
        buckets.push(row.map_err(|e| format!("解析趋势数据失败：{e}"))?);
    }
    Ok(buckets)
}

fn upstream_request_counts(conn: &Connection) -> Result<Vec<UpstreamRequestStat>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT value, requests
             FROM dashboard_summary_stats
             WHERE scope = 'all' AND dimension = 'upstream' AND requests > 0
             ORDER BY requests DESC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游请求排行失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UpstreamRequestStat {
                upstream: row.get(0)?,
                requests: read_u64(row, 1)?,
            })
        })
        .map_err(|e| format!("读取上游请求排行失败：{e}"))?;

    let mut stats = Vec::new();
    for row in rows {
        stats.push(row.map_err(|e| format!("解析上游请求排行失败：{e}"))?);
    }
    Ok(stats)
}

fn upstream_avg_latency(conn: &Connection) -> Result<Vec<UpstreamLatencyStat>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT
                value,
                CAST(ROUND(
                    CAST(latency_total_ms AS REAL) / latency_samples
                ) AS INTEGER)
             FROM dashboard_summary_stats
             WHERE scope = 'all'
               AND dimension = 'upstream'
               AND latency_samples > 0
             ORDER BY CAST(latency_total_ms AS REAL) / latency_samples ASC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游响应时间排行失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UpstreamLatencyStat {
                upstream: row.get(0)?,
                avg_ms: read_u64(row, 1)?,
            })
        })
        .map_err(|e| format!("读取上游响应时间排行失败：{e}"))?;

    let mut stats = Vec::new();
    for row in rows {
        stats.push(row.map_err(|e| format!("解析上游响应时间排行失败：{e}"))?);
    }
    Ok(stats)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn u64_to_db_i64(value: u64, field: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{field}超出数据库 INTEGER 范围"))
}

fn optional_u64_to_db_i64(value: Option<u64>, field: &str) -> Result<Option<i64>, String> {
    value.map(|value| u64_to_db_i64(value, field)).transpose()
}

fn db_i64_to_u64(index: usize, value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn read_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    db_i64_to_u64(index, row.get(index)?)
}

fn read_optional_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| db_i64_to_u64(index, value))
        .transpose()
}

fn anonymize_ip(value: &str) -> String {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => {
            let [a, b, c, _] = addr.octets();
            format!("{a}.{b}.{c}.0")
        }
        Ok(IpAddr::V6(addr)) => {
            let mut segments = addr.segments();
            segments[4..].fill(0);
            segments
                .iter()
                .map(|segment| format!("{segment:x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
        Err(_) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_config_and_query_logs() {
        let db = Database::open_in_memory().expect("db should open");
        let config = AppConfig {
            query_log_retention_hours: 6,
            ..AppConfig::default()
        };

        db.save_config(&config).expect("config should save");
        let stored = db
            .load_config()
            .expect("config should load")
            .expect("config should exist");

        assert_eq!(
            stored.query_log_retention_hours,
            config.query_log_retention_hours
        );

        db.insert_query_logs(&[
            (
                QueryLogEntry {
                    domain: "ads.example.org".into(),
                    query_type: 1,
                    query_class: 1,
                    transport: "udp".into(),
                    response_source: "blocked".into(),
                    response: Some(DnsResponseSummary {
                        code: 0,
                        answer_count: 1,
                        answers: vec![DnsResponseAnswer {
                            record_type: 1,
                            value: "0.0.0.0".into(),
                            ttl: 60,
                        }],
                        truncated: false,
                    }),
                    client_ip: Some("192.168.1.42".into()),
                    blocked: true,
                    forwarded: false,
                    failed: false,
                    upstream_server: None,
                    upstream_duration_ms: None,
                    processing_duration_ms: 0.26,
                    error: None,
                    matched_rule: Some("||example.org^".into()),
                    rule_source: Some("测试清单".into()),
                    rule_type: Some("suffix block".into()),
                    important_overrode: false,
                    allowlist_rule: None,
                },
                true,
            ),
            (
                QueryLogEntry {
                    domain: "www.example.org".into(),
                    query_type: 28,
                    query_class: 1,
                    transport: "tcp".into(),
                    response_source: "upstream".into(),
                    response: Some(DnsResponseSummary {
                        code: 0,
                        answer_count: 1,
                        answers: vec![DnsResponseAnswer {
                            record_type: 28,
                            value: "2001:db8::1".into(),
                            ttl: 300,
                        }],
                        truncated: false,
                    }),
                    client_ip: Some("192.168.1.43".into()),
                    blocked: false,
                    forwarded: true,
                    failed: false,
                    upstream_server: Some("223.5.5.5:53".into()),
                    upstream_duration_ms: Some(24),
                    processing_duration_ms: 24.75,
                    error: None,
                    matched_rule: None,
                    rule_source: None,
                    rule_type: None,
                    important_overrode: false,
                    allowlist_rule: None,
                },
                true,
            ),
        ])
        .expect("query logs should save");

        let stats = db.log_stats(6).expect("stats should load");
        assert_eq!(stats.queries, 2);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.query_domains.get("ads.example.org"), Some(&1));
        assert_eq!(stats.blocked_domains.get("ads.example.org"), Some(&1));
        assert_eq!(stats.traffic.len(), 1);
        assert_eq!(stats.upstream_requests[0].upstream, "223.5.5.5:53");
        assert_eq!(stats.upstream_requests[0].requests, 1);
        assert_eq!(stats.upstream_avg_latency[0].upstream, "223.5.5.5:53");
        assert_eq!(stats.upstream_avg_latency[0].avg_ms, 24);
        // 两条日志的客户端 IP 匿名化后同属 192.168.1.0
        assert_eq!(stats.client_requests.get("192.168.1.0"), Some(&2));
        assert_eq!(stats.blocklist_hits.get("测试清单"), Some(&1));
        assert_eq!(stats.blocklist_hits.len(), 1);

        let logs = db
            .query_logs(6, "all", "", 1, 20)
            .expect("logs should load");
        assert_eq!(logs.total, 2);
        assert_eq!(logs.records.len(), 2);
        assert_eq!(logs.records[0].domain, "www.example.org");
        assert_eq!(logs.records[0].query_type, Some(28));
        assert_eq!(logs.records[0].query_class, Some(1));
        assert_eq!(logs.records[0].transport.as_deref(), Some("tcp"));
        assert_eq!(logs.records[0].response_source.as_deref(), Some("upstream"));
        assert_eq!(
            logs.records[0]
                .response
                .as_ref()
                .map(|response| response.code),
            Some(0)
        );
        assert_eq!(
            logs.records[0]
                .response
                .as_ref()
                .and_then(|response| response.answers.first())
                .map(|answer| answer.value.as_str()),
            Some("2001:db8::1")
        );
        assert_eq!(logs.records[0].processing_duration_ms, Some(24.75));
        assert_eq!(logs.records[0].client_ip.as_deref(), Some("192.168.1.0"));

        let blocked_logs = db
            .query_logs(6, "blocked", "ads", 1, 20)
            .expect("blocked logs should load");
        assert_eq!(blocked_logs.total, 1);
        assert_eq!(blocked_logs.records.len(), 1);
        assert!(blocked_logs.records[0].blocked);
        assert_eq!(
            blocked_logs.records[0].matched_rule.as_deref(),
            Some("||example.org^")
        );

        {
            let conn = db.lock().expect("database should lock");
            conn.execute("UPDATE query_logs SET timestamp = 0", [])
                .expect("raw logs should become expired");
            conn.execute("UPDATE query_log_minute_stats SET minute = 0", [])
                .expect("minute stats should become expired");
            conn.execute("UPDATE query_log_domain_stats SET minute = 0", [])
                .expect("domain stats should become expired");
            conn.execute("UPDATE query_log_upstream_stats SET minute = 0", [])
                .expect("upstream stats should become expired");
            conn.execute("UPDATE query_log_client_stats SET minute = 0", [])
                .expect("client stats should become expired");
            conn.execute("UPDATE query_log_blocklist_stats SET minute = 0", [])
                .expect("blocklist stats should become expired");
        }
        db.prune_query_logs(1).expect("expired logs should prune");
        let preserved = db
            .log_stats(1)
            .expect("dashboard summary should survive pruning");
        assert_eq!(preserved.queries, 2);
        assert_eq!(preserved.blocked, 1);
        assert_eq!(preserved.query_domains.get("ads.example.org"), Some(&1));
    }

    #[test]
    fn anonymizes_client_ip() {
        assert_eq!(anonymize_ip("192.168.1.42"), "192.168.1.0");
        assert_eq!(anonymize_ip("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn migrates_existing_query_log_table_before_creating_new_indexes() {
        let conn = Connection::open_in_memory().expect("db should open");
        conn.execute_batch(
            "
            CREATE TABLE query_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                client_ip TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                forwarded INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );
            ",
        )
        .expect("old table should create");

        init_schema(&conn).expect("schema should migrate");

        let upstream_server: String = conn
            .query_row(
                "SELECT name FROM pragma_table_info('query_logs') WHERE name = 'upstream_server'",
                [],
                |row| row.get(0),
            )
            .expect("upstream_server column should exist");
        let upstream_index: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_query_logs_upstream_server'",
                [],
                |row| row.get(0),
            )
            .expect("upstream index should exist");
        let query_type: String = conn
            .query_row(
                "SELECT name FROM pragma_table_info('query_logs') WHERE name = 'query_type'",
                [],
                |row| row.get(0),
            )
            .expect("query_type column should exist");
        let response_source: String = conn
            .query_row(
                "SELECT name FROM pragma_table_info('query_logs') WHERE name = 'response_source'",
                [],
                |row| row.get(0),
            )
            .expect("response_source column should exist");
        let processing_duration_ms: String = conn
            .query_row(
                "SELECT name FROM pragma_table_info('query_logs') WHERE name = 'processing_duration_ms'",
                [],
                |row| row.get(0),
            )
            .expect("processing_duration_ms column should exist");
        let response_answers: String = conn
            .query_row(
                "SELECT name FROM pragma_table_info('query_logs') WHERE name = 'response_answers'",
                [],
                |row| row.get(0),
            )
            .expect("response_answers column should exist");
        let client_stats_table: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'query_log_client_stats'",
                [],
                |row| row.get(0),
            )
            .expect("client stats table should exist");
        let blocklist_stats_table: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'query_log_blocklist_stats'",
                [],
                |row| row.get(0),
            )
            .expect("blocklist stats table should exist");

        assert_eq!(upstream_server, "upstream_server");
        assert_eq!(upstream_index, "idx_query_logs_upstream_server");
        assert_eq!(query_type, "query_type");
        assert_eq!(response_source, "response_source");
        assert_eq!(processing_duration_ms, "processing_duration_ms");
        assert_eq!(response_answers, "response_answers");
        assert_eq!(client_stats_table, "query_log_client_stats");
        assert_eq!(blocklist_stats_table, "query_log_blocklist_stats");
    }

    #[test]
    fn backfills_query_log_stats_for_existing_rows() {
        let conn = Connection::open_in_memory().expect("db should open");
        conn.execute_batch(
            "
            CREATE TABLE query_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                client_ip TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                forwarded INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                upstream_server TEXT,
                upstream_duration_ms INTEGER,
                error TEXT
            );

            INSERT INTO query_logs (
                timestamp,
                domain,
                client_ip,
                blocked,
                forwarded,
                failed,
                upstream_server,
                upstream_duration_ms,
                error
            ) VALUES
                (120, 'ads.example.org', '192.168.1.2', 1, 0, 0, NULL, NULL, NULL),
                (121, 'www.example.org', '192.168.1.3', 0, 1, 0, '223.5.5.5:53', 24, NULL);
            ",
        )
        .expect("old logs should create");

        init_schema(&conn).expect("schema should initialize and backfill stats");

        let (queries, blocked, forwarded): (u64, u64, u64) = conn
            .query_row(
                "SELECT queries, blocked, forwarded
                 FROM query_log_minute_stats
                 WHERE minute = 2",
                [],
                |row| Ok((read_u64(row, 0)?, read_u64(row, 1)?, read_u64(row, 2)?)),
            )
            .expect("minute stats should backfill");
        let ads_blocked = conn
            .query_row(
                "SELECT blocked
                 FROM query_log_domain_stats
                 WHERE minute = 2 AND domain = 'ads.example.org'",
                [],
                |row| read_u64(row, 0),
            )
            .expect("domain stats should backfill");
        let latency_total = conn
            .query_row(
                "SELECT latency_total_ms
                 FROM query_log_upstream_stats
                 WHERE minute = 2 AND upstream_server = '223.5.5.5:53'",
                [],
                |row| read_u64(row, 0),
            )
            .expect("upstream stats should backfill");
        let client_queries = conn
            .query_row(
                "SELECT SUM(queries)
                 FROM query_log_client_stats
                 WHERE client_ip IN ('192.168.1.2', '192.168.1.3')",
                [],
                |row| read_u64(row, 0),
            )
            .expect("client stats should backfill");
        let unknown_blocklist_hits = conn
            .query_row(
                "SELECT hits
                 FROM query_log_blocklist_stats
                 WHERE minute = 2 AND rule_source = '未知来源'",
                [],
                |row| read_u64(row, 0),
            )
            .expect("blocklist stats should backfill");
        let dashboard_total = conn
            .query_row(
                "SELECT queries, blocked, forwarded
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'total' AND value = ''",
                [],
                |row| Ok((read_u64(row, 0)?, read_u64(row, 1)?, read_u64(row, 2)?)),
            )
            .expect("dashboard lifetime total should backfill");
        let dashboard_domain = conn
            .query_row(
                "SELECT blocked
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'domain' AND value = 'ads.example.org'",
                [],
                |row| read_u64(row, 0),
            )
            .expect("dashboard domain summary should backfill");

        assert_eq!(queries, 2);
        assert_eq!(blocked, 1);
        assert_eq!(forwarded, 1);
        assert_eq!(ads_blocked, 1);
        assert_eq!(latency_total, 24);
        assert_eq!(client_queries, 2);
        assert_eq!(unknown_blocklist_hits, 1);
        assert_eq!(dashboard_total, (2, 1, 1));
        assert_eq!(dashboard_domain, 1);
    }

    #[test]
    fn file_database_reads_log_stats_with_connection_pool() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let storage_dir = std::env::temp_dir().join(format!(
            "dnsblackhole-database-test-{}-{unique}",
            std::process::id()
        ));

        fs::create_dir_all(&storage_dir).expect("test storage directory should create");
        let database = Database::open(&storage_dir).expect("file database should open");

        assert_eq!(database.read_conns.len(), READ_CONNECTION_POOL_SIZE);
        let stats = database
            .log_stats(6)
            .expect("parallel log stats should load");
        assert_eq!(stats.queries, 0);
        assert_eq!(stats.blocked, 0);

        drop(database);
        fs::remove_dir_all(storage_dir).expect("test storage directory should remove");
    }

    #[test]
    fn checkpoint_truncates_wal_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let storage_dir = std::env::temp_dir().join(format!(
            "dnsblackhole-wal-test-{}-{unique}",
            std::process::id()
        ));
        let database_path = storage_dir.join("test.sqlite3");
        let wal_path = wal_path_for_database(&database_path);

        fs::create_dir_all(&storage_dir).expect("test storage directory should create");
        let conn = Connection::open(&database_path).expect("test database should open");
        configure_connection(&conn).expect("test database should configure");
        conn.execute_batch(
            "
            CREATE TABLE wal_test (value BLOB NOT NULL);
            WITH RECURSIVE sequence(value) AS (
                SELECT 1
                UNION ALL
                SELECT value + 1 FROM sequence WHERE value < 100
            )
            INSERT INTO wal_test (value) SELECT zeroblob(2048) FROM sequence;
            ",
        )
        .expect("test WAL should receive data");
        assert!(
            fs::metadata(&wal_path)
                .expect("test WAL should exist")
                .len()
                > 0
        );

        assert!(checkpoint_and_truncate_wal(&conn).expect("test WAL should checkpoint"));
        assert_eq!(
            fs::metadata(&wal_path)
                .expect("truncated WAL should remain accessible")
                .len(),
            0
        );

        drop(conn);
        fs::remove_dir_all(storage_dir).expect("test storage directory should remove");
    }
}
