use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, Row, named_params, params};
use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::{
    config::{self, AppConfig},
    dns::{TrafficBucket, UpstreamLatencyStat, UpstreamRequestStat},
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
            error
        )
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

const UPSERT_QUERY_LOG_MINUTE_STATS_SQL: &str = "
    INSERT INTO query_log_minute_stats
        (minute, queries, blocked, forwarded, failed)
    VALUES (?1, 1, ?2, ?3, ?4)
    ON CONFLICT(minute) DO UPDATE SET
        queries = queries + 1,
        blocked = blocked + excluded.blocked,
        forwarded = forwarded + excluded.forwarded,
        failed = failed + excluded.failed";

const UPSERT_QUERY_LOG_DOMAIN_STATS_SQL: &str = "
    INSERT INTO query_log_domain_stats
        (minute, domain, queries, blocked)
    VALUES (?1, ?2, 1, ?3)
    ON CONFLICT(minute, domain) DO UPDATE SET
        queries = queries + 1,
        blocked = blocked + excluded.blocked";

const UPSERT_QUERY_LOG_UPSTREAM_STATS_SQL: &str = "
    INSERT INTO query_log_upstream_stats
        (minute, upstream_server, requests, latency_total_ms, latency_samples)
    VALUES (?1, ?2, 1, ?3, ?4)
    ON CONFLICT(minute, upstream_server) DO UPDATE SET
        requests = requests + 1,
        latency_total_ms = latency_total_ms + excluded.latency_total_ms,
        latency_samples = latency_samples + excluded.latency_samples";

pub struct Database {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct QueryLogEntry {
    pub domain: String,
    pub client_ip: Option<String>,
    pub blocked: bool,
    pub forwarded: bool,
    pub failed: bool,
    pub upstream_server: Option<String>,
    pub upstream_duration_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryLogRecord {
    pub id: i64,
    pub timestamp: u64,
    pub domain: String,
    pub client_ip: Option<String>,
    pub blocked: bool,
    pub forwarded: bool,
    pub failed: bool,
    pub upstream_server: Option<String>,
    pub upstream_duration_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
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
    pub traffic: Vec<TrafficBucket>,
    pub upstream_requests: Vec<UpstreamRequestStat>,
    pub upstream_avg_latency: Vec<UpstreamLatencyStat>,
}

impl Database {
    pub fn open(app: &AppHandle) -> Result<Self, String> {
        let path = database_path(app)?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("创建数据库目录失败：{e}"))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("打开数据库失败：{e}"))?;
        Self::from_connection(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("打开内存数据库失败：{e}"))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, String> {
        conn.busy_timeout(Duration::from_secs(2))
            .map_err(|e| format!("设置数据库等待超时失败：{e}"))?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn load_or_migrate_config(&self, app: &AppHandle) -> Result<AppConfig, String> {
        if let Some(config) = self.load_config()? {
            return Ok(config);
        }

        let config = config::load(app).unwrap_or_default();
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
            let mut minute_stats_stmt = tx
                .prepare(UPSERT_QUERY_LOG_MINUTE_STATS_SQL)
                .map_err(|e| format!("准备写入分钟统计失败：{e}"))?;
            let mut domain_stats_stmt = tx
                .prepare(UPSERT_QUERY_LOG_DOMAIN_STATS_SQL)
                .map_err(|e| format!("准备写入域名统计失败：{e}"))?;
            let mut upstream_stats_stmt = tx
                .prepare(UPSERT_QUERY_LOG_UPSTREAM_STATS_SQL)
                .map_err(|e| format!("准备写入上游统计失败：{e}"))?;
            for (entry, anonymize_client_ip) in entries {
                let timestamp = unix_now();
                execute_query_log_insert(&mut insert_stmt, entry, *anonymize_client_ip, timestamp)?;
                upsert_query_log_stats(
                    &mut minute_stats_stmt,
                    &mut domain_stats_stmt,
                    &mut upstream_stats_stmt,
                    entry,
                    timestamp,
                )?;
            }
        }
        tx.commit()
            .map_err(|e| format!("提交查询日志批量写入失败：{e}"))?;
        Ok(())
    }

    pub fn prune_query_logs(&self, retention_hours: u32) -> Result<(), String> {
        let since_raw = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let since = u64_to_db_i64(since_raw, "日志清理时间戳")?;
        let since_minute = u64_to_db_i64(since_raw / 60, "日志统计清理分钟")?;
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM query_logs WHERE timestamp < ?1",
            params![since],
        )
        .map_err(|e| format!("清理查询日志失败：{e}"))?;
        conn.execute(
            "DELETE FROM query_log_minute_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理分钟统计失败：{e}"))?;
        conn.execute(
            "DELETE FROM query_log_domain_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理域名统计失败：{e}"))?;
        conn.execute(
            "DELETE FROM query_log_upstream_stats WHERE minute < ?1",
            params![since_minute],
        )
        .map_err(|e| format!("清理上游统计失败：{e}"))?;
        Ok(())
    }

    pub fn log_stats(&self, retention_hours: u32) -> Result<LogStats, String> {
        let since = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let since_minute = since / 60;
        let since_param = u64_to_db_i64(since_minute, "日志统计起始分钟")?;
        let conn = self.lock()?;
        let (queries, blocked, forwarded, failed) = conn
            .query_row(
                "SELECT
                    COALESCE(SUM(queries), 0),
                    COALESCE(SUM(blocked), 0),
                    COALESCE(SUM(forwarded), 0),
                    COALESCE(SUM(failed), 0)
                 FROM query_log_minute_stats
                 WHERE minute >= ?1",
                params![since_param],
                |row| {
                    Ok((
                        read_u64(row, 0)?,
                        read_u64(row, 1)?,
                        read_u64(row, 2)?,
                        read_u64(row, 3)?,
                    ))
                },
            )
            .map_err(|e| format!("读取查询日志统计失败：{e}"))?;

        Ok(LogStats {
            queries,
            blocked,
            forwarded,
            failed,
            query_domains: grouped_domain_counts(&conn, since_minute, false)?,
            blocked_domains: grouped_domain_counts(&conn, since_minute, true)?,
            traffic: traffic_buckets(&conn, since_minute)?,
            upstream_requests: upstream_request_counts(&conn, since_minute)?,
            upstream_avg_latency: upstream_avg_latency(&conn, since_minute)?,
        })
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
                error
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
        let conn = self.lock()?;
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
}

fn execute_query_log_insert(
    stmt: &mut rusqlite::Statement<'_>,
    entry: &QueryLogEntry,
    anonymize_client_ip: bool,
    timestamp: u64,
) -> Result<(), String> {
    let timestamp = u64_to_db_i64(timestamp, "查询日志时间戳")?;
    let upstream_duration_ms = optional_u64_to_db_i64(entry.upstream_duration_ms, "上游响应时间")?;
    let client_ip = entry.client_ip.as_deref().map(|ip| {
        if anonymize_client_ip {
            anonymize_ip(ip)
        } else {
            ip.to_string()
        }
    });

    stmt.execute(params![
        timestamp,
        entry.domain.as_str(),
        client_ip.as_deref(),
        bool_to_i64(entry.blocked),
        bool_to_i64(entry.forwarded),
        bool_to_i64(entry.failed),
        entry.upstream_server.as_deref(),
        upstream_duration_ms,
        entry.error.as_deref(),
    ])
    .map_err(|e| format!("写入查询日志失败：{e}"))?;
    Ok(())
}

fn upsert_query_log_stats(
    minute_stmt: &mut rusqlite::Statement<'_>,
    domain_stmt: &mut rusqlite::Statement<'_>,
    upstream_stmt: &mut rusqlite::Statement<'_>,
    entry: &QueryLogEntry,
    timestamp: u64,
) -> Result<(), String> {
    let minute = u64_to_db_i64(timestamp / 60, "查询日志统计分钟")?;
    minute_stmt
        .execute(params![
            minute,
            bool_to_i64(entry.blocked),
            bool_to_i64(entry.forwarded),
            bool_to_i64(entry.failed),
        ])
        .map_err(|e| format!("写入分钟统计失败：{e}"))?;
    domain_stmt
        .execute(params![
            minute,
            entry.domain.as_str(),
            bool_to_i64(entry.blocked),
        ])
        .map_err(|e| format!("写入域名统计失败：{e}"))?;

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
        upstream_stmt
            .execute(params![
                minute,
                upstream_server,
                latency_total,
                latency_samples
            ])
            .map_err(|e| format!("写入上游统计失败：{e}"))?;
    }

    Ok(())
}

fn read_query_log_record(row: &Row<'_>) -> rusqlite::Result<QueryLogRecord> {
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
        error: row.get(9)?,
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
            error TEXT
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
        ",
    )
    .map_err(|e| format!("初始化数据库失败：{e}"))?;
    add_column_if_missing(conn, "query_logs", "upstream_server", "TEXT")?;
    add_column_if_missing(conn, "query_logs", "upstream_duration_ms", "INTEGER")?;
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
        ",
    )
    .map_err(|e| format!("初始化数据库索引失败：{e}"))?;
    backfill_query_log_stats_if_empty(conn)?;
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
    Ok(())
}

fn backfill_query_log_stats_if_empty(conn: &Connection) -> Result<(), String> {
    let existing_stats = conn
        .query_row("SELECT COUNT(*) FROM query_log_minute_stats", [], |row| {
            read_u64(row, 0)
        })
        .map_err(|e| format!("检查查询日志统计失败：{e}"))?;
    if existing_stats > 0 {
        return Ok(());
    }

    let existing_logs = conn
        .query_row("SELECT COUNT(*) FROM query_logs", [], |row| {
            read_u64(row, 0)
        })
        .map_err(|e| format!("检查查询日志回填数据失败：{e}"))?;
    if existing_logs == 0 {
        return Ok(());
    }

    conn.execute_batch(
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

        INSERT INTO query_log_domain_stats (minute, domain, queries, blocked)
        SELECT
            timestamp / 60,
            domain,
            COUNT(*),
            COALESCE(SUM(blocked), 0)
        FROM query_logs
        GROUP BY timestamp / 60, domain;

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
    )
    .map_err(|e| format!("回填查询日志统计失败：{e}"))?;
    Ok(())
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

fn grouped_domain_counts(
    conn: &Connection,
    since_minute: u64,
    blocked_only: bool,
) -> Result<HashMap<String, u64>, String> {
    let since = u64_to_db_i64(since_minute, "域名排行起始分钟")?;
    let sql = if blocked_only {
        "SELECT domain, COALESCE(SUM(blocked), 0)
         FROM query_log_domain_stats
         WHERE minute >= ?1
         GROUP BY domain
         HAVING COALESCE(SUM(blocked), 0) > 0
         ORDER BY COALESCE(SUM(blocked), 0) DESC, domain ASC
         LIMIT 200"
    } else {
        "SELECT domain, COALESCE(SUM(queries), 0)
         FROM query_log_domain_stats
         WHERE minute >= ?1
         GROUP BY domain
         HAVING COALESCE(SUM(queries), 0) > 0
         ORDER BY COALESCE(SUM(queries), 0) DESC, domain ASC
         LIMIT 200"
    };

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("准备域名排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, read_u64(row, 1)?))
        })
        .map_err(|e| format!("读取域名排行失败：{e}"))?;

    let mut counts = HashMap::new();
    for row in rows {
        let (domain, count) = row.map_err(|e| format!("解析域名排行失败：{e}"))?;
        counts.insert(domain, count);
    }
    Ok(counts)
}

fn traffic_buckets(conn: &Connection, since_minute: u64) -> Result<Vec<TrafficBucket>, String> {
    let since = u64_to_db_i64(since_minute, "趋势起始分钟")?;
    let mut stmt = conn
        .prepare(
            "SELECT minute, queries, blocked
             FROM query_log_minute_stats
             WHERE minute >= ?1
             ORDER BY minute",
        )
        .map_err(|e| format!("准备趋势查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
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

fn upstream_request_counts(
    conn: &Connection,
    since_minute: u64,
) -> Result<Vec<UpstreamRequestStat>, String> {
    let since = u64_to_db_i64(since_minute, "上游请求排行起始分钟")?;
    let mut stmt = conn
        .prepare(
            "SELECT upstream_server, COALESCE(SUM(requests), 0)
             FROM query_log_upstream_stats
             WHERE minute >= ?1
             GROUP BY upstream_server
             HAVING COALESCE(SUM(requests), 0) > 0
             ORDER BY COALESCE(SUM(requests), 0) DESC, upstream_server ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游请求排行失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
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

fn upstream_avg_latency(
    conn: &Connection,
    since_minute: u64,
) -> Result<Vec<UpstreamLatencyStat>, String> {
    let since = u64_to_db_i64(since_minute, "上游响应时间排行起始分钟")?;
    let mut stmt = conn
        .prepare(
            "SELECT
                upstream_server,
                CAST(ROUND(
                    CAST(SUM(latency_total_ms) AS REAL) / SUM(latency_samples)
                ) AS INTEGER)
             FROM query_log_upstream_stats
             WHERE minute >= ?1
               AND latency_samples > 0
             GROUP BY upstream_server
             HAVING SUM(latency_samples) > 0
             ORDER BY CAST(SUM(latency_total_ms) AS REAL) / SUM(latency_samples) ASC,
                upstream_server ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游响应时间排行失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
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

fn database_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join("dnsblackhole.sqlite3"))
        .map_err(|_| "无法获取数据库目录".to_string())
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
                    client_ip: Some("192.168.1.42".into()),
                    blocked: true,
                    forwarded: false,
                    failed: false,
                    upstream_server: None,
                    upstream_duration_ms: None,
                    error: None,
                },
                true,
            ),
            (
                QueryLogEntry {
                    domain: "www.example.org".into(),
                    client_ip: Some("192.168.1.43".into()),
                    blocked: false,
                    forwarded: true,
                    failed: false,
                    upstream_server: Some("223.5.5.5:53".into()),
                    upstream_duration_ms: Some(24),
                    error: None,
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

        let logs = db
            .query_logs(6, "all", "", 1, 20)
            .expect("logs should load");
        assert_eq!(logs.total, 2);
        assert_eq!(logs.records.len(), 2);
        assert_eq!(logs.records[0].domain, "www.example.org");
        assert_eq!(logs.records[0].client_ip.as_deref(), Some("192.168.1.0"));

        let blocked_logs = db
            .query_logs(6, "blocked", "ads", 1, 20)
            .expect("blocked logs should load");
        assert_eq!(blocked_logs.total, 1);
        assert_eq!(blocked_logs.records.len(), 1);
        assert!(blocked_logs.records[0].blocked);
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

        assert_eq!(upstream_server, "upstream_server");
        assert_eq!(upstream_index, "idx_query_logs_upstream_server");
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

        assert_eq!(queries, 2);
        assert_eq!(blocked, 1);
        assert_eq!(forwarded, 1);
        assert_eq!(ads_blocked, 1);
        assert_eq!(latency_total, 24);
    }
}
