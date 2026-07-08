use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, named_params, params};
use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::{
    config::{self, AppConfig},
    dns::{TrafficBucket, UpstreamLatencyStat, UpstreamRequestStat},
};

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
            let config: AppConfig =
                serde_json::from_str(&value).map_err(|e| format!("解析数据库配置失败：{e}"))?;
            config.validate()?;
            Ok(config)
        })
        .transpose()
    }

    pub fn save_config(&self, config: &AppConfig) -> Result<(), String> {
        config.validate()?;
        let raw = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
        let now = unix_now();
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

    pub fn insert_query_log(
        &self,
        entry: &QueryLogEntry,
        anonymize_client_ip: bool,
    ) -> Result<(), String> {
        let now = unix_now();
        let client_ip = entry.client_ip.as_deref().map(|ip| {
            if anonymize_client_ip {
                anonymize_ip(ip)
            } else {
                ip.to_string()
            }
        });
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO query_logs
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                now,
                entry.domain,
                client_ip,
                bool_to_i64(entry.blocked),
                bool_to_i64(entry.forwarded),
                bool_to_i64(entry.failed),
                entry.upstream_server,
                entry.upstream_duration_ms,
                entry.error,
            ],
        )
        .map_err(|e| format!("写入查询日志失败：{e}"))?;
        Ok(())
    }

    pub fn prune_query_logs(&self, retention_hours: u32) -> Result<(), String> {
        let since = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM query_logs WHERE timestamp < ?1",
            params![since],
        )
        .map_err(|e| format!("清理查询日志失败：{e}"))?;
        Ok(())
    }

    pub fn log_stats(&self, retention_hours: u32) -> Result<LogStats, String> {
        let since = unix_now().saturating_sub(u64::from(retention_hours) * 3600);
        let conn = self.lock()?;
        let (queries, blocked, forwarded, failed) = conn
            .query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(blocked), 0),
                    COALESCE(SUM(forwarded), 0),
                    COALESCE(SUM(failed), 0)
                 FROM query_logs
                 WHERE timestamp >= ?1",
                params![since],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .map_err(|e| format!("读取查询日志统计失败：{e}"))?;

        Ok(LogStats {
            queries,
            blocked,
            forwarded,
            failed,
            query_domains: grouped_domain_counts(&conn, since, false)?,
            blocked_domains: grouped_domain_counts(&conn, since, true)?,
            traffic: traffic_buckets(&conn, since)?,
            upstream_requests: upstream_request_counts(&conn, since)?,
            upstream_avg_latency: upstream_avg_latency(&conn, since)?,
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
        let filter_sql = match filter {
            "blocked" => " AND blocked = 1",
            "processed" => " AND blocked = 0 AND failed = 0",
            "failed" => " AND failed = 1",
            _ => "",
        };
        let where_sql = format!(
            "timestamp >= :since
             AND (
                domain LIKE :search
                OR COALESCE(client_ip, '') LIKE :search
                OR COALESCE(upstream_server, '') LIKE :search
                OR COALESCE(error, '') LIKE :search
             )
             {filter_sql}"
        );
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
        let search_pattern = format!("%{}%", search.trim());
        let page = page.max(1);
        let page_size = page_size.clamp(20, 200);
        let limit = i64::from(page_size);
        let offset = i64::from(page.saturating_sub(1)) * i64::from(page_size);
        let conn = self.lock()?;
        let total_sql = format!("SELECT COUNT(*) FROM query_logs WHERE {where_sql}");
        let total = conn
            .query_row(
                &total_sql,
                named_params! {
                    ":since": since,
                    ":search": search_pattern,
                },
                |row| row.get::<_, u64>(0),
            )
            .map_err(|e| format!("统计查询日志失败：{e}"))?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("准备查询日志失败：{e}"))?;
        let rows = stmt
            .query_map(
                named_params! {
                    ":since": since,
                    ":search": search_pattern,
                    ":limit": limit,
                    ":offset": offset,
                },
                |row| {
                    Ok(QueryLogRecord {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        domain: row.get(2)?,
                        client_ip: row.get(3)?,
                        blocked: row.get::<_, i64>(4)? != 0,
                        forwarded: row.get::<_, i64>(5)? != 0,
                        failed: row.get::<_, i64>(6)? != 0,
                        upstream_server: row.get(7)?,
                        upstream_duration_ms: row.get(8)?,
                        error: row.get(9)?,
                    })
                },
            )
            .map_err(|e| format!("读取查询日志失败：{e}"))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| format!("解析查询日志失败：{e}"))?);
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
        ",
    )
    .map_err(|e| format!("初始化数据库索引失败：{e}"))?;
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
    since: u64,
    blocked_only: bool,
) -> Result<HashMap<String, u64>, String> {
    let sql = if blocked_only {
        "SELECT domain, COUNT(*)
         FROM query_logs
         WHERE timestamp >= ?1 AND blocked = 1
         GROUP BY domain
         ORDER BY COUNT(*) DESC, domain ASC
         LIMIT 200"
    } else {
        "SELECT domain, COUNT(*)
         FROM query_logs
         WHERE timestamp >= ?1
         GROUP BY domain
         ORDER BY COUNT(*) DESC, domain ASC
         LIMIT 200"
    };

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("准备域名排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })
        .map_err(|e| format!("读取域名排行失败：{e}"))?;

    let mut counts = HashMap::new();
    for row in rows {
        let (domain, count) = row.map_err(|e| format!("解析域名排行失败：{e}"))?;
        counts.insert(domain, count);
    }
    Ok(counts)
}

fn traffic_buckets(conn: &Connection, since: u64) -> Result<Vec<TrafficBucket>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT timestamp / 60 AS minute, COUNT(*), COALESCE(SUM(blocked), 0)
             FROM query_logs
             WHERE timestamp >= ?1
             GROUP BY minute
             ORDER BY minute",
        )
        .map_err(|e| format!("准备趋势查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok(TrafficBucket {
                minute: row.get(0)?,
                queries: row.get(1)?,
                blocked: row.get(2)?,
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
    since: u64,
) -> Result<Vec<UpstreamRequestStat>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT upstream_server, COUNT(*)
             FROM query_logs
             WHERE timestamp >= ?1
               AND forwarded = 1
               AND upstream_server IS NOT NULL
             GROUP BY upstream_server
             ORDER BY COUNT(*) DESC, upstream_server ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游请求排行失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok(UpstreamRequestStat {
                upstream: row.get(0)?,
                requests: row.get(1)?,
            })
        })
        .map_err(|e| format!("读取上游请求排行失败：{e}"))?;

    let mut stats = Vec::new();
    for row in rows {
        stats.push(row.map_err(|e| format!("解析上游请求排行失败：{e}"))?);
    }
    Ok(stats)
}

fn upstream_avg_latency(conn: &Connection, since: u64) -> Result<Vec<UpstreamLatencyStat>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT upstream_server, CAST(ROUND(AVG(upstream_duration_ms)) AS INTEGER)
             FROM query_logs
             WHERE timestamp >= ?1
               AND forwarded = 1
               AND upstream_server IS NOT NULL
               AND upstream_duration_ms IS NOT NULL
             GROUP BY upstream_server
             ORDER BY AVG(upstream_duration_ms) ASC, upstream_server ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备上游响应时间排行失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok(UpstreamLatencyStat {
                upstream: row.get(0)?,
                avg_ms: row.get(1)?,
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
        let mut config = AppConfig::default();
        config.query_log_retention_hours = 6;

        db.save_config(&config).expect("config should save");
        let stored = db
            .load_config()
            .expect("config should load")
            .expect("config should exist");

        assert_eq!(
            stored.query_log_retention_hours,
            config.query_log_retention_hours
        );

        db.insert_query_log(
            &QueryLogEntry {
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
        )
        .expect("query log should save");

        db.insert_query_log(
            &QueryLogEntry {
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
        )
        .expect("forwarded query log should save");

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
}
