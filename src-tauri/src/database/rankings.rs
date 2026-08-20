use std::collections::HashMap;

use rusqlite::{Connection, params};

use crate::dns::{TrafficBucket, UpstreamLatencyStat, UpstreamRequestStat};

use super::{DomainRankings, TRAFFIC_RETENTION_HOURS, read_u64, u64_to_db_i64, unix_now};

type ClientRankings = (HashMap<String, u64>, HashMap<String, u64>);

pub(super) fn grouped_domain_counts(
    conn: &Connection,
    since_hour: u64,
) -> Result<DomainRankings, String> {
    if since_hour == 0 {
        return grouped_lifetime_domain_counts(conn);
    }
    let since = u64_to_db_i64(since_hour, "域名统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "WITH aggregated AS MATERIALIZED (
                 SELECT value, SUM(queries) AS queries, SUM(blocked) AS blocked
                 FROM statistics_hourly
                 WHERE dimension = 'domain' AND hour >= ?1
                 GROUP BY value
             ),
             query_rank AS (
                 SELECT 0 AS ranking, value, queries AS count
                 FROM aggregated
                 WHERE queries > 0
                 ORDER BY queries DESC, value ASC
                 LIMIT 200
             ),
             blocked_rank AS (
                 SELECT 1 AS ranking, value, blocked AS count
                 FROM aggregated
                 WHERE blocked > 0
                 ORDER BY blocked DESC, value ASC
                 LIMIT 200
             )
             SELECT * FROM query_rank
             UNION ALL
             SELECT * FROM blocked_rank",
        )
        .map_err(|e| format!("准备域名排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
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

fn grouped_lifetime_domain_counts(conn: &Connection) -> Result<DomainRankings, String> {
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
             )",
        )
        .map_err(|e| format!("准备永久域名排行查询失败：{e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                read_u64(row, 2)?,
            ))
        })
        .map_err(|e| format!("读取永久域名排行失败：{e}"))?;

    let mut query_counts = HashMap::new();
    let mut blocked_counts = HashMap::new();
    for row in rows {
        let (ranking, domain, count) = row.map_err(|e| format!("解析永久域名排行失败：{e}"))?;
        match ranking {
            0 => {
                query_counts.insert(domain, count);
            }
            1 => {
                blocked_counts.insert(domain, count);
            }
            _ => return Err("永久域名排行类型无效".into()),
        }
    }
    Ok((query_counts, blocked_counts))
}

pub(super) fn client_counts(conn: &Connection, since_hour: u64) -> Result<ClientRankings, String> {
    if since_hour == 0 {
        let mut stmt = conn
            .prepare(
                "SELECT value, queries, blocked
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'client' AND queries > 0
                 ORDER BY queries DESC, value ASC
                 LIMIT 200",
            )
            .map_err(|e| format!("准备永久客户端排行查询失败：{e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    read_u64(row, 1)?,
                    read_u64(row, 2)?,
                ))
            })
            .map_err(|e| format!("读取永久客户端排行失败：{e}"))?;
        return collect_client_counts(rows, "永久客户端排行");
    }
    let since = u64_to_db_i64(since_hour, "客户端统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "SELECT value, SUM(queries) AS queries, SUM(blocked) AS blocked
             FROM statistics_hourly
             WHERE dimension = 'client' AND hour >= ?1
             GROUP BY value
             HAVING SUM(queries) > 0
             ORDER BY SUM(queries) DESC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备客户端排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok((
                row.get::<_, String>(0)?,
                read_u64(row, 1)?,
                read_u64(row, 2)?,
            ))
        })
        .map_err(|e| format!("读取客户端排行失败：{e}"))?;

    collect_client_counts(rows, "客户端排行")
}

fn collect_client_counts<T>(rows: T, label: &str) -> Result<ClientRankings, String>
where
    T: IntoIterator<Item = rusqlite::Result<(String, u64, u64)>>,
{
    let mut requests = HashMap::new();
    let mut blocked = HashMap::new();
    for row in rows {
        let (client, query_count, blocked_count) =
            row.map_err(|e| format!("解析{label}失败：{e}"))?;
        requests.insert(client.clone(), query_count);
        if blocked_count > 0 {
            blocked.insert(client, blocked_count);
        }
    }
    Ok((requests, blocked))
}

pub(super) fn blocklist_hit_counts(
    conn: &Connection,
    since_hour: u64,
) -> Result<HashMap<String, u64>, String> {
    if since_hour == 0 {
        return lifetime_count_ranking(conn, "blocklist", "blocked", "黑名单");
    }
    let since = u64_to_db_i64(since_hour, "黑名单统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "SELECT value, SUM(blocked) AS blocked
             FROM statistics_hourly
             WHERE dimension = 'blocklist' AND hour >= ?1
             GROUP BY value
             HAVING SUM(blocked) > 0
             ORDER BY SUM(blocked) DESC, value ASC
             LIMIT 200",
        )
        .map_err(|e| format!("准备黑名单排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, read_u64(row, 1)?))
        })
        .map_err(|e| format!("读取黑名单排行失败：{e}"))?;

    let mut counts = HashMap::new();
    for row in rows {
        let (source, count) = row.map_err(|e| format!("解析黑名单排行失败：{e}"))?;
        counts.insert(source, count);
    }
    Ok(counts)
}

fn lifetime_count_ranking(
    conn: &Connection,
    dimension: &str,
    count_column: &str,
    label: &str,
) -> Result<HashMap<String, u64>, String> {
    let sql = format!(
        "SELECT value, {count_column}
         FROM dashboard_summary_stats
         WHERE scope = 'all' AND dimension = ?1 AND {count_column} > 0
         ORDER BY {count_column} DESC, value ASC
         LIMIT 200"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("准备永久{label}排行查询失败：{e}"))?;
    let rows = stmt
        .query_map(params![dimension], |row| {
            Ok((row.get::<_, String>(0)?, read_u64(row, 1)?))
        })
        .map_err(|e| format!("读取永久{label}排行失败：{e}"))?;
    let mut counts = HashMap::new();
    for row in rows {
        let (value, count) = row.map_err(|e| format!("解析永久{label}排行失败：{e}"))?;
        counts.insert(value, count);
    }
    Ok(counts)
}

pub(super) fn traffic_buckets(conn: &Connection) -> Result<Vec<TrafficBucket>, String> {
    let since_hour = unix_now().saturating_sub(TRAFFIC_RETENTION_HOURS * 3600) / 3600;
    let since = u64_to_db_i64(since_hour, "趋势统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "SELECT
            CAST(strftime(
                '%s',
                datetime(hour * 3600, 'unixepoch', 'localtime', 'start of day'),
                'utc'
            ) AS INTEGER) / 60 AS bucket_minute,
            SUM(queries),
            SUM(blocked)
         FROM statistics_hourly
         WHERE dimension = 'total' AND value = '' AND hour >= ?1
         GROUP BY date(hour * 3600, 'unixepoch', 'localtime')
         ORDER BY bucket_minute",
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

pub(super) fn upstream_request_counts(
    conn: &Connection,
    since_hour: u64,
) -> Result<Vec<UpstreamRequestStat>, String> {
    if since_hour == 0 {
        let mut stmt = conn
            .prepare(
                "SELECT value, requests
                 FROM dashboard_summary_stats
                 WHERE scope = 'all' AND dimension = 'upstream' AND requests > 0
                 ORDER BY requests DESC, value ASC
                 LIMIT 200",
            )
            .map_err(|e| format!("准备永久上游请求排行失败：{e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(UpstreamRequestStat {
                    upstream: row.get(0)?,
                    requests: read_u64(row, 1)?,
                })
            })
            .map_err(|e| format!("读取永久上游请求排行失败：{e}"))?;
        return rows
            .map(|row| row.map_err(|e| format!("解析永久上游请求排行失败：{e}")))
            .collect();
    }
    let since = u64_to_db_i64(since_hour, "上游统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "SELECT value, SUM(requests) AS requests
             FROM statistics_hourly
             WHERE dimension = 'upstream' AND hour >= ?1
             GROUP BY value
             HAVING SUM(requests) > 0
             ORDER BY SUM(requests) DESC, value ASC
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

pub(super) fn upstream_avg_latency(
    conn: &Connection,
    since_hour: u64,
) -> Result<Vec<UpstreamLatencyStat>, String> {
    if since_hour == 0 {
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
            .map_err(|e| format!("准备永久上游响应时间排行失败：{e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(UpstreamLatencyStat {
                    upstream: row.get(0)?,
                    avg_ms: read_u64(row, 1)?,
                })
            })
            .map_err(|e| format!("读取永久上游响应时间排行失败：{e}"))?;
        return rows
            .map(|row| row.map_err(|e| format!("解析永久上游响应时间排行失败：{e}")))
            .collect();
    }
    let since = u64_to_db_i64(since_hour, "上游延迟统计起始小时")?;
    let mut stmt = conn
        .prepare(
            "SELECT
                value,
                CAST(ROUND(
                    CAST(SUM(latency_total_ms) AS REAL) / SUM(latency_samples)
                ) AS INTEGER)
             FROM statistics_hourly
             WHERE dimension = 'upstream' AND hour >= ?1
             GROUP BY value
             HAVING SUM(latency_samples) > 0
             ORDER BY CAST(SUM(latency_total_ms) AS REAL) / SUM(latency_samples) ASC, value ASC
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
