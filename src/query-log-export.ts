import { exportQueryLogFile, getQueryLogs, isTauriRuntime } from "./api";
import { downloadBrowserFile } from "./browser-file";
import type { QueryLogPage, QueryLogQuery, QueryLogRecord } from "./types";
import { t } from "./i18n";

const EXPORT_PAGE_SIZE = 200;
const EXPORT_RECORD_LIMIT = 50_000;

export type QueryLogExportResult = {
  exported: number;
  total: number;
  truncated: boolean;
};

type QueryLogExportPageRequest = QueryLogQuery & {
  page: number;
  pageSize: number;
  cursor: string | null;
};

type QueryLogExportPageLoader = (request: QueryLogExportPageRequest) => Promise<QueryLogPage>;

export type CollectedQueryLogExport = QueryLogExportResult & {
  records: QueryLogRecord[];
};

export async function exportFilteredQueryLogs(
  query: QueryLogQuery,
  onProgress?: (exported: number, total: number) => void,
): Promise<QueryLogExportResult | null> {
  let path: string | null = null;
  if (isTauriRuntime()) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    path = await save({
      title: t("导出查询日志"),
      defaultPath: `DnsBlackhole-query-logs-${dateStamp()}.csv`,
      filters: [{ name: t("CSV 表格"), extensions: ["csv"] }],
    });
    if (!path) {
      return null;
    }
  }

  const collected = await collectQueryLogExportRecords(query, getQueryLogs, onProgress);
  const content = serializeQueryLogsCsv(collected.records);
  if (path) {
    await exportQueryLogFile(path, content);
  } else {
    downloadBrowserFile(
      `DnsBlackhole-query-logs-${dateStamp()}.csv`,
      content,
      "text/csv;charset=utf-8",
    );
  }
  return {
    exported: collected.exported,
    total: collected.total,
    truncated: collected.truncated,
  };
}

export async function collectQueryLogExportRecords(
  query: QueryLogQuery,
  loadPage: QueryLogExportPageLoader,
  onProgress?: (exported: number, total: number) => void,
): Promise<CollectedQueryLogExport> {
  const records: QueryLogRecord[] = [];
  let total = 0;
  let cursor: string | null = query.sort === "slowest" ? null : "";
  for (let page = 1; records.length < EXPORT_RECORD_LIMIT; page += 1) {
    const result = await loadPage({ ...query, page, pageSize: EXPORT_PAGE_SIZE, cursor });
    total = result.total;
    records.push(...result.records.slice(0, EXPORT_RECORD_LIMIT - records.length));
    onProgress?.(records.length, Math.min(total, EXPORT_RECORD_LIMIT));
    if (
      result.records.length < EXPORT_PAGE_SIZE ||
      records.length >= total ||
      (cursor !== null && result.next_cursor === null)
    ) {
      break;
    }
    cursor = cursor === null ? null : result.next_cursor;
  }

  return {
    records,
    exported: records.length,
    total,
    truncated: records.length < total,
  };
}

export function serializeQueryLogsCsv(records: QueryLogRecord[]): string {
  const header = [
    t("时间"),
    t("域名"),
    t("查询类型"),
    t("传输协议"),
    t("客户端"),
    t("状态"),
    t("响应来源"),
    t("上游服务器"),
    t("上游耗时(ms)"),
    t("总耗时(ms)"),
    t("响应代码"),
    t("响应记录"),
    t("命中规则"),
    t("规则来源"),
    t("错误"),
  ];
  const rows = records.map((record) => [
    new Date(record.timestamp * 1000).toISOString(),
    record.domain,
    record.query_type ?? "",
    record.transport?.toUpperCase() ?? "",
    record.client_ip ?? "",
    record.failed ? t("失败") : record.blocked ? t("已拦截") : t("已处理"),
    record.response_source ?? "",
    record.upstream_server ?? "",
    record.upstream_duration_ms ?? "",
    record.processing_duration_ms ?? "",
    record.response?.code ?? "",
    record.response?.answers.map((answer) => `${answer.record_type} ${answer.value}`).join(" | ") ?? "",
    record.matched_rule ?? "",
    record.rule_source ?? "",
    record.error ?? "",
  ]);
  return `\uFEFF${[header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n")}\r\n`;
}

function csvCell(value: string | number): string {
  let text = String(value);
  // 防止用 Excel 等表格软件打开时把域名或错误文本解释成公式。
  if (/^[=+\-@]/.test(text)) {
    text = `'${text}`;
  }
  return `"${text.replace(/"/g, '""')}"`;
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10).replace(/-/g, "");
}
