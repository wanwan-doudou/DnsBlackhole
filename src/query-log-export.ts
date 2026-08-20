import { save } from "@tauri-apps/plugin-dialog";

import { exportQueryLogFile, getQueryLogs } from "./api";
import type { QueryLogFilter, QueryLogRecord } from "./types";

const EXPORT_PAGE_SIZE = 200;
const EXPORT_RECORD_LIMIT = 50_000;

export type QueryLogExportResult = {
  exported: number;
  total: number;
  truncated: boolean;
};

export async function exportFilteredQueryLogs(
  filter: QueryLogFilter,
  search: string,
  onProgress?: (exported: number, total: number) => void,
): Promise<QueryLogExportResult | null> {
  const path = await save({
    title: "导出查询日志",
    defaultPath: `DnsBlackhole-query-logs-${dateStamp()}.csv`,
    filters: [{ name: "CSV 表格", extensions: ["csv"] }],
  });
  if (!path) {
    return null;
  }

  const records: QueryLogRecord[] = [];
  let total = 0;
  for (let page = 1; records.length < EXPORT_RECORD_LIMIT; page += 1) {
    const result = await getQueryLogs({ filter, search, page, pageSize: EXPORT_PAGE_SIZE });
    total = result.total;
    records.push(...result.records.slice(0, EXPORT_RECORD_LIMIT - records.length));
    onProgress?.(records.length, Math.min(total, EXPORT_RECORD_LIMIT));
    if (result.records.length < EXPORT_PAGE_SIZE || records.length >= total) {
      break;
    }
  }

  const content = serializeQueryLogsCsv(records);
  await exportQueryLogFile(path, content);
  return {
    exported: records.length,
    total,
    truncated: records.length < total,
  };
}

export function serializeQueryLogsCsv(records: QueryLogRecord[]): string {
  const header = [
    "时间",
    "域名",
    "查询类型",
    "传输协议",
    "客户端",
    "状态",
    "响应来源",
    "上游服务器",
    "上游耗时(ms)",
    "总耗时(ms)",
    "响应代码",
    "响应记录",
    "命中规则",
    "规则来源",
    "错误",
  ];
  const rows = records.map((record) => [
    new Date(record.timestamp * 1000).toISOString(),
    record.domain,
    record.query_type ?? "",
    record.transport?.toUpperCase() ?? "",
    record.client_ip ?? "",
    record.failed ? "失败" : record.blocked ? "已拦截" : "已处理",
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
