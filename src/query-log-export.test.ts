import { describe, expect, it } from "vitest";

import { collectQueryLogExportRecords, serializeQueryLogsCsv } from "./query-log-export";
import type { QueryLogPage, QueryLogQuery, QueryLogRecord } from "./types";

function record(domain: string): QueryLogRecord {
  return {
    id: 1,
    timestamp: 1_700_000_000,
    domain,
    query_type: 1,
    query_class: 1,
    transport: "udp",
    response_source: "upstream",
    response: null,
    client_ip: "192.168.1.20",
    blocked: false,
    forwarded: true,
    failed: false,
    upstream_server: "1.1.1.1:53",
    upstream_duration_ms: 12,
    processing_duration_ms: 13,
    error: null,
    matched_rule: null,
    rule_source: null,
    rule_type: null,
    important_overrode: false,
    allowlist_rule: null,
  };
}

describe("serializeQueryLogsCsv", () => {
  it("adds UTF-8 BOM and escapes quotes", () => {
    const csv = serializeQueryLogsCsv([record('a"b.example')]);
    expect(csv.startsWith("\uFEFF")).toBe(true);
    expect(csv).toContain('"a""b.example"');
  });

  it("neutralizes spreadsheet formulas", () => {
    const csv = serializeQueryLogsCsv([record("=HYPERLINK.example")]);
    expect(csv).toContain('"\'=HYPERLINK.example"');
  });

  it("collects and serializes a 30000-record export through cursor pages", async () => {
    const records = Array.from({ length: 30_000 }, (_, index) => ({
      ...record(`host-${index}.example`),
      id: index + 1,
    }));
    const query: QueryLogQuery = {
      filter: "all",
      search: "",
      domain: null,
      hours: 24,
      source: "all",
      queryType: "all",
      sort: "newest",
    };
    let calls = 0;
    const progress: Array<[number, number]> = [];
    const loadPage = async ({ page, pageSize, cursor }: QueryLogQuery & {
      page: number;
      pageSize: number;
      cursor: string | null;
    }): Promise<QueryLogPage> => {
      calls += 1;
      const offset = cursor ? Number(cursor) : 0;
      const nextOffset = Math.min(offset + pageSize, records.length);
      return {
        records: records.slice(offset, nextOffset),
        total: records.length,
        page,
        page_size: pageSize,
        next_cursor: nextOffset < records.length ? String(nextOffset) : null,
      };
    };

    const collected = await collectQueryLogExportRecords(query, loadPage, (exported, total) => {
      progress.push([exported, total]);
    });
    const csv = serializeQueryLogsCsv(collected.records);

    expect(calls).toBe(150);
    expect(collected.exported).toBe(30_000);
    expect(collected.total).toBe(30_000);
    expect(collected.truncated).toBe(false);
    expect(progress[progress.length - 1]).toEqual([30_000, 30_000]);
    expect(csv).toContain('"host-0.example"');
    expect(csv).toContain('"host-29999.example"');
    expect(csv.split("\r\n")).toHaveLength(30_002);
  });
});
