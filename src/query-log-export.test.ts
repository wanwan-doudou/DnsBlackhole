import { describe, expect, it } from "vitest";

import { serializeQueryLogsCsv } from "./query-log-export";
import type { QueryLogRecord } from "./types";

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
});
