import { describe, expect, it } from "vitest";

import { dnsQueryTypeLabel, renderQueryLogRow } from "./query-log-render";
import type { QueryLogRecord } from "./types";

describe("query log renderer", () => {
  it("escapes persisted text before rendering HTML", () => {
    const record: QueryLogRecord = {
      id: 1,
      timestamp: 1_700_000_000,
      domain: '<img src=x onerror="alert(1)">',
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
      upstream_duration_ms: 10,
      processing_duration_ms: 11,
      error: null,
      matched_rule: null,
      rule_source: null,
      rule_type: null,
      important_overrode: false,
      allowlist_rule: null,
    };

    const html = renderQueryLogRow(record, {
      clientDisplayName: () => "<script>bad()</script>",
      formatClientLabel: () => "client",
    });
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>bad()");
    expect(html).toContain("&lt;img");
    expect(html).toContain("&lt;script&gt;");
  });

  it("labels known and unknown DNS query types", () => {
    expect(dnsQueryTypeLabel(65)).toBe("HTTPS");
    expect(dnsQueryTypeLabel(65000)).toBe("TYPE65000");
  });
});
