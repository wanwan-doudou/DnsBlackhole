import { describe, expect, it, vi } from "vitest";

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
  it("keeps legacy ANY refusals classified when the UI uses English", async () => {
    vi.resetModules();
    vi.stubGlobal("window", { localStorage: { getItem: () => "en-US" } });
    try {
      const { renderQueryLogRow: renderEnglish } = await import("./query-log-render");
      const { getLocale } = await import("./i18n");
      expect(getLocale()).toBe("en-US");
      const record: QueryLogRecord = {
        id: 2, timestamp: 1_700_000_000, domain: "example.com", query_type: 255,
        query_class: 1, transport: "udp", response_source: null, response: null,
        client_ip: "192.168.1.20", blocked: false, forwarded: false, failed: false,
        upstream_server: null, upstream_duration_ms: null, processing_duration_ms: 0,
        error: "已拒绝 ANY 查询", matched_rule: null, rule_source: null,
        rule_type: null, important_overrode: false, allowlist_rule: null,
      };
      const html = renderEnglish(record, { clientDisplayName: () => null, formatClientLabel: () => "client" });
      expect(html).toContain('class="refused"');
      expect(html).toContain("Refused");
      expect(html).not.toContain('class="processed"');
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }
  });

});
