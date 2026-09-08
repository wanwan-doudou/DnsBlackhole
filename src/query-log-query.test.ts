import { describe, expect, it } from "vitest";

import {
  DEFAULT_QUERY_LOG_QUERY,
  activeAdvancedQueryFilterCount,
  domainRankingQuery,
  parseQueryLogHours,
} from "./query-log-query";

describe("query log query", () => {
  it("parses configured and bounded time ranges", () => {
    expect(parseQueryLogHours("configured")).toBeNull();
    expect(parseQueryLogHours("24")).toBe(24);
    expect(parseQueryLogHours("invalid")).toBeNull();
  });

  it("counts only non-default advanced filters", () => {
    expect(activeAdvancedQueryFilterCount(DEFAULT_QUERY_LOG_QUERY)).toBe(0);
    expect(
      activeAdvancedQueryFilterCount({
        ...DEFAULT_QUERY_LOG_QUERY,
        hours: 24,
        source: "cache",
        sort: "slowest",
      }),
    ).toBe(3);
  });

  it("clears unrelated filters when drilling down from domain rankings", () => {
    expect(domainRankingQuery(" example.com ", false)).toEqual({
      ...DEFAULT_QUERY_LOG_QUERY,
      domain: "example.com",
    });
    expect(domainRankingQuery("blocked.example", true)).toEqual({
      ...DEFAULT_QUERY_LOG_QUERY,
      domain: "blocked.example",
      filter: "blocked",
    });
  });
});
