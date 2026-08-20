import { describe, expect, it } from "vitest";

import { DAILY_TREND_DAYS, trendDayCountForHours } from "./charts";

describe("trendDayCountForHours", () => {
  it("按统计窗口生成足够且不过量的日趋势节点", () => {
    expect(trendDayCountForHours(24)).toBe(2);
    expect(trendDayCountForHours(7 * 24)).toBe(8);
    expect(trendDayCountForHours(30 * 24)).toBe(DAILY_TREND_DAYS);
    expect(trendDayCountForHours(0)).toBe(DAILY_TREND_DAYS);
  });
});
