import { describe, expect, it } from "vitest";

import {
  DAILY_TREND_DAYS,
  HOURLY_TREND_MAX_HOURS,
  buildTrafficSeries,
  trendDayCountForHours,
} from "./charts";
import type { TrafficBucket } from "./types";

describe("trendDayCountForHours", () => {
  it("按统计窗口生成足够且不过量的日趋势节点", () => {
    expect(trendDayCountForHours(24)).toBe(2);
    expect(trendDayCountForHours(7 * 24)).toBe(8);
    expect(trendDayCountForHours(30 * 24)).toBe(DAILY_TREND_DAYS);
    expect(trendDayCountForHours(0)).toBe(DAILY_TREND_DAYS);
  });
});

describe("buildTrafficSeries", () => {
  const now = Date.UTC(2026, 8, 6, 20, 0, 0);
  const currentHour = new Date(now);
  currentHour.setMinutes(0, 0, 0);
  const currentHourStart = currentHour.getTime();
  const minuteAt = (hoursAgo: number, minuteOffset = 0) =>
    Math.floor((currentHourStart - hoursAgo * 3_600_000) / 60_000) + minuteOffset;

  it("短窗口改用小时粒度，不再把 24 小时压成两个点", () => {
    // 修复前按自然日聚合，24 小时窗口只剩 2 个节点，曲线等于一条直线
    const series = buildTrafficSeries([], "queries", 24, now);
    expect(series).toHaveLength(24);
    // 标签按本地时区渲染，这里只断言粒度是整小时，不假设测试机时区
    expect(series[series.length - 1].label).toMatch(/^\d{2}\/\d{2} \d{2}:00$/);
    expect(series[0].label).not.toBe(series[series.length - 1].label);
    expect(new Set(series.map((point) => point.label)).size).toBe(24);
  });

  it("把分钟桶归并到对应的小时节点", () => {
    const buckets: TrafficBucket[] = [
      { minute: minuteAt(0, 5), queries: 3, blocked: 1 },
      { minute: minuteAt(0, 42), queries: 4, blocked: 2 },
      { minute: minuteAt(2), queries: 10, blocked: 5 },
      // 落在窗口之外，必须被忽略
      { minute: minuteAt(30), queries: 999, blocked: 999 },
    ];
    const series = buildTrafficSeries(buckets, "queries", 6, now);
    expect(series).toHaveLength(6);
    expect(series[5].value).toBe(7); // 当前小时内的两个分钟桶合并
    expect(series[3].value).toBe(10); // 两小时前
    expect(series.reduce((sum, point) => sum + point.value, 0)).toBe(17);

    const blocked = buildTrafficSeries(buckets, "blocked", 6, now);
    expect(blocked[5].value).toBe(3);
    expect(blocked.reduce((sum, point) => sum + point.value, 0)).toBe(8);
  });

  it("超过小时粒度上限或全部历史时回到日粒度", () => {
    expect(buildTrafficSeries([], "queries", HOURLY_TREND_MAX_HOURS, now)).toHaveLength(
      HOURLY_TREND_MAX_HOURS,
    );
    expect(
      buildTrafficSeries([], "queries", HOURLY_TREND_MAX_HOURS + 1, now),
    ).toHaveLength(trendDayCountForHours(HOURLY_TREND_MAX_HOURS + 1));
    expect(buildTrafficSeries([], "queries", 30 * 24, now)).toHaveLength(DAILY_TREND_DAYS);
    expect(buildTrafficSeries([], "queries", 0, now)).toHaveLength(DAILY_TREND_DAYS);
  });
});
