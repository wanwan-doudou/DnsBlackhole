import { describe, expect, it } from "vitest";
import { queryLogPaginationState, totalQueryLogPages } from "./query-log-pagination";

describe("queryLogPaginationState", () => {
  it("在第一页保留可用的下一页按钮", () => {
    expect(queryLogPaginationState(1, 120, 50, false)).toEqual({
      totalPages: 3,
      start: 1,
      end: 50,
      previousDisabled: true,
      nextDisabled: false,
    });
  });

  it("加载期间临时禁用分页，结束后恢复", () => {
    const loading = queryLogPaginationState(1, 120, 50, true);
    const finished = queryLogPaginationState(1, 120, 50, false);

    expect(loading.nextDisabled).toBe(true);
    expect(finished.nextDisabled).toBe(false);
  });

  it("在最后一页禁用下一页并计算剩余范围", () => {
    expect(queryLogPaginationState(3, 120, 50, false)).toEqual({
      totalPages: 3,
      start: 101,
      end: 120,
      previousDisabled: false,
      nextDisabled: true,
    });
  });

  it("正确处理空日志", () => {
    expect(queryLogPaginationState(1, 0, 50, false)).toEqual({
      totalPages: 1,
      start: 0,
      end: 0,
      previousDisabled: true,
      nextDisabled: true,
    });
  });
});

describe("totalQueryLogPages", () => {
  it("至少返回一页", () => {
    expect(totalQueryLogPages(0, 50)).toBe(1);
    expect(totalQueryLogPages(51, 50)).toBe(2);
  });
});
