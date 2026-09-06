import { describe, expect, it } from "vitest";

import {
  createSearchCompositionState,
  onSearchBlur,
  onSearchCompositionEnd,
  onSearchCompositionStart,
  onSearchInput,
} from "./query-log-search";

describe("查询日志搜索的组合输入状态机", () => {
  it("普通打字直接发起搜索", () => {
    const state = createSearchCompositionState();
    expect(onSearchInput(state, false)).toBe("schedule");
    expect(state.composing).toBe(false);
  });

  it("完整的 IME 组合流程只在结束时发起一次搜索", () => {
    const state = createSearchCompositionState();
    expect(onSearchCompositionStart(state)).toBe("cancel");
    expect(onSearchInput(state, true)).toBe("cancel");
    expect(onSearchInput(state, true)).toBe("cancel");
    expect(state.composing).toBe(true);
    expect(onSearchCompositionEnd(state)).toBe("schedule");
    expect(state.composing).toBe(false);
  });

  it("丢失 compositionend 后，下一次普通输入必须自愈", () => {
    // 这是修复前的死锁场景：compositionstart 之后 compositionend 丢了
    // （切窗口 / IME 取消 / 组合中被程序化改写 value），
    // 旧实现的闭锁从此永远为 true，搜索框永久失效且无任何提示。
    const state = createSearchCompositionState();
    onSearchCompositionStart(state);
    expect(state.composing).toBe(true);

    expect(onSearchInput(state, false)).toBe("schedule");
    expect(state.composing).toBe(false);
    // 自愈之后必须能继续正常工作
    expect(onSearchInput(state, false)).toBe("schedule");
  });

  it("组合中失焦兜底解锁并发起搜索", () => {
    const state = createSearchCompositionState();
    onSearchCompositionStart(state);
    expect(onSearchBlur(state)).toBe("schedule");
    expect(state.composing).toBe(false);
  });

  it("非组合态失焦什么都不做，避免无谓请求", () => {
    const state = createSearchCompositionState();
    expect(onSearchBlur(state)).toBe("skip");
    onSearchInput(state, false);
    expect(onSearchBlur(state)).toBe("skip");
  });

  it("重复的 compositionstart 不会把状态搞乱", () => {
    const state = createSearchCompositionState();
    onSearchCompositionStart(state);
    onSearchCompositionStart(state);
    expect(state.composing).toBe(true);
    expect(onSearchCompositionEnd(state)).toBe("schedule");
    expect(state.composing).toBe(false);
  });

  it("孤立的 compositionend 也能解锁，不依赖先有 start", () => {
    const state = createSearchCompositionState();
    expect(onSearchCompositionEnd(state)).toBe("schedule");
    expect(state.composing).toBe(false);
  });
});
