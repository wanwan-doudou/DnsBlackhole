/**
 * 查询日志搜索框的组合输入（IME）状态机。
 *
 * 早期实现在模块里放一个布尔闭锁，`compositionstart` 置 true，且**只有**同一个输入框的
 * `compositionend` 能解开；`scheduleQueryLogSearch()` 开头直接按这个闭锁短路返回。
 * 问题在于 `compositionend` 不是必达事件——切换窗口、IME 取消、以及组合进行中被
 * 程序化改写 `value`（重置按钮、从仪表盘点客户端跳转都会这么做）都可能让它丢失。
 * 一旦丢失，闭锁永久停在 true，搜索框从此打字无效，而且没有任何提示。
 *
 * 这里把状态机独立成纯函数，关键性质是**每条出路都能解锁**：
 * 非组合态的 `input` 事件即权威解锁（用事件自带的 `isComposing`，不依赖自己维护的标志），
 * 失焦也兜底解锁。这样即使丢了 `compositionend` 也会在下一次按键时自愈。
 */

export type SearchCompositionState = {
  composing: boolean;
};

/** schedule = 走防抖发起搜索；cancel = 取消待发起的搜索；skip = 什么都不做 */
export type SearchScheduleDecision = "schedule" | "cancel" | "skip";

export function createSearchCompositionState(): SearchCompositionState {
  return { composing: false };
}

export function onSearchInput(
  state: SearchCompositionState,
  isComposing: boolean,
): SearchScheduleDecision {
  if (isComposing) {
    // 拼音/注音的中间态没有检索意义，取消待发起的搜索但不清空状态
    state.composing = true;
    return "cancel";
  }
  // 非组合态的输入是权威信号：无论之前是否卡在组合态，这里都必须解锁
  state.composing = false;
  return "schedule";
}

export function onSearchCompositionStart(state: SearchCompositionState): SearchScheduleDecision {
  state.composing = true;
  return "cancel";
}

export function onSearchCompositionEnd(state: SearchCompositionState): SearchScheduleDecision {
  state.composing = false;
  return "schedule";
}

export function onSearchBlur(state: SearchCompositionState): SearchScheduleDecision {
  if (!state.composing) {
    return "skip";
  }
  // 组合中失焦：compositionend 可能永远不来，这里兜底解锁并把已输入的内容发起搜索
  state.composing = false;
  return "schedule";
}
