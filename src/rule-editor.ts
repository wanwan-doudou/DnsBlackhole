import type { RuleAnalysis } from "./types";

type RuleEditorOptions = {
  textarea: HTMLTextAreaElement;
  gutter: HTMLElement;
  summary: HTMLElement;
  diagnostics: HTMLElement;
  search: HTMLInputElement;
  analyze: (rules: string) => Promise<RuleAnalysis>;
};

export type RuleEditorController = {
  refresh: () => void;
};

const ANALYSIS_DEBOUNCE_MS = 320;

export function createRuleEditorController(options: RuleEditorOptions): RuleEditorController {
  let timer: number | undefined;
  let analysisToken = 0;
  let searchCursor = 0;

  function updateGutter(): void {
    const lineCount = Math.max(1, options.textarea.value.split("\n").length);
    options.gutter.textContent = Array.from({ length: lineCount }, (_, index) => index + 1).join("\n");
    options.gutter.scrollTop = options.textarea.scrollTop;
  }

  function selectLine(line: number): void {
    const lines = options.textarea.value.split("\n");
    const target = Math.max(0, Math.min(line - 1, lines.length - 1));
    const start = lines.slice(0, target).reduce((total, value) => total + value.length + 1, 0);
    options.textarea.focus();
    options.textarea.setSelectionRange(start, start + (lines[target]?.length ?? 0));
    const lineHeight = Number.parseFloat(getComputedStyle(options.textarea).lineHeight) || 20;
    options.textarea.scrollTop = Math.max(0, target * lineHeight - options.textarea.clientHeight / 3);
    updateGutter();
  }

  function renderAnalysis(analysis: RuleAnalysis): void {
    const summary = analysis.summary;
    options.summary.textContent = [
      `${summary.block_rules.toLocaleString()} 条拦截`,
      `${summary.allow_rules.toLocaleString()} 条允许`,
      analysis.disabled_rules > 0 ? `${analysis.disabled_rules.toLocaleString()} 条 badfilter` : null,
      analysis.diagnostics.length > 0 ? `${analysis.diagnostics.length.toLocaleString()} 条需处理` : "格式检查通过",
    ].filter(Boolean).join(" · ");
    options.summary.classList.toggle("has-errors", analysis.diagnostics.some((item) => item.severity === "error"));
    options.summary.classList.toggle("has-warnings", analysis.diagnostics.length > 0);

    options.diagnostics.replaceChildren();
    if (analysis.diagnostics.length === 0) {
      const empty = document.createElement("span");
      empty.className = "rule-diagnostic-empty";
      empty.textContent = "没有发现无效或不受支持的规则。";
      options.diagnostics.append(empty);
      return;
    }
    analysis.diagnostics.slice(0, 100).forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `rule-diagnostic ${item.severity}`;
      button.textContent = `第 ${item.line} 行：${item.message}`;
      button.addEventListener("click", () => selectLine(item.line));
      options.diagnostics.append(button);
    });
    if (analysis.diagnostics.length > 100) {
      const more = document.createElement("span");
      more.className = "rule-diagnostic-empty";
      more.textContent = `另有 ${analysis.diagnostics.length - 100} 条未展开，请先修复上面的规则。`;
      options.diagnostics.append(more);
    }
  }

  async function analyzeNow(): Promise<void> {
    const token = ++analysisToken;
    options.summary.textContent = "正在检查规则…";
    try {
      const analysis = await options.analyze(options.textarea.value);
      if (token === analysisToken) {
        renderAnalysis(analysis);
      }
    } catch (error) {
      if (token === analysisToken) {
        options.summary.textContent = `规则检查失败：${String(error)}`;
        options.summary.classList.add("has-errors");
      }
    }
  }

  function refresh(): void {
    updateGutter();
    window.clearTimeout(timer);
    timer = window.setTimeout(() => void analyzeNow(), ANALYSIS_DEBOUNCE_MS);
  }

  function findNext(): void {
    const term = options.search.value.trim().toLocaleLowerCase();
    if (!term) {
      return;
    }
    const haystack = options.textarea.value.toLocaleLowerCase();
    let match = haystack.indexOf(term, Math.max(searchCursor, options.textarea.selectionEnd));
    if (match < 0) {
      match = haystack.indexOf(term);
    }
    if (match < 0) {
      options.search.setCustomValidity("没有找到匹配规则");
      options.search.reportValidity();
      return;
    }
    options.search.setCustomValidity("");
    searchCursor = match + term.length;
    options.textarea.focus();
    options.textarea.setSelectionRange(match, searchCursor);
    const line = options.textarea.value.slice(0, match).split("\n").length;
    selectLine(line);
    options.textarea.setSelectionRange(match, searchCursor);
  }

  options.textarea.addEventListener("input", refresh);
  options.textarea.addEventListener("scroll", updateGutter, { passive: true });
  new ResizeObserver(() => {
    options.gutter.style.height = `${options.textarea.offsetHeight}px`;
  }).observe(options.textarea);
  options.search.addEventListener("input", () => {
    searchCursor = 0;
    options.search.setCustomValidity("");
  });
  options.search.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      findNext();
    }
  });

  updateGutter();
  return { refresh };
}
