import { describe, expect, it } from "vitest";

import { escapeHtml, formatRetentionScope, retentionWindowIsShorter } from "./format";

describe("escapeHtml", () => {
  it("转义会破坏属性和标签的全部字符", () => {
    expect(escapeHtml(`<img src=x onerror='alert(1)'>`)).toBe(
      "&lt;img src=x onerror=&#39;alert(1)&#39;&gt;",
    );
    expect(escapeHtml('a"b')).toBe("a&quot;b");
    // & 必须先转义，否则会二次转义后面生成的实体
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });
});

describe("formatRetentionScope", () => {
  it("不足两天时保留小时单位", () => {
    // 24 小时写成"1 天"反而更含糊，这是页脚实测后调的
    expect(formatRetentionScope(24)).toBe("保留最近 24 小时");
    expect(formatRetentionScope(1)).toBe("保留最近 1 小时");
    expect(formatRetentionScope(36)).toBe("保留最近 36 小时");
  });

  it("整天且不少于两天时用天", () => {
    expect(formatRetentionScope(48)).toBe("保留最近 2 天");
    expect(formatRetentionScope(90 * 24)).toBe("保留最近 90 天");
  });

  it("非整天的长窗口仍用小时，避免四舍五入误导", () => {
    expect(formatRetentionScope(50)).toBe("保留最近 50 小时");
  });

  it("0 表示永久保留", () => {
    expect(formatRetentionScope(0)).toBe("保留全部历史");
  });
});

describe("retentionWindowIsShorter", () => {
  it("统计永久保留时，任何有限的日志窗口都更短", () => {
    expect(retentionWindowIsShorter(24, 0)).toBe(true);
    expect(retentionWindowIsShorter(90 * 24, 0)).toBe(true);
  });

  it("按实际时长比较", () => {
    // 实测环境：日志 24 小时、统计永久 —— 从排行榜点进日志会落到空结果
    expect(retentionWindowIsShorter(24, 30 * 24)).toBe(true);
    expect(retentionWindowIsShorter(30 * 24, 30 * 24)).toBe(false);
    expect(retentionWindowIsShorter(90 * 24, 30 * 24)).toBe(false);
  });

  it("日志本身永久保留时不提示", () => {
    expect(retentionWindowIsShorter(0, 0)).toBe(false);
    expect(retentionWindowIsShorter(0, 30 * 24)).toBe(false);
  });
});
