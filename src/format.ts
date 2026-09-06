import { t } from "./i18n";
// 缓存 Intl 格式化器：构造开销较大，仪表盘定时刷新会高频调用，复用可避免重复创建。
const countFormatter = new Intl.NumberFormat("zh-CN");
const percentFormatter = new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 });
const filterTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});
const sparkDateFormatter = new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit" });
const sparkHourFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});
const logTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const logDateFormatter = new Intl.DateTimeFormat("zh-CN", {
  year: "numeric",
  month: "numeric",
  day: "numeric",
});

export function formatCount(value: number): string {
  return countFormatter.format(value);
}

export function formatElapsedMs(value: number): string {
  const formatted = value < 1 ? value.toFixed(2) : Math.floor(value).toString();
  return t("{p0} 毫秒", { p0: formatted });
}

export function formatBytes(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB"];
  let size = Math.max(0, value);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unit]}`;
}

export function formatRate(blocked: number, queries: number): string {
  if (queries === 0) {
    return "0%";
  }
  return `${Math.round((blocked / queries) * 100)}%`;
}

export function formatPercent(value: number): string {
  return `${percentFormatter.format(value * 100)}%`;
}

export function formatDuration(hours: number): string {
  if (hours % (24 * 30) === 0) {
    return t("{p0} 个月", { p0: hours / (24 * 30) });
  }
  if (hours % 24 === 0) {
    return t("{p0} 天", { p0: hours / 24 });
  }
  return t("{p0} 小时", { p0: hours });
}

export function formatTime(value: number | null): string {
  if (!value) {
    return "-";
  }
  return filterTimeFormatter.format(new Date(value * 1000));
}

export function formatLogTime(value: number): string {
  return logTimeFormatter.format(new Date(value * 1000));
}

export function formatLogDate(value: number): string {
  return logDateFormatter.format(new Date(value * 1000));
}

/// 把保留小时数描述成人话。不足两天时保留"小时"，否则 24 小时会被写成"1 天"，反而更含糊。
export function formatRetentionScope(hours: number): string {
  if (hours <= 0) {
    return t("保留全部历史");
  }
  if (hours >= 48 && hours % 24 === 0) {
    return t("保留最近 {p0} 天", { p0: String(hours / 24) });
  }
  return t("保留最近 {p0} 小时", { p0: String(hours) });
}

/// 查询日志的时间窗是否短于仪表盘统计。
/// 仪表盘按统计库汇总（statisticsHours 为 0 表示永久），查询日志按自己的保留期滚动删除，
/// 两者差距可能是几十倍——从排行榜点进日志很容易落到空结果，需要显式解释。
export function retentionWindowIsShorter(queryLogHours: number, statisticsHours: number): boolean {
  if (queryLogHours <= 0) {
    return false;
  }
  return statisticsHours <= 0 || statisticsHours > queryLogHours;
}

export function formatSparkDayLabel(minute: number): string {
  return sparkDateFormatter.format(new Date(minute * 60000));
}

export function formatSparkHourLabel(minute: number): string {
  return sparkHourFormatter.format(new Date(minute * 60000));
}

// 查询日志里的域名、上游地址、错误文本都是完全不可信的输入，而渲染是纯字符串拼 HTML。
// 单引号也必须转义：目前所有插值属性都用双引号，但只要将来有一处写成单引号属性就是注入点。
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
