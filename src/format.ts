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
  return `${formatted} 毫秒`;
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
    return `${hours / (24 * 30)} 个月`;
  }
  if (hours % 24 === 0) {
    return `${hours / 24} 天`;
  }
  return `${hours} 小时`;
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

export function formatSparkDayLabel(minute: number): string {
  return sparkDateFormatter.format(new Date(minute * 60000));
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
