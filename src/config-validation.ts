import type { AppConfig, ViewName } from "./types";
import { validateIpAddress, validateIpv4Address, validateIpv6Address } from "./client-policy-form";

export type ConfigValidationCode =
  | "ip_address"
  | "ipv4_address"
  | "ipv6_address"
  | "port"
  | "monitoring_port_conflict"
  | "rate_limit"
  | "cache_size"
  | "cache_ttl"
  | "cache_stale"
  | "cache_prefetch"
  | "watchdog_interval"
  | "blocking_ttl";

export type ConfigValidationIssue = {
  fieldId: string;
  view: ViewName;
  code: ConfigValidationCode;
};

export function validateConfigDraft(config: AppConfig): ConfigValidationIssue[] {
  const issues: ConfigValidationIssue[] = [];
  if (!validateIpv4Address(config.listen_host)) {
    issues.push({ fieldId: "listen_host", view: "dns", code: "ipv4_address" });
  }
  if (!integerInRange(config.listen_port, 1, 65_535)) {
    issues.push({ fieldId: "listen_port", view: "dns", code: "port" });
  }
  if (config.listen_ipv6 && !validateIpv6Address(config.listen_ipv6_host)) {
    issues.push({ fieldId: "listen_ipv6_host", view: "dns", code: "ipv6_address" });
  }
  if (!integerInRange(config.rate_limit_per_second, 0, 100_000)) {
    issues.push({ fieldId: "rate_limit_per_second", view: "security", code: "rate_limit" });
  }
  if (config.dns_cache_enabled && !integerInRange(config.dns_cache_size, 1, 512 * 1024 * 1024)) {
    issues.push({ fieldId: "dns_cache_size", view: "settings", code: "cache_size" });
  }
  if (
    !integerInRange(config.dns_cache_min_ttl, 0, 7 * 24 * 3600) ||
    !integerInRange(config.dns_cache_max_ttl, 0, 7 * 24 * 3600) ||
    (config.dns_cache_max_ttl > 0 && config.dns_cache_min_ttl > config.dns_cache_max_ttl)
  ) {
    issues.push({ fieldId: "dns_cache_min_ttl", view: "settings", code: "cache_ttl" });
  }
  if (!integerInRange(config.dns_cache_optimistic_max_stale_seconds, 60, 7 * 24 * 3600)) {
    issues.push({ fieldId: "dns_cache_optimistic_max_stale_seconds", view: "settings", code: "cache_stale" });
  }
  if (!integerInRange(config.dns_cache_prefetch_hit_threshold, 2, 10_000)) {
    issues.push({ fieldId: "dns_cache_prefetch_hit_threshold", view: "settings", code: "cache_prefetch" });
  }
  if (!integerInRange(config.runtime_watchdog_interval_seconds, 10, 3600)) {
    issues.push({ fieldId: "runtime_watchdog_interval_seconds", view: "settings", code: "watchdog_interval" });
  }
  if (!integerInRange(config.blocking_response_ttl, 0, 7 * 24 * 3600)) {
    issues.push({ fieldId: "blocking_response_ttl", view: "dns", code: "blocking_ttl" });
  }
  if (config.monitoring_api_enabled) {
    if (!validateIpAddress(config.monitoring_api_listen_host)) {
      issues.push({ fieldId: "monitoring_api_listen_host", view: "settings", code: "ip_address" });
    }
    if (!integerInRange(config.monitoring_api_port, 1, 65_535)) {
      issues.push({ fieldId: "monitoring_api_port", view: "settings", code: "port" });
    } else if (config.monitoring_api_port === config.listen_port) {
      issues.push({ fieldId: "monitoring_api_port", view: "settings", code: "monitoring_port_conflict" });
    }
  }
  return issues;
}

export function mapBackendConfigError(message: string): { fieldId: string; view: ViewName } | null {
  const mappings: Array<[RegExp, string, ViewName]> = [
    [
      /监听 (?:UDP|TCP) .+失败.*(?:只允许使用一次|正在使用|already in use|os error 10048)/i,
      "listen_port",
      "dns",
    ],
    [/监听 (?:UDP|TCP) \[[^\]]+\]:\d+ 失败/i, "listen_ipv6_host", "dns"],
    [
      /监听 (?:UDP|TCP) .+失败.*(?:地址无效|不能分配|cannot assign|not valid in its context|os error 10049)/i,
      "listen_host",
      "dns",
    ],
    [/IPv6 监听地址/, "listen_ipv6_host", "dns"],
    [/监听地址/, "listen_host", "dns"],
    [/监听端口/, "listen_port", "dns"],
    [/客户端过滤策略/, "client_filtering_rules", "security"],
    [/客户端策略组/, "client_policy_groups", "security"],
    [/允许客户端/, "allowed_clients", "security"],
    [/拒绝客户端/, "blocked_clients", "security"],
    [/每客户端限速/, "rate_limit_per_second", "security"],
    [/监控接口.*地址/, "monitoring_api_listen_host", "settings"],
    [/监控接口.*端口/, "monitoring_api_port", "settings"],
    [/缓存.*TTL/, "dns_cache_min_ttl", "settings"],
    [/缓存大小/, "dns_cache_size", "settings"],
    [/自恢复检查间隔/, "runtime_watchdog_interval_seconds", "settings"],
    [/拦截响应 TTL/, "blocking_response_ttl", "dns"],
    [/DNS 重写/, "dns_rewrites", "custom"],
    [/过滤器/, "filters_body", "filters"],
  ];
  const matched = mappings.find(([pattern]) => pattern.test(message));
  return matched ? { fieldId: matched[1], view: matched[2] } : null;
}

function integerInRange(value: number, minimum: number, maximum: number): boolean {
  return Number.isInteger(value) && value >= minimum && value <= maximum;
}
