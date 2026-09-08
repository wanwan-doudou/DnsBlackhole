import { invoke } from "@tauri-apps/api/core";

import type {
  AppConfig,
  DnsDiagnosticReport,
  RuleAnalysis,
  FilterCacheClearResult,
  FilterUpdateProgress,
  FilterUpdateResult,
  LinuxSystemDnsStatus,
  MacosServiceStatus,
  QueryLogQuery,
  QueryLogPage,
  QueryLogRuleAction,
  QueryLogRuleActionResult,
  RuntimeStatus,
  StorageInfo,
  StorageTargetInfo,
  WindowsServiceStatus,
  WindowsSystemDnsFallbackSelection,
  WindowsSystemDnsStatus,
} from "./types";

export function analyzeCustomRules(rules: string): Promise<RuleAnalysis> {
  return timedInvoke<RuleAnalysis>("analyze_custom_rules", { rules });
}

export type QueryLogRequest = QueryLogQuery & {
  page: number;
  pageSize: number;
  cursor: string | null;
};

type WebRoute = {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  body?: (args: Record<string, unknown>) => unknown;
  contentType?: "application/json" | "text/plain";
};

const WEB_ROUTES: Record<string, WebRoute> = {
  get_web_version: { method: "GET", path: "/api/v1/admin/version" },
  analyze_custom_rules: { method: "POST", path: "/api/v1/admin/rules/analyze" },
  get_config: { method: "GET", path: "/api/v1/admin/config" },
  save_config: {
    method: "PUT",
    path: "/api/v1/admin/config",
    body: (args) => args.config,
  },
  import_config_content: {
    method: "POST",
    path: "/api/v1/admin/config/import",
    body: (args) => args.content,
    contentType: "text/plain",
  },
  get_status: { method: "POST", path: "/api/v1/admin/status/query" },
  get_query_logs: { method: "POST", path: "/api/v1/admin/query-logs/search" },
  clear_query_logs: { method: "DELETE", path: "/api/v1/admin/query-logs" },
  apply_query_log_rule: { method: "POST", path: "/api/v1/admin/query-logs/rule" },
  run_dns_diagnostic: { method: "POST", path: "/api/v1/admin/diagnostics/query" },
  export_diagnostic_report: { method: "POST", path: "/api/v1/admin/diagnostics/export" },
  clear_statistics: { method: "DELETE", path: "/api/v1/admin/statistics" },
  clear_security_events: { method: "DELETE", path: "/api/v1/admin/security-events" },
  update_filters: {
    method: "POST",
    path: "/api/v1/admin/filters/update",
    body: (args) => args.config,
  },
  get_filter_update_progress: { method: "GET", path: "/api/v1/admin/filters/progress" },
  cancel_filter_update: { method: "POST", path: "/api/v1/admin/filters/cancel" },
  start_dns: { method: "POST", path: "/api/v1/admin/dns/start" },
  stop_dns: { method: "POST", path: "/api/v1/admin/dns/stop" },
  pause_protection: { method: "POST", path: "/api/v1/admin/dns/pause" },
  resume_protection: { method: "POST", path: "/api/v1/admin/dns/resume" },
  clear_dns_cache: { method: "DELETE", path: "/api/v1/admin/dns/cache" },
  clear_filter_cache: { method: "DELETE", path: "/api/v1/admin/filters/cache" },
  get_storage_info: { method: "GET", path: "/api/v1/admin/storage" },
  get_linux_system_dns_status: { method: "GET", path: "/api/v1/admin/system-dns" },
  take_over_linux_system_dns: { method: "POST", path: "/api/v1/admin/system-dns/takeover" },
  restore_linux_system_dns: { method: "POST", path: "/api/v1/admin/system-dns/restore" },
};

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function timedInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const started = performance.now();
  const request = isTauriRuntime()
    ? invoke<T>(command, args)
    : webInvoke<T>(command, args ?? {});
  return request.then(
    (result) => {
      console.info(`[加载耗时][前端 IPC] ${command}：${(performance.now() - started).toFixed(1)} ms`);
      return result;
    },
    (error: unknown) => {
      console.error(
        `[加载耗时][前端 IPC] ${command} 失败：${(performance.now() - started).toFixed(1)} ms`,
        error,
      );
      throw error;
    },
  );
}

async function webInvoke<T>(command: string, args: Record<string, unknown>): Promise<T> {
  if (["record_frontend_timing", "set_tray_locale", "set_tray_runtime_status"].includes(command)) {
    return undefined as T;
  }
  if (command === "detect_system_proxy") {
    return null as T;
  }
  const route = WEB_ROUTES[command];
  if (!route) {
    throw new Error(`Web 管理后台不支持桌面专属操作：${command}`);
  }
  const headers = new Headers({ Accept: "application/json" });
  const mutation = route.method !== "GET";
  if (mutation) {
    headers.set("Content-Type", route.contentType ?? "application/json");
  }
  const requestBody = route.body ? route.body(args) : args;
  const body = mutation
    ? route.contentType === "text/plain"
      ? String(requestBody ?? "")
      : JSON.stringify(requestBody)
    : undefined;
  const response = await fetch(route.path, {
    method: route.method,
    headers,
    body,
  });
  const payload = await readWebResponse(response);
  if (!response.ok) {
    throw new Error(webErrorMessage(payload, response.status));
  }
  return payload as T;
}

async function readWebResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

function webErrorMessage(payload: unknown, status: number): string {
  if (payload && typeof payload === "object" && "error" in payload) {
    return String((payload as { error: unknown }).error);
  }
  return `Web 管理请求失败（HTTP ${status}）`;
}

export function getWebVersion(): Promise<string> {
  if (isTauriRuntime()) {
    throw new Error("桌面运行时不使用 Web 版本接口");
  }
  return webInvoke<string>("get_web_version", {});
}

export function getConfig(): Promise<AppConfig> {
  return timedInvoke<AppConfig>("get_config");
}

export function saveConfig(config: AppConfig): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("save_config", { config });
}

export function getStatus(
  force: boolean,
  includeLogStats = true,
  statisticsHours?: number,
): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("get_status", {
    force,
    includeLogStats,
    statisticsHours: statisticsHours ?? null,
  });
}

export function getQueryLogs(request: QueryLogRequest): Promise<QueryLogPage> {
  return timedInvoke<QueryLogPage>("get_query_logs", request);
}

export function clearQueryLogs(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("clear_query_logs");
}

export function applyQueryLogRule(
  domain: string,
  action: QueryLogRuleAction,
  target?: string,
): Promise<QueryLogRuleActionResult> {
  return timedInvoke<QueryLogRuleActionResult>("apply_query_log_rule", {
    domain,
    action,
    target,
  });
}

export function runDnsDiagnostic(
  domain: string,
  queryType: string,
  clientIp?: string,
): Promise<DnsDiagnosticReport> {
  return timedInvoke<DnsDiagnosticReport>("run_dns_diagnostic", {
    domain,
    queryType,
    clientIp: clientIp || null,
  });
}

export function exportConfigFile(path: string, config: AppConfig): Promise<void> {
  return timedInvoke<void>("export_config_file", { path, config });
}

export function importConfigFile(path: string): Promise<AppConfig> {
  return timedInvoke<AppConfig>("import_config_file", { path });
}

export function importConfigContent(content: string): Promise<AppConfig> {
  return timedInvoke<AppConfig>("import_config_content", { content });
}

export function exportDiagnosticFile(
  path: string,
  config: AppConfig,
  status: RuntimeStatus | null,
): Promise<void> {
  return timedInvoke<void>("export_diagnostic_file", { path, config, status });
}

export function exportDiagnosticReport(
  config: AppConfig,
  status: RuntimeStatus | null,
): Promise<unknown> {
  return timedInvoke<unknown>("export_diagnostic_report", { config, status });
}

export function exportQueryLogFile(path: string, content: string): Promise<void> {
  return timedInvoke<void>("export_query_log_file", { path, content });
}

export function clearStatistics(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("clear_statistics");
}

export function setTrayLocale(locale: string): Promise<void> {
  return timedInvoke<void>("set_tray_locale", { locale });
}

export function clearSecurityEvents(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("clear_security_events");
}

export function updateFilters(config: AppConfig): Promise<FilterUpdateResult> {
  return timedInvoke<FilterUpdateResult>("update_filters", { config });
}

export function getFilterUpdateProgress(): Promise<FilterUpdateProgress> {
  return timedInvoke<FilterUpdateProgress>("get_filter_update_progress");
}

export function cancelFilterUpdate(): Promise<FilterUpdateProgress> {
  return timedInvoke<FilterUpdateProgress>("cancel_filter_update");
}

export function detectSystemProxy(): Promise<string | null> {
  return timedInvoke<string | null>("detect_system_proxy");
}

export function startDns(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("start_dns");
}

export function stopDns(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("stop_dns");
}

export function pauseProtection(durationSeconds: number): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("pause_protection", { durationSeconds });
}

export function resumeProtection(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("resume_protection");
}

export function setTrayRuntimeStatus(
  running: boolean,
  protectionPaused: boolean,
  pausedUntil: number | null,
): Promise<void> {
  return timedInvoke<void>("set_tray_runtime_status", {
    running,
    protectionPaused,
    pausedUntil,
  });
}

export function clearDnsCache(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("clear_dns_cache");
}

export function clearFilterCache(): Promise<FilterCacheClearResult> {
  return timedInvoke<FilterCacheClearResult>("clear_filter_cache");
}

export function getStorageInfo(): Promise<StorageInfo> {
  return timedInvoke<StorageInfo>("get_storage_info");
}

export function inspectDataStorageTarget(
  targetPath: string,
): Promise<StorageTargetInfo> {
  return timedInvoke<StorageTargetInfo>("inspect_data_storage_target", { targetPath });
}

export function requestDataMigration(targetPath: string): Promise<StorageInfo> {
  return timedInvoke<StorageInfo>("request_data_migration", { targetPath });
}

export function getMacosServiceStatus(): Promise<MacosServiceStatus> {
  return timedInvoke<MacosServiceStatus>("get_macos_service_status");
}

export function installMacosService(force = false): Promise<MacosServiceStatus> {
  return timedInvoke<MacosServiceStatus>("install_macos_service", { force });
}

export function uninstallMacosService(): Promise<MacosServiceStatus> {
  return timedInvoke<MacosServiceStatus>("uninstall_macos_service");
}

export function openMacosServiceSettings(): Promise<void> {
  return timedInvoke<void>("open_macos_service_settings");
}

export function getWindowsServiceStatus(): Promise<WindowsServiceStatus> {
  return timedInvoke<WindowsServiceStatus>("get_windows_service_status");
}

export function installWindowsService(): Promise<WindowsServiceStatus> {
  return timedInvoke<WindowsServiceStatus>("install_windows_service");
}

export function uninstallWindowsService(): Promise<WindowsServiceStatus> {
  return timedInvoke<WindowsServiceStatus>("uninstall_windows_service");
}

export function getWindowsSystemDnsStatus(): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("get_windows_system_dns_status");
}

export function takeOverWindowsSystemDns(): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("take_over_windows_system_dns");
}

export function restoreWindowsSystemDns(): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("restore_windows_system_dns");
}

export function replaceUnmanagedWindowsSystemDns(
  selection: WindowsSystemDnsFallbackSelection,
): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("replace_unmanaged_windows_system_dns", {
    preset: selection.preset,
    ipv4Servers: selection.ipv4Servers ?? [],
    ipv6Servers: selection.ipv6Servers ?? [],
  });
}

export function restoreWindowsSystemDnsWithFallback(
  selection: WindowsSystemDnsFallbackSelection,
): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("restore_windows_system_dns_with_fallback", {
    preset: selection.preset,
    ipv4Servers: selection.ipv4Servers ?? [],
    ipv6Servers: selection.ipv6Servers ?? [],
  });
}

export function recordFrontendTiming(
  module: string,
  durationMs: number,
  sinceStartMs: number,
  detail?: string,
): Promise<void> {
  return timedInvoke<void>("record_frontend_timing", {
    module,
    durationMs,
    sinceStartMs,
    detail,
  });
}

export function getLinuxSystemDnsStatus(): Promise<LinuxSystemDnsStatus> {
  return timedInvoke<LinuxSystemDnsStatus>("get_linux_system_dns_status");
}

export function takeOverLinuxSystemDns(): Promise<LinuxSystemDnsStatus> {
  return timedInvoke<LinuxSystemDnsStatus>("take_over_linux_system_dns");
}

export function restoreLinuxSystemDns(): Promise<LinuxSystemDnsStatus> {
  return timedInvoke<LinuxSystemDnsStatus>("restore_linux_system_dns");
}
