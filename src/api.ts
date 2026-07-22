import { invoke } from "@tauri-apps/api/core";

import type {
  AppConfig,
  FilterCacheClearResult,
  FilterUpdateProgress,
  FilterUpdateResult,
  MacosServiceStatus,
  QueryLogFilter,
  QueryLogPage,
  RuntimeStatus,
  StorageInfo,
  WindowsServiceStatus,
  WindowsSystemDnsFallback,
  WindowsSystemDnsStatus,
} from "./types";

type QueryLogRequest = {
  filter: QueryLogFilter;
  search: string;
  page: number;
  pageSize: number;
};

function timedInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const started = performance.now();
  return invoke<T>(command, args).then(
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

export function getConfig(): Promise<AppConfig> {
  return timedInvoke<AppConfig>("get_config");
}

export function saveConfig(config: AppConfig): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("save_config", { config });
}

export function getStatus(force: boolean, includeLogStats = true): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("get_status", { force, includeLogStats });
}

export function getQueryLogs(request: QueryLogRequest): Promise<QueryLogPage> {
  return timedInvoke<QueryLogPage>("get_query_logs", request);
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

export function clearDnsCache(): Promise<RuntimeStatus> {
  return timedInvoke<RuntimeStatus>("clear_dns_cache");
}

export function clearFilterCache(): Promise<FilterCacheClearResult> {
  return timedInvoke<FilterCacheClearResult>("clear_filter_cache");
}

export function getStorageInfo(): Promise<StorageInfo> {
  return timedInvoke<StorageInfo>("get_storage_info");
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
  preset: WindowsSystemDnsFallback,
): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("replace_unmanaged_windows_system_dns", { preset });
}

export function restoreWindowsSystemDnsWithFallback(
  preset: WindowsSystemDnsFallback,
): Promise<WindowsSystemDnsStatus> {
  return timedInvoke<WindowsSystemDnsStatus>("restore_windows_system_dns_with_fallback", {
    preset,
  });
}

export function recordFrontendTiming(
  module: string,
  durationMs: number,
  sinceStartMs: number,
  detail?: string,
): Promise<void> {
  return invoke<void>("record_frontend_timing", {
    module,
    durationMs,
    sinceStartMs,
    detail,
  });
}
