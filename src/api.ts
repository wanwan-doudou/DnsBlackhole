import { invoke } from "@tauri-apps/api/core";

import type {
  AppConfig,
  FilterCacheClearResult,
  FilterUpdateResult,
  MacosServiceStatus,
  QueryLogFilter,
  QueryLogPage,
  RuntimeStatus,
  StorageInfo,
  WindowsServiceStatus,
} from "./types";

type QueryLogRequest = {
  filter: QueryLogFilter;
  search: string;
  page: number;
  pageSize: number;
};

export function getConfig(): Promise<AppConfig> {
  return invoke<AppConfig>("get_config");
}

export function saveConfig(config: AppConfig): Promise<RuntimeStatus> {
  return invoke<RuntimeStatus>("save_config", { config });
}

export function getStatus(force: boolean, includeLogStats = true): Promise<RuntimeStatus> {
  return invoke<RuntimeStatus>("get_status", { force, includeLogStats });
}

export function getQueryLogs(request: QueryLogRequest): Promise<QueryLogPage> {
  return invoke<QueryLogPage>("get_query_logs", request);
}

export function updateFilters(config: AppConfig): Promise<FilterUpdateResult> {
  return invoke<FilterUpdateResult>("update_filters", { config });
}

export function startDns(): Promise<RuntimeStatus> {
  return invoke<RuntimeStatus>("start_dns");
}

export function stopDns(): Promise<RuntimeStatus> {
  return invoke<RuntimeStatus>("stop_dns");
}

export function clearDnsCache(): Promise<RuntimeStatus> {
  return invoke<RuntimeStatus>("clear_dns_cache");
}

export function clearFilterCache(): Promise<FilterCacheClearResult> {
  return invoke<FilterCacheClearResult>("clear_filter_cache");
}

export function getStorageInfo(): Promise<StorageInfo> {
  return invoke<StorageInfo>("get_storage_info");
}

export function requestDataMigration(targetPath: string): Promise<StorageInfo> {
  return invoke<StorageInfo>("request_data_migration", { targetPath });
}

export function getMacosServiceStatus(): Promise<MacosServiceStatus> {
  return invoke<MacosServiceStatus>("get_macos_service_status");
}

export function installMacosService(force = false): Promise<MacosServiceStatus> {
  return invoke<MacosServiceStatus>("install_macos_service", { force });
}

export function uninstallMacosService(): Promise<MacosServiceStatus> {
  return invoke<MacosServiceStatus>("uninstall_macos_service");
}

export function openMacosServiceSettings(): Promise<void> {
  return invoke<void>("open_macos_service_settings");
}

export function getWindowsServiceStatus(): Promise<WindowsServiceStatus> {
  return invoke<WindowsServiceStatus>("get_windows_service_status");
}

export function installWindowsService(): Promise<WindowsServiceStatus> {
  return invoke<WindowsServiceStatus>("install_windows_service");
}

export function uninstallWindowsService(): Promise<WindowsServiceStatus> {
  return invoke<WindowsServiceStatus>("uninstall_windows_service");
}
