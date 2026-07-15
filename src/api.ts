import { invoke } from "@tauri-apps/api/core";

import type {
  AppConfig,
  FilterCacheClearResult,
  FilterUpdateResult,
  QueryLogFilter,
  QueryLogPage,
  RuntimeStatus,
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
