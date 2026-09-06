import { getVersion } from "@tauri-apps/api/app";
import { listen } from "@tauri-apps/api/event";
import type { Update } from "@tauri-apps/plugin-updater";
import {
  analyzeCustomRules,
  applyQueryLogRule,
  cancelFilterUpdate,
  clearQueryLogs as clearQueryLogsCommand,
  clearSecurityEvents as clearSecurityEventsCommand,
  clearStatistics as clearStatisticsCommand,
  clearDnsCache as clearDnsCacheCommand,
  clearFilterCache as clearFilterCacheCommand,
  detectSystemProxy,
  getConfig,
  getFilterUpdateProgress,
  getMacosServiceStatus,
  getWindowsSystemDnsStatus,
  getWindowsServiceStatus,
  getStorageInfo,
  inspectDataStorageTarget,
  getQueryLogs,
  getStatus,
  saveConfig as saveConfigCommand,
  requestDataMigration,
  restoreWindowsSystemDns,
  installMacosService,
  installWindowsService,
  openMacosServiceSettings,
  pauseProtection,
  recordFrontendTiming,
  replaceUnmanagedWindowsSystemDns,
  restoreWindowsSystemDnsWithFallback,
  resumeProtection,
  runDnsDiagnostic,
  setTrayLocale,
  setTrayRuntimeStatus,
  startDns,
  stopDns,
  takeOverWindowsSystemDns,
  uninstallMacosService,
  uninstallWindowsService,
  updateFilters as updateFiltersCommand,
} from "./api";
import appIconUrl from "./app-icon.png";
import { buildTrafficSeries, renderSparkline } from "./charts";
import { query } from "./dom";
import {
  createSearchCompositionState,
  onSearchBlur,
  onSearchCompositionEnd,
  onSearchCompositionStart,
  onSearchInput,
  type SearchScheduleDecision,
} from "./query-log-search";
import {
  escapeHtml,
  formatCount,
  formatBytes,
  formatElapsedMs,
  formatLogDate,
  formatLogTime,
  formatPercent,
  formatRate,
  formatRetentionScope,
  formatTime,
  retentionWindowIsShorter,
} from "./format";
import {
  queryLogPaginationState,
} from "./query-log-pagination";
import {
  DEFAULT_QUERY_LOG_QUERY,
  activeAdvancedQueryFilterCount,
  parseQueryLogHours,
} from "./query-log-query";
import { renderAppTemplate } from "./template";
import {
  applyTheme,
  getThemePreference,
  setThemePreference,
  watchSystemTheme,
  type ThemePreference,
} from "./theme";
import {
  getLocale,
  getLocalePreference,
  setLocalePreference,
  t,
  type LocalePreference,
} from "./i18n";
import { createRuleEditorController } from "./rule-editor";
import {
  chooseConfigBackup,
  exportConfigBackup,
  exportSanitizedDiagnostics,
} from "./config-transfer";
import { exportFilteredQueryLogs } from "./query-log-export";
import { dnsQueryTypeLabel, renderQueryLogRow } from "./query-log-render";
import {
  loadSavedQueryLogViews,
  persistSavedQueryLogViews,
  removeSavedQueryLogView,
  upsertSavedQueryLogView,
  type SavedQueryLogView,
} from "./query-log-saved-views";
import type {
  AppConfig,
  BlockingMode,
  DnsDiagnosticReport,
  FilterSubscription,
  FilterProxyMode,
  FilterUpdateProgress,
  MacosServiceState,
  MacosServiceStatus,
  QueryLogFilter,
  QueryLogQuery,
  QueryLogPage,
  QueryLogRuleAction,
  QueryLogSort,
  QueryLogSourceFilter,
  QueryLogTypeFilter,
  RefreshOptions,
  RenderStatusOptions,
  RuntimeStatus,
  SecurityEvent,
  StorageInfo,
  StorageTargetInfo,
  UpstreamLatencyStat,
  UpstreamMode,
  UpstreamRequestStat,
  ViewName,
  WindowsServiceState,
  WindowsServiceStatus,
  WindowsSystemDnsFallback,
  WindowsSystemDnsStatus,
} from "./types";
import "./styles/query-log.css";
import "./style.css";
import "./styles/ui-extras.css";

const frontendStartedAt = performance.now();
const CURRENT_CONFIG_SCHEMA_VERSION = 17;

function logLoadTime(
  module: string,
  started: number,
  detail?: string,
  forwardToBackend = true,
): void {
  const finished = performance.now();
  const durationMs = finished - started;
  const detailText = detail ? `，${detail}` : "";
  console.info(`[加载耗时][前端] ${module}：${durationMs.toFixed(1)} ms${detailText}`);
  if (forwardToBackend) {
    void recordFrontendTiming(module, durationMs, finished - frontendStartedAt, detail).catch(
      (error) => console.error("记录前端加载耗时失败", error),
    );
  }
}

let messageTimer = 0;
let updateStatusTimer = 0;
let lastStatusErrorKey: string | null = null;
const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error(t("缺少应用挂载节点"));
}

const templateStarted = performance.now();
app.innerHTML = renderAppTemplate(appIconUrl);
logLoadTime("页面模板渲染", templateStarted);

let activeView: ViewName = "dashboard";
let filtersState: FilterSubscription[] = [];
let editingFilterIds = new Set<string>();
let currentQueryLogEnabled = true;
let refreshInFlight = false;
let statusRefreshQueued = false;
let isContentScrolling = false;
let queuedAutoRefresh = false;
let scrollIdleTimer: number | undefined;
let pendingUpdate: Update | null = null;
let manualDownloadUrl = "";
let queryLogPage = 1;
let queryLogTotal = 0;
let queryLogCursorStack = [""];
let queryLogNextCursor: string | null = null;
let queryLogRefreshInFlight = false;
let queryLogRefreshQueued = false;
let queryLogSearchTimer: number | undefined;
const queryLogSearchComposition = createSearchCompositionState();
let queryLogLivePaused = false;
let lastDashboardRefreshAt: number | null = null;
let currentConfigSchemaVersion = CURRENT_CONFIG_SCHEMA_VERSION;
let currentStatisticsRetentionHours = 30 * 24;
let currentQueryLogRetentionHours = 90 * 24;
let dashboardStatisticsHours: number | undefined;
let dashboardStatisticsRevision = 0;
let latestDashboardStartedAt: number | null | undefined;
let latestDashboardEndedAt: number | null | undefined;
let clientNameMap = new Map<string, string>();
let currentStorageInfo: StorageInfo | null = null;
let selectedDataStoragePath = "";
let selectedStorageTarget: StorageTargetInfo | null = null;
let storageSelectionError = "";
let storageInspectionToken = 0;
let configLoaded = false;
const isMacOS = navigator.userAgent.includes("Macintosh");
const isWindows = navigator.userAgent.includes("Windows");
let currentMacosServiceStatus: MacosServiceStatus | null = null;
let currentWindowsServiceStatus: WindowsServiceStatus | null = null;
let currentWindowsSystemDnsStatus: WindowsSystemDnsStatus | null = null;
let initialBootstrapComplete = false;
let backgroundServiceRefreshInFlight = false;
let windowsServiceStatusInFlight: Promise<WindowsServiceStatus | null> | null = null;
let windowsSystemDnsStatusInFlight: Promise<WindowsSystemDnsStatus | null> | null = null;
let windowsServiceUnavailableSince: number | null = null;
let detectedSystemProxy: string | null = null;
let savedSystemProxyUrl = "";
let filterUpdateProgressTimer: number | undefined;
let filterUpdateProgressInFlight = false;
let savedConfigFingerprint = "";
let configDirty = false;
let latestRuntimeStatus: RuntimeStatus | null = null;
let pauseExpiryTimer: number | undefined;
let lastTrayRuntimeSignature = "";

const RELEASES_URL = "https://github.com/wanwan-doudou/DnsBlackhole/releases";
const RELEASES_API_URL =
  "https://api.github.com/repos/wanwan-doudou/DnsBlackhole/releases";
const ABOUT_LINKS = {
  docs: "https://github.com/wanwan-doudou/DnsBlackhole/blob/main/README.md",
  repository: "https://github.com/wanwan-doudou/DnsBlackhole",
  releases: RELEASES_URL,
  issues: "https://github.com/wanwan-doudou/DnsBlackhole/issues",
  license: "https://github.com/wanwan-doudou/DnsBlackhole/blob/main/LICENSE",
} as const;
const ABOUT_LINK_LABELS: Record<keyof typeof ABOUT_LINKS, string> = {
  docs: t("使用文档"),
  repository: t("项目源码"),
  releases: t("更新记录"),
  issues: t("问题反馈"),
  license: t("开源许可"),
};
const QUERY_LOG_PAGE_SIZE = 50;
const QUERY_LOG_SEARCH_DEBOUNCE_MS = 800;
const BACKGROUND_REFRESH_INTERVAL_MS = 5_000;
const DASHBOARD_AUTO_REFRESH_INTERVAL_MS = 30_000;
// 仪表盘只展示最有价值的前几项，避免页面和卡片同时出现滚动条。
const RANK_ROW_LIMIT = 8;
const CHECK_RETRY_DELAYS_MS = [800, 2_000, 5_000];
const DOWNLOAD_RETRY_DELAYS_MS = [1_000, 2_500, 5_000];
const CHECK_TIMEOUT_MS = 20_000;
const DOWNLOAD_TIMEOUT_MS = 180_000;
const WINDOWS_SERVICE_STARTUP_RETRY_DELAYS_MS = [150, 250, 400, 700, 1_100, 1_800, 2_500, 3_000];
const WINDOWS_SERVICE_ERROR_GRACE_MS = 10_000;
// 切换语言要重载页面，重载前把当前页面暂存在这里，重载后接着看，不跳回仪表盘。
const PENDING_VIEW_KEY = "dnsblackhole.pendingView";

async function openExternalUrl(url: string): Promise<void> {
  const { openUrl } = await import("@tauri-apps/plugin-opener");
  await openUrl(url);
}

function aboutPlatformLabel(): string {
  if (isWindows) {
    return "Windows";
  }
  if (isMacOS) {
    return "macOS";
  }
  return t("当前桌面平台");
}

function renderAboutRuntimeInfo(): void {
  aboutRuntimePlatformElement.textContent = aboutPlatformLabel();

  if (isWindows) {
    const service = currentWindowsServiceStatus;
    aboutRuntimeServiceElement.textContent = !service
      ? t("正在读取…")
      : service.ready
        ? t("已连接{p0}", { p0: service.serviceVersion ? ` · v${service.serviceVersion}` : "" })
        : service.installed
          ? t("需要修复{p0}", { p0: service.serviceVersion ? ` · v${service.serviceVersion}` : "" })
          : t("尚未安装");
  } else if (isMacOS) {
    const service = currentMacosServiceStatus;
    aboutRuntimeServiceElement.textContent = !service
      ? t("正在读取…")
      : service.enabled && !service.needsRepair
        ? t("已启用{p0}", { p0: service.serviceVersion ? ` · v${service.serviceVersion}` : "" })
        : service.state === "not_registered" || service.state === "not_found"
          ? t("尚未安装")
          : t("需要处理");
  } else {
    aboutRuntimeServiceElement.textContent = t("当前平台无需系统服务");
  }

  aboutRuntimeCoreElement.textContent = !latestRuntimeStatus
    ? t("正在读取…")
    : latestRuntimeStatus.protection_paused
      ? t("保护已暂停")
      : latestRuntimeStatus.running
        ? t("保护运行中")
        : t("当前未运行");
}

async function writeClipboardText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    if (!document.execCommand("copy")) {
      throw new Error(t("当前系统不允许写入剪贴板"));
    }
  } finally {
    textarea.remove();
  }
}

async function openAboutLink(link: keyof typeof ABOUT_LINKS): Promise<void> {
  const url = ABOUT_LINKS[link];
  const label = ABOUT_LINK_LABELS[link];
  try {
    await openExternalUrl(url);
  } catch (error) {
    console.error(`打开${label}失败`, error);
    showMessage(t("无法打开{p0}。请重试，或复制链接后在浏览器中打开。", { p0: label }), true, {
      actions: [
        {
          label: t("重试"),
          run: () => openAboutLink(link),
        },
        {
          label: t("复制链接"),
          run: async () => {
            await writeClipboardText(url);
            showMessage(t("{p0}链接已复制", { p0: label }), false);
          },
        },
      ],
    });
  }
}

async function copyAboutSupportInfo(): Promise<void> {
  const appVersion = appVersionElement.textContent?.trim() || t("未知");
  const takeoverState = !isWindows
    ? t("不适用")
    : !currentWindowsSystemDnsStatus
      ? t("未知")
      : currentWindowsSystemDnsStatus.managed && currentWindowsSystemDnsStatus.inEffect
        ? t("已接管")
        : currentWindowsSystemDnsStatus.managed
          ? t("接管状态异常")
          : t("未接管");
  const summary = [
    `DnsBlackhole v${appVersion}`,
    t("运行平台：{p0}", { p0: aboutRuntimePlatformElement.textContent }),
    t("后台服务：{p0}", { p0: aboutRuntimeServiceElement.textContent }),
    t("DNS 核心：{p0}", { p0: aboutRuntimeCoreElement.textContent }),
    t("系统 DNS：{p0}", { p0: takeoverState }),
    t("配置架构：v{p0}", { p0: CURRENT_CONFIG_SCHEMA_VERSION }),
  ].join("\n");

  const originalText = copySupportInfoButton.textContent ?? t("复制支持信息");
  copySupportInfoButton.disabled = true;
  try {
    await writeClipboardText(summary);
    copySupportInfoButton.textContent = t("已复制");
    showMessage(t("支持信息已复制，不包含域名、客户端或访问令牌"), false);
  } catch (error) {
    showMessage(t("复制支持信息失败：{p0}", { p0: String(error) }), true);
  } finally {
    window.setTimeout(() => {
      copySupportInfoButton.textContent = originalText;
      copySupportInfoButton.disabled = false;
    }, 1600);
  }
}

async function relaunchApplication(): Promise<void> {
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}

async function checkApplicationUpdate(): Promise<Update | null> {
  const { check } = await import("@tauri-apps/plugin-updater");
  return check({ timeout: CHECK_TIMEOUT_MS });
}

const contentElement = query<HTMLDivElement>(".content");
const dashboardView = query<HTMLElement>('[data-view-panel="dashboard"]');
const dashboardRangeField = query<HTMLElement>(".dashboard-range-field");
const dashboardStatisticsRange = query<HTMLSelectElement>("#dashboard_statistics_range");
const clientRankBody = query<HTMLDivElement>("#client_rank");
const contextNav = query<HTMLElement>("#context_nav");
const headerRuntime = query<HTMLElement>("#header_runtime");
const runtimeStatusButton = query<HTMLButtonElement>("#runtime_status_btn");
const runtimeStatusLabel = query<HTMLElement>("#runtime_status_label");
const runtimeStatusDetail = query<HTMLElement>("#runtime_status_detail");
const runtimeStatusMenu = query<HTMLElement>("#runtime_status_menu");
const enabledInput = query<HTMLInputElement>("#enabled");
const launchAtStartupInput = query<HTMLInputElement>("#launch_at_startup");
const useFiltersInput = query<HTMLInputElement>("#use_filters");
const upstreamInput = query<HTMLTextAreaElement>("#upstream_dns");
const fallbackInput = query<HTMLTextAreaElement>("#fallback_dns");
const bootstrapInput = query<HTMLTextAreaElement>("#bootstrap_dns");
const domainUpstreamRulesInput = query<HTMLTextAreaElement>("#domain_upstream_rules");
const clientUpstreamRulesInput = query<HTMLTextAreaElement>("#client_upstream_rules");
const dnssecEnabledInput = query<HTMLInputElement>("#dnssec_enabled");
const listenHostInput = query<HTMLInputElement>("#listen_host");
const listenPortInput = query<HTMLInputElement>("#listen_port");
const listenIpv6Input = query<HTMLInputElement>("#listen_ipv6");
const allowedClientsInput = query<HTMLTextAreaElement>("#allowed_clients");
const blockedClientsInput = query<HTMLTextAreaElement>("#blocked_clients");
const clientFilteringRulesInput = query<HTMLTextAreaElement>("#client_filtering_rules");
const clientPolicyGroupsInput = query<HTMLTextAreaElement>("#client_policy_groups");
const familySafeSearchInput = query<HTMLInputElement>("#family_safe_search");
const familyBlockedServicesInput = query<HTMLTextAreaElement>("#family_blocked_services");
const rateLimitPerSecondInput = query<HTMLInputElement>("#rate_limit_per_second");
const refuseAnyInput = query<HTMLInputElement>("#refuse_any");
const filterUpdateIntervalInput = query<HTMLSelectElement>("#filter_update_interval");
const filterMaxSizeInput = query<HTMLInputElement>("#filter_max_size_mb");
const filterProxyModeInput = query<HTMLSelectElement>("#filter_proxy_mode");
const filterProxyUrlField = query<HTMLLabelElement>("#filter_proxy_url_field");
const filterProxyUrlInput = query<HTMLInputElement>("#filter_proxy_url");
const filterProxyStatus = query<HTMLElement>("#filter_proxy_status");
const allowInsecureHttpInput = query<HTMLInputElement>("#allow_insecure_http");
const upstreamModeInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="upstream_mode"]'),
);
const queryLogEnabledInput = query<HTMLInputElement>("#query_log_enabled");
const anonymizeClientIpInput = query<HTMLInputElement>("#anonymize_client_ip");
const queryLogRetentionInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="query_log_retention"]'),
);
const customRetentionField = query<HTMLLabelElement>("#custom_retention_field");
const queryLogRetentionCustomInput = query<HTMLInputElement>("#query_log_retention_custom");
const statisticsEnabledInput = query<HTMLInputElement>("#statistics_enabled");
const statisticsRetentionInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="statistics_retention"]'),
);
const statisticsCustomRetentionField = query<HTMLLabelElement>(
  "#statistics_custom_retention_field",
);
const statisticsRetentionCustomInput = query<HTMLInputElement>("#statistics_retention_custom");
const dnsCacheEnabledInput = query<HTMLInputElement>("#dns_cache_enabled");
const dnsCacheSizeInput = query<HTMLInputElement>("#dns_cache_size");
const dnsCacheMinTtlInput = query<HTMLInputElement>("#dns_cache_min_ttl");
const dnsCacheMaxTtlInput = query<HTMLInputElement>("#dns_cache_max_ttl");
const dnsCacheOptimisticInput = query<HTMLInputElement>("#dns_cache_optimistic");
const dnsCacheOptimisticMaxStaleInput = query<HTMLInputElement>(
  "#dns_cache_optimistic_max_stale_seconds",
);
const dnsCachePrefetchEnabledInput = query<HTMLInputElement>("#dns_cache_prefetch_enabled");
const dnsCachePrefetchHitThresholdInput = query<HTMLInputElement>(
  "#dns_cache_prefetch_hit_threshold",
);
const runtimeWatchdogEnabledInput = query<HTMLInputElement>("#runtime_watchdog_enabled");
const runtimeWatchdogIntervalInput = query<HTMLInputElement>("#runtime_watchdog_interval_seconds");
const monitoringApiEnabledInput = query<HTMLInputElement>("#monitoring_api_enabled");
const monitoringApiListenHostInput = query<HTMLInputElement>("#monitoring_api_listen_host");
const monitoringApiPortInput = query<HTMLInputElement>("#monitoring_api_port");
const monitoringApiTokenInput = query<HTMLInputElement>("#monitoring_api_token");
const blockingModeInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="blocking_mode"]'),
);
const blockingCustomFields = query<HTMLDivElement>("#blocking_custom_fields");
const blockingCustomIpv4Input = query<HTMLInputElement>("#blocking_custom_ipv4");
const blockingCustomIpv6Input = query<HTMLInputElement>("#blocking_custom_ipv6");
const blockingResponseTtlInput = query<HTMLInputElement>("#blocking_response_ttl");
const rebindingProtectionEnabledInput = query<HTMLInputElement>(
  "#rebinding_protection_enabled",
);
const rebindingAllowedDomainsInput = query<HTMLTextAreaElement>("#rebinding_allowed_domains");
const cnameCloakingEnabledInput = query<HTMLInputElement>("#cname_cloaking_enabled");
const privateReverseDnsEnabledInput = query<HTMLInputElement>("#private_reverse_dns_enabled");
const dnsRewritesInput = query<HTMLTextAreaElement>("#dns_rewrites");
const clientNamesInput = query<HTMLTextAreaElement>("#client_names");
const queryLogIgnoredInput = query<HTMLTextAreaElement>("#query_log_ignored_domains");
const statisticsIgnoredInput = query<HTMLTextAreaElement>("#statistics_ignored_domains");
const clearQueryLogsButton = query<HTMLButtonElement>("#clear_query_logs_btn");
const clearStatisticsButton = query<HTMLButtonElement>("#clear_statistics_btn");
const blacklistInput = query<HTMLTextAreaElement>("#blacklist");
const ruleLineNumbers = query<HTMLElement>("#rule_line_numbers");
const ruleAnalysisSummary = query<HTMLElement>("#rule_analysis_summary");
const ruleDiagnostics = query<HTMLElement>("#rule_diagnostics");
const customRuleSearchInput = query<HTMLInputElement>("#custom_rule_search");
const filtersTable = query<HTMLDivElement>(".filters-table");
const filtersBody = query<HTMLDivElement>("#filters_body");
const saveButton = query<HTMLButtonElement>("#save_btn");
const saveSettingsButton = query<HTMLButtonElement>("#save_settings_btn");
const saveSecurityButton = query<HTMLButtonElement>("#save_security_btn");
const saveFiltersButton = query<HTMLButtonElement>("#save_filters_btn");
const saveCustomButton = query<HTMLButtonElement>("#save_custom_btn");
const saveStateLabels = Array.from(document.querySelectorAll<HTMLElement>(".save-state-label"));
const configSaveButtons = [
  saveButton,
  saveSettingsButton,
  saveSecurityButton,
  saveFiltersButton,
  saveCustomButton,
];
configSaveButtons.forEach((button) => {
  button.disabled = true;
});
const startButton = query<HTMLButtonElement>("#start_btn");
const stopButton = query<HTMLButtonElement>("#stop_btn");
const addFilterButton = query<HTMLButtonElement>("#add_filter_btn");
const updateFiltersButton = query<HTMLButtonElement>("#update_filters_btn");
const cancelFilterUpdateButton = query<HTMLButtonElement>("#cancel_filter_update_btn");
const filterUpdateProgressElement = query<HTMLElement>("#filter_update_progress");
const clearDnsCacheButton = query<HTMLButtonElement>("#clear_dns_cache_btn");
const clearFilterCacheButton = query<HTMLButtonElement>("#clear_filter_cache_btn");
const dataStoragePathInput = query<HTMLInputElement>("#data_storage_path");
const dataStorageSizeElement = query<HTMLElement>("#data_storage_size");
const dataStorageStateElement = query<HTMLElement>("#data_storage_state");
const dataStoragePending = query<HTMLElement>("#data_storage_pending");
const dataStoragePendingText = query<HTMLElement>("#data_storage_pending_text");
const dataStorageError = query<HTMLElement>("#data_storage_error");
const chooseDataStorageButton = query<HTMLButtonElement>("#choose_data_storage_btn");
const resetDataStorageButton = query<HTMLButtonElement>("#reset_data_storage_btn");
const migrateDataStorageButton = query<HTMLButtonElement>("#migrate_data_storage_btn");
const exportConfigButton = query<HTMLButtonElement>("#export_config_btn");
const importConfigButton = query<HTMLButtonElement>("#import_config_btn");
const exportDiagnosticButton = query<HTMLButtonElement>("#export_diagnostic_btn");
const macosServiceSection = query<HTMLElement>("#macos_service_section");
const macosServiceStatusElement = query<HTMLElement>("#macos_service_status");
const installMacosServiceButton = query<HTMLButtonElement>("#install_macos_service_btn");
const uninstallMacosServiceButton = query<HTMLButtonElement>("#uninstall_macos_service_btn");
const openMacosServiceSettingsButton = query<HTMLButtonElement>(
  "#open_macos_service_settings_btn",
);
const windowsServiceSection = query<HTMLElement>("#windows_service_section");
const windowsServiceStatusElement = query<HTMLElement>("#windows_service_status");
const installWindowsServiceButton = query<HTMLButtonElement>("#install_windows_service_btn");
const uninstallWindowsServiceButton = query<HTMLButtonElement>("#uninstall_windows_service_btn");
const windowsSystemDnsSection = query<HTMLElement>("#windows_system_dns_section");
const windowsSystemDnsStatusElement = query<HTMLElement>("#windows_system_dns_status");
const windowsSystemDnsDetailElement = query<HTMLElement>("#windows_system_dns_detail");
const takeOverWindowsSystemDnsButton = query<HTMLButtonElement>(
  "#take_over_windows_system_dns_btn",
);
const restoreWindowsSystemDnsButton = query<HTMLButtonElement>("#restore_windows_system_dns_btn");
const dnsFallbackDialog = query<HTMLDialogElement>("#dns_fallback_dialog");
const dnsFallbackDialogCloseButton = query<HTMLButtonElement>(
  "#dns_fallback_dialog_close_btn",
);
const dnsFallbackDialogCancelButton = query<HTMLButtonElement>(
  "#dns_fallback_dialog_cancel_btn",
);
const dnsFallbackDialogConfirmButton = query<HTMLButtonElement>(
  "#dns_fallback_dialog_confirm_btn",
);
const dnsFallbackDialogTitle = query<HTMLElement>("#dns_fallback_dialog_title");
const dnsFallbackDialogIntro = query<HTMLElement>("#dns_fallback_dialog_intro");
const dnsRestoreOriginalOption = query<HTMLElement>("#dns_restore_original_option");
const dnsRestoreOriginalDetail = query<HTMLElement>("#dns_restore_original_detail");
const dnsFallbackCustomOption = query<HTMLElement>("#dns_fallback_custom_option");
const dnsCustomIpv4Input = query<HTMLInputElement>("#dns_custom_ipv4");
const dnsCustomIpv6Input = query<HTMLInputElement>("#dns_custom_ipv6");
const dnsFallbackInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="dns_fallback"]'),
);
const appVersionElement = query<HTMLElement>("#app_version");
const aboutRuntimeAppVersionElement = query<HTMLElement>("#about_runtime_app_version");
const aboutRuntimePlatformElement = query<HTMLElement>("#about_runtime_platform");
const aboutRuntimeServiceElement = query<HTMLElement>("#about_runtime_service");
const aboutRuntimeCoreElement = query<HTMLElement>("#about_runtime_core");
const copySupportInfoButton = query<HTMLButtonElement>("#copy_support_info_btn");
const checkUpdateButton = query<HTMLButtonElement>("#check_update_btn");
const installUpdateButton = query<HTMLButtonElement>("#install_update_btn");
const manualDownloadButton = query<HTMLButtonElement>("#manual_download_btn");
const updateStatusElement = query<HTMLElement>("#update_status");
const updateDialog = query<HTMLDialogElement>("#update_dialog");
const updateDialogCloseButton = query<HTMLButtonElement>("#update_dialog_close_btn");
const updateDialogLaterButton = query<HTMLButtonElement>("#update_dialog_later_btn");
const updateCurrentVersionElement = query<HTMLElement>("#update_current_version");
const updateReleaseVersionElement = query<HTMLElement>("#update_release_version");
const updateReleaseNotesBodyElement = query<HTMLElement>("#update_release_notes_body");
const queryLogRefreshButton = query<HTMLButtonElement>("#query_log_refresh_btn");
const queryLogPauseButton = query<HTMLButtonElement>("#query_log_pause_btn");
const queryLogExportButton = query<HTMLButtonElement>("#query_log_export_btn");
const queryLogSearchInput = query<HTMLInputElement>("#query_log_search");
const queryLogFilterInput = query<HTMLSelectElement>("#query_log_filter");
const queryLogFilterMenu = query<HTMLDivElement>("#query_log_filter_menu");
const queryLogFilterButton = query<HTMLButtonElement>("#query_log_filter_button");
const queryLogFilterLabel = query<HTMLElement>("#query_log_filter_label");
const queryLogAdvancedButton = query<HTMLButtonElement>("#query_log_advanced_btn");
const queryLogAdvancedCount = query<HTMLElement>("#query_log_advanced_count");
const queryLogAdvancedPanel = query<HTMLElement>("#query_log_advanced_panel");
const queryLogTimeRange = query<HTMLSelectElement>("#query_log_time_range");
const queryLogSource = query<HTMLSelectElement>("#query_log_source");
const queryLogQueryType = query<HTMLSelectElement>("#query_log_query_type");
const queryLogSort = query<HTMLSelectElement>("#query_log_sort");
const queryLogSavedViewSelect = query<HTMLSelectElement>("#query_log_saved_view");
const queryLogViewNameInput = query<HTMLInputElement>("#query_log_view_name");
const queryLogSaveViewButton = query<HTMLButtonElement>("#query_log_save_view_btn");
const queryLogDeleteViewButton = query<HTMLButtonElement>("#query_log_delete_view_btn");
const queryLogResetButton = query<HTMLButtonElement>("#query_log_reset_btn");
const queryLogBody = query<HTMLDivElement>("#query_log_body");
const queryLogPageInfo = query<HTMLElement>("#query_log_page_info");
const queryLogPrevButton = query<HTMLButtonElement>("#query_log_prev_btn");
const queryLogNextButton = query<HTMLButtonElement>("#query_log_next_btn");
let savedQueryLogViews: SavedQueryLogView[] = loadSavedQueryLogViews();
const queryRuleDialog = query<HTMLDialogElement>("#query_rule_dialog");
const queryRuleForm = query<HTMLFormElement>("#query_rule_form");
const queryRuleDomain = query<HTMLElement>("#query_rule_domain");
const queryRuleTarget = query<HTMLInputElement>("#query_rule_target");
const queryRuleDialogCloseButton = query<HTMLButtonElement>("#query_rule_dialog_close_btn");
const queryRuleDialogCancelButton = query<HTMLButtonElement>("#query_rule_dialog_cancel_btn");
let pendingQueryRuleDomain = "";
const securityAccessDenied = query<HTMLElement>("#security_access_denied");
const securityRateLimited = query<HTMLElement>("#security_rate_limited");
const securityDroppedUdp = query<HTMLElement>("#security_dropped_udp");
const securityRefusedAny = query<HTMLElement>("#security_refused_any");
const securityRebindingBlocked = query<HTMLElement>("#security_rebinding_blocked");
const securityCnameBlocked = query<HTMLElement>("#security_cname_blocked");
const workerQueueDropped = query<HTMLElement>("#worker_queue_dropped");
const persistenceQueueDropped = query<HTMLElement>("#persistence_queue_dropped");
const upstreamTaskQueueRejected = query<HTMLElement>("#upstream_task_queue_rejected");
const tcpConnectionRejected = query<HTMLElement>("#tcp_connection_rejected");
const securityEventBody = query<HTMLDivElement>("#security_event_body");
const securityEventRetentionInput = query<HTMLSelectElement>("#security_event_retention_hours");
const clearSecurityEventsButton = query<HTMLButtonElement>("#clear_security_events_btn");
const themePreferenceInput = query<HTMLSelectElement>("#theme_preference");
const languagePreferenceInput = query<HTMLSelectElement>("#language_preference");
const systemHostsEnabledInput = query<HTMLInputElement>("#system_hosts_enabled");
const cacheHitRate = query<HTMLElement>("#cache_hit_rate");
const cacheHitMiss = query<HTMLElement>("#cache_hit_miss");
const cacheStaleHits = query<HTMLElement>("#cache_stale_hits");
const cacheRefreshes = query<HTMLElement>("#cache_refreshes");
const cachePrefetches = query<HTMLElement>("#cache_prefetches");
const cacheEvictions = query<HTMLElement>("#cache_evictions");
const cacheEntries = query<HTMLElement>("#cache_entries");
const cacheBytes = query<HTMLElement>("#cache_bytes");
const diagnosticDomainInput = query<HTMLInputElement>("#diagnostic_domain");
const diagnosticQueryTypeInput = query<HTMLSelectElement>("#diagnostic_query_type");
const diagnosticClientIpInput = query<HTMLInputElement>("#diagnostic_client_ip");
const runDiagnosticButton = query<HTMLButtonElement>("#run_diagnostic_btn");
const diagnosticResults = query<HTMLDivElement>("#diagnostic_results");

const ruleEditor = createRuleEditorController({
  textarea: blacklistInput,
  gutter: ruleLineNumbers,
  summary: ruleAnalysisSummary,
  diagnostics: ruleDiagnostics,
  search: customRuleSearchInput,
  analyze: analyzeCustomRules,
});

type CustomSelectElements = {
  root: HTMLDivElement;
  trigger: HTMLButtonElement;
  valueLabel: HTMLSpanElement;
  menu: HTMLDivElement;
  options: HTMLButtonElement[];
};

const customSelects = new Map<HTMLSelectElement, CustomSelectElements>();

function initializeCustomSelect(select: HTMLSelectElement): void {
  const fieldLabel = select.parentElement?.querySelector<HTMLElement>(":scope > span");
  const root = document.createElement("div");
  const trigger = document.createElement("button");
  const valueLabel = document.createElement("span");
  const arrow = document.createElement("i");
  const menu = document.createElement("div");
  const menuId = `${select.id}_custom_options`;
  const valueId = `${select.id}_custom_value`;

  root.className = "custom-select";
  trigger.className = "custom-select-trigger";
  trigger.type = "button";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("aria-controls", menuId);
  valueLabel.id = valueId;
  arrow.setAttribute("aria-hidden", "true");
  trigger.append(valueLabel, arrow);

  if (fieldLabel) {
    fieldLabel.id ||= `${select.id}_field_label`;
    trigger.setAttribute("aria-labelledby", `${fieldLabel.id} ${valueId}`);
    menu.setAttribute("aria-labelledby", fieldLabel.id);
  } else {
    trigger.setAttribute("aria-label", select.getAttribute("aria-label") || select.id);
  }

  menu.className = "custom-select-options";
  menu.id = menuId;
  menu.setAttribute("role", "listbox");

  const optionButtons = Array.from(select.options).map((option) => {
    const button = document.createElement("button");
    button.className = "custom-select-option";
    button.type = "button";
    button.dataset.value = option.value;
    button.disabled = option.disabled;
    button.textContent = option.textContent;
    button.setAttribute("role", "option");
    button.addEventListener("click", () => {
      if (select.disabled || option.disabled) {
        return;
      }
      const changed = select.value !== option.value;
      select.value = option.value;
      syncCustomSelect(select);
      setCustomSelectOpen(select, false);
      trigger.focus();
      if (changed) {
        select.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    button.addEventListener("keydown", (event) => {
      const currentIndex = optionButtons.indexOf(button);
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const direction = event.key === "ArrowDown" ? 1 : -1;
        focusCustomSelectOption(optionButtons, currentIndex + direction);
      } else if (event.key === "Home" || event.key === "End") {
        event.preventDefault();
        focusCustomSelectOption(optionButtons, event.key === "Home" ? 0 : optionButtons.length - 1);
      } else if (event.key === "Escape") {
        event.preventDefault();
        setCustomSelectOpen(select, false);
        trigger.focus();
      } else if (event.key === "Tab") {
        setCustomSelectOpen(select, false);
      }
    });
    menu.append(button);
    return button;
  });

  select.classList.add("custom-select-native");
  select.tabIndex = -1;
  select.setAttribute("aria-hidden", "true");
  select.insertAdjacentElement("afterend", root);
  root.append(trigger, menu);
  customSelects.set(select, { root, trigger, valueLabel, menu, options: optionButtons });

  trigger.addEventListener("click", () => {
    if (!select.disabled) {
      setCustomSelectOpen(select, !root.classList.contains("open"));
    }
  });
  trigger.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setCustomSelectOpen(select, true);
      const selectedIndex = Math.max(0, select.selectedIndex);
      focusCustomSelectOption(optionButtons, event.key === "ArrowDown" ? selectedIndex : selectedIndex - 1);
    } else if (event.key === "Escape") {
      setCustomSelectOpen(select, false);
    }
  });
  select.addEventListener("change", () => syncCustomSelect(select));
  syncCustomSelect(select);
}

function focusCustomSelectOption(options: HTMLButtonElement[], requestedIndex: number): void {
  if (options.length === 0) {
    return;
  }
  let index = (requestedIndex + options.length) % options.length;
  for (let attempt = 0; attempt < options.length; attempt += 1) {
    if (!options[index].disabled) {
      options[index].focus();
      return;
    }
    index = (index + 1) % options.length;
  }
}

function setCustomSelectOpen(select: HTMLSelectElement, open: boolean): void {
  const elements = customSelects.get(select);
  if (!elements) {
    return;
  }
  if (open) {
    closeCustomSelects(select);
    const rect = elements.trigger.getBoundingClientRect();
    const estimatedMenuHeight = Math.min(elements.options.length * 38 + 12, 240);
    const spaceBelow = window.innerHeight - rect.bottom - 12;
    elements.root.classList.toggle(
      "open-upward",
      spaceBelow < estimatedMenuHeight && rect.top > spaceBelow,
    );
  }
  elements.root.classList.toggle("open", open);
  elements.trigger.setAttribute("aria-expanded", String(open));
}

function closeCustomSelects(except?: HTMLSelectElement): void {
  customSelects.forEach((elements, select) => {
    if (select !== except) {
      elements.root.classList.remove("open", "open-upward");
      elements.trigger.setAttribute("aria-expanded", "false");
    }
  });
}

function syncCustomSelect(select: HTMLSelectElement): void {
  const elements = customSelects.get(select);
  if (!elements) {
    return;
  }
  const selectedOption = select.selectedOptions[0] || select.options[0];
  elements.valueLabel.textContent = selectedOption?.textContent || t("请选择");
  elements.trigger.disabled = select.disabled;
  elements.options.forEach((button, index) => {
    const selected = button.dataset.value === select.value;
    button.disabled = select.options[index]?.disabled ?? false;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = -1;
  });
}

// 选项固定的下拉框统一换成自绘控件，原生 select 在 WebView2 里样式不可控。
// 已保存视图的选项会动态重建，不能走这里（initializeCustomSelect 只快照一次）。
[
  filterProxyModeInput,
  filterUpdateIntervalInput,
  diagnosticQueryTypeInput,
  dashboardStatisticsRange,
  themePreferenceInput,
  languagePreferenceInput,
  securityEventRetentionInput,
].forEach(initializeCustomSelect);

document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    const view = button.dataset.view as ViewName | undefined;
    if (view) {
      setActiveView(view);
    }
  });
});

document.querySelectorAll<HTMLButtonElement>("[data-about-link]").forEach((button) => {
  button.addEventListener("click", () => {
    const link = button.dataset.aboutLink as keyof typeof ABOUT_LINKS | undefined;
    if (!link || !(link in ABOUT_LINKS)) {
      return;
    }
    void openAboutLink(link);
  });
});

copySupportInfoButton.addEventListener("click", () => {
  void copyAboutSupportInfo();
});

function closeQueryLogFilter(): void {
  queryLogFilterMenu.classList.remove("open");
  queryLogFilterButton.setAttribute("aria-expanded", "false");
}

function focusCompositeOption(
  options: HTMLButtonElement[],
  current: HTMLButtonElement | null,
  key: "ArrowDown" | "ArrowUp" | "Home" | "End",
): void {
  const enabled = options.filter((option) => !option.disabled);
  if (enabled.length === 0) {
    return;
  }
  const currentIndex = current ? enabled.indexOf(current) : -1;
  const nextIndex = key === "Home"
    ? 0
    : key === "End"
      ? enabled.length - 1
      : key === "ArrowUp"
        ? (currentIndex <= 0 ? enabled.length : currentIndex) - 1
        : (currentIndex + 1) % enabled.length;
  enabled[nextIndex].focus();
}

document.addEventListener("click", (e) => {
  const target = e.target as HTMLElement;
  if (!target.closest(".query-log-filter")) {
    closeQueryLogFilter();
  }
  if (!target.closest(".custom-select")) {
    closeCustomSelects();
  }
  if (!target.closest(".header-runtime")) {
    closeRuntimeStatusMenu();
  }
});

runtimeStatusButton.addEventListener("click", (event) => {
  event.stopPropagation();
  const open = !headerRuntime.classList.contains("open");
  headerRuntime.classList.toggle("open", open);
  runtimeStatusButton.setAttribute("aria-expanded", String(open));
});

runtimeStatusButton.addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    headerRuntime.classList.add("open");
    runtimeStatusButton.setAttribute("aria-expanded", "true");
    focusCompositeOption(
      Array.from(runtimeStatusMenu.querySelectorAll<HTMLButtonElement>("[role='menuitem']")),
      null,
      event.key === "ArrowDown" ? "Home" : "End",
    );
  } else if (event.key === "Escape") {
    closeRuntimeStatusMenu();
  }
});

runtimeStatusMenu.querySelectorAll<HTMLButtonElement>("[role='menuitem']").forEach((button) => {
  button.tabIndex = -1;
});

runtimeStatusMenu.addEventListener("keydown", (event) => {
  const options = Array.from(
    runtimeStatusMenu.querySelectorAll<HTMLButtonElement>("[role='menuitem']"),
  );
  if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
    event.preventDefault();
    focusCompositeOption(
      options,
      (event.target as HTMLElement).closest<HTMLButtonElement>("[role='menuitem']"),
      event.key as "ArrowDown" | "ArrowUp" | "Home" | "End",
    );
  } else if (event.key === "Escape") {
    event.preventDefault();
    closeRuntimeStatusMenu();
    runtimeStatusButton.focus();
  } else if (event.key === "Tab") {
    closeRuntimeStatusMenu();
  }
});

runtimeStatusMenu.addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>(
    "[data-protection-action]",
  );
  if (!button || button.disabled) {
    return;
  }
  closeRuntimeStatusMenu();
  if (event.detail === 0) {
    runtimeStatusButton.focus();
  }
  void runProtectionAction(
    button.dataset.protectionAction === "resume"
      ? "resume"
      : "pause",
    Number(button.dataset.duration || 0),
  );
});

document.querySelectorAll<HTMLButtonElement>("[data-refresh-dashboard]").forEach((button) => {
  button.setAttribute("aria-label", button.title || t("刷新仪表盘"));
  button.addEventListener("click", async () => {
    await refreshStatus({ button });
  });
});

queryLogRefreshButton.addEventListener("click", async () => {
  await refreshQueryLogs({ button: queryLogRefreshButton });
});

function applySearchScheduleDecision(decision: SearchScheduleDecision): void {
  if (decision === "cancel") {
    window.clearTimeout(queryLogSearchTimer);
    return;
  }
  if (decision === "schedule") {
    scheduleQueryLogSearch();
  }
}

queryLogSearchInput.addEventListener("input", (event) => {
  const isComposing = event instanceof InputEvent && event.isComposing;
  applySearchScheduleDecision(onSearchInput(queryLogSearchComposition, isComposing));
});

queryLogSearchInput.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") {
    return;
  }
  event.preventDefault();
  window.clearTimeout(queryLogSearchTimer);
  resetQueryLogPagination();
  void refreshQueryLogs();
});

queryLogSearchInput.addEventListener("compositionstart", () => {
  applySearchScheduleDecision(onSearchCompositionStart(queryLogSearchComposition));
});

queryLogSearchInput.addEventListener("compositionend", () => {
  applySearchScheduleDecision(onSearchCompositionEnd(queryLogSearchComposition));
});

// compositionend 不是必达事件，失焦时兜底解锁，避免搜索框永久失效
queryLogSearchInput.addEventListener("blur", () => {
  applySearchScheduleDecision(onSearchBlur(queryLogSearchComposition));
});

queryLogFilterInput.addEventListener("change", () => {
  resetQueryLogPagination();
  void refreshQueryLogs();
});

queryLogAdvancedButton.addEventListener("click", () => {
  const open = queryLogAdvancedPanel.hidden;
  queryLogAdvancedPanel.hidden = !open;
  queryLogAdvancedButton.setAttribute("aria-expanded", String(open));
  refreshQueryLogAdvancedState();
});

[queryLogTimeRange, queryLogSource, queryLogQueryType, queryLogSort].forEach((control) => {
  control.addEventListener("change", () => {
    resetQueryLogPagination();
    refreshQueryLogAdvancedState();
    void refreshQueryLogs();
  });
});

queryLogResetButton.addEventListener("click", () => {
  queryLogSearchInput.value = DEFAULT_QUERY_LOG_QUERY.search;
  setQueryLogFilterValue(DEFAULT_QUERY_LOG_QUERY.filter);
  queryLogTimeRange.value = "configured";
  queryLogSource.value = DEFAULT_QUERY_LOG_QUERY.source;
  queryLogQueryType.value = DEFAULT_QUERY_LOG_QUERY.queryType;
  queryLogSort.value = DEFAULT_QUERY_LOG_QUERY.sort;
  resetQueryLogPagination();
  refreshQueryLogAdvancedState();
  void refreshQueryLogs();
});
queryLogSavedViewSelect.addEventListener("change", () => {
  const saved = savedQueryLogViews.find((view) => view.id === queryLogSavedViewSelect.value);
  queryLogDeleteViewButton.disabled = !saved;
  if (!saved) {
    return;
  }
  applyQueryLogQuery(saved.query);
  resetQueryLogPagination();
  refreshQueryLogAdvancedState();
  void refreshQueryLogs();
});

queryLogSaveViewButton.addEventListener("click", () => {
  try {
    savedQueryLogViews = upsertSavedQueryLogView(
      savedQueryLogViews,
      queryLogViewNameInput.value,
      collectQueryLogQuery(),
    );
    persistSavedQueryLogViews(savedQueryLogViews);
    const saved = savedQueryLogViews.find(
      (view) => view.name === queryLogViewNameInput.value.replace(/\s+/g, " ").trim(),
    );
    renderSavedQueryLogViews(saved?.id ?? "");
    queryLogViewNameInput.value = "";
    showMessage(saved ? t("已保存查询视图“{p0}”", { p0: saved.name }) : t("查询视图已保存"), false);
  } catch (error) {
    showMessage(String(error), true);
  }
});

queryLogViewNameInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    queryLogSaveViewButton.click();
  }
});

queryLogDeleteViewButton.addEventListener("click", () => {
  const saved = savedQueryLogViews.find((view) => view.id === queryLogSavedViewSelect.value);
  if (!saved || !window.confirm(t("删除查询视图“{p0}”？", { p0: saved.name }))) {
    return;
  }
  savedQueryLogViews = removeSavedQueryLogView(savedQueryLogViews, saved.id);
  persistSavedQueryLogViews(savedQueryLogViews);
  renderSavedQueryLogViews();
  showMessage(t("已删除查询视图“{p0}”", { p0: saved.name }), false);
});
renderSavedQueryLogViews();
refreshQueryLogAdvancedState();

queryLogFilterButton.addEventListener("click", (event) => {
  event.stopPropagation();
  if (queryLogFilterButton.disabled) {
    return;
  }
  const open = !queryLogFilterMenu.classList.contains("open");
  queryLogFilterMenu.classList.toggle("open", open);
  queryLogFilterButton.setAttribute("aria-expanded", String(open));
});

queryLogFilterMenu.querySelectorAll<HTMLButtonElement>("[data-filter]").forEach((option) => {
  option.tabIndex = -1;
  option.addEventListener("click", (event) => {
    event.stopPropagation();
    const value = option.dataset.filter as QueryLogFilter | undefined;
    if (!value || queryLogFilterInput.value === value) {
      closeQueryLogFilter();
      if (event.detail === 0) {
        queryLogFilterButton.focus();
      }
      return;
    }
    setQueryLogFilterValue(value);
    closeQueryLogFilter();
    if (event.detail === 0) {
      queryLogFilterButton.focus();
    }
    queryLogFilterInput.dispatchEvent(new Event("change"));
  });
});

queryLogFilterButton.addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    queryLogFilterMenu.classList.add("open");
    queryLogFilterButton.setAttribute("aria-expanded", "true");
    const options = Array.from(
      queryLogFilterMenu.querySelectorAll<HTMLButtonElement>("[data-filter]"),
    );
    const selected = options.find((option) => option.getAttribute("aria-selected") === "true") ?? null;
    focusCompositeOption(options, selected, event.key);
  } else if (event.key === "Escape") {
    closeQueryLogFilter();
    queryLogFilterButton.focus();
  }
});

queryLogFilterMenu.addEventListener("keydown", (event) => {
  const options = Array.from(
    queryLogFilterMenu.querySelectorAll<HTMLButtonElement>("[data-filter]"),
  );
  if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
    event.preventDefault();
    focusCompositeOption(
      options,
      (event.target as HTMLElement).closest<HTMLButtonElement>("[data-filter]"),
      event.key as "ArrowDown" | "ArrowUp" | "Home" | "End",
    );
  } else if (event.key === "Escape") {
    event.preventDefault();
    closeQueryLogFilter();
    queryLogFilterButton.focus();
  } else if (event.key === "Tab") {
    closeQueryLogFilter();
  }
});

queryLogPrevButton.addEventListener("click", () => {
  if (queryLogPage <= 1) {
    return;
  }
  queryLogPage -= 1;
  contentElement.scrollTop = 0;
  void refreshQueryLogs();
});

queryLogNextButton.addEventListener("click", () => {
  if (queryLogUsesCursor()) {
    if (!queryLogNextCursor) {
      return;
    }
    queryLogCursorStack[queryLogPage] = queryLogNextCursor;
    queryLogCursorStack.length = queryLogPage + 1;
    queryLogPage += 1;
  } else {
    const pagination = queryLogPaginationState(
      queryLogPage,
      queryLogTotal,
      QUERY_LOG_PAGE_SIZE,
      false,
    );
    if (pagination.nextDisabled) {
      return;
    }
    queryLogPage += 1;
  }
  contentElement.scrollTop = 0;
  void refreshQueryLogs();
});

queryLogBody.addEventListener("pointerover", (event) => {
  const anchor = (event.target as HTMLElement).closest<HTMLElement>(".log-detail-anchor");
  if (anchor) {
    placeLogDetailPopover(anchor);
  }
});

queryLogBody.addEventListener("focusin", (event) => {
  const anchor = (event.target as HTMLElement).closest<HTMLElement>(".log-detail-anchor");
  if (anchor) {
    placeLogDetailPopover(anchor);
  }
});

contentElement.addEventListener("scroll", markContentScrolling, { passive: true });

queryLogEnabledInput.addEventListener("change", updateLogControls);
statisticsEnabledInput.addEventListener("change", updateStatisticsControls);
filterProxyModeInput.addEventListener("change", updateFilterProxyControls);
dnsCacheEnabledInput.addEventListener("change", updateDnsCacheControls);
dnsCacheOptimisticInput.addEventListener("change", updateDnsCacheControls);
dnsCachePrefetchEnabledInput.addEventListener("change", updateDnsCacheControls);
rebindingProtectionEnabledInput.addEventListener("change", updateResponseProtectionControls);
runtimeWatchdogEnabledInput.addEventListener("change", updateRuntimeWatchdogControls);
monitoringApiEnabledInput.addEventListener("change", updateMonitoringApiControls);
blockingModeInputs.forEach((input) => {
  input.addEventListener("change", updateBlockingModeControls);
});
queryLogRetentionInputs.forEach((input) => {
  input.addEventListener("change", () => {
    updateLogControls();
    if (input.checked && input.value === "custom") {
      queryLogRetentionCustomInput.focus();
    }
  });
});
statisticsRetentionInputs.forEach((input) => {
  input.addEventListener("change", () => {
    updateStatisticsControls();
    if (input.checked && input.value === "custom") {
      statisticsRetentionCustomInput.focus();
    }
  });
});

runDiagnosticButton.addEventListener("click", () => {
  void runDiagnostic();
});

diagnosticDomainInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void runDiagnostic();
  }
});

queryLogBody.addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("[data-log-rule-action]");
  if (!button || button.disabled) {
    return;
  }
  const action = button.dataset.logRuleAction as QueryLogRuleAction | undefined;
  const domain = button.dataset.domain;
  if (!action || !domain) {
    return;
  }
  if (configDirty) {
    showMessage(t("请先保存当前配置更改，再从查询日志添加规则"), true);
    return;
  }
  if (action === "rewrite") {
    openQueryRuleDialog(domain);
    return;
  }
  void runQueryLogRuleAction(domain, action);
});

queryRuleDialogCloseButton.addEventListener("click", closeQueryRuleDialog);
queryRuleDialogCancelButton.addEventListener("click", closeQueryRuleDialog);
queryRuleDialog.addEventListener("cancel", () => {
  pendingQueryRuleDomain = "";
});
queryRuleForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = queryRuleTarget.value.trim();
  if (!target) {
    queryRuleTarget.focus();
    showMessage(t("请填写 DNS 重写目标 IP"), true);
    return;
  }
  const domain = pendingQueryRuleDomain;
  closeQueryRuleDialog();
  if (domain) {
    void runQueryLogRuleAction(domain, "rewrite", target);
  }
});

const CONFIG_VIEW_SELECTOR = [
  '[data-view-panel="settings"]',
  '[data-view-panel="dns"]',
  '[data-view-panel="security"]',
  '[data-view-panel="filters"]',
  '[data-view-panel="custom"]',
].join(",");

function handleConfigFieldChange(event: Event): void {
  const target = event.target;
  if (
    !(
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement
    )
  ) {
    return;
  }
  const readOnly =
    (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) && target.readOnly;
  // 界面偏好（主题、语言）存在本机且立即生效，不该让"保存更改"变成待保存状态
  if (readOnly || target.closest("[data-ui-preference]") || !target.closest(CONFIG_VIEW_SELECTOR)) {
    return;
  }
  window.queueMicrotask(updateConfigDirtyState);
}

app.addEventListener("input", handleConfigFieldChange);
app.addEventListener("change", handleConfigFieldChange);

window.addEventListener("keydown", (event) => {
  if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "s") {
    return;
  }
  if (!configLoaded || !configDirty) {
    return;
  }
  event.preventDefault();
  void saveConfig();
});

window.addEventListener("beforeunload", (event) => {
  if (!configDirty) {
    return;
  }
  event.preventDefault();
  event.returnValue = "";
});

saveButton.addEventListener("click", async () => {
  await saveConfig();
});

saveSettingsButton.addEventListener("click", async () => {
  await saveConfig();
});

saveSecurityButton.addEventListener("click", async () => {
  await saveConfig();
});

saveFiltersButton.addEventListener("click", async () => {
  await saveConfig();
});

saveCustomButton.addEventListener("click", async () => {
  await saveConfig();
});

queryLogPauseButton.addEventListener("click", () => {
  queryLogLivePaused = !queryLogLivePaused;
  queryLogPauseButton.classList.toggle("active", queryLogLivePaused);
  queryLogPauseButton.textContent = queryLogLivePaused ? t("恢复实时刷新") : t("暂停实时刷新");
  if (!queryLogLivePaused) {
    void refreshQueryLogs();
  }
});

queryLogExportButton.addEventListener("click", () => {
  if (!window.confirm(t("导出的 CSV 会包含当前筛选中的域名和客户端地址，请妥善保管。是否继续？"))) {
    return;
  }
  void runFileAction(queryLogExportButton, t("准备导出…"), async () => {
    const result = await exportFilteredQueryLogs(
      collectQueryLogQuery(),
      (exported, total) => {
        queryLogExportButton.textContent = t("导出 {p0}/{p1}", { p0: exported.toLocaleString(), p1: total.toLocaleString() });
      },
    );
    if (!result) {
      return;
    }
    showMessage(
      result.truncated
        ? t("已导出最近 {p0} 条；当前筛选共 {p1} 条，请缩小筛选范围以导出其余记录", { p0: formatCount(result.exported), p1: formatCount(result.total) })
        : t("已导出 {p0} 条查询日志", { p0: formatCount(result.exported) }),
      result.truncated,
    );
  });
});

dashboardStatisticsRange.addEventListener("change", () => {
  dashboardStatisticsHours = dashboardStatisticsRange.value === "configured"
    ? undefined
    : Number(dashboardStatisticsRange.value);
  dashboardStatisticsRevision += 1;
  syncCustomSelect(dashboardStatisticsRange);
  setDashboardLoading(true);
  void refreshStatus({ button: document.querySelector<HTMLButtonElement>("[data-refresh-dashboard]") ?? undefined });
});

clientRankBody.addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("[data-client-log]");
  const client = button?.dataset.clientLog;
  if (!client) {
    return;
  }
  queryLogSearchInput.value = client;
  resetQueryLogPagination();
  setActiveView("logs");
  queryLogSearchInput.focus();
});

exportConfigButton.addEventListener("click", () => {
  void runFileAction(exportConfigButton, t("导出中…"), async () => {
    if (!configLoaded) {
      throw new Error(t("配置尚未加载，无法导出"));
    }
    if (await exportConfigBackup(collectConfig())) {
      showMessage(t("配置备份已导出"), false);
    }
  });
});

importConfigButton.addEventListener("click", () => {
  void runFileAction(importConfigButton, t("恢复中…"), async () => {
    if (configDirty && !window.confirm(t("恢复配置会覆盖当前未保存的更改，是否继续？"))) {
      return;
    }
    const imported = await chooseConfigBackup();
    if (!imported) {
      return;
    }
    currentStatisticsRetentionHours = imported.statistics_retention_hours;
    currentQueryLogRetentionHours = imported.query_log_retention_hours;
    const status = await saveConfigCommand(imported);
    await loadConfig();
    renderStatus(status);
    showMessage(t("配置已校验、迁移并恢复"), false);
  });
});

exportDiagnosticButton.addEventListener("click", () => {
  void runFileAction(exportDiagnosticButton, t("导出中…"), async () => {
    if (!configLoaded) {
      throw new Error(t("配置尚未加载，无法导出诊断信息"));
    }
    if (await exportSanitizedDiagnostics(collectConfig(), latestRuntimeStatus)) {
      showMessage(t("脱敏诊断信息已导出"), false);
    }
  });
});

async function runFileAction(
  button: HTMLButtonElement,
  busyText: string,
  action: () => Promise<void>,
): Promise<void> {
  const text = button.textContent ?? "";
  button.disabled = true;
  button.textContent = busyText;
  try {
    await action();
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    button.disabled = false;
    button.textContent = text;
  }
}

startButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    await saveConfigOnly();
    const status = await startDns();
    renderStatus(status);
    showMessage(t("DNS 服务已启动"), false);
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    setBusy(false);
  }
});

stopButton.addEventListener("click", async () => {
  await runStatusAction(() => stopDns(), t("DNS 服务已停止"));
});

addFilterButton.addEventListener("click", () => {
  const id = `custom-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  filtersState = [
    ...filtersState,
    {
      id,
      name: t("新黑名单"),
      url: "",
      enabled: true,
      rule_count: 0,
      block_rule_count: 0,
      allow_rule_count: 0,
      ignored_rule_count: 0,
      ignored_comment_count: 0,
      ignored_regex_count: 0,
      ignored_unsupported_count: 0,
      ignored_invalid_count: 0,
      last_updated: null,
      last_error: null,
    },
  ];
  editingFilterIds.add(id);
  renderFilters();
  updateConfigDirtyState();
});

updateFiltersButton.addEventListener("click", async () => {
  setFilterUpdating(true);
  startFilterUpdateProgressPolling();
  try {
    await waitForPaint();
    const result = await updateFiltersCommand(collectConfig());
    renderStatus(result.status);
    showMessage(result.message, result.failed > 0 && result.cancelled === 0);
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    stopFilterUpdateProgressPolling();
    setFilterUpdating(false);
  }
});

cancelFilterUpdateButton.addEventListener("click", async () => {
  cancelFilterUpdateButton.disabled = true;
  cancelFilterUpdateButton.textContent = t("正在取消");
  try {
    const progress = await cancelFilterUpdate();
    renderFilterUpdateProgress(progress);
  } catch (error) {
    cancelFilterUpdateButton.disabled = false;
    cancelFilterUpdateButton.textContent = t("取消更新");
    showMessage(String(error), true);
  }
});

clearDnsCacheButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    const status = await clearDnsCacheCommand();
    renderStatus(status);
    showMessage(t("DNS 缓存已清除"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    setBusy(false);
    updateDnsCacheControls();
  }
});

clearFilterCacheButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("这会删除可重新生成的规则编译缓存。已下载的远程黑名单和当前生效规则不会删除；下次启动或规则变更时会自动重新生成缓存。是否继续？"),
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  clearFilterCacheButton.classList.add("loading");
  try {
    const result = await clearFilterCacheCommand();
    renderStatus(result.status);
    showMessage(result.message, false);
    await loadStorageInfo();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    clearFilterCacheButton.classList.remove("loading");
    setBusy(false);
  }
});

chooseDataStorageButton.addEventListener("click", async () => {
  if (!currentStorageInfo) {
    return;
  }
  try {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      directory: true,
      multiple: false,
      title: t("选择 DnsBlackhole 数据存储目录"),
      defaultPath: currentStorageInfo.current_path,
    });
    if (typeof selected === "string") {
      await selectDataStoragePath(selected);
    }
  } catch (error) {
    showMessage(t("选择数据目录失败：{p0}", { p0: String(error) }), true);
  }
});

resetDataStorageButton.addEventListener("click", async () => {
  if (!currentStorageInfo) {
    return;
  }
  await selectDataStoragePath(currentStorageInfo.default_path);
});

migrateDataStorageButton.addEventListener("click", async () => {
  if (
    !currentStorageInfo ||
    !hasPendingStorageSelection() ||
    !selectedStorageTarget ||
    selectedStorageTarget.action === "current"
  ) {
    return;
  }
  const targetPath = selectedDataStoragePath;
  const useExisting = selectedStorageTarget.action === "use_existing";
  const confirmed = window.confirm(
    useExisting
      ? t("检测到现有 DnsBlackhole 数据：\n{p0}\n\n应用将验证并备份该数据库，然后切换使用此目录。现有目录和当前目录都不会被删除。是否继续？", { p0: targetPath })
      : t("应用将重启并把数据库与过滤器缓存迁移到：\n{p0}\n\n目标数据验证成功后才会清理原目录。是否继续？", { p0: targetPath }),
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  migrateDataStorageButton.classList.add("loading");
  try {
    await requestDataMigration(targetPath);
    showMessage(
      useExisting
        ? t("现有数据接管任务已保存，正在重启应用…")
        : t("迁移任务已保存，正在重启应用…"),
      false,
    );
    await relaunchApplication();
  } catch (error) {
    showMessage(String(error), true);
    await loadStorageInfo();
  } finally {
    migrateDataStorageButton.classList.remove("loading");
    setBusy(false);
  }
});

checkUpdateButton.addEventListener("click", async () => {
  checkUpdateButton.disabled = true;
  checkUpdateButton.classList.add("loading");
  checkUpdateButton.textContent = t("检查中");
  setUpdateStatus("info", t("正在检查更新..."));
  closeUpdateDialog();
  pendingUpdate = null;
  manualDownloadUrl = "";

  try {
    const currentVersion = await getVersion();
    pendingUpdate = await checkForUpdateWithRetry();
    if (pendingUpdate) {
      let notes = pendingUpdate.body ?? "";
      manualDownloadUrl = resolveManualDownloadUrl(pendingUpdate);
      try {
        const release = await fetchGitHubReleaseWithRetry(pendingUpdate.version);
        notes = release.notes || notes;
        manualDownloadUrl = release.downloadUrl;
      } catch (error) {
        console.warn("读取 GitHub Release 更新日志失败", error);
      }

      setUpdateStatus("ok", t("发现新版本 v{p0}", { p0: pendingUpdate.version }));
      showUpdateDialog(currentVersion, pendingUpdate.version, notes);
      installUpdateButton.disabled = false;
      manualDownloadButton.disabled = false;
    } else {
      setUpdateStatus("ok", t("已是最新版本 v{p0}", { p0: currentVersion }));
    }
  } catch (error) {
    console.error("检查更新失败", error);
    const message = formatUpdateError(error);
    if (/platform.+(was )?not found/i.test(message)) {
      setUpdateStatus("err", t("当前平台暂无自动更新包，请前往 GitHub Releases 手动下载"));
    } else {
      setUpdateStatus("err", t("检查更新失败：{p0}", { p0: message }));
    }
    manualDownloadUrl = "";
  } finally {
    checkUpdateButton.disabled = false;
    checkUpdateButton.classList.remove("loading");
    checkUpdateButton.textContent = t("检查更新");
  }
});

installUpdateButton.addEventListener("click", async () => {
  if (!pendingUpdate) {
    return;
  }

  closeUpdateDialog();
  installUpdateButton.disabled = true;
  manualDownloadButton.disabled = true;

  try {
    await downloadAndInstallWithRetry();
    setUpdateStatus("ok", t("安装完成，即将重启应用..."));
    await relaunchApplication();
  } catch (error) {
    console.error("更新失败", error);
    const fallbackTip = manualDownloadUrl
      ? t("\n可重试，或点击“浏览器下载”手动安装。")
      : "";
    setUpdateStatus("err", t("更新失败：{p0}{p1}", { p0: formatUpdateError(error), p1: fallbackTip }));
    installUpdateButton.disabled = false;
    manualDownloadButton.disabled = false;
  }
});

manualDownloadButton.addEventListener("click", async () => {
  const url = manualDownloadUrl || RELEASES_URL;
  closeUpdateDialog();
  manualDownloadButton.disabled = true;

  try {
    await openExternalUrl(url);
  } catch (error) {
    console.error("打开下载链接失败", error);
    setUpdateStatus("err", t("打开浏览器失败：{p0}\n下载地址：{p1}", { p0: formatUpdateError(error), p1: url }));
  } finally {
    manualDownloadButton.disabled = false;
  }
});

updateDialogCloseButton.addEventListener("click", closeUpdateDialog);
updateDialogLaterButton.addEventListener("click", closeUpdateDialog);
updateDialog.addEventListener("click", (event) => {
  if (event.target === updateDialog) {
    closeUpdateDialog();
  }
});

installMacosServiceButton.addEventListener("click", async () => {
  installMacosServiceButton.disabled = true;
  installMacosServiceButton.classList.add("loading");
  try {
    // 服务已启用但无响应时刷新注册并等待重新就绪（不会注销、不影响已有批准）
    const force = currentMacosServiceStatus?.enabled ?? false;
    const status = await installMacosService(force);
    renderMacosServiceStatus(status);
    if (status.state === "requires_approval") {
      showMessage(t("请在“系统设置 → 通用 → 登录项与扩展”中批准 DnsBlackhole 后台服务"), false);
      // 直接带用户到批准页面，避免在设置里找不到入口
      await openMacosServiceSettings();
    } else if (status.enabled && !status.needsRepair) {
      showMessage(t("macOS DNS 后台服务已启用"), false);
      await refreshAfterBackgroundServiceEnabled();
    } else if (status.needsRepair) {
      showMessage(
        t("后台服务已注册但暂未响应，请稍后重新进入本页检查；若持续无响应请重启 Mac 后再试"),
        true,
      );
    }
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    installMacosServiceButton.disabled = false;
    installMacosServiceButton.classList.remove("loading");
  }
});

uninstallMacosServiceButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("卸载后台服务后，DNS 将无法监听 53 端口，局域网设备的 DNS 查询会立即失败。是否继续卸载？"),
  );
  if (!confirmed) {
    return;
  }
  uninstallMacosServiceButton.disabled = true;
  uninstallMacosServiceButton.classList.add("loading");
  try {
    const status = await uninstallMacosService();
    renderMacosServiceStatus(status);
    showMessage(t("macOS DNS 后台服务已卸载"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    uninstallMacosServiceButton.disabled = false;
    uninstallMacosServiceButton.classList.remove("loading");
  }
});

openMacosServiceSettingsButton.addEventListener("click", async () => {
  try {
    await openMacosServiceSettings();
  } catch (error) {
    showMessage(String(error), true);
  }
});

clearQueryLogsButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("这会永久删除全部查询日志，但不会删除统计数据和配置。清除后，新查询仍会继续记录。是否继续？"),
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  clearQueryLogsButton.classList.add("loading");
  try {
    const status = await clearQueryLogsCommand();
    renderStatus(status);
    resetQueryLogPagination();
    await refreshQueryLogs();
    await loadStorageInfo();
    showMessage(t("查询日志已清除，统计数据未受影响"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    clearQueryLogsButton.classList.remove("loading");
    setBusy(false);
  }
});

clearStatisticsButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("这会永久删除全部累计统计、趋势和排行，但不会删除查询日志和配置。清除后将从新的 DNS 查询重新统计。是否继续？"),
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  clearStatisticsButton.classList.add("loading");
  try {
    const status = await clearStatisticsCommand();
    renderStatus(status);
    await loadStorageInfo();
    showMessage(t("统计数据已清除，查询日志未受影响"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    clearStatisticsButton.classList.remove("loading");
    setBusy(false);
  }
});

// 主题在模板渲染后立刻落定，并把当前偏好回填到下拉框。
applyTheme();
themePreferenceInput.value = getThemePreference();
syncCustomSelect(themePreferenceInput);
themePreferenceInput.addEventListener("change", () => {
  setThemePreference(themePreferenceInput.value as ThemePreference);
});
watchSystemTheme();

// 语言在模板渲染时就已生效，这里只回填当前选择并处理切换。
languagePreferenceInput.value = getLocalePreference();
syncCustomSelect(languagePreferenceInput);
// 托盘菜单在后端创建，界面就绪后把当前语言同步过去。
void setTrayLocale(getLocale()).catch((error: unknown) => {
  console.warn("同步托盘语言失败", error);
});
languagePreferenceInput.addEventListener("change", () => {
  setLocalePreference(languagePreferenceInput.value as LocalePreference, () => {
    rememberViewAcrossReload(activeView);
  });
});

clearSecurityEventsButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("这会永久删除已落盘的全部安全事件历史，但不会影响统计数据和查询日志。是否继续？"),
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  clearSecurityEventsButton.classList.add("loading");
  try {
    const status = await clearSecurityEventsCommand();
    renderStatus(status);
    showMessage(t("安全事件已清除"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    clearSecurityEventsButton.classList.remove("loading");
    setBusy(false);
  }
});

installWindowsServiceButton.addEventListener("click", async () => {
  installWindowsServiceButton.disabled = true;
  installWindowsServiceButton.classList.add("loading");
  try {
    let status = requireWindowsServiceStatus(await installWindowsService());
    renderWindowsServiceStatus(status);
    if (shouldWaitForWindowsService(status)) {
      status = (await waitForWindowsServiceReady(status)) ?? status;
    }
    if (status.ready) {
      showMessage(t("Windows DNS 系统服务已安装并启动"), false);
      await refreshAfterBackgroundServiceEnabled();
    } else {
      showMessage(t("系统服务已注册但暂未就绪，请稍候重试；详情可查看服务日志"), true);
    }
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    installWindowsServiceButton.disabled = false;
    installWindowsServiceButton.classList.remove("loading");
  }
});

uninstallWindowsServiceButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    t("卸载 Windows DNS 系统服务后，127.0.0.1/::1 将不再提供 DNS；若系统 DNS 已接管，会先自动恢复原 DNS。是否继续？"),
  );
  if (!confirmed) {
    return;
  }
  uninstallWindowsServiceButton.disabled = true;
  uninstallWindowsServiceButton.classList.add("loading");
  try {
    const status = requireWindowsServiceStatus(await uninstallWindowsService());
    renderWindowsServiceStatus(status);
    currentWindowsSystemDnsStatus = null;
    showMessage(t("Windows DNS 系统服务已卸载，原 DNS 已恢复，数据和配置未删除"), false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    uninstallWindowsServiceButton.disabled = false;
    uninstallWindowsServiceButton.classList.remove("loading");
  }
});

takeOverWindowsSystemDnsButton.addEventListener("click", async () => {
  const synchronizing = currentWindowsSystemDnsStatus?.managed === true;
  const confirmed = window.confirm(
    synchronizing
      ? t("同步后，当前活动的有线或无线网卡会使用 127.0.0.1 和 ::1。每张网卡现有的自动获取或手动 DNS 都会分别保存；已在 Windows 中改过的配置会作为新的恢复配置。是否继续？")
      : t("接管后，当前已连接的物理网卡将只使用 127.0.0.1 和 ::1 作为 DNS，不设置公共备用 DNS。每张网卡的原 DNS（包括自动获取）会先分别保存，可随时恢复。是否继续？"),
  );
  if (!confirmed) {
    return;
  }
  setWindowsSystemDnsBusy(true);
  try {
    const status = requireWindowsSystemDnsStatus(await takeOverWindowsSystemDns());
    renderWindowsSystemDnsStatus(status);
    showMessage(
      status.inEffect
        ? synchronizing
          ? t("当前活动网卡已同步接管")
          : t("系统 DNS 已接管，所有 DNS 查询将交给 DnsBlackhole")
        : t("系统 DNS 备份已保存，但接管状态需要检查"),
      !status.inEffect,
    );
  } catch (error) {
    showMessage(String(error), true);
    await loadWindowsSystemDnsStatus();
  } finally {
    setWindowsSystemDnsBusy(false);
  }
});

restoreWindowsSystemDnsButton.addEventListener("click", async () => {
  const statusBeforeAction = currentWindowsSystemDnsStatus;
  if (!statusBeforeAction) {
    return;
  }
  if (statusBeforeAction.managed || statusBeforeAction.inEffect) {
    showDnsFallbackDialog();
  }
});

dnsFallbackDialogCloseButton.addEventListener("click", closeDnsFallbackDialog);
dnsFallbackDialogCancelButton.addEventListener("click", closeDnsFallbackDialog);
dnsFallbackDialog.addEventListener("click", (event) => {
  if (event.target === dnsFallbackDialog) {
    closeDnsFallbackDialog();
  }
});
for (const input of [dnsCustomIpv4Input, dnsCustomIpv6Input]) {
  input.addEventListener("focus", () => {
    const customRadio = dnsFallbackCustomOption.querySelector<HTMLInputElement>(
      'input[type="radio"]',
    );
    if (customRadio) {
      customRadio.checked = true;
    }
  });
}
dnsFallbackDialogConfirmButton.addEventListener("click", async () => {
  const selection = dnsFallbackInputs.find((input) => input.checked)?.value ?? "dns114";
  const ipv4Servers = parseDnsServerInput(dnsCustomIpv4Input.value);
  const ipv6Servers = parseDnsServerInput(dnsCustomIpv6Input.value);
  if (selection === "custom" && ipv4Servers.length === 0 && ipv6Servers.length === 0) {
    showMessage(t("请至少填写一个自定义 DNS 服务器地址"), true);
    dnsCustomIpv4Input.focus();
    return;
  }
  const restoringManagedDns = currentWindowsSystemDnsStatus?.managed === true;
  setWindowsSystemDnsBusy(true);
  dnsFallbackDialogConfirmButton.disabled = true;
  dnsFallbackDialogConfirmButton.classList.add("loading");
  try {
    const result = restoringManagedDns
      ? selection === "original"
        ? await restoreWindowsSystemDns()
        : await restoreWindowsSystemDnsWithFallback({
            preset: selection as WindowsSystemDnsFallback,
            ipv4Servers,
            ipv6Servers,
          })
      : await replaceUnmanagedWindowsSystemDns({
          preset: selection as WindowsSystemDnsFallback,
          ipv4Servers,
          ipv6Servers,
        });
    const status = requireWindowsSystemDnsStatus(result);
    renderWindowsSystemDnsStatus(status);
    closeDnsFallbackDialog();
    showMessage(
      restoringManagedDns
        ? selection === "original"
          ? t("已恢复仍由 DnsBlackhole 接管的 DNS；在 Windows 中另行修改的配置保持不变")
          : t("已恢复为所选外部 DNS")
        : t("已解除本机 DNS，现在可以重新接管并保存该恢复配置"),
      false,
    );
  } catch (error) {
    showMessage(String(error), true);
    await loadWindowsSystemDnsStatus();
  } finally {
    dnsFallbackDialogConfirmButton.disabled = false;
    dnsFallbackDialogConfirmButton.classList.remove("loading");
    setWindowsSystemDnsBusy(false);
  }
});

filtersBody.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }

  const row = target.closest<HTMLElement>("[data-id]");
  if (!row) {
    return;
  }

  updateFilterField(row.dataset.id ?? "", target);
});

filtersBody.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }

  const row = target.closest<HTMLElement>("[data-id]");
  if (!row) {
    return;
  }

  updateFilterField(row.dataset.id ?? "", target);
});

filtersBody.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) {
    return;
  }

  const row = target.closest<HTMLElement>("[data-id]");
  if (!row) {
    return;
  }

  const id = row.dataset.id ?? "";
  if (target.dataset.action === "remove") {
    filtersState = filtersState.filter((filter) => filter.id !== id);
    editingFilterIds.delete(id);
    renderFilters();
    updateConfigDirtyState();
  }
  if (target.dataset.action === "edit") {
    editingFilterIds = toggleEditing(editingFilterIds, id);
    renderFilters();
  }
});

async function bootstrapApplication(): Promise<void> {
  void getVersion().then((version) => {
    appVersionElement.textContent = version;
    aboutRuntimeAppVersionElement.textContent = `v${version}`;
  });
  const systemProxyReady = loadDetectedSystemProxy();

  const serviceStatusStarted = performance.now();
  let [initialWindowsServiceStatus] = await Promise.all([
    loadWindowsServiceStatus(),
    loadMacosServiceStatus(),
  ]);
  if (isWindows && shouldWaitForWindowsService(initialWindowsServiceStatus)) {
    initialWindowsServiceStatus = await waitForWindowsServiceReady(initialWindowsServiceStatus);
  }
  logLoadTime(
    "后台服务就绪检查",
    serviceStatusStarted,
    isWindows ? `ready=${initialWindowsServiceStatus?.ready ?? false}` : "非 Windows 平台",
  );
  const windowsCoreReady = !isWindows || (initialWindowsServiceStatus?.ready ?? false);
  const initialDataStarted = performance.now();
  const [configReady] = windowsCoreReady
    ? await Promise.all([loadConfig(), loadStorageInfo()])
    : [false];
  await systemProxyReady;
  updateFilterProxyControls();
  logLoadTime("初始配置与存储信息", initialDataStarted, `configReady=${configReady}`);
  // 语言切换重载后接着看原来的页面；核心没就绪时仍然强制落在设置页。
  let initialView = viewAfterReload ?? activeView;
  if (!windowsCoreReady && !configReady) {
    initialView = "settings";
  }
  void listen<FilterSubscription[]>("filters-updated", ({ payload }) => {
    syncFilterUpdateMetadata(payload);
  }).catch((error) => {
    console.error("监听过滤器更新失败", error);
  });
  void listen<string>("tray-protection-action", ({ payload }) => {
    if (payload === "resume") {
      void runProtectionAction("resume");
      return;
    }
    const durations: Record<string, number> = {
      pause_5m: 300,
      pause_30m: 1800,
      pause_1h: 3600,
    };
    const duration = durations[payload];
    if (duration) {
      void runProtectionAction("pause", duration);
    }
  }).catch((error) => {
    console.error("监听托盘过滤控制失败", error);
  });
  if (configReady) {
    await refreshStatus();
  }
  const initialViewStarted = performance.now();
  setActiveView(initialView);
  logLoadTime("初始页面切换与渲染", initialViewStarted, `view=${initialView}`);
  initialBootstrapComplete = true;
  logLoadTime("前端启动总计", frontendStartedAt);

  startBackgroundRefresh();
}

async function loadDetectedSystemProxy(): Promise<void> {
  try {
    detectedSystemProxy = await detectSystemProxy();
  } catch (error) {
    detectedSystemProxy = null;
    console.warn("检测当前用户系统代理失败", error);
  }
}

function startBackgroundRefresh(): void {
  window.setInterval(() => {
    // 窗口不可见（最小化 / 切到托盘）时跳过轮询，避免无谓的 IPC 与重渲染
    if (document.hidden) {
      return;
    }
    refreshActiveView();
  }, BACKGROUND_REFRESH_INTERVAL_MS);

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      return;
    }
    refreshActiveView();
    // 用户可能刚从系统设置批准完服务回来，仅在配置页重新同步一次运行状态。
    if (activeView === "settings") {
      void refreshSettingsRuntimeStatus();
    }
  });
}

function refreshActiveView(): void {
  if (activeView !== "logs" && activeView !== "dashboard") {
    return;
  }
  if (isContentScrolling) {
    queuedAutoRefresh = true;
    return;
  }
  if (activeView === "logs") {
    if (shouldAutoRefreshQueryLogs()) {
      void refreshQueryLogs({ auto: true });
    }
  } else if (activeView === "dashboard") {
    if (shouldAutoRefreshDashboard()) {
      void refreshStatus({ auto: true });
    }
  }
}

function shouldAutoRefreshQueryLogs(): boolean {
  const query = collectQueryLogQuery();
  return (
    !queryLogLivePaused &&
    queryLogPage === 1 &&
    query.filter === DEFAULT_QUERY_LOG_QUERY.filter &&
    query.search === DEFAULT_QUERY_LOG_QUERY.search &&
    activeAdvancedQueryFilterCount(query) === 0 &&
    !queryLogSearchComposition.composing
  );
}

function shouldAutoRefreshDashboard(): boolean {
  return (
    lastDashboardRefreshAt === null ||
    performance.now() - lastDashboardRefreshAt >= DASHBOARD_AUTO_REFRESH_INTERVAL_MS
  );
}

async function loadConfig(): Promise<boolean> {
  const started = performance.now();
  let succeeded = false;
  try {
    const config = await getConfig();
    if (!config || typeof config.schema_version !== "number") {
      throw new Error(t("DNS 服务返回了空配置或配置格式无效"));
    }
    currentConfigSchemaVersion = Math.max(config.schema_version, CURRENT_CONFIG_SCHEMA_VERSION);
    currentStatisticsRetentionHours = config.statistics_retention_hours;
    currentQueryLogRetentionHours = config.query_log_retention_hours;
    updateDashboardRangeOptions();
    enabledInput.checked = config.enabled;
    launchAtStartupInput.checked = config.launch_at_startup;
    useFiltersInput.checked = config.use_filters;
    upstreamInput.value = config.upstream_dns;
    fallbackInput.value = config.fallback_dns;
    bootstrapInput.value = config.bootstrap_dns;
    domainUpstreamRulesInput.value = config.domain_upstream_rules;
    clientUpstreamRulesInput.value = config.client_upstream_rules;
    dnssecEnabledInput.checked = config.dnssec_enabled;
    listenHostInput.value = config.listen_host;
    listenPortInput.value = String(config.listen_port);
    listenIpv6Input.checked = config.listen_ipv6;
    allowedClientsInput.value = config.allowed_clients;
    blockedClientsInput.value = config.blocked_clients;
    clientFilteringRulesInput.value = config.client_filtering_rules;
    clientPolicyGroupsInput.value = config.client_policy_groups;
    familySafeSearchInput.checked = config.family_safe_search;
    familyBlockedServicesInput.value = config.family_blocked_services;
    rateLimitPerSecondInput.value = String(config.rate_limit_per_second);
    refuseAnyInput.checked = config.refuse_any;
    filterUpdateIntervalInput.value = String(config.filter_update_interval_hours);
    filterMaxSizeInput.value = String(config.filter_max_size_mb);
    filterProxyModeInput.value = config.filter_proxy_mode;
    syncCustomSelect(filterUpdateIntervalInput);
    syncCustomSelect(filterProxyModeInput);
    filterProxyUrlInput.value = config.filter_proxy_url;
    savedSystemProxyUrl = config.filter_system_proxy_url;
    allowInsecureHttpInput.checked = config.allow_insecure_http;
    setRadioValue(upstreamModeInputs, config.upstream_mode);
    queryLogEnabledInput.checked = config.query_log_enabled;
    anonymizeClientIpInput.checked = config.anonymize_client_ip;
    setRetentionValue(config.query_log_retention_hours);
    statisticsEnabledInput.checked = config.statistics_enabled;
    setStatisticsRetentionValue(config.statistics_retention_hours);
    setSecurityEventRetentionValue(config.security_event_retention_hours);
    systemHostsEnabledInput.checked = config.system_hosts_enabled;
    dnsCacheEnabledInput.checked = config.dns_cache_enabled;
    dnsCacheSizeInput.value = String(config.dns_cache_size);
    dnsCacheMinTtlInput.value = String(config.dns_cache_min_ttl);
    dnsCacheMaxTtlInput.value = String(config.dns_cache_max_ttl);
    dnsCacheOptimisticInput.checked = config.dns_cache_optimistic;
    dnsCacheOptimisticMaxStaleInput.value = String(
      config.dns_cache_optimistic_max_stale_seconds,
    );
    dnsCachePrefetchEnabledInput.checked = config.dns_cache_prefetch_enabled;
    dnsCachePrefetchHitThresholdInput.value = String(config.dns_cache_prefetch_hit_threshold);
    runtimeWatchdogEnabledInput.checked = config.runtime_watchdog_enabled;
    runtimeWatchdogIntervalInput.value = String(config.runtime_watchdog_interval_seconds);
    monitoringApiEnabledInput.checked = config.monitoring_api_enabled;
    monitoringApiListenHostInput.value = config.monitoring_api_listen_host;
    monitoringApiPortInput.value = String(config.monitoring_api_port);
    monitoringApiTokenInput.value = config.monitoring_api_token;
    setRadioValue(blockingModeInputs, config.blocking_mode);
    blockingResponseTtlInput.value = String(config.blocking_response_ttl);
    blockingCustomIpv4Input.value = config.blocking_custom_ipv4;
    blockingCustomIpv6Input.value = config.blocking_custom_ipv6;
    rebindingProtectionEnabledInput.checked = config.rebinding_protection_enabled;
    rebindingAllowedDomainsInput.value = config.rebinding_allowed_domains;
    cnameCloakingEnabledInput.checked = config.cname_cloaking_enabled;
    privateReverseDnsEnabledInput.checked = config.private_reverse_dns_enabled;
    dnsRewritesInput.value = config.dns_rewrites;
    clientNamesInput.value = config.client_names;
    queryLogIgnoredInput.value = config.query_log_ignored_domains;
    statisticsIgnoredInput.value = config.statistics_ignored_domains;
    clientNameMap = parseClientNames(config.client_names);
    currentQueryLogEnabled = config.query_log_enabled;
    updateLogControls();
    updateStatisticsControls();
    renderDashboardSummaryWindow();
    updateFilterProxyControls();
    updateDnsCacheControls();
    updateResponseProtectionControls();
    updateRuntimeWatchdogControls();
    updateMonitoringApiControls();
    updateBlockingModeControls();
    blacklistInput.value = config.blacklist;
    ruleEditor.refresh();
    filtersState = config.filters;
    renderFilters();
    configLoaded = true;
    savedConfigFingerprint = configFingerprint(collectConfig());
    configDirty = false;
    updateConfigSaveState();
    succeeded = true;
    return true;
  } catch (error) {
    configLoaded = false;
    savedConfigFingerprint = "";
    configDirty = false;
    updateConfigSaveState();
    showMessage(String(error), true);
    return false;
  } finally {
    logLoadTime("设置配置加载与渲染", started, `success=${succeeded}`);
  }
}

async function loadStorageInfo(): Promise<void> {
  const started = performance.now();
  let succeeded = false;
  try {
    currentStorageInfo = await getStorageInfo();
    selectedDataStoragePath = currentStorageInfo.pending_path ?? currentStorageInfo.current_path;
    selectedStorageTarget = null;
    storageSelectionError = "";
    renderStorageInfo(currentStorageInfo);
    if (currentStorageInfo.pending_path) {
      await selectDataStoragePath(currentStorageInfo.pending_path);
    }
    succeeded = true;
  } catch (error) {
    dataStorageError.textContent = String(error);
    dataStorageError.classList.remove("hidden");
  } finally {
    logLoadTime("存储信息加载与渲染", started, `success=${succeeded}`);
  }
}

const MACOS_SERVICE_STATE_TEXT: Record<MacosServiceState, string> = {
  not_registered: t("后台服务尚未安装。安装并授权后，DNS 才能监听 53 端口。"),
  enabled: t("后台服务已启用，DNS 可以监听 53 端口。"),
  requires_approval: t("等待批准：请在“系统设置 → 通用 → 登录项与扩展”中允许 DnsBlackhole。"),
  not_found: t("未找到后台服务，可能已被系统移除，请重新安装。"),
  unknown: t("后台服务状态未知，可尝试“安装或修复”。"),
};

async function refreshSettingsRuntimeStatus(): Promise<void> {
  const [, windowsStatus] = await Promise.all([
    loadMacosServiceStatus(),
    loadWindowsServiceStatus(),
  ]);
  if (windowsStatus?.ready) {
    await loadWindowsSystemDnsStatus();
  }
}

async function loadMacosServiceStatus(): Promise<void> {
  if (!isMacOS) {
    return;
  }
  macosServiceSection.classList.remove("hidden");
  try {
    // “就绪”要求服务已启用且探测到响应；needsRepair 期间视为未就绪，
    // 恢复响应后重新加载依赖后台服务的数据
    const wasReady =
      (currentMacosServiceStatus?.enabled ?? false) &&
      !(currentMacosServiceStatus?.needsRepair ?? false);
    const status = await getMacosServiceStatus();
    renderMacosServiceStatus(status);
    if (
      initialBootstrapComplete &&
      status.enabled &&
      !status.needsRepair &&
      !wasReady
    ) {
      await refreshAfterBackgroundServiceEnabled();
    }
  } catch (error) {
    currentMacosServiceStatus = null;
    macosServiceStatusElement.textContent = t("读取后台服务状态失败：{p0}", { p0: String(error) });
  }
}

async function refreshAfterBackgroundServiceEnabled(): Promise<void> {
  if (backgroundServiceRefreshInFlight) {
    return;
  }
  backgroundServiceRefreshInFlight = true;
  try {
    const [configReady] = await Promise.all([
      loadConfig(),
      loadStorageInfo(),
      loadWindowsSystemDnsStatus(),
    ]);
    if (configReady) {
      await refreshStatus();
    }
  } finally {
    backgroundServiceRefreshInFlight = false;
  }
}

function renderMacosServiceStatus(status: MacosServiceStatus): void {
  currentMacosServiceStatus = status;
  macosServiceSection.classList.toggle("is-ready", status.enabled);
  macosServiceSection.classList.toggle("needs-approval", status.requiresApproval);
  const stateText =
    MACOS_SERVICE_STATE_TEXT[status.state] ?? MACOS_SERVICE_STATE_TEXT.unknown;
  const versionText =
    status.enabled && status.serviceVersion
      ? t(" 当前服务版本 v{p0}。", { p0: status.serviceVersion })
      : "";
  macosServiceStatusElement.textContent = status.needsRepair
    ? t("后台服务已启用但暂未响应，可稍后重新进入本页检查；持续无响应时点击“安装或修复”。")
    : `${stateText}${versionText}`;
  openMacosServiceSettingsButton.classList.toggle("hidden", !status.requiresApproval);
  uninstallMacosServiceButton.disabled =
    status.state === "not_registered" || status.state === "not_found";
  renderAboutRuntimeInfo();
}

const WINDOWS_SERVICE_STATE_TEXT: Record<WindowsServiceState, string> = {
  not_installed: t("系统服务尚未安装，DNS 核心无法在开机阶段自动启动。"),
  stopped: t("系统服务已停止，可点击“安装或修复”恢复。"),
  start_pending: t("系统服务正在启动，请稍候…"),
  stop_pending: t("系统服务正在停止，请稍候…"),
  running: t("系统服务正在运行，DNS 核心不依赖 GUI。"),
  continue_pending: t("系统服务正在恢复运行，请稍候…"),
  pause_pending: t("系统服务正在暂停，请稍候…"),
  paused: t("系统服务已暂停，可点击“安装或修复”恢复。"),
};

async function loadWindowsServiceStatus(): Promise<WindowsServiceStatus | null> {
  if (!isWindows) {
    return null;
  }
  if (windowsServiceStatusInFlight) {
    return windowsServiceStatusInFlight;
  }
  const started = performance.now();
  let loadDetail = t("无有效状态");
  windowsServiceSection.classList.remove("hidden");
  const request = (async (): Promise<WindowsServiceStatus | null> => {
    let rawStatus: WindowsServiceStatus;
    try {
      rawStatus = await getWindowsServiceStatus();
    } catch (error) {
      loadDetail = `IPC error=${String(error)}`;
      const now = Date.now();
      windowsServiceUnavailableSince ??= now;
      windowsServiceSection.classList.remove("is-ready");
      const persistent = now - windowsServiceUnavailableSince >= WINDOWS_SERVICE_ERROR_GRACE_MS;
      windowsServiceSection.classList.toggle("needs-repair", persistent);
      windowsServiceStatusElement.textContent = persistent
        ? t("连续读取 Windows 系统服务状态失败：{p0}", { p0: String(error) })
        : t("正在等待 Windows 系统服务响应…");
      return null;
    }

    const wasReady = currentWindowsServiceStatus?.ready ?? false;
    loadDetail = `rawState=${rawStatus.state}, rawReady=${rawStatus.ready}, rawIpcReady=${rawStatus.ipcReady}`;
    const status = requireWindowsServiceStatus(rawStatus);
    renderWindowsServiceStatus(status);
    loadDetail = `state=${status.state}, ready=${status.ready}, ipcReady=${status.ipcReady}, needsRepair=${status.needsRepair}, diagnostic=${status.diagnostic}`;
    if (initialBootstrapComplete && status.ready && !wasReady) {
      await refreshAfterBackgroundServiceEnabled();
    }
    return status;
  })();
  windowsServiceStatusInFlight = request;
  try {
    return await request;
  } finally {
    windowsServiceStatusInFlight = null;
    logLoadTime(
      "Windows 服务状态加载",
      started,
      loadDetail,
    );
  }
}

function renderWindowsServiceStatus(status: WindowsServiceStatus): void {
  currentWindowsServiceStatus = status;
  const now = Date.now();
  if (status.ready || !status.running || status.ipcReady) {
    windowsServiceUnavailableSince = null;
  } else {
    windowsServiceUnavailableSince ??= now;
  }
  const ipcFailurePersistent =
    status.running &&
    !status.ipcReady &&
    windowsServiceUnavailableSince !== null &&
    now - windowsServiceUnavailableSince >= WINDOWS_SERVICE_ERROR_GRACE_MS;
  const showRepair = status.needsRepair || ipcFailurePersistent;
  windowsServiceSection.classList.toggle("is-ready", status.ready);
  windowsServiceSection.classList.toggle("needs-repair", showRepair);
  const stateText = WINDOWS_SERVICE_STATE_TEXT[status.state];
  const versionText = status.serviceVersion ? t(" 当前服务版本 v{p0}。", { p0: status.serviceVersion }) : "";
  if (status.ready) {
    windowsServiceStatusElement.textContent = `${stateText}${versionText}`;
  } else if (status.running && status.ipcReady && status.needsRepair) {
    windowsServiceStatusElement.textContent = t("系统服务版本不一致（当前 {p0}，需要 {p1}），请点击“安装或修复”。", { p0: status.serviceVersion ?? t("未知"), p1: status.expectedVersion });
  } else if (status.running && ipcFailurePersistent) {
    windowsServiceStatusElement.textContent = t("系统服务已运行，但 IPC 连续无响应，请点击“安装或修复”。");
  } else if (status.running && !status.ipcReady) {
    windowsServiceStatusElement.textContent = t("系统服务正在完成启动并建立通信，请稍候…");
  } else {
    windowsServiceStatusElement.textContent = `${stateText}${versionText}`;
  }
  uninstallWindowsServiceButton.disabled = !status.installed;
  if (!status.ready) {
    renderWindowsSystemDnsUnavailable(t("请先安装并启动 Windows DNS 系统服务"));
  }
  renderAboutRuntimeInfo();
}

async function loadWindowsSystemDnsStatus(): Promise<WindowsSystemDnsStatus | null> {
  if (!isWindows) {
    return null;
  }
  windowsSystemDnsSection.classList.remove("hidden");
  if (!currentWindowsServiceStatus?.ready) {
    renderWindowsSystemDnsUnavailable(t("请先安装并启动 Windows DNS 系统服务"));
    return null;
  }
  if (windowsSystemDnsStatusInFlight) {
    return windowsSystemDnsStatusInFlight;
  }
  const request = (async (): Promise<WindowsSystemDnsStatus | null> => {
    try {
      const status = requireWindowsSystemDnsStatus(await getWindowsSystemDnsStatus());
      renderWindowsSystemDnsStatus(status);
      return status;
    } catch (error) {
      windowsSystemDnsSection.classList.remove("is-ready");
      windowsSystemDnsSection.classList.add("needs-repair");
      windowsSystemDnsStatusElement.textContent = t("读取系统 DNS 状态失败：{p0}", { p0: String(error) });
      takeOverWindowsSystemDnsButton.disabled = true;
      restoreWindowsSystemDnsButton.disabled = true;
      return null;
    }
  })();
  windowsSystemDnsStatusInFlight = request;
  try {
    return await request;
  } finally {
    windowsSystemDnsStatusInFlight = null;
  }
}

function renderWindowsSystemDnsStatus(status: WindowsSystemDnsStatus): void {
  currentWindowsSystemDnsStatus = status;
  windowsSystemDnsSection.classList.remove("hidden");
  windowsSystemDnsSection.classList.toggle("is-ready", status.managed && status.inEffect);
  windowsSystemDnsSection.classList.toggle(
    "needs-repair",
    (status.managed && !status.inEffect) || (!status.managed && status.inEffect),
  );
  const activeAdapterNames = status.activeAdapters.map((adapter) => adapter.name).join(t("、"));
  const activeDnsText = formatActiveDnsAdapters(status);
  const backupDnsText = formatBackupDnsAdapters(status);
  if (status.managed && status.inEffect) {
    windowsSystemDnsStatusElement.textContent = t("已接管当前活动网卡：{p0}。", { p0: activeAdapterNames });
    windowsSystemDnsDetailElement.textContent = t("当前 DNS 均指向 127.0.0.1 / ::1。接管前配置：{p0}。", { p0: backupDnsText });
  } else if (status.managed) {
    windowsSystemDnsStatusElement.textContent = status.activeAdapters.length > 0
      ? t("当前活动网卡尚未全部接管：{p0}。", { p0: activeAdapterNames })
      : t("已保留 DNS 接管备份，但当前没有活动的物理网卡。");
    windowsSystemDnsDetailElement.textContent = t("当前配置：{p0}。历史恢复配置：{p1}。可同步接管当前网卡，或选择恢复方式。", { p0: activeDnsText, p1: backupDnsText });
  } else if (status.inEffect) {
    const localAdapters = status.activeAdapters
      .filter((adapter) => adapter.usesLocalDns)
      .map((adapter) => adapter.name)
      .join(t("、"));
    windowsSystemDnsStatusElement.textContent = t("检测到 {p0} 使用本机 DNS，但没有原配置备份。", { p0: localAdapters });
    windowsSystemDnsDetailElement.textContent = t("当前配置：{p0}。请选择自动获取、公共 DNS 或自定义 DNS 来解除。", { p0: activeDnsText });
  } else {
    windowsSystemDnsStatusElement.textContent = status.activeAdapters.length > 0
      ? t("尚未接管，当前活动网卡：{p0}。", { p0: activeAdapterNames })
      : t("尚未接管，当前未检测到已连接的物理网卡。");
    windowsSystemDnsDetailElement.textContent = status.activeAdapters.length > 0
      ? t("当前配置：{p0}。接管时会按网卡分别保存这些设置。", { p0: activeDnsText })
      : t("连接有线或无线网络后，可将其 DNS 指向 DnsBlackhole。");
  }
  const canReplaceUnmanagedLocalDns = !status.managed && status.inEffect;
  restoreWindowsSystemDnsButton.textContent = canReplaceUnmanagedLocalDns
    ? t("解除本机 DNS")
    : t("恢复 DNS");
  takeOverWindowsSystemDnsButton.textContent = status.managed
    ? status.inEffect
      ? t("已接管")
      : t("同步接管")
    : t("接管 DNS");
  updateWindowsSystemDnsButtons();
}

function renderWindowsSystemDnsUnavailable(message: string): void {
  if (!isWindows) {
    return;
  }
  windowsSystemDnsSection.classList.remove("hidden", "is-ready", "needs-repair");
  windowsSystemDnsStatusElement.textContent = message;
  windowsSystemDnsDetailElement.textContent = t("系统服务就绪后会读取当前活动网卡及每张网卡的 DNS 恢复配置。");
  takeOverWindowsSystemDnsButton.disabled = true;
  restoreWindowsSystemDnsButton.disabled = true;
}

function setWindowsSystemDnsBusy(busy: boolean): void {
  takeOverWindowsSystemDnsButton.classList.toggle("loading", busy);
  restoreWindowsSystemDnsButton.classList.toggle("loading", busy);
  if (busy) {
    takeOverWindowsSystemDnsButton.disabled = true;
    restoreWindowsSystemDnsButton.disabled = true;
    return;
  }
  updateWindowsSystemDnsButtons();
}

function updateWindowsSystemDnsButtons(): void {
  const status = currentWindowsSystemDnsStatus;
  const ready = currentWindowsServiceStatus?.ready === true;
  const hasUnbackedLocalDns = status?.activeAdapters.some(
    (adapter) => !adapter.backedUp && adapter.usesLocalDns,
  );
  takeOverWindowsSystemDnsButton.disabled =
    !ready ||
    !status ||
    status.activeAdapters.length === 0 ||
    status.inEffect ||
    hasUnbackedLocalDns === true;
  restoreWindowsSystemDnsButton.disabled =
    !ready || !status || (!status.managed && !status.inEffect);
}

function showDnsFallbackDialog(): void {
  const restoringManagedDns = currentWindowsSystemDnsStatus?.managed === true;
  dnsRestoreOriginalOption.classList.toggle("hidden", !restoringManagedDns);
  dnsFallbackDialogTitle.textContent = restoringManagedDns ? t("选择恢复后的 DNS") : t("解除本机 DNS");
  dnsFallbackDialogIntro.textContent = restoringManagedDns
    ? t("“按接管前配置恢复”只还原仍指向本机 DNS 的部分，保留你后来在 Windows 中做的修改；选择其他方式则会将历史备份中的网卡设置为所选 DNS。")
    : t("当前没有原 DNS 备份，请选择解除后使用的 DNS。只会修改仍指向 127.0.0.1 或 ::1 的设置。");
  dnsRestoreOriginalDetail.textContent = currentWindowsSystemDnsStatus
    ? formatBackupDnsAdapters(currentWindowsSystemDnsStatus)
    : t("保留接管前的自动获取或手动 DNS 设置");
  dnsFallbackDialogConfirmButton.textContent = restoringManagedDns ? t("确认恢复") : t("确认解除");
  const recommended = dnsFallbackInputs.find((input) =>
    restoringManagedDns ? input.value === "original" : input.value === "automatic",
  );
  if (recommended) {
    recommended.checked = true;
  }
  if (!dnsFallbackDialog.open) {
    dnsFallbackDialog.showModal();
  }
}

function parseDnsServerInput(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((server) => server.trim())
    .filter(Boolean);
}

function formatDnsServers(servers: string[] | null): string {
  return servers && servers.length > 0 ? servers.join(" / ") : t("自动获取");
}

function formatActiveDnsAdapters(status: WindowsSystemDnsStatus): string {
  if (status.activeAdapters.length === 0) {
    return t("无活动物理网卡");
  }
  return status.activeAdapters
    .map(
      (adapter) =>
        t("{p0}（IPv4 {p1}，IPv6 {p2}）", { p0: adapter.name, p1: formatDnsServers(adapter.ipv4Servers), p2: formatDnsServers(adapter.ipv6Servers) }),
    )
    .join(t("；"));
}

function formatBackupDnsAdapters(status: WindowsSystemDnsStatus): string {
  if (status.backupAdapters.length === 0) {
    return t("无历史备份");
  }
  return status.backupAdapters
    .map(
      (adapter) =>
        t("{p0}（IPv4 {p1}，IPv6 {p2}）", { p0: adapter.name, p1: formatDnsServers(adapter.ipv4Servers), p2: formatDnsServers(adapter.ipv6Servers) }),
    )
    .join(t("；"));
}

function closeDnsFallbackDialog(): void {
  if (dnsFallbackDialog.open) {
    dnsFallbackDialog.close();
  }
}

function requireWindowsSystemDnsStatus(value: unknown): WindowsSystemDnsStatus {
  if (!value || typeof value !== "object") {
    throw new Error(t("Windows 系统 DNS 状态接口返回了空结果"));
  }
  const status = value as Partial<WindowsSystemDnsStatus>;
  if (
    typeof status.managed !== "boolean" ||
    typeof status.inEffect !== "boolean" ||
    !Array.isArray(status.adapters) ||
    status.adapters.some((adapter) => typeof adapter !== "string") ||
    !Array.isArray(status.activeAdapters) ||
    status.activeAdapters.some(
      (adapter) =>
        !adapter ||
        typeof adapter !== "object" ||
        typeof adapter.name !== "string" ||
        !isDnsServerList(adapter.ipv4Servers) ||
        !isDnsServerList(adapter.ipv6Servers) ||
        typeof adapter.backedUp !== "boolean" ||
        typeof adapter.inEffect !== "boolean" ||
        typeof adapter.usesLocalDns !== "boolean",
    ) ||
    !Array.isArray(status.backupAdapters) ||
    status.backupAdapters.some(
      (adapter) =>
        !adapter ||
        typeof adapter !== "object" ||
        typeof adapter.name !== "string" ||
        !isDnsServerList(adapter.ipv4Servers) ||
        !isDnsServerList(adapter.ipv6Servers),
    ) ||
    typeof status.restoreIpv4Automatic !== "boolean"
  ) {
    throw new Error(t("Windows 系统 DNS 状态接口返回格式无效"));
  }
  return status as WindowsSystemDnsStatus;
}

function isDnsServerList(value: unknown): value is string[] | null {
  return value === null || (Array.isArray(value) && value.every((server) => typeof server === "string"));
}

function shouldWaitForWindowsService(status: WindowsServiceStatus | null): boolean {
  if (!status) {
    return true;
  }
  if (status.ready || status.needsRepair || !status.installed) {
    return false;
  }
  return status.running || status.state === "start_pending" || status.state === "continue_pending";
}

async function waitForWindowsServiceReady(
  initialStatus: WindowsServiceStatus | null,
): Promise<WindowsServiceStatus | null> {
  const started = performance.now();
  let status = initialStatus;
  for (const [index, delay] of WINDOWS_SERVICE_STARTUP_RETRY_DELAYS_MS.entries()) {
    if (!shouldWaitForWindowsService(status)) {
      break;
    }
    const attemptStarted = performance.now();
    await new Promise((resolve) => window.setTimeout(resolve, delay));
    const next = await loadWindowsServiceStatus();
    if (next) {
      status = next;
    }
    logLoadTime(
      `Windows 服务启动重试 #${index + 1}`,
      attemptStarted,
      `计划等待=${delay}ms, ready=${status?.ready ?? false}`,
    );
  }
  logLoadTime("Windows 服务启动等待总计", started, `ready=${status?.ready ?? false}`);
  return status;
}

function requireWindowsServiceStatus(value: unknown): WindowsServiceStatus {
  if (!value || typeof value !== "object") {
    throw new Error(t("Windows 系统服务状态接口返回了空结果"));
  }
  const status = value as Partial<WindowsServiceStatus>;
  if (
    !isWindowsServiceState(status.state) ||
    typeof status.installed !== "boolean" ||
    typeof status.running !== "boolean" ||
    typeof status.ready !== "boolean" ||
    typeof status.ipcReady !== "boolean" ||
    typeof status.expectedVersion !== "string" ||
    typeof status.needsRepair !== "boolean" ||
    (status.serviceVersion !== null && typeof status.serviceVersion !== "string") ||
    (status.diagnostic !== null && typeof status.diagnostic !== "string")
  ) {
    throw new Error(t("Windows 系统服务状态接口返回格式无效"));
  }
  return status as WindowsServiceStatus;
}

function isWindowsServiceState(value: unknown): value is WindowsServiceState {
  switch (value) {
    case "not_installed":
    case "stopped":
    case "start_pending":
    case "stop_pending":
    case "running":
    case "continue_pending":
    case "pause_pending":
    case "paused":
      return true;
    default:
      return false;
  }
}

function renderStorageInfo(info: StorageInfo): void {
  const displayPath = selectedDataStoragePath || info.current_path;
  dataStoragePathInput.value = displayPath;
  dataStorageSizeElement.textContent = t("当前占用 {p0}（数据库 {p1}，过滤器数据 {p2}）", { p0: formatBytes(info.total_bytes), p1: formatBytes(info.database_bytes), p2: formatBytes(info.filter_cache_bytes) });
  dataStorageStateElement.textContent = info.is_default ? t("默认目录") : t("自定义目录");
  dataStorageStateElement.classList.toggle("custom", !info.is_default);

  const pending = hasPendingStorageSelection();
  dataStoragePending.classList.toggle("hidden", !pending);
  if (!pending) {
    dataStoragePendingText.textContent = "";
    migrateDataStorageButton.textContent = t("迁移并重启");
  } else if (!selectedStorageTarget) {
    dataStoragePendingText.textContent = storageSelectionError
      ? t("所选目录不可用")
      : t("正在检查所选目录…");
    migrateDataStorageButton.textContent = t("检查目录中…");
  } else if (selectedStorageTarget.action === "use_existing") {
    dataStoragePendingText.textContent = t("检测到现有数据 {p0}（数据库 {p1}，过滤器数据 {p2}）", { p0: formatBytes(selectedStorageTarget.total_bytes), p1: formatBytes(selectedStorageTarget.database_bytes), p2: formatBytes(selectedStorageTarget.filter_cache_bytes) });
    migrateDataStorageButton.textContent = t("使用现有数据并重启");
  } else {
    dataStoragePendingText.textContent = t("重启后迁移到：{p0}", { p0: displayPath });
    migrateDataStorageButton.textContent = t("迁移并重启");
  }
  migrateDataStorageButton.disabled =
    !pending || !selectedStorageTarget || Boolean(storageSelectionError);
  resetDataStorageButton.disabled = info.is_default && !pending;

  const error = storageSelectionError || info.migration_error || "";
  dataStorageError.textContent = error;
  dataStorageError.classList.toggle("hidden", !error);
}

async function selectDataStoragePath(path: string): Promise<void> {
  if (!currentStorageInfo) {
    return;
  }
  const token = ++storageInspectionToken;
  selectedDataStoragePath = path;
  selectedStorageTarget = null;
  storageSelectionError = "";
  renderStorageInfo(currentStorageInfo);
  if (!hasPendingStorageSelection()) {
    return;
  }

  try {
    const target = await inspectDataStorageTarget(path);
    if (token !== storageInspectionToken) {
      return;
    }
    selectedDataStoragePath = target.path;
    selectedStorageTarget = target;
  } catch (error) {
    if (token !== storageInspectionToken) {
      return;
    }
    storageSelectionError = String(error);
  }
  renderStorageInfo(currentStorageInfo);
}

function hasPendingStorageSelection(): boolean {
  if (!currentStorageInfo || !selectedDataStoragePath) {
    return false;
  }
  return normalizePath(selectedDataStoragePath) !== normalizePath(currentStorageInfo.current_path);
}

function normalizePath(value: string): string {
  return value.replace(/[\\/]+$/, "").toLocaleLowerCase();
}

async function saveConfig(): Promise<void> {
  if (!configLoaded) {
    showMessage(t("配置尚未从 DNS 服务加载，已阻止保存以保护原配置"), true);
    return;
  }
  await runStatusAction(() => saveConfigOnly(), t("配置已保存"));
}

async function saveConfigOnly(): Promise<RuntimeStatus> {
  const config = collectConfig();
  const previousStatisticsRetentionHours = currentStatisticsRetentionHours;
  const previousQueryLogRetentionHours = currentQueryLogRetentionHours;
  currentStatisticsRetentionHours = config.statistics_retention_hours;
  currentQueryLogRetentionHours = config.query_log_retention_hours;
  try {
    const status = await saveConfigCommand(config);
    savedConfigFingerprint = configFingerprint(config);
    configDirty = false;
    updateConfigSaveState();
    return status;
  } catch (error) {
    currentStatisticsRetentionHours = previousStatisticsRetentionHours;
    currentQueryLogRetentionHours = previousQueryLogRetentionHours;
    throw error;
  }
}

function collectConfig(): AppConfig {
  return {
    schema_version: Math.max(currentConfigSchemaVersion, CURRENT_CONFIG_SCHEMA_VERSION),
    enabled: enabledInput.checked,
    launch_at_startup: launchAtStartupInput.checked,
    use_filters: useFiltersInput.checked,
    upstream_dns: upstreamInput.value.trim(),
    fallback_dns: fallbackInput.value.trim(),
    bootstrap_dns: bootstrapInput.value.trim(),
    upstream_mode: selectedRadioValue(upstreamModeInputs, "load_balance") as UpstreamMode,
    domain_upstream_rules: domainUpstreamRulesInput.value.trim(),
    client_upstream_rules: clientUpstreamRulesInput.value.trim(),
    dnssec_enabled: dnssecEnabledInput.checked,
    allowed_clients: allowedClientsInput.value.trim(),
    blocked_clients: blockedClientsInput.value.trim(),
    client_filtering_rules: clientFilteringRulesInput.value.trim(),
    client_policy_groups: clientPolicyGroupsInput.value.trim(),
    family_safe_search: familySafeSearchInput.checked,
    family_blocked_services: familyBlockedServicesInput.value.trim(),
    rate_limit_per_second: Number(rateLimitPerSecondInput.value || 0),
    refuse_any: refuseAnyInput.checked,
    filter_update_interval_hours: Number(filterUpdateIntervalInput.value),
    filter_max_size_mb: Number(filterMaxSizeInput.value || 50),
    filter_proxy_mode: filterProxyModeInput.value as FilterProxyMode,
    filter_proxy_url: filterProxyUrlInput.value.trim(),
    filter_system_proxy_url: detectedSystemProxy ?? savedSystemProxyUrl,
    allow_insecure_http: allowInsecureHttpInput.checked,
    query_log_enabled: queryLogEnabledInput.checked,
    anonymize_client_ip: anonymizeClientIpInput.checked,
    query_log_retention_hours: selectedRetentionHours(),
    statistics_enabled: statisticsEnabledInput.checked,
    statistics_retention_hours: selectedStatisticsRetentionHours(),
    security_event_retention_hours: Number(securityEventRetentionInput.value || 720),
    dns_cache_enabled: dnsCacheEnabledInput.checked,
    dns_cache_size: Number(dnsCacheSizeInput.value || 0),
    dns_cache_min_ttl: Number(dnsCacheMinTtlInput.value || 0),
    dns_cache_max_ttl: Number(dnsCacheMaxTtlInput.value || 0),
    dns_cache_optimistic: dnsCacheOptimisticInput.checked,
    dns_cache_optimistic_max_stale_seconds: Number(
      dnsCacheOptimisticMaxStaleInput.value || 0,
    ),
    dns_cache_prefetch_enabled: dnsCachePrefetchEnabledInput.checked,
    dns_cache_prefetch_hit_threshold: Number(dnsCachePrefetchHitThresholdInput.value || 10),
    runtime_watchdog_enabled: runtimeWatchdogEnabledInput.checked,
    runtime_watchdog_interval_seconds: Number(runtimeWatchdogIntervalInput.value || 0),
    monitoring_api_enabled: monitoringApiEnabledInput.checked,
    monitoring_api_listen_host: monitoringApiListenHostInput.value.trim(),
    monitoring_api_port: Number(monitoringApiPortInput.value || 0),
    monitoring_api_token: monitoringApiTokenInput.value.trim(),
    blocking_mode: selectedRadioValue(blockingModeInputs, "null_ip") as BlockingMode,
    blocking_response_ttl: Number(blockingResponseTtlInput.value || 0),
    blocking_custom_ipv4: blockingCustomIpv4Input.value.trim(),
    blocking_custom_ipv6: blockingCustomIpv6Input.value.trim(),
    rebinding_protection_enabled: rebindingProtectionEnabledInput.checked,
    rebinding_allowed_domains: rebindingAllowedDomainsInput.value,
    cname_cloaking_enabled: cnameCloakingEnabledInput.checked,
    private_reverse_dns_enabled: privateReverseDnsEnabledInput.checked,
    dns_rewrites: dnsRewritesInput.value,
    system_hosts_enabled: systemHostsEnabledInput.checked,
    client_names: clientNamesInput.value,
    query_log_ignored_domains: queryLogIgnoredInput.value,
    statistics_ignored_domains: statisticsIgnoredInput.value,
    listen_host: listenHostInput.value.trim(),
    listen_port: Number(listenPortInput.value),
    listen_ipv6: listenIpv6Input.checked,
    filters: filtersState.map((filter) => ({
      ...filter,
      name: filter.name.trim(),
      url: filter.url.trim(),
    })),
    blacklist: blacklistInput.value,
  };
}

function configFingerprint(config: AppConfig): string {
  return JSON.stringify(
    {
      ...config,
      filters: config.filters.map(({ id, name, url, enabled }) => ({ id, name, url, enabled })),
    },
    (key, value) => (key === "filter_system_proxy_url" ? undefined : value),
  );
}

function updateConfigDirtyState(): void {
  if (!configLoaded) {
    return;
  }
  configDirty = configFingerprint(collectConfig()) !== savedConfigFingerprint;
  updateConfigSaveState();
}

function updateConfigSaveState(): void {
  const label = !configLoaded
    ? t("配置不可用")
    : configDirty
      ? t("有未保存的更改")
      : t("所有更改已保存");
  saveStateLabels.forEach((element) => {
    element.textContent = label;
    element.classList.toggle("dirty", configLoaded && configDirty);
  });
  configSaveButtons.forEach((button) => {
    button.disabled = !configLoaded || !configDirty;
  });
}

async function refreshStatus(options: RefreshOptions = {}): Promise<void> {
  if (options.auto && isContentScrolling) {
    queuedAutoRefresh = true;
    return;
  }
  if (refreshInFlight) {
    if (!options.auto || activeView === "dashboard") {
      statusRefreshQueued = true;
    }
    return;
  }

  const started = performance.now();
  const renderDashboard = activeView === "dashboard";
  const requestedStatisticsHours = dashboardStatisticsHours;
  const requestedStatisticsRevision = dashboardStatisticsRevision;
  let succeeded = false;
  refreshInFlight = true;
  setRefreshButtonState(options.button, true);
  if (renderDashboard && options.auto !== true) {
    setDashboardLoading(true);
  }
  try {
    const status = await getStatus(
      options.auto !== true,
      renderDashboard,
      renderDashboard ? requestedStatisticsHours : undefined,
    );
    if (options.auto && isContentScrolling) {
      queuedAutoRefresh = true;
      return;
    }
    const dashboardRangeIsCurrent = requestedStatisticsRevision === dashboardStatisticsRevision;
    renderStatus(status, { renderDashboard: renderDashboard && dashboardRangeIsCurrent });
    if (renderDashboard && dashboardRangeIsCurrent) {
      lastDashboardRefreshAt = performance.now();
    } else if (renderDashboard) {
      statusRefreshQueued = true;
    }
    succeeded = true;
  } catch (error) {
    // 自动轮询会撞上后台服务重启或等待批准的窗口，瞬态错误只记录不打扰用户
    if (options.auto) {
      console.error("自动刷新状态失败", error);
    } else {
      showMessage(String(error), true);
    }
  } finally {
    logLoadTime(
      "首页状态加载与渲染",
      started,
      `success=${succeeded}, auto=${options.auto === true}`,
      options.auto !== true,
    );
    refreshInFlight = false;
    setRefreshButtonState(options.button, false);
    const runQueuedRefresh = statusRefreshQueued;
    statusRefreshQueued = false;
    if (runQueuedRefresh) {
      void refreshStatus();
    } else {
      setDashboardLoading(false);
    }
  }
}

function collectQueryLogQuery(): QueryLogQuery {
  return {
    filter: queryLogFilterInput.value as QueryLogFilter,
    search: queryLogSearchInput.value.trim(),
    hours: parseQueryLogHours(queryLogTimeRange.value),
    source: queryLogSource.value as QueryLogSourceFilter,
    queryType: queryLogQueryType.value as QueryLogTypeFilter,
    sort: queryLogSort.value as QueryLogSort,
  };
}

function queryLogUsesCursor(query = collectQueryLogQuery()): boolean {
  return query.sort === "newest" || query.sort === "oldest";
}

function resetQueryLogPagination(): void {
  queryLogPage = 1;
  queryLogCursorStack = [""];
  queryLogNextCursor = null;
}

function applyQueryLogQuery(queryValue: QueryLogQuery): void {
  queryLogSearchInput.value = queryValue.search;
  setQueryLogFilterValue(queryValue.filter);
  queryLogTimeRange.value = queryValue.hours === null ? "configured" : String(queryValue.hours);
  queryLogSource.value = queryValue.source;
  queryLogQueryType.value = queryValue.queryType;
  queryLogSort.value = queryValue.sort;
  [queryLogTimeRange, queryLogSource, queryLogQueryType, queryLogSort].forEach(syncCustomSelect);
}

function renderSavedQueryLogViews(selectedId = queryLogSavedViewSelect.value): void {
  queryLogSavedViewSelect.innerHTML = [
    t("<option value=\"\">选择已保存视图</option>"),
    ...savedQueryLogViews.map(
      (view) => `<option value="${escapeHtml(view.id)}">${escapeHtml(view.name)}</option>`,
    ),
  ].join("");
  queryLogSavedViewSelect.value = savedQueryLogViews.some((view) => view.id === selectedId)
    ? selectedId
    : "";
  queryLogDeleteViewButton.disabled = queryLogSavedViewSelect.value === "";
  syncCustomSelect(queryLogSavedViewSelect);
}

function syncSavedQueryLogViewSelection(): void {
  const queryValue = collectQueryLogQuery();
  const matched = savedQueryLogViews.find(
    (view) => JSON.stringify(view.query) === JSON.stringify(queryValue),
  );
  if (queryLogSavedViewSelect.value !== (matched?.id ?? "")) {
    queryLogSavedViewSelect.value = matched?.id ?? "";
    syncCustomSelect(queryLogSavedViewSelect);
  }
  queryLogDeleteViewButton.disabled = !matched;
}

function refreshQueryLogAdvancedState(): void {
  const count = activeAdvancedQueryFilterCount(collectQueryLogQuery());
  queryLogAdvancedCount.textContent = String(count);
  queryLogAdvancedCount.hidden = count === 0;
  queryLogAdvancedButton.classList.toggle("active", count > 0);
  queryLogAdvancedButton.title = count > 0 ? t("已启用 {p0} 个高级筛选", { p0: count }) : "";
  queryLogAdvancedButton.setAttribute(
    "aria-label",
    count > 0 ? t("更多筛选，已启用 {p0} 个条件", { p0: count }) : t("更多筛选"),
  );
  syncSavedQueryLogViewSelection();
}

function scheduleQueryLogSearch(): void {
  window.clearTimeout(queryLogSearchTimer);
  queryLogSearchTimer = window.setTimeout(() => {
    resetQueryLogPagination();
    void refreshQueryLogs();
  }, QUERY_LOG_SEARCH_DEBOUNCE_MS);
}

async function refreshQueryLogs(options: RefreshOptions = {}): Promise<void> {
  if (options.auto && isContentScrolling) {
    queuedAutoRefresh = true;
    return;
  }
  if (queryLogRefreshInFlight) {
    queryLogRefreshQueued = true;
    return;
  }

  queryLogRefreshInFlight = true;
  setRefreshButtonState(options.button, true);
  setQueryLogLoading(true, options.auto === true);
  try {
    const requestedQuery = collectQueryLogQuery();
    const requestedPage = queryLogPage;
    const requestedCursor = queryLogUsesCursor(requestedQuery)
      ? (queryLogCursorStack[requestedPage - 1] ?? "")
      : null;
    const page = await getQueryLogs({
      ...requestedQuery,
      page: requestedPage,
      pageSize: QUERY_LOG_PAGE_SIZE,
      cursor: requestedCursor,
    });
    if (options.auto && isContentScrolling) {
      queuedAutoRefresh = true;
      return;
    }
    if (
      JSON.stringify(requestedQuery) !== JSON.stringify(collectQueryLogQuery()) ||
      requestedPage !== queryLogPage ||
      (queryLogUsesCursor(requestedQuery) &&
        requestedCursor !== (queryLogCursorStack[requestedPage - 1] ?? ""))
    ) {
      queryLogRefreshQueued = true;
      return;
    }
    queryLogPage = page.page;
    queryLogTotal = page.total;
    queryLogNextCursor = page.next_cursor;
    renderQueryLogs(page);
  } catch (error) {
    if (options.auto) {
      console.error("自动刷新查询日志失败", error);
    } else {
      showMessage(String(error), true);
    }
  } finally {
    queryLogRefreshInFlight = false;
    setQueryLogLoading(false, options.auto === true);
    setRefreshButtonState(options.button, false);
    if (queryLogRefreshQueued) {
      queryLogRefreshQueued = false;
      void refreshQueryLogs();
    }
  }
}

async function runStatusAction(
  action: () => Promise<RuntimeStatus>,
  successMessage: string,
): Promise<void> {
  setBusy(true);
  try {
    const status = await action();
    renderStatus(status);
    showMessage(successMessage, false);
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    setBusy(false);
  }
}

function rememberViewAcrossReload(view: ViewName): void {
  try {
    window.sessionStorage.setItem(PENDING_VIEW_KEY, view);
  } catch (error) {
    // 存不下最多是重载后回到仪表盘，不影响功能。
    console.warn("保存当前页面失败", error);
  }
}

/** 取出并清除待恢复的页面：只对紧接着的那一次重载生效，正常启动仍然落在仪表盘。 */
function takeViewAfterReload(): ViewName | null {
  let stored: string | null = null;
  try {
    stored = window.sessionStorage.getItem(PENDING_VIEW_KEY);
    window.sessionStorage.removeItem(PENDING_VIEW_KEY);
  } catch (error) {
    console.warn("读取待恢复页面失败", error);
    return null;
  }
  if (!stored || !/^[a-z]+$/.test(stored)) {
    return null;
  }
  // 用模板里实际存在的面板校验，省得和 ViewName 各维护一份清单。
  return document.querySelector(`[data-view-panel="${stored}"]`) ? (stored as ViewName) : null;
}

/** 只切换面板与导航高亮，不触发任何数据刷新。 */
function applyViewVisibility(view: ViewName): void {
  updateContextNavigation(view);
  document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
    const isFilterGroup =
      button.dataset.navGroup === "filters" && (view === "filters" || view === "custom");
    const isSettingsGroup =
      button.dataset.navGroup === "settings" &&
      (view === "settings" || view === "dns" || view === "security" || view === "diagnostics");
    const selected = button.dataset.view === view || isFilterGroup || isSettingsGroup;
    button.classList.toggle("active", selected);
    if (selected) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });
  document.querySelectorAll<HTMLElement>("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
}

function setActiveView(view: ViewName): void {
  const viewChanged = activeView !== view;
  if (viewChanged) {
    isContentScrolling = false;
    queuedAutoRefresh = false;
    if (scrollIdleTimer !== undefined) {
      window.clearTimeout(scrollIdleTimer);
      scrollIdleTimer = undefined;
    }
  }
  activeView = view;
  showMessage("", false);
  applyViewVisibility(view);
  // 所有页面共享同一个滚动容器，导航和初始化落页时都从顶部开始。
  contentElement.scrollTop = 0;
  if (view === "dashboard" && viewChanged) {
    void refreshStatus({ auto: true });
  }
  if (view === "logs") {
    void refreshQueryLogs();
  }
  if (view === "filters" && viewChanged) {
    void refreshFilterUpdateMetadata();
  }
  if (view === "security" && viewChanged) {
    void refreshStatus({ auto: true });
  }
  if (view === "settings" && viewChanged) {
    void refreshSettingsRuntimeStatus();
    void refreshStatus({ auto: true });
  }
}

function updateContextNavigation(view: ViewName): void {
  const group =
    view === "settings" || view === "dns" || view === "security" || view === "diagnostics"
      ? "settings"
      : view === "filters" || view === "custom"
        ? "filters"
        : null;

  contextNav.classList.toggle("visible", group !== null);
  contextNav.querySelectorAll<HTMLElement>("[data-context-group]").forEach((navigation) => {
    navigation.classList.toggle("active", navigation.dataset.contextGroup === group);
  });
}

async function runDiagnostic(): Promise<void> {
  const domain = diagnosticDomainInput.value.trim();
  if (!domain) {
    diagnosticDomainInput.focus();
    showMessage(t("请输入要诊断的域名"), true);
    return;
  }
  runDiagnosticButton.classList.add("loading");
  runDiagnosticButton.textContent = t("诊断中");
  runDiagnosticButton.disabled = true;
  diagnosticResults.innerHTML = `
    <div class="diagnostic-empty loading-state">
      <strong>${t("正在并行测试上游…")}</strong>
      <span>${t("不可用的服务器最多等待 3 秒。")}</span>
    </div>
  `;
  try {
    const report = await runDnsDiagnostic(
      domain,
      diagnosticQueryTypeInput.value,
      diagnosticClientIpInput.value.trim(),
    );
    renderDiagnosticReport(report);
  } catch (error) {
    diagnosticResults.innerHTML = `
      <div class="diagnostic-empty error-state">
        <strong>${t("诊断失败")}</strong>
        <span>${escapeHtml(String(error))}</span>
      </div>
    `;
    showMessage(String(error), true);
  } finally {
    runDiagnosticButton.classList.remove("loading");
    runDiagnosticButton.textContent = t("开始诊断");
    runDiagnosticButton.disabled = false;
  }
}

function renderDiagnosticReport(report: DnsDiagnosticReport): void {
  const localLabels: Record<DnsDiagnosticReport["local_status"], string> = {
    allowed: t("本地判定：允许"),
    blocked: t("本地判定：已拦截"),
    bypassed: t("本地判定：客户端已绕过"),
    rewrite: t("本地判定：DNS 重写"),
    paused: t("本地判定：保护已暂停"),
    stopped: t("本地判定：服务未运行"),
  };
  const localDetails = [
    report.client_ip ? [t("模拟客户端"), report.client_ip] : null,
    report.client_ip
      ? [
          t("客户端策略"),
          report.client_policy === "bypass"
            ? t("绕过过滤{p0}", { p0: report.client_policy_source ? `（${report.client_policy_source}）` : "" })
            : t("正常过滤{p0}", { p0: report.client_policy_source ? `（${report.client_policy_source}）` : "" }),
        ]
      : null,
    report.matched_rule ? [t("命中规则"), report.matched_rule] : null,
    report.rule_source ? [t("规则来源"), report.rule_source] : null,
    report.rule_type ? [t("规则类型"), report.rule_type] : null,
    report.allowlist_rule ? [t("被覆盖的允许规则"), report.allowlist_rule] : null,
  ].filter((entry): entry is string[] => entry !== null);
  const localDetailRows = localDetails.length > 0
    ? `<dl class="diagnostic-local-details">${localDetails
        .map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`)
        .join("")}</dl>`
    : "";
  const upstreamRows = report.upstreams.length > 0
    ? report.upstreams.map((result) => {
        const answers = result.answers.length > 0
          ? result.answers
              .map((answer) => `${dnsQueryTypeLabel(answer.record_type)} ${answer.value}`)
              .join(" · ")
          : result.success
            ? t("响应中没有可展示的记录")
            : result.error || t("上游无响应");
        return `
          <div class="diagnostic-upstream ${result.success ? "success" : "failed"}">
            <i aria-hidden="true"></i>
            <div>
              <strong title="${escapeHtml(result.upstream)}">${escapeHtml(result.upstream)}</strong>
              <span title="${escapeHtml(answers)}">${escapeHtml(answers)}</span>
            </div>
            <div class="diagnostic-upstream-meta">
              <strong>${result.success ? `${dnsResponseCodeShortLabel(result.response_code)}${result.authenticated_data ? " · DNSSEC" : ""}` : t("失败")}</strong>
              <span>${result.latency_ms === null ? "-" : formatElapsedMs(result.latency_ms)}</span>
            </div>
          </div>
        `;
      }).join("")
    : t("<div class=\"diagnostic-empty\"><strong>没有已配置的上游</strong></div>");
  diagnosticResults.innerHTML = `
    <section class="diagnostic-local ${report.local_status}">
      <div>
        <span>${escapeHtml(report.domain)} · ${escapeHtml(report.query_type)}</span>
        <strong>${localLabels[report.local_status]}</strong>
      </div>
      <p>${escapeHtml(report.local_detail)}</p>
      ${report.important_overrode ? `<p class="diagnostic-note">${t("该重要规则覆盖了一条允许规则。")}</p>` : ""}
      ${localDetailRows}
    </section>
    <section class="diagnostic-upstream-list">
      <div class="diagnostic-result-heading">
        <h3>${t("上游测试")}</h3>
        <span>${report.upstreams.filter((result) => result.success).length}/${report.upstreams.length} ${t("个可用")}</span>
      </div>
      ${upstreamRows}
    </section>
  `;
}

function dnsResponseCodeShortLabel(code: number | null): string {
  if (code === null) {
    return t("已响应");
  }
  const labels: Record<number, string> = {
    0: "NOERROR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    5: "REFUSED",
  };
  return labels[code] || `RCODE ${code}`;
}

function renderFilters(): void {
  if (filtersState.length === 0) {
    filtersBody.innerHTML = t("<div class=\"empty-row\" role=\"row\"><span role=\"cell\">暂无远程清单</span></div>");
    return;
  }

  filtersBody.innerHTML = filtersState.map(renderFilter).join("");
}

function syncFilterUpdateMetadata(updatedFilters: FilterSubscription[]): void {
  const updatedById = new Map(updatedFilters.map((filter) => [filter.id, filter]));
  let changed = false;
  filtersState = filtersState.map((filter) => {
    const updated = updatedById.get(filter.id);
    if (!updated) {
      return filter;
    }
    const next = {
      ...filter,
      rule_count: updated.rule_count,
      block_rule_count: updated.block_rule_count,
      allow_rule_count: updated.allow_rule_count,
      ignored_rule_count: updated.ignored_rule_count,
      ignored_comment_count: updated.ignored_comment_count,
      ignored_regex_count: updated.ignored_regex_count,
      ignored_unsupported_count: updated.ignored_unsupported_count,
      ignored_invalid_count: updated.ignored_invalid_count,
      last_updated: updated.last_updated,
      last_error: updated.last_error,
    };
    changed ||= filterUpdateMetadataKey(filter) !== filterUpdateMetadataKey(next);
    return next;
  });
  if (changed) {
    renderFilters();
  }
}

function filterUpdateMetadataKey(filter: FilterSubscription): string {
  return JSON.stringify([
    filter.rule_count,
    filter.block_rule_count,
    filter.allow_rule_count,
    filter.ignored_rule_count,
    filter.ignored_comment_count,
    filter.ignored_regex_count,
    filter.ignored_unsupported_count,
    filter.ignored_invalid_count,
    filter.last_updated,
    filter.last_error,
  ]);
}

async function refreshFilterUpdateMetadata(): Promise<void> {
  if (editingFilterIds.size > 0) {
    return;
  }
  try {
    const config = await getConfig();
    syncFilterUpdateMetadata(config.filters);
  } catch (error) {
    console.warn("刷新过滤器更新状态失败", error);
  }
}

function renderFilter(filter: FilterSubscription): string {
  const isEditing = editingFilterIds.has(filter.id);
  const accessibleName = filter.name.trim() || t("未命名清单");
  const hasUnsupportedIgnoredRules =
    filter.ignored_regex_count + filter.ignored_unsupported_count + filter.ignored_invalid_count > 0;
  const statusText = filter.last_error
    ? t("更新失败")
    : filter.last_updated
      ? hasUnsupportedIgnoredRules
        ? t("部分忽略")
        : t("已更新")
      : t("未更新");
  const statusClass = filter.last_error
    ? "danger"
    : filter.last_updated
      ? hasUnsupportedIgnoredRules
        ? "warning"
        : "ok"
      : "muted";
  const ruleSummary = formatFilterRuleSummary(filter);

  return `
    <div class="filter-item" data-id="${escapeHtml(filter.id)}" role="rowgroup">
      <div class="filter-summary" role="row">
        <label class="switch" title="${t("启用清单")}" role="cell">
          <input class="filter-enabled" data-field="enabled" type="checkbox" aria-label="${t("启用黑名单 {p0}", { p0: escapeHtml(accessibleName) })}" ${filter.enabled ? "checked" : ""} />
        </label>
        <div class="filter-meta" role="cell">
          <strong>${escapeHtml(filter.name || t("未命名清单"))}</strong>
          <span class="url-line" title="${escapeHtml(filter.url)}">${escapeHtml(filter.url || t("尚未填写清单网址"))}</span>
        </div>
        <span class="rule-count" role="cell" title="${escapeHtml(ruleSummary)}">${formatCount(filter.rule_count)}</span>
        <span class="update-time" role="cell">${formatTime(filter.last_updated)}</span>
        <span class="state-tag ${statusClass}" role="cell" title="${escapeHtml(filter.last_error ?? "")}">${statusText}</span>
        <div class="row-actions" role="cell">
          <button data-action="edit" type="button" aria-label="${isEditing ? t("收起黑名单 {p0}", { p0: escapeHtml(accessibleName) }) : t("编辑黑名单 {p0}", { p0: escapeHtml(accessibleName) })}">${isEditing ? t("收起") : t("编辑")}</button>
          <button data-action="remove" type="button" aria-label="${t("删除黑名单 {p0}", { p0: escapeHtml(accessibleName) })}">${t("删除")}</button>
        </div>
      </div>
      ${
        isEditing
          ? `
            <div role="row">
              <div class="filter-edit" role="cell" aria-colspan="6">
                <label class="field">
                  <span>${t("名称")}</span>
                  <input data-field="name" value="${escapeHtml(filter.name)}" spellcheck="false" />
                </label>
                <label class="field">
                  <span>${t("清单网址")}</span>
                  <input data-field="url" value="${escapeHtml(filter.url)}" spellcheck="false" />
                </label>
                <small class="filter-rule-detail">${escapeHtml(ruleSummary)}</small>
              </div>
            </div>
          `
          : ""
      }
    </div>
  `;
}

function renderStatus(status: RuntimeStatus, options: RenderStatusOptions = {}): void {
  const renderDashboard = options.renderDashboard ?? true;

  latestRuntimeStatus = status;
  renderRuntimeStatus(status);
  renderAboutRuntimeInfo();

  const lastError = status.error ?? status.stats.last_error;
  const statusErrorKey = status.error
    ? `runtime:${status.error}`
    : lastError
      ? `dns:${lastError}`
      : null;
  if (lastError && statusErrorKey !== lastStatusErrorKey) {
    showMessage(lastError, true);
  }
  lastStatusErrorKey = statusErrorKey;
  renderSecurityEvents(status);
  renderCacheStats(status);

  if (!renderDashboard) {
    return;
  }

  setTextIfChanged(query("#queries"), formatCount(status.stats.queries));
  setTextIfChanged(query("#blocked"), formatCount(status.stats.blocked));
  setTextIfChanged(query("#block_rate"), formatRate(status.stats.blocked, status.stats.queries));
  renderDashboardSummaryWindow(status.stats.dashboard_started_at, status.stats.dashboard_ended_at);
  const effectiveStatisticsHours = dashboardStatisticsHours ?? currentStatisticsRetentionHours;
  const allTraffic = status.stats.traffic ?? [];
  const traffic = effectiveStatisticsHours === 0
    ? allTraffic
    : allTraffic.filter(
        (bucket) => bucket.minute >= Math.floor(Date.now() / 60_000) - effectiveStatisticsHours * 60,
      );
  renderSparkline(
    "#query_sparkline",
    buildTrafficSeries(traffic, "queries", effectiveStatisticsHours),
  );
  renderSparkline(
    "#blocked_sparkline",
    buildTrafficSeries(traffic, "blocked", effectiveStatisticsHours),
  );
  renderRankTable("#query_rank", status.stats.query_domains ?? {}, status.stats.queries);
  renderRankTable("#blocked_rank", status.stats.blocked_domains ?? {}, status.stats.blocked);
  renderClientOverview(status.stats.client_requests ?? {}, status.stats.client_blocked ?? {});
  renderRankTable("#blocklist_rank", status.stats.blocklist_hits ?? {}, status.stats.blocked);
  renderUpstreamRequestRank(
    "#upstream_rank",
    status.stats.upstream_requests ?? [],
    status.stats.forwarded,
  );
  renderUpstreamLatencyRank("#upstream_latency_rank", status.stats.upstream_avg_latency ?? []);
}

function renderSecurityEvents(status: RuntimeStatus): void {
  setTextIfChanged(securityAccessDenied, formatCount(status.stats.access_denied_total));
  setTextIfChanged(securityRateLimited, formatCount(status.stats.rate_limited_total));
  setTextIfChanged(securityDroppedUdp, formatCount(status.stats.dropped_udp_total));
  setTextIfChanged(securityRefusedAny, formatCount(status.stats.refused_any_total));
  setTextIfChanged(
    securityRebindingBlocked,
    formatCount(status.stats.rebinding_blocked_total ?? 0),
  );
  setTextIfChanged(
    securityCnameBlocked,
    formatCount(status.stats.cname_cloaking_blocked_total ?? 0),
  );
  setTextIfChanged(workerQueueDropped, formatCount(status.stats.worker_queue_dropped_total ?? 0));
  setTextIfChanged(
    persistenceQueueDropped,
    formatCount(status.stats.persistence_queue_dropped_total ?? 0),
  );
  setTextIfChanged(
    upstreamTaskQueueRejected,
    formatCount(status.stats.upstream_task_queue_rejected_total ?? 0),
  );
  setTextIfChanged(
    tcpConnectionRejected,
    formatCount(status.stats.tcp_connection_rejected_total ?? 0),
  );

  const events = [...(status.stats.security_events ?? [])].reverse();
  if (events.length === 0) {
    setHtmlIfChanged(
      securityEventBody,
      t("<div class=\"security-event-empty\" role=\"row\"><span role=\"cell\">暂无安全事件</span></div>"),
    );
    return;
  }
  setHtmlIfChanged(securityEventBody, events.map(renderSecurityEvent).join(""));
}

function renderCacheStats(status: RuntimeStatus): void {
  const hits = status.stats.cache_hits ?? 0;
  const misses = status.stats.cache_misses ?? 0;
  const total = hits + misses;
  setTextIfChanged(cacheHitRate, total > 0 ? `${((hits / total) * 100).toFixed(1)}%` : "0%");
  setTextIfChanged(cacheHitMiss, `${formatCount(hits)} / ${formatCount(misses)}`);
  setTextIfChanged(cacheStaleHits, formatCount(status.stats.cache_stale_hits ?? 0));
  setTextIfChanged(
    cacheRefreshes,
    `${formatCount(status.stats.cache_refresh_completed ?? 0)} / ${formatCount(status.stats.cache_refresh_failed ?? 0)}`,
  );
  setTextIfChanged(
    cachePrefetches,
    `${formatCount(status.stats.cache_prefetch_completed ?? 0)} / ${formatCount(status.stats.cache_prefetch_failed ?? 0)}`,
  );
  setTextIfChanged(cacheEvictions, formatCount(status.stats.cache_evictions ?? 0));
  setTextIfChanged(cacheEntries, formatCount(status.stats.cache_entries ?? 0));
  setTextIfChanged(cacheBytes, formatBytes(status.stats.cache_bytes ?? 0));
}

function renderSecurityEvent(event: SecurityEvent): string {
  const eventLabel = event.event_type === "rate_limited" ? t("触发限速") : t("访问拒绝");
  const clientLabel = clientDisplayName(event.client_ip) ?? event.client_ip;
  const detail = `${event.protocol.toUpperCase()} · ${event.reason}`;
  const detailTitle =
    event.count > 1
      ? t("{p0}；首次：{p1} {p2}", { p0: detail, p1: formatLogDate(event.first_seen_at), p2: formatLogTime(event.first_seen_at) })
      : detail;
  return `
    <div class="security-event-row ${event.event_type}" role="row">
      <div role="cell">
        <strong>${escapeHtml(formatLogTime(event.last_seen_at))}</strong>
        <span>${escapeHtml(formatLogDate(event.last_seen_at))}</span>
      </div>
      <div role="cell">
        <strong title="${escapeHtml(event.client_ip)}">${escapeHtml(clientLabel)}</strong>
        <span>${escapeHtml(event.client_ip)}</span>
      </div>
      <div role="cell">
        <strong>${eventLabel}</strong>
        <span title="${escapeHtml(detailTitle)}">${escapeHtml(detail)}</span>
      </div>
      <strong class="security-event-count" role="cell">${escapeHtml(formatCount(event.count))}</strong>
    </div>
  `;
}

function formatFilterRuleSummary(filter: FilterSubscription): string {
  const ignoredParts = [
    filter.ignored_comment_count > 0 ? t("空行/注释 {p0}", { p0: formatCount(filter.ignored_comment_count) }) : "",
    filter.ignored_regex_count > 0 ? t("正则 {p0}", { p0: formatCount(filter.ignored_regex_count) }) : "",
    filter.ignored_unsupported_count > 0
      ? t("高级修饰符 {p0}", { p0: formatCount(filter.ignored_unsupported_count) })
      : "",
    filter.ignored_invalid_count > 0 ? t("非法域名 {p0}", { p0: formatCount(filter.ignored_invalid_count) }) : "",
  ].filter(Boolean);

  const ignoredText =
    filter.ignored_rule_count > 0
      ? t("，忽略 {p0}（{p1}）", { p0: formatCount(filter.ignored_rule_count), p1: ignoredParts.join("，") || t("未分类") })
      : "";

  return t("有效 {p0}，黑名单 {p1}，白名单 {p2}{p3}", { p0: formatCount(filter.rule_count), p1: formatCount(filter.block_rule_count), p2: formatCount(filter.allow_rule_count), p3: ignoredText });
}

function renderQueryLogs(page: QueryLogPage): void {
  renderQueryLogPagination(page);

  if (!currentQueryLogEnabled) {
    setHtmlIfChanged(queryLogBody, t("<div class=\"query-log-empty\">查询日志未启用，请在设置中开启日志配置。</div>"));
    return;
  }

  if (page.records.length === 0) {
    const query = collectQueryLogQuery();
    const hasSearch =
      query.search.length > 0 ||
      query.filter !== DEFAULT_QUERY_LOG_QUERY.filter ||
      activeAdvancedQueryFilterCount(query) > 0;
    const hint =
      hasSearch &&
      retentionWindowIsShorter(currentQueryLogRetentionHours, currentStatisticsRetentionHours)
        ? t("<small>查询日志只{p0}，仪表盘统计的时间范围更长；排行榜里的域名可能已经超出日志保留期。</small>", {
            p0: formatRetentionScope(currentQueryLogRetentionHours),
          })
        : "";
    setHtmlIfChanged(
      queryLogBody,
      t("<div class=\"query-log-empty\">{p0}{p1}</div>", {
        p0: hasSearch ? t("没有匹配的查询记录") : t("暂无查询记录"),
        p1: hint,
      }),
    );
    return;
  }

  const html = page.records
    .map((record) => renderQueryLogRow(record, { clientDisplayName, formatClientLabel }))
    .join("");
  setHtmlIfChanged(queryLogBody, html);
}

function renderQueryLogPagination(page: QueryLogPage): void {
  const pagination = queryLogPaginationState(
    page.page,
    page.total,
    page.page_size,
    queryLogRefreshInFlight,
  );
  const totalLabel =
    page.total === 0
      ? t("0 条记录")
      : t("{p0}-{p1} / {p2} 条", { p0: formatCount(pagination.start), p1: formatCount(pagination.end), p2: formatCount(page.total) });
  queryLogPageInfo.textContent = `${totalLabel} · ${formatRetentionScope(currentQueryLogRetentionHours)}`;
  queryLogPrevButton.disabled = queryLogRefreshInFlight || page.page <= 1;
  queryLogNextButton.disabled = queryLogUsesCursor()
    ? queryLogRefreshInFlight || page.next_cursor === null
    : pagination.nextDisabled;
}

function syncQueryLogPaginationDisabled(loading: boolean): void {
  const pagination = queryLogPaginationState(
    queryLogPage,
    queryLogTotal,
    QUERY_LOG_PAGE_SIZE,
    loading,
  );
  queryLogPrevButton.disabled = loading || queryLogPage <= 1;
  queryLogNextButton.disabled = queryLogUsesCursor()
    ? loading || queryLogNextCursor === null
    : pagination.nextDisabled;
}

function setQueryLogFilterValue(value: QueryLogFilter): void {
  const options = queryLogFilterMenu.querySelectorAll<HTMLButtonElement>("[data-filter]");
  let label = t("所有查询记录");

  options.forEach((option) => {
    const selected = option.dataset.filter === value;
    option.classList.toggle("active", selected);
    option.setAttribute("aria-selected", String(selected));
    if (selected) {
      label = option.textContent?.trim() || label;
    }
  });

  queryLogFilterInput.value = value;
  queryLogFilterLabel.textContent = label;
}

function placeLogDetailPopover(anchor: HTMLElement): void {
  const popover = anchor.querySelector<HTMLElement>(".log-detail-popover");
  if (!popover) {
    return;
  }

  anchor.classList.remove("show-above", "align-right");
  const contentRect = contentElement.getBoundingClientRect();
  const anchorRect = anchor.getBoundingClientRect();
  const bottomLimit = Math.min(window.innerHeight, contentRect.bottom) - 12;
  const topLimit = Math.max(0, contentRect.top) + 12;
  const rightLimit = Math.min(window.innerWidth, contentRect.right) - 12;
  const spaceBelow = bottomLimit - anchorRect.bottom;
  const spaceAbove = anchorRect.top - topLimit;
  const shouldShowAbove = spaceBelow < popover.offsetHeight + 16 && spaceAbove > spaceBelow;
  const shouldAlignRight = anchorRect.left - 6 + popover.offsetWidth > rightLimit;

  anchor.classList.toggle("show-above", shouldShowAbove);
  anchor.classList.toggle("align-right", shouldAlignRight);
}

function setRadioValue(inputs: HTMLInputElement[], value: string): void {
  for (const input of inputs) {
    input.checked = input.value === value;
  }
}

function selectedRadioValue(inputs: HTMLInputElement[], fallback: string): string {
  return inputs.find((input) => input.checked)?.value ?? fallback;
}

function setRetentionValue(hours: number): void {
  const normalizedHours = hours === 6 ? 24 : hours;
  const preset = queryLogRetentionInputs.find((input) => input.value === String(normalizedHours));
  if (preset) {
    preset.checked = true;
    queryLogRetentionCustomInput.value = "";
    return;
  }

  setRadioValue(queryLogRetentionInputs, "custom");
  queryLogRetentionCustomInput.value = String(hours);
}

function selectedRetentionHours(): number {
  const value = selectedRadioValue(queryLogRetentionInputs, "2160");
  if (value !== "custom") {
    return Number(value);
  }

  return Number(queryLogRetentionCustomInput.value || 2160);
}

/// 保留期用固定选项呈现。配置里若是导入的非预设值，回落到不小于它的最小预设，
/// 避免下拉框显示空白、保存时又把用户原来的设置改小。
function setSecurityEventRetentionValue(hours: number): void {
  const options = Array.from(securityEventRetentionInput.options).map((option) =>
    Number(option.value),
  );
  const matched = options.includes(hours)
    ? hours
    : (options.find((option) => option >= hours) ?? options[options.length - 1]);
  securityEventRetentionInput.value = String(matched);
  syncCustomSelect(securityEventRetentionInput);
}

function setStatisticsRetentionValue(hours: number): void {
  if (hours === 0) {
    setRadioValue(statisticsRetentionInputs, "forever");
    statisticsRetentionCustomInput.value = "";
    return;
  }
  const preset = statisticsRetentionInputs.find((input) => input.value === String(hours));
  if (preset) {
    preset.checked = true;
    statisticsRetentionCustomInput.value = "";
    return;
  }

  setRadioValue(statisticsRetentionInputs, "custom");
  statisticsRetentionCustomInput.value = String(Math.ceil(hours / 24));
}

function selectedStatisticsRetentionHours(): number {
  const value = selectedRadioValue(statisticsRetentionInputs, "720");
  if (value === "forever") {
    return 0;
  }
  if (value !== "custom") {
    return Number(value);
  }

  return Number(statisticsRetentionCustomInput.value || 30) * 24;
}

function updateLogControls(): void {
  const enabled = queryLogEnabledInput.checked;
  updatePersistencePrivacyControl();
  queryLogIgnoredInput.disabled = !enabled;

  for (const input of queryLogRetentionInputs) {
    input.disabled = !enabled;
  }

  queryLogRetentionCustomInput.disabled =
    !enabled || selectedRadioValue(queryLogRetentionInputs, "2160") !== "custom";
  customRetentionField.classList.toggle(
    "visible",
    enabled && selectedRadioValue(queryLogRetentionInputs, "2160") === "custom",
  );
}

function updateStatisticsControls(): void {
  const enabled = statisticsEnabledInput.checked;
  updatePersistencePrivacyControl();
  statisticsIgnoredInput.disabled = !enabled;

  for (const input of statisticsRetentionInputs) {
    input.disabled = !enabled;
  }

  statisticsRetentionCustomInput.disabled =
    !enabled || selectedRadioValue(statisticsRetentionInputs, "720") !== "custom";
  statisticsCustomRetentionField.classList.toggle(
    "visible",
    enabled && selectedRadioValue(statisticsRetentionInputs, "720") === "custom",
  );
}

function updatePersistencePrivacyControl(): void {
  anonymizeClientIpInput.disabled = !queryLogEnabledInput.checked && !statisticsEnabledInput.checked;
}

function updateDnsCacheControls(): void {
  const enabled = dnsCacheEnabledInput.checked;
  dnsCacheSizeInput.disabled = !enabled;
  dnsCacheMinTtlInput.disabled = !enabled;
  dnsCacheMaxTtlInput.disabled = !enabled;
  dnsCacheOptimisticInput.disabled = !enabled;
  dnsCacheOptimisticMaxStaleInput.disabled = !enabled || !dnsCacheOptimisticInput.checked;
  dnsCachePrefetchEnabledInput.disabled = !enabled;
  dnsCachePrefetchHitThresholdInput.disabled =
    !enabled || !dnsCachePrefetchEnabledInput.checked;
  clearDnsCacheButton.disabled = !enabled;
}

function updateResponseProtectionControls(): void {
  rebindingAllowedDomainsInput.disabled = !rebindingProtectionEnabledInput.checked;
}

function updateRuntimeWatchdogControls(): void {
  runtimeWatchdogIntervalInput.disabled = !runtimeWatchdogEnabledInput.checked;
}

function updateMonitoringApiControls(): void {
  const enabled = monitoringApiEnabledInput.checked;
  monitoringApiListenHostInput.disabled = !enabled;
  monitoringApiPortInput.disabled = !enabled;
  monitoringApiTokenInput.disabled = !enabled;
}

function updateBlockingModeControls(): void {
  const isCustom = selectedRadioValue(blockingModeInputs, "null_ip") === "custom_ip";
  blockingCustomFields.classList.toggle("visible", isCustom);
  blockingCustomIpv4Input.disabled = !isCustom;
  blockingCustomIpv6Input.disabled = !isCustom;
}

function parseClientNames(value: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of value.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#") || trimmed.startsWith("!")) {
      continue;
    }
    const spaceIndex = trimmed.search(/\s/);
    if (spaceIndex <= 0) {
      continue;
    }
    const ip = trimmed.slice(0, spaceIndex);
    const name = trimmed.slice(spaceIndex).trim();
    if (name.length > 0) {
      map.set(ip, name);
    }
  }
  return map;
}

function clientDisplayName(ip: string | null): string | null {
  if (!ip) {
    return null;
  }
  return clientNameMap.get(ip) ?? (ip === "127.0.0.1" || ip === "::1" ? t("本机") : null);
}

function formatClientLabel(ip: string | null): string {
  if (!ip) {
    return t("未知客户端");
  }
  const name = clientDisplayName(ip);
  return name ? t("{p0}（{p1}）", { p0: name, p1: ip }) : ip;
}

function formatClientRankLabel(ip: string): string {
  return ip === "127.0.0.1" || ip === "::1" ? ip : formatClientLabel(ip);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function formatUpdateError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.replace(/\s+/g, " ").trim();
  return normalized.length > 280 ? `${normalized.slice(0, 280)}...` : normalized;
}

function isRetriableUpdateError(error: unknown): boolean {
  const message = formatUpdateError(error).toLowerCase();
  const nonRetriableTokens = [
    "signature",
    "checksum",
    "hash",
    "digest",
    "verify",
    "invalid json",
    "decoding response body",
  ];
  if (nonRetriableTokens.some((token) => message.includes(token))) {
    return false;
  }

  const retriableTokens = [
    "error sending request",
    "failed to fetch",
    "timeout",
    "timed out",
    "dns",
    "tls",
    "ssl",
    "proxy",
    "connection",
    "network",
  ];
  return retriableTokens.some((token) => message.includes(token));
}

async function retryWithBackoff<T>(
  action: (attempt: number) => Promise<T>,
  delays: readonly number[],
  onRetry: (attempt: number, delayMs: number, error: unknown) => void,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= delays.length + 1; attempt += 1) {
    try {
      return await action(attempt);
    } catch (error) {
      lastError = error;
      const delayMs = delays[attempt - 1];
      if (!delayMs || !isRetriableUpdateError(error)) {
        throw error;
      }
      onRetry(attempt, delayMs, error);
      await sleep(delayMs);
    }
  }
  throw lastError;
}

function setUpdateStatus(kind: "info" | "ok" | "err", message: string, autoHideMs = 0): void {
  window.clearTimeout(updateStatusTimer);
  updateStatusElement.classList.remove("hidden", "ok", "err");
  updateStatusElement.setAttribute("role", kind === "err" ? "alert" : "status");
  updateStatusElement.setAttribute("aria-live", kind === "err" ? "assertive" : "polite");
  if (kind !== "info") {
    updateStatusElement.classList.add(kind);
  }
  updateStatusElement.textContent = message;

  if (autoHideMs > 0) {
    updateStatusTimer = window.setTimeout(() => {
      updateStatusElement.classList.add("hidden");
      updateStatusElement.textContent = "";
    }, autoHideMs);
  }
}

type GitHubRelease = {
  tag_name: string;
  body: string | null;
  html_url: string;
  assets: {
    name: string;
    browser_download_url: string;
  }[];
};

type GitHubReleaseAsset = {
  name: string;
  browser_download_url: string;
};

type GitHubReleaseInfo = {
  version: string;
  notes: string;
  downloadUrl: string;
};

function normalizeVersion(version: string): string {
  return version.trim().replace(/^v/i, "");
}

function resolveReleaseAssetUrl(assets: GitHubReleaseAsset[], pageUrl: string): string {
  const patterns = isMacOS
    ? [/universal.*\.dmg$/i, /\.dmg$/i]
    : [/_x64-setup\.exe$/i, /\.exe$/i, /\.msi$/i];

  for (const pattern of patterns) {
    const asset = assets.find(({ name }) => pattern.test(name));
    if (asset) {
      return asset.browser_download_url;
    }
  }
  return pageUrl;
}

async function fetchGitHubRelease(version: string): Promise<GitHubReleaseInfo> {
  const endpoint = `${RELEASES_API_URL}/tags/v${encodeURIComponent(normalizeVersion(version))}`;
  const response = await fetch(endpoint, {
    headers: { Accept: "application/vnd.github+json" },
    signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(t("GitHub Release 请求失败（HTTP {p0}）", { p0: response.status }));
  }

  const release = (await response.json()) as GitHubRelease;
  const releaseVersion = normalizeVersion(release.tag_name);
  if (!releaseVersion) {
    throw new Error(t("GitHub Release 缺少版本号"));
  }

  return {
    version: releaseVersion,
    notes: release.body?.trim() ?? "",
    downloadUrl: resolveReleaseAssetUrl(release.assets, release.html_url || RELEASES_URL),
  };
}

async function fetchGitHubReleaseWithRetry(version: string): Promise<GitHubReleaseInfo> {
  return retryWithBackoff(
    () => fetchGitHubRelease(version),
    CHECK_RETRY_DELAYS_MS,
    (attempt, delayMs, error) => {
      setUpdateStatus(
        "info",
        t("读取更新信息失败，{p0} 秒后重试（{p1}/{p2}）：{p3}", { p0: Math.round(delayMs / 1_000), p1: attempt, p2: CHECK_RETRY_DELAYS_MS.length, p3: formatUpdateError(error) }),
      );
    },
  );
}

function formatReleaseNotes(notes: string): string {
  const visibleLines: string[] = [];
  let hiddenSectionLevel: number | null = null;
  for (const line of notes.trim().split(/\r?\n/)) {
    const heading = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      if (hiddenSectionLevel !== null && level <= hiddenSectionLevel) {
        hiddenSectionLevel = null;
      }
      if (/^(验证|测试|质量验证|构建与验证|下载说明|sha-?256|校验和|checksums?)$/i.test(heading[2])) {
        hiddenSectionLevel = level;
        continue;
      }
    }
    if (hiddenSectionLevel === null) {
      visibleLines.push(line);
    }
  }
  return visibleLines
    .join("\n")
    .trim()
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
}

function showUpdateDialog(currentVersion: string, version: string, notes: string): void {
  const content = formatReleaseNotes(notes) || t("此版本暂未提供更新说明。");
  updateCurrentVersionElement.textContent = currentVersion;
  updateReleaseVersionElement.textContent = `v${version}`;
  updateReleaseNotesBodyElement.textContent = content;
  if (!updateDialog.open) {
    updateDialog.showModal();
  }
}

function closeUpdateDialog(): void {
  if (updateDialog.open) {
    updateDialog.close();
  }
}

function extractUrl(value: unknown): string | null {
  if (typeof value === "string" && value.startsWith("http")) {
    return value;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  const record = value as Record<string, unknown>;
  for (const key of ["url", "download_url", "html_url", "details_url"]) {
    const url = extractUrl(record[key]);
    if (url) {
      return url;
    }
  }
  return null;
}

// WKWebView 的 UA 无法区分 Apple Silicon 与 Intel，macOS 上按顺序尝试两个架构键
const MANUAL_DOWNLOAD_PLATFORM_KEYS = isMacOS
  ? ["darwin-aarch64", "darwin-x86_64"]
  : ["windows-x86_64"];

function resolveManualDownloadUrl(update: Update): string {
  const platforms = update.rawJson.platforms;
  if (platforms && typeof platforms === "object" && !Array.isArray(platforms)) {
    const platformMap = platforms as Record<string, unknown>;
    for (const key of MANUAL_DOWNLOAD_PLATFORM_KEYS) {
      const currentPlatformUrl = extractUrl(platformMap[key]);
      if (currentPlatformUrl) {
        return currentPlatformUrl;
      }
    }
    // 找不到当前平台键时不回退到其他平台的安装包，避免下错文件
  }

  return `${RELEASES_URL}/tag/v${update.version}`;
}

async function checkForUpdateWithRetry(): Promise<Update | null> {
  return retryWithBackoff(
    () => checkApplicationUpdate(),
    CHECK_RETRY_DELAYS_MS,
    (attempt, delayMs, error) => {
      setUpdateStatus(
        "info",
        t("检查更新失败，{p0} 秒后重试（{p1}/{p2}）：{p3}", { p0: Math.round(delayMs / 1_000), p1: attempt, p2: CHECK_RETRY_DELAYS_MS.length, p3: formatUpdateError(error) }),
      );
    },
  );
}

async function downloadAndInstallWithRetry(): Promise<void> {
  await retryWithBackoff(
    async (attempt) => {
      const candidate = await checkApplicationUpdate();
      if (!candidate) {
        throw new Error(t("重新检查时未发现可安装的新版本"));
      }

      pendingUpdate = candidate;
      manualDownloadUrl = resolveManualDownloadUrl(candidate);
      let downloaded = 0;
      let total = 0;
      const prefix =
        attempt > 1 ? t("第 {p0}/{p1} 次下载：", { p0: attempt, p1: DOWNLOAD_RETRY_DELAYS_MS.length + 1 }) : "";

      try {
        await candidate.downloadAndInstall(
          (event) => {
            if (event.event === "Started") {
              downloaded = 0;
              total = event.data.contentLength ?? 0;
              setUpdateStatus("info", `${prefix}${t("开始下载更新...")}`);
            } else if (event.event === "Progress") {
              downloaded += event.data.chunkLength;
              const percent = total ? Math.round((downloaded / total) * 100) : 0;
              setUpdateStatus("info", `${prefix}${t("下载中... {p0}%", { p0: percent })}`);
            } else if (event.event === "Finished") {
              setUpdateStatus("info", `${prefix}${t("下载完成，正在安装...")}`);
            }
          },
          { timeout: DOWNLOAD_TIMEOUT_MS },
        );
      } catch (error) {
        await candidate.close().catch(() => undefined);
        throw error;
      }
    },
    DOWNLOAD_RETRY_DELAYS_MS,
    (attempt, delayMs, error) => {
      setUpdateStatus(
        "info",
        t("下载更新失败，{p0} 秒后重试（{p1}/{p2}）：{p3}", { p0: Math.round(delayMs / 1_000), p1: attempt, p2: DOWNLOAD_RETRY_DELAYS_MS.length, p3: formatUpdateError(error) }),
      );
    },
  );
}

function renderDashboardSummaryWindow(
  startedAt?: number | null,
  endedAt?: number | null,
): void {
  if (startedAt !== undefined) {
    latestDashboardStartedAt = startedAt;
  }
  if (endedAt !== undefined) {
    latestDashboardEndedAt = endedAt;
  }
  const summaryStartedAt = startedAt ?? latestDashboardStartedAt;
  const summaryEndedAt = endedAt ?? latestDashboardEndedAt;
  let label: string;
  const effectiveHours = dashboardStatisticsHours ?? currentStatisticsRetentionHours;
  if (effectiveHours !== 0) {
    label = effectiveHours < 48
      ? t("最近 {p0} 小时", { p0: effectiveHours })
      : t("最近 {p0} 天", { p0: Math.max(1, Math.ceil(effectiveHours / 24)) });
  } else if (summaryStartedAt && summaryEndedAt) {
    const start = new Date(summaryStartedAt * 1000);
    const end = new Date(summaryEndedAt * 1000);
    const days = Math.max(1, Math.floor((end.getTime() - start.getTime()) / 86_400_000) + 1);
    if (days < 32) {
      label = t("累计汇总 {p0} 天", { p0: days });
    } else {
      const months = Math.max(
        1,
        (end.getFullYear() - start.getFullYear()) * 12 + end.getMonth() - start.getMonth() + 1,
      );
      label = t("累计汇总 {p0} 个月", { p0: months });
    }
  } else {
    label = t("暂无汇总数据");
  }
  query("#query_rank_window").textContent = label;
  query("#blocked_rank_window").textContent = label;
  query("#client_rank_window").textContent = label;
  query("#blocklist_rank_window").textContent = label;
  query("#upstream_rank_window").textContent = label;
  query("#upstream_latency_window").textContent = label;
}

function updateDashboardRangeOptions(): void {
  Array.from(dashboardStatisticsRange.options).forEach((option) => {
    if (option.value === "configured" || option.value === "0") {
      option.disabled = false;
      return;
    }
    const hours = Number(option.value);
    option.disabled = currentStatisticsRetentionHours > 0 && hours > currentStatisticsRetentionHours;
  });
  if (dashboardStatisticsRange.selectedOptions[0]?.disabled) {
    dashboardStatisticsRange.value = "configured";
    dashboardStatisticsHours = undefined;
  }
  syncCustomSelect(dashboardStatisticsRange);
}

function updateFilterField(id: string, target: HTMLInputElement): void {
  const field = target.dataset.field;
  filtersState = filtersState.map((filter) => {
    if (filter.id !== id) {
      return filter;
    }

    if (field === "enabled") {
      return { ...filter, enabled: target.checked };
    }
    if (field === "name") {
      return { ...filter, name: target.value };
    }
    if (field === "url") {
      return { ...filter, url: target.value };
    }
    return filter;
  });
  updateConfigDirtyState();
}

function openQueryRuleDialog(domain: string): void {
  pendingQueryRuleDomain = domain;
  queryRuleDomain.textContent = domain;
  queryRuleTarget.value = "";
  queryRuleDialog.showModal();
  window.setTimeout(() => queryRuleTarget.focus(), 0);
}

function closeQueryRuleDialog(): void {
  pendingQueryRuleDomain = "";
  queryRuleDialog.close();
}

async function runQueryLogRuleAction(
  domain: string,
  action: QueryLogRuleAction,
  target?: string,
): Promise<void> {
  setBusy(true);
  try {
    const result = await applyQueryLogRule(domain, action, target);
    renderStatus(result.status, { renderDashboard: false });
    await loadConfig();
    showMessage(result.message, false);
    await refreshQueryLogs({ auto: true });
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    setBusy(false);
  }
}

function closeRuntimeStatusMenu(): void {
  headerRuntime.classList.remove("open");
  runtimeStatusButton.setAttribute("aria-expanded", "false");
}

function renderRuntimeStatus(status: RuntimeStatus): void {
  const state = !status.running
    ? "stopped"
    : status.protection_paused
      ? "paused"
      : status.error
        ? "error"
        : "running";
  const label = state === "running"
    ? t("保护运行中")
    : state === "paused"
      ? t("过滤已暂停")
      : state === "error"
        ? t("运行异常")
        : t("服务已停止");
  runtimeStatusButton.className = `runtime-status-trigger ${state}`;
  runtimeStatusLabel.textContent = label;
  runtimeStatusDetail.textContent = state === "paused"
    ? t("DNS 仍在运行，黑名单过滤将在{p0}后自动恢复。", { p0: formatPauseRemaining(status.protection_paused_until) })
    : state === "running"
      ? t("正在监听 {p0}，可临时暂停黑名单过滤。", { p0: status.listen_addr })
      : state === "error"
        ? status.error || t("DNS 运行时出现异常")
        : t("请先启动 DNS 服务，再使用临时暂停。");

  runtimeStatusMenu.querySelectorAll<HTMLButtonElement>('[data-protection-action="pause"]')
    .forEach((button) => {
      button.disabled = !status.running || status.protection_paused;
    });
  const resumeButton = runtimeStatusMenu.querySelector<HTMLButtonElement>(
    '[data-protection-action="resume"]',
  );
  if (resumeButton) {
    resumeButton.disabled = !status.running || !status.protection_paused;
  }

  window.clearTimeout(pauseExpiryTimer);
  pauseExpiryTimer = undefined;
  if (status.protection_paused_until) {
    const remainingMs = Math.max(0, status.protection_paused_until * 1000 - Date.now());
    pauseExpiryTimer = window.setTimeout(() => {
      void refreshStatus({ auto: true });
    }, Math.min(remainingMs + 250, 2_147_000_000));
  }

  const traySignature = `${status.running}:${status.protection_paused}:${status.protection_paused_until ?? 0}`;
  if (traySignature !== lastTrayRuntimeSignature) {
    lastTrayRuntimeSignature = traySignature;
    void setTrayRuntimeStatus(
      status.running,
      status.protection_paused,
      status.protection_paused_until,
    ).catch((error) => console.warn("同步托盘运行状态失败", error));
  }
}

function formatPauseRemaining(deadline: number | null): string {
  if (!deadline) {
    // 与"更新对话框-稍后"按钮同形不同义，这里换个说法避免字典键冲突
    return t("片刻");
  }
  const seconds = Math.max(0, deadline - Math.floor(Date.now() / 1000));
  if (seconds >= 3600) {
    return t("{p0} 小时", { p0: Math.ceil(seconds / 3600) });
  }
  return t("{p0} 分钟", { p0: Math.max(1, Math.ceil(seconds / 60)) });
}

async function runProtectionAction(
  action: "pause" | "resume",
  durationSeconds = 0,
): Promise<void> {
  setBusy(true);
  try {
    const status = action === "resume"
      ? await resumeProtection()
      : await pauseProtection(durationSeconds);
    renderStatus(status, { renderDashboard: activeView === "dashboard" });
    showMessage(
      action === "resume"
        ? t("过滤保护已恢复")
        : t("过滤保护已暂停 {p0}", { p0: formatPauseRemaining(status.protection_paused_until) }),
      false,
    );
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus({ auto: true });
  } finally {
    setBusy(false);
  }
}

function renderRankTable(
  selector: string,
  counts: Record<string, number>,
  total: number,
  formatLabel?: (key: string) => string,
): void {
  const container = query<HTMLDivElement>(selector);
  const rows = Object.entries(counts)
    .filter(([domain, count]) => domain.length > 0 && count > 0)
    .sort((a, b) => b[1] - a[1] || compareRankLabel(a[0], b[0]))
    .slice(0, RANK_ROW_LIMIT);

  if (rows.length === 0) {
    setHtmlIfChanged(container, `<div class="empty-rank">${t("暂无请求数据")}</div>`);
    return;
  }

  const maxCount = rows[0]?.[1] ?? 1;
  const html = rows
    .map(([key, count]) => {
      const barWidth = maxCount > 0 ? Math.max((count / maxCount) * 100, 2) : 0;
      const percent = total > 0 ? count / total : 0;
      const label = formatLabel ? formatLabel(key) : key;

      return `
        <div class="rank-row">
          <div class="rank-domain" title="${escapeHtml(label)}">
            <span>${escapeHtml(label)}</span>
          </div>
          <div class="rank-value">
            <span class="rank-count">${formatCount(count)}</span>
            <span class="rank-percent">${formatPercent(percent)}</span>
            <span class="rank-bar"><span style="width: ${barWidth.toFixed(2)}%"></span></span>
          </div>
        </div>
      `;
    })
    .join("");
  setHtmlIfChanged(container, html);
}

function renderClientOverview(
  requests: Record<string, number>,
  blocked: Record<string, number>,
): void {
  const rows = Object.entries(requests)
    .filter(([client, count]) => client.length > 0 && count > 0)
    .sort((a, b) => b[1] - a[1] || compareRankLabel(a[0], b[0]))
    .slice(0, RANK_ROW_LIMIT);
  if (rows.length === 0) {
    setHtmlIfChanged(clientRankBody, `<div class="empty-rank">${t("暂无客户端数据")}</div>`);
    return;
  }
  const html = rows.map(([client, count]) => {
    const blockedCount = blocked[client] ?? 0;
    const label = formatClientRankLabel(client);
    return `
      <div class="rank-row client-rank-row">
        <button class="rank-domain rank-client-button" data-client-log="${escapeHtml(client)}" type="button" title="${t("查看 {p0} 的查询日志", { p0: escapeHtml(label) })}">
          <span>${escapeHtml(label)}</span>
        </button>
        <span class="client-rank-metric">${formatCount(count)}</span>
        <span class="client-rank-metric blocked">${formatRate(blockedCount, count)}</span>
      </div>
    `;
  }).join("");
  setHtmlIfChanged(clientRankBody, html);
}

function renderUpstreamRequestRank(
  selector: string,
  rows: UpstreamRequestStat[],
  total: number,
): void {
  const container = query<HTMLDivElement>(selector);
  const visibleRows = rows
    .filter((row) => row.upstream.length > 0 && row.requests > 0)
    .sort(
      (a, b) => b.requests - a.requests || compareRankLabel(a.upstream, b.upstream),
    )
    .slice(0, RANK_ROW_LIMIT);

  if (visibleRows.length === 0) {
    setHtmlIfChanged(container, `<div class="empty-rank">${t("暂无上游请求数据")}</div>`);
    return;
  }

  const maxCount = visibleRows[0]?.requests ?? 1;
  const html = visibleRows
    .map((row) => {
      const barWidth = maxCount > 0 ? Math.max((row.requests / maxCount) * 100, 2) : 0;
      const percent = total > 0 ? row.requests / total : 0;

      return `
        <div class="rank-row">
          <div class="rank-domain" title="${escapeHtml(row.upstream)}">
            <span>${escapeHtml(row.upstream)}</span>
          </div>
          <div class="rank-value">
            <span class="rank-count">${formatCount(row.requests)}</span>
            <span class="rank-percent">${formatPercent(percent)}</span>
            <span class="rank-bar"><span style="width: ${barWidth.toFixed(2)}%"></span></span>
          </div>
        </div>
      `;
    })
    .join("");
  setHtmlIfChanged(container, html);
}

function renderUpstreamLatencyRank(selector: string, rows: UpstreamLatencyStat[]): void {
  const container = query<HTMLDivElement>(selector);
  const visibleRows = rows
    .filter((row) => row.upstream.length > 0)
    .sort((a, b) => a.avg_ms - b.avg_ms || compareRankLabel(a.upstream, b.upstream))
    .slice(0, RANK_ROW_LIMIT);

  if (visibleRows.length === 0) {
    setHtmlIfChanged(container, `<div class="empty-rank">${t("暂无上游响应时间数据")}</div>`);
    return;
  }

  const html = visibleRows
    .map(
      (row) => `
        <div class="rank-row">
          <div class="rank-domain" title="${escapeHtml(row.upstream)}">
            <span>${escapeHtml(row.upstream)}</span>
          </div>
          <div class="rank-latency">${formatCount(row.avg_ms)} ms</div>
        </div>
      `,
    )
    .join("");
  setHtmlIfChanged(container, html);
}

function compareRankLabel(a: string, b: string): number {
  return a.localeCompare(b, "zh-CN", { numeric: true, sensitivity: "base" });
}

function setTextIfChanged(element: Element, value: string): void {
  if (element.textContent !== value) {
    element.textContent = value;
  }
}

function setHtmlIfChanged(element: HTMLElement, value: string): void {
  if (element.dataset.renderedHtml !== value) {
    element.innerHTML = value;
    element.dataset.renderedHtml = value;
  }
}

function toggleEditing(current: Set<string>, id: string): Set<string> {
  const next = new Set(current);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  return next;
}

function setBusy(busy: boolean): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>("button")) {
    button.disabled = busy;
  }
  if (!busy && currentStorageInfo) {
    renderStorageInfo(currentStorageInfo);
  }
  if (!busy) {
    updateConfigSaveState();
    if (latestRuntimeStatus) {
      renderRuntimeStatus(latestRuntimeStatus);
    }
  }
}

function markContentScrolling(): void {
  if (!isContentScrolling) {
    isContentScrolling = true;
    closeCustomSelects();
  }
  if (scrollIdleTimer !== undefined) {
    window.clearTimeout(scrollIdleTimer);
  }

  scrollIdleTimer = window.setTimeout(() => {
    isContentScrolling = false;
    if (queuedAutoRefresh) {
      queuedAutoRefresh = false;
      refreshActiveView();
    }
  }, 240);
}

function setRefreshButtonState(button: HTMLButtonElement | undefined, refreshing: boolean): void {
  if (!button) {
    return;
  }

  button.classList.toggle("refreshing", refreshing);
  button.disabled = refreshing;
  button.setAttribute("aria-busy", String(refreshing));
}

function setDashboardLoading(loading: boolean): void {
  dashboardView.classList.toggle("is-loading", loading);
  dashboardView.setAttribute("aria-busy", String(loading));
  dashboardRangeField.classList.toggle("is-loading", loading);
  customSelects
    .get(dashboardStatisticsRange)
    ?.trigger.setAttribute("aria-busy", String(loading));
}

function setFilterUpdating(updating: boolean): void {
  updateFiltersButton.classList.toggle("loading", updating);
  updateFiltersButton.textContent = updating ? t("更新中") : t("检查更新");
  updateFiltersButton.disabled = updating;
  addFilterButton.disabled = updating;
  filtersTable.classList.toggle("is-updating", updating);
  for (const control of filtersTable.querySelectorAll<HTMLInputElement | HTMLButtonElement>(
    "input, button",
  )) {
    control.disabled = updating;
  }
  cancelFilterUpdateButton.classList.toggle("hidden", !updating);
  cancelFilterUpdateButton.disabled = !updating;
  cancelFilterUpdateButton.textContent = t("取消更新");
  filterUpdateProgressElement.classList.toggle("hidden", !updating);
  if (updating) {
    filterUpdateProgressElement.textContent = t("正在准备更新…");
  }
}

function updateFilterProxyControls(): void {
  const mode = filterProxyModeInput.value as FilterProxyMode;
  filterProxyUrlField.classList.toggle("hidden", mode !== "custom");
  filterProxyUrlInput.disabled = mode !== "custom";

  if (mode === "direct") {
    filterProxyStatus.textContent = t("后台将直接连接，不使用任何系统或环境代理。");
    return;
  }
  if (mode === "custom") {
    filterProxyStatus.textContent = t("后台服务将使用这里填写的 HTTP/HTTPS 代理地址。");
    return;
  }

  const proxy = detectedSystemProxy ?? savedSystemProxyUrl;
  filterProxyStatus.textContent = proxy
    ? t("已同步当前用户的系统代理：{p0}", { p0: proxy })
    : t("当前未检测到系统代理；后台将按系统默认网络直接连接。");
}

function startFilterUpdateProgressPolling(): void {
  if (filterUpdateProgressTimer !== undefined) {
    window.clearInterval(filterUpdateProgressTimer);
  }
  void refreshFilterUpdateProgress();
  filterUpdateProgressTimer = window.setInterval(() => {
    void refreshFilterUpdateProgress();
  }, 400);
}

function stopFilterUpdateProgressPolling(): void {
  if (filterUpdateProgressTimer !== undefined) {
    window.clearInterval(filterUpdateProgressTimer);
    filterUpdateProgressTimer = undefined;
  }
}

async function refreshFilterUpdateProgress(): Promise<void> {
  if (filterUpdateProgressInFlight) {
    return;
  }
  filterUpdateProgressInFlight = true;
  try {
    renderFilterUpdateProgress(await getFilterUpdateProgress());
  } catch (error) {
    console.warn("读取过滤器更新进度失败", error);
  } finally {
    filterUpdateProgressInFlight = false;
  }
}

function renderFilterUpdateProgress(progress: FilterUpdateProgress): void {
  if (!progress.running && progress.total === 0) {
    return;
  }
  const suffix = progress.cancel_requested
    ? ` · ${t("正在取消")}`
    : ` · ${t("成功 {p0} · 失败 {p1}", { p0: progress.updated, p1: progress.failed })}`;
  filterUpdateProgressElement.textContent = t("已处理 {p0}/{p1}{p2}", { p0: progress.completed, p1: progress.total, p2: suffix });
  cancelFilterUpdateButton.disabled = progress.cancel_requested || !progress.running;
  cancelFilterUpdateButton.textContent = progress.cancel_requested ? t("正在取消") : t("取消更新");
}

function setQueryLogLoading(loading: boolean, background = false): void {
  queryLogRefreshButton.classList.toggle("loading", loading);
  syncQueryLogPaginationDisabled(loading);
  if (background) {
    return;
  }
  queryLogRefreshButton.disabled = loading;
  queryLogFilterInput.disabled = loading;
  queryLogFilterButton.disabled = loading;
  queryLogAdvancedButton.disabled = loading;
  queryLogTimeRange.disabled = loading;
  queryLogSource.disabled = loading;
  queryLogQueryType.disabled = loading;
  queryLogSort.disabled = loading;
  queryLogResetButton.disabled = loading;
  if (loading) {
    closeQueryLogFilter();
  }
}

function waitForPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}


type MessageAction = {
  label: string;
  run: () => void | Promise<void>;
};

type MessageOptions = {
  actions?: MessageAction[];
};

function showMessage(value: string, isError: boolean, options: MessageOptions = {}): void {
  clearTimeout(messageTimer);

  document.querySelectorAll(".message").forEach((el) => el.remove());

  if (value.length === 0) return;

  const el = document.createElement("div");
  el.className = isError ? "message error" : "message";
  el.setAttribute("role", isError ? "alert" : "status");
  el.setAttribute("aria-live", isError ? "assertive" : "polite");
  el.setAttribute("aria-atomic", "true");

  const icon = document.createElement("span");
  icon.className = "message-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.innerHTML = isError
    ? `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="m9 9 6 6m0-6-6 6"></path></svg>`
    : `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="m8 12 2.5 2.5L16 9"></path></svg>`;

  const content = document.createElement("div");
  content.className = "message-content";
  const text = document.createElement("span");
  text.className = "msg-text";
  text.textContent = value;
  content.appendChild(text);

  const dismiss = () => {
    window.clearTimeout(messageTimer);
    el.classList.add("fade-out");
    window.setTimeout(() => el.remove(), 300);
  };

  if (options.actions?.length) {
    const actions = document.createElement("div");
    actions.className = "message-actions";
    options.actions.forEach((action) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "message-action";
      button.textContent = action.label;
      button.addEventListener("click", () => {
        dismiss();
        void Promise.resolve(action.run()).catch((error) => {
          console.error(`通知操作“${action.label}”失败`, error);
          showMessage(t("{p0}失败，请稍后重试。", { p0: action.label }), true);
        });
      });
      actions.appendChild(button);
    });
    content.appendChild(actions);
  }
  el.append(icon, content);

  if (isError) {
    const close = document.createElement("button");
    close.type = "button";
    close.className = "message-close";
    close.textContent = t("关闭");
    close.setAttribute("aria-label", t("关闭错误提示"));
    close.addEventListener("click", dismiss);
    el.appendChild(close);
  }
  document.body.appendChild(el);

  if (!isError) {
    messageTimer = window.setTimeout(dismiss, 3000);
  }
}

renderAboutRuntimeInfo();

// 切换语言是整页重载，这里先把面板切回原来的页面，避免启动过程中先闪一下仪表盘。
// 真正的数据刷新仍然留给启动流程末尾的 setActiveView。
const viewAfterReload = takeViewAfterReload();
if (viewAfterReload) {
  applyViewVisibility(viewAfterReload);
}

void bootstrapApplication().catch((error) => {
  console.error("应用启动失败", error);
  showMessage(t("应用启动失败：{p0}", { p0: String(error) }), true);
  logLoadTime("前端启动失败", frontendStartedAt, String(error));
});
