import { getVersion } from "@tauri-apps/api/app";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import {
  applyQueryLogRule,
  cancelFilterUpdate,
  clearQueryLogs as clearQueryLogsCommand,
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
  setTrayRuntimeStatus,
  startDns,
  stopDns,
  takeOverWindowsSystemDns,
  uninstallMacosService,
  uninstallWindowsService,
  updateFilters as updateFiltersCommand,
} from "./api";
import appIconUrl from "./app-icon.png";
import { buildDailyTrafficSeries, renderSparkline } from "./charts";
import { query } from "./dom";
import {
  escapeHtml,
  formatCount,
  formatBytes,
  formatElapsedMs,
  formatLogDate,
  formatLogTime,
  formatPercent,
  formatRate,
  formatTime,
} from "./format";
import { renderAppTemplate } from "./template";
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
  QueryLogPage,
  QueryLogRecord,
  QueryLogRuleAction,
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
import "./style.css";

const frontendStartedAt = performance.now();
const CURRENT_CONFIG_SCHEMA_VERSION = 14;

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
  throw new Error("缺少应用挂载节点");
}

const templateStarted = performance.now();
app.innerHTML = renderAppTemplate(appIconUrl);
logLoadTime("页面模板渲染", templateStarted);

let activeView: ViewName = "dashboard";
let filtersState: FilterSubscription[] = [];
let editingFilterIds = new Set<string>();
let currentQueryLogEnabled = true;
let refreshInFlight = false;
let isContentScrolling = false;
let queuedAutoRefresh = false;
let scrollIdleTimer: number | undefined;
let pendingUpdate: Update | null = null;
let manualDownloadUrl = "";
let queryLogPage = 1;
let queryLogTotal = 0;
let queryLogRefreshInFlight = false;
let queryLogRefreshQueued = false;
let queryLogSearchTimer: number | undefined;
let queryLogSearchComposing = false;
let lastDashboardRefreshAt: number | null = null;
let currentConfigSchemaVersion = CURRENT_CONFIG_SCHEMA_VERSION;
let currentStatisticsRetentionHours = 30 * 24;
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
  repository: "https://github.com/wanwan-doudou/DnsBlackhole",
  releases: RELEASES_URL,
  issues: "https://github.com/wanwan-doudou/DnsBlackhole/issues",
  license: "https://github.com/wanwan-doudou/DnsBlackhole/blob/main/LICENSE",
} as const;
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

const contentElement = query<HTMLDivElement>(".content");
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
const dnsCachePrefetchEnabledInput = query<HTMLInputElement>("#dns_cache_prefetch_enabled");
const dnsCachePrefetchHitThresholdInput = query<HTMLInputElement>(
  "#dns_cache_prefetch_hit_threshold",
);
const runtimeWatchdogEnabledInput = query<HTMLInputElement>("#runtime_watchdog_enabled");
const runtimeWatchdogIntervalInput = query<HTMLInputElement>("#runtime_watchdog_interval_seconds");
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
const dnsRewritesInput = query<HTMLTextAreaElement>("#dns_rewrites");
const clientNamesInput = query<HTMLTextAreaElement>("#client_names");
const queryLogIgnoredInput = query<HTMLTextAreaElement>("#query_log_ignored_domains");
const statisticsIgnoredInput = query<HTMLTextAreaElement>("#statistics_ignored_domains");
const clearQueryLogsButton = query<HTMLButtonElement>("#clear_query_logs_btn");
const clearStatisticsButton = query<HTMLButtonElement>("#clear_statistics_btn");
const blacklistInput = query<HTMLTextAreaElement>("#blacklist");
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
const queryLogSearchInput = query<HTMLInputElement>("#query_log_search");
const queryLogFilterInput = query<HTMLSelectElement>("#query_log_filter");
const queryLogFilterMenu = query<HTMLDivElement>("#query_log_filter_menu");
const queryLogFilterButton = query<HTMLButtonElement>("#query_log_filter_button");
const queryLogFilterLabel = query<HTMLElement>("#query_log_filter_label");
const queryLogBody = query<HTMLDivElement>("#query_log_body");
const queryLogPageInfo = query<HTMLElement>("#query_log_page_info");
const queryLogPrevButton = query<HTMLButtonElement>("#query_log_prev_btn");
const queryLogNextButton = query<HTMLButtonElement>("#query_log_next_btn");
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
const runDiagnosticButton = query<HTMLButtonElement>("#run_diagnostic_btn");
const diagnosticResults = query<HTMLDivElement>("#diagnostic_results");

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
  elements.valueLabel.textContent = selectedOption?.textContent || "请选择";
  elements.trigger.disabled = select.disabled;
  elements.options.forEach((button) => {
    const selected = button.dataset.value === select.value;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-selected", String(selected));
  });
}

[filterProxyModeInput, filterUpdateIntervalInput, diagnosticQueryTypeInput].forEach(
  initializeCustomSelect,
);

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
    void openUrl(ABOUT_LINKS[link]).catch((error) => {
      console.error("打开关于链接失败", error);
      showMessage(`打开浏览器失败：${String(error)}`, true);
    });
  });
});

function closeQueryLogFilter(): void {
  queryLogFilterMenu.classList.remove("open");
  queryLogFilterButton.setAttribute("aria-expanded", "false");
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
  if (event.key === "Escape") {
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
  void runProtectionAction(
    button.dataset.protectionAction === "resume"
      ? "resume"
      : "pause",
    Number(button.dataset.duration || 0),
  );
});

document.querySelectorAll<HTMLButtonElement>("[data-refresh-dashboard]").forEach((button) => {
  button.addEventListener("click", async () => {
    await refreshStatus({ button });
  });
});

queryLogRefreshButton.addEventListener("click", async () => {
  await refreshQueryLogs({ button: queryLogRefreshButton });
});

queryLogSearchInput.addEventListener("input", () => {
  scheduleQueryLogSearch();
});

queryLogSearchInput.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") {
    return;
  }
  event.preventDefault();
  window.clearTimeout(queryLogSearchTimer);
  queryLogPage = 1;
  void refreshQueryLogs();
});

queryLogSearchInput.addEventListener("compositionstart", () => {
  queryLogSearchComposing = true;
  window.clearTimeout(queryLogSearchTimer);
});

queryLogSearchInput.addEventListener("compositionend", () => {
  queryLogSearchComposing = false;
  scheduleQueryLogSearch();
});

queryLogFilterInput.addEventListener("change", () => {
  queryLogPage = 1;
  void refreshQueryLogs();
});

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
  option.addEventListener("click", (event) => {
    event.stopPropagation();
    const value = option.dataset.filter as QueryLogFilter | undefined;
    if (!value || queryLogFilterInput.value === value) {
      closeQueryLogFilter();
      return;
    }
    setQueryLogFilterValue(value);
    closeQueryLogFilter();
    queryLogFilterInput.dispatchEvent(new Event("change"));
  });
});

queryLogFilterButton.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeQueryLogFilter();
    queryLogFilterButton.focus();
  }
});

queryLogPrevButton.addEventListener("click", () => {
  if (queryLogPage <= 1) {
    return;
  }
  queryLogPage -= 1;
  void refreshQueryLogs();
});

queryLogNextButton.addEventListener("click", () => {
  if (queryLogPage >= totalQueryLogPages()) {
    return;
  }
  queryLogPage += 1;
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
dnsCachePrefetchEnabledInput.addEventListener("change", updateDnsCacheControls);
rebindingProtectionEnabledInput.addEventListener("change", updateResponseProtectionControls);
runtimeWatchdogEnabledInput.addEventListener("change", updateRuntimeWatchdogControls);
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
    showMessage("请先保存当前配置更改，再从查询日志添加规则", true);
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
    showMessage("请填写 DNS 重写目标 IP", true);
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
  if (readOnly || !target.closest(CONFIG_VIEW_SELECTOR)) {
    return;
  }
  window.queueMicrotask(updateConfigDirtyState);
}

app.addEventListener("input", handleConfigFieldChange);
app.addEventListener("change", handleConfigFieldChange);

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

startButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    await saveConfigOnly();
    const status = await startDns();
    renderStatus(status);
    showMessage("DNS 服务已启动", false);
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    setBusy(false);
  }
});

stopButton.addEventListener("click", async () => {
  await runStatusAction(() => stopDns(), "DNS 服务已停止");
});

addFilterButton.addEventListener("click", () => {
  const id = `custom-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  filtersState = [
    ...filtersState,
    {
      id,
      name: "新黑名单",
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
  cancelFilterUpdateButton.textContent = "正在取消";
  try {
    const progress = await cancelFilterUpdate();
    renderFilterUpdateProgress(progress);
  } catch (error) {
    cancelFilterUpdateButton.disabled = false;
    cancelFilterUpdateButton.textContent = "取消更新";
    showMessage(String(error), true);
  }
});

clearDnsCacheButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    const status = await clearDnsCacheCommand();
    renderStatus(status);
    showMessage("DNS 缓存已清除", false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    setBusy(false);
    updateDnsCacheControls();
  }
});

clearFilterCacheButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    "这会删除可重新生成的规则编译缓存。已下载的远程黑名单和当前生效规则不会删除；下次启动或规则变更时会自动重新生成缓存。是否继续？",
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
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: "选择 DnsBlackhole 数据存储目录",
      defaultPath: currentStorageInfo.current_path,
    });
    if (typeof selected === "string") {
      await selectDataStoragePath(selected);
    }
  } catch (error) {
    showMessage(`选择数据目录失败：${String(error)}`, true);
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
      ? `检测到现有 DnsBlackhole 数据：\n${targetPath}\n\n应用将验证并备份该数据库，然后切换使用此目录。现有目录和当前目录都不会被删除。是否继续？`
      : `应用将重启并把数据库与过滤器缓存迁移到：\n${targetPath}\n\n目标数据验证成功后才会清理原目录。是否继续？`,
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
        ? "现有数据接管任务已保存，正在重启应用…"
        : "迁移任务已保存，正在重启应用…",
      false,
    );
    await relaunch();
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
  checkUpdateButton.textContent = "检查中";
  setUpdateStatus("info", "正在检查更新...");
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

      setUpdateStatus("ok", `发现新版本 v${pendingUpdate.version}`);
      showUpdateDialog(currentVersion, pendingUpdate.version, notes);
      installUpdateButton.disabled = false;
      manualDownloadButton.disabled = false;
    } else {
      setUpdateStatus("ok", `已是最新版本 v${currentVersion}`, 3500);
    }
  } catch (error) {
    console.error("检查更新失败", error);
    const message = formatUpdateError(error);
    if (/platform.+(was )?not found/i.test(message)) {
      setUpdateStatus("err", "当前平台暂无自动更新包，请前往 GitHub Releases 手动下载");
    } else {
      setUpdateStatus("err", `检查更新失败：${message}`);
    }
    manualDownloadUrl = "";
  } finally {
    checkUpdateButton.disabled = false;
    checkUpdateButton.classList.remove("loading");
    checkUpdateButton.textContent = "检查更新";
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
    setUpdateStatus("ok", "安装完成，即将重启应用...");
    await relaunch();
  } catch (error) {
    console.error("更新失败", error);
    const fallbackTip = manualDownloadUrl
      ? "\n可重试，或点击“浏览器下载”手动安装。"
      : "";
    setUpdateStatus("err", `更新失败：${formatUpdateError(error)}${fallbackTip}`);
    installUpdateButton.disabled = false;
    manualDownloadButton.disabled = false;
  }
});

manualDownloadButton.addEventListener("click", async () => {
  const url = manualDownloadUrl || RELEASES_URL;
  closeUpdateDialog();
  manualDownloadButton.disabled = true;

  try {
    await openUrl(url);
  } catch (error) {
    console.error("打开下载链接失败", error);
    setUpdateStatus("err", `打开浏览器失败：${formatUpdateError(error)}\n下载地址：${url}`);
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
      showMessage("请在“系统设置 → 通用 → 登录项与扩展”中批准 DnsBlackhole 后台服务", false);
      // 直接带用户到批准页面，避免在设置里找不到入口
      await openMacosServiceSettings();
    } else if (status.enabled && !status.needsRepair) {
      showMessage("macOS DNS 后台服务已启用", false);
      await refreshAfterBackgroundServiceEnabled();
    } else if (status.needsRepair) {
      showMessage(
        "后台服务已注册但暂未响应，请稍后重新进入本页检查；若持续无响应请重启 Mac 后再试",
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
    "卸载后台服务后，DNS 将无法监听 53 端口，局域网设备的 DNS 查询会立即失败。是否继续卸载？",
  );
  if (!confirmed) {
    return;
  }
  uninstallMacosServiceButton.disabled = true;
  uninstallMacosServiceButton.classList.add("loading");
  try {
    const status = await uninstallMacosService();
    renderMacosServiceStatus(status);
    showMessage("macOS DNS 后台服务已卸载", false);
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
    "这会永久删除全部查询日志，但不会删除统计数据和配置。清除后，新查询仍会继续记录。是否继续？",
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  clearQueryLogsButton.classList.add("loading");
  try {
    const status = await clearQueryLogsCommand();
    renderStatus(status);
    queryLogPage = 1;
    await refreshQueryLogs();
    await loadStorageInfo();
    showMessage("查询日志已清除，统计数据未受影响", false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    clearQueryLogsButton.classList.remove("loading");
    setBusy(false);
  }
});

clearStatisticsButton.addEventListener("click", async () => {
  const confirmed = window.confirm(
    "这会永久删除全部累计统计、趋势和排行，但不会删除查询日志和配置。清除后将从新的 DNS 查询重新统计。是否继续？",
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
    showMessage("统计数据已清除，查询日志未受影响", false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    clearStatisticsButton.classList.remove("loading");
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
      showMessage("Windows DNS 系统服务已安装并启动", false);
      await refreshAfterBackgroundServiceEnabled();
    } else {
      showMessage("系统服务已注册但暂未就绪，请稍候重试；详情可查看服务日志", true);
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
    "卸载 Windows DNS 系统服务后，127.0.0.1/::1 将不再提供 DNS；若系统 DNS 已接管，会先自动恢复原 DNS。是否继续？",
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
    showMessage("Windows DNS 系统服务已卸载，原 DNS 已恢复，数据和配置未删除", false);
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
      ? "同步后，当前活动的有线或无线网卡会使用 127.0.0.1 和 ::1。每张网卡现有的自动获取或手动 DNS 都会分别保存；已在 Windows 中改过的配置会作为新的恢复配置。是否继续？"
      : "接管后，当前已连接的物理网卡将只使用 127.0.0.1 和 ::1 作为 DNS，不设置公共备用 DNS。每张网卡的原 DNS（包括自动获取）会先分别保存，可随时恢复。是否继续？",
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
          ? "当前活动网卡已同步接管"
          : "系统 DNS 已接管，所有 DNS 查询将交给 DnsBlackhole"
        : "系统 DNS 备份已保存，但接管状态需要检查",
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
    showMessage("请至少填写一个自定义 DNS 服务器地址", true);
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
          ? "已恢复仍由 DnsBlackhole 接管的 DNS；在 Windows 中另行修改的配置保持不变"
          : "已恢复为所选外部 DNS"
        : "已解除本机 DNS，现在可以重新接管并保存该恢复配置",
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
  if (!windowsCoreReady && !configReady) {
    activeView = "settings";
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
  setActiveView(activeView);
  logLoadTime("初始页面切换与渲染", initialViewStarted, `view=${activeView}`);
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
  return (
    queryLogPage === 1 &&
    queryLogFilterInput.value === "all" &&
    queryLogSearchInput.value.trim() === "" &&
    !queryLogSearchComposing
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
      throw new Error("DNS 服务返回了空配置或配置格式无效");
    }
    currentConfigSchemaVersion = Math.max(config.schema_version, CURRENT_CONFIG_SCHEMA_VERSION);
    currentStatisticsRetentionHours = config.statistics_retention_hours;
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
    dnsCacheEnabledInput.checked = config.dns_cache_enabled;
    dnsCacheSizeInput.value = String(config.dns_cache_size);
    dnsCacheMinTtlInput.value = String(config.dns_cache_min_ttl);
    dnsCacheMaxTtlInput.value = String(config.dns_cache_max_ttl);
    dnsCacheOptimisticInput.checked = config.dns_cache_optimistic;
    dnsCachePrefetchEnabledInput.checked = config.dns_cache_prefetch_enabled;
    dnsCachePrefetchHitThresholdInput.value = String(config.dns_cache_prefetch_hit_threshold);
    runtimeWatchdogEnabledInput.checked = config.runtime_watchdog_enabled;
    runtimeWatchdogIntervalInput.value = String(config.runtime_watchdog_interval_seconds);
    setRadioValue(blockingModeInputs, config.blocking_mode);
    blockingResponseTtlInput.value = String(config.blocking_response_ttl);
    blockingCustomIpv4Input.value = config.blocking_custom_ipv4;
    blockingCustomIpv6Input.value = config.blocking_custom_ipv6;
    rebindingProtectionEnabledInput.checked = config.rebinding_protection_enabled;
    rebindingAllowedDomainsInput.value = config.rebinding_allowed_domains;
    cnameCloakingEnabledInput.checked = config.cname_cloaking_enabled;
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
    updateBlockingModeControls();
    blacklistInput.value = config.blacklist;
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
  not_registered: "后台服务尚未安装。安装并授权后，DNS 才能监听 53 端口。",
  enabled: "后台服务已启用，DNS 可以监听 53 端口。",
  requires_approval: "等待批准：请在“系统设置 → 通用 → 登录项与扩展”中允许 DnsBlackhole。",
  not_found: "未找到后台服务，可能已被系统移除，请重新安装。",
  unknown: "后台服务状态未知，可尝试“安装或修复”。",
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
    macosServiceStatusElement.textContent = `读取后台服务状态失败：${String(error)}`;
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
      ? ` 当前服务版本 v${status.serviceVersion}。`
      : "";
  macosServiceStatusElement.textContent = status.needsRepair
    ? "后台服务已启用但暂未响应，可稍后重新进入本页检查；持续无响应时点击“安装或修复”。"
    : `${stateText}${versionText}`;
  openMacosServiceSettingsButton.classList.toggle("hidden", !status.requiresApproval);
  uninstallMacosServiceButton.disabled =
    status.state === "not_registered" || status.state === "not_found";
}

const WINDOWS_SERVICE_STATE_TEXT: Record<WindowsServiceState, string> = {
  not_installed: "系统服务尚未安装，DNS 核心无法在开机阶段自动启动。",
  stopped: "系统服务已停止，可点击“安装或修复”恢复。",
  start_pending: "系统服务正在启动，请稍候…",
  stop_pending: "系统服务正在停止，请稍候…",
  running: "系统服务正在运行，DNS 核心不依赖 GUI。",
  continue_pending: "系统服务正在恢复运行，请稍候…",
  pause_pending: "系统服务正在暂停，请稍候…",
  paused: "系统服务已暂停，可点击“安装或修复”恢复。",
};

async function loadWindowsServiceStatus(): Promise<WindowsServiceStatus | null> {
  if (!isWindows) {
    return null;
  }
  if (windowsServiceStatusInFlight) {
    return windowsServiceStatusInFlight;
  }
  const started = performance.now();
  let loadDetail = "无有效状态";
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
        ? `连续读取 Windows 系统服务状态失败：${String(error)}`
        : "正在等待 Windows 系统服务响应…";
      return null;
    }

    const wasReady = currentWindowsServiceStatus?.ready ?? false;
    loadDetail = `rawState=${rawStatus.state}, rawReady=${rawStatus.ready}, rawIpcReady=${rawStatus.ipcReady}`;
    const status = requireWindowsServiceStatus(rawStatus);
    renderWindowsServiceStatus(status);
    loadDetail = `state=${status.state}, ready=${status.ready}, ipcReady=${status.ipcReady}, needsRepair=${status.needsRepair}, diagnostic=${status.diagnostic ?? "无"}`;
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
  const versionText = status.serviceVersion ? ` 当前服务版本 v${status.serviceVersion}。` : "";
  if (status.ready) {
    windowsServiceStatusElement.textContent = `${stateText}${versionText}`;
  } else if (status.running && status.ipcReady && status.needsRepair) {
    windowsServiceStatusElement.textContent = `系统服务版本不一致（当前 ${status.serviceVersion ?? "未知"}，需要 ${status.expectedVersion}），请点击“安装或修复”。`;
  } else if (status.running && ipcFailurePersistent) {
    windowsServiceStatusElement.textContent = "系统服务已运行，但 IPC 连续无响应，请点击“安装或修复”。";
  } else if (status.running && !status.ipcReady) {
    windowsServiceStatusElement.textContent = "系统服务正在完成启动并建立通信，请稍候…";
  } else {
    windowsServiceStatusElement.textContent = `${stateText}${versionText}`;
  }
  uninstallWindowsServiceButton.disabled = !status.installed;
  if (!status.ready) {
    renderWindowsSystemDnsUnavailable("请先安装并启动 Windows DNS 系统服务");
  }
}

async function loadWindowsSystemDnsStatus(): Promise<WindowsSystemDnsStatus | null> {
  if (!isWindows) {
    return null;
  }
  windowsSystemDnsSection.classList.remove("hidden");
  if (!currentWindowsServiceStatus?.ready) {
    renderWindowsSystemDnsUnavailable("请先安装并启动 Windows DNS 系统服务");
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
      windowsSystemDnsStatusElement.textContent = `读取系统 DNS 状态失败：${String(error)}`;
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
  const activeAdapterNames = status.activeAdapters.map((adapter) => adapter.name).join("、");
  const activeDnsText = formatActiveDnsAdapters(status);
  const backupDnsText = formatBackupDnsAdapters(status);
  if (status.managed && status.inEffect) {
    windowsSystemDnsStatusElement.textContent = `已接管当前活动网卡：${activeAdapterNames}。`;
    windowsSystemDnsDetailElement.textContent = `当前 DNS 均指向 127.0.0.1 / ::1。接管前配置：${backupDnsText}。`;
  } else if (status.managed) {
    windowsSystemDnsStatusElement.textContent = status.activeAdapters.length > 0
      ? `当前活动网卡尚未全部接管：${activeAdapterNames}。`
      : "已保留 DNS 接管备份，但当前没有活动的物理网卡。";
    windowsSystemDnsDetailElement.textContent = `当前配置：${activeDnsText}。历史恢复配置：${backupDnsText}。可同步接管当前网卡，或选择恢复方式。`;
  } else if (status.inEffect) {
    const localAdapters = status.activeAdapters
      .filter((adapter) => adapter.usesLocalDns)
      .map((adapter) => adapter.name)
      .join("、");
    windowsSystemDnsStatusElement.textContent = `检测到 ${localAdapters} 使用本机 DNS，但没有原配置备份。`;
    windowsSystemDnsDetailElement.textContent = `当前配置：${activeDnsText}。请选择自动获取、公共 DNS 或自定义 DNS 来解除。`;
  } else {
    windowsSystemDnsStatusElement.textContent = status.activeAdapters.length > 0
      ? `尚未接管，当前活动网卡：${activeAdapterNames}。`
      : "尚未接管，当前未检测到已连接的物理网卡。";
    windowsSystemDnsDetailElement.textContent = status.activeAdapters.length > 0
      ? `当前配置：${activeDnsText}。接管时会按网卡分别保存这些设置。`
      : "连接有线或无线网络后，可将其 DNS 指向 DnsBlackhole。";
  }
  const canReplaceUnmanagedLocalDns = !status.managed && status.inEffect;
  restoreWindowsSystemDnsButton.textContent = canReplaceUnmanagedLocalDns
    ? "解除本机 DNS"
    : "恢复 DNS";
  takeOverWindowsSystemDnsButton.textContent = status.managed
    ? status.inEffect
      ? "已接管"
      : "同步接管"
    : "接管 DNS";
  updateWindowsSystemDnsButtons();
}

function renderWindowsSystemDnsUnavailable(message: string): void {
  if (!isWindows) {
    return;
  }
  windowsSystemDnsSection.classList.remove("hidden", "is-ready", "needs-repair");
  windowsSystemDnsStatusElement.textContent = message;
  windowsSystemDnsDetailElement.textContent = "系统服务就绪后会读取当前活动网卡及每张网卡的 DNS 恢复配置。";
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
  dnsFallbackDialogTitle.textContent = restoringManagedDns ? "选择恢复后的 DNS" : "解除本机 DNS";
  dnsFallbackDialogIntro.textContent = restoringManagedDns
    ? "“按接管前配置恢复”只还原仍指向本机 DNS 的部分，保留你后来在 Windows 中做的修改；选择其他方式则会将历史备份中的网卡设置为所选 DNS。"
    : "当前没有原 DNS 备份，请选择解除后使用的 DNS。只会修改仍指向 127.0.0.1 或 ::1 的设置。";
  dnsRestoreOriginalDetail.textContent = currentWindowsSystemDnsStatus
    ? formatBackupDnsAdapters(currentWindowsSystemDnsStatus)
    : "保留接管前的自动获取或手动 DNS 设置";
  dnsFallbackDialogConfirmButton.textContent = restoringManagedDns ? "确认恢复" : "确认解除";
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
  return servers && servers.length > 0 ? servers.join(" / ") : "自动获取";
}

function formatActiveDnsAdapters(status: WindowsSystemDnsStatus): string {
  if (status.activeAdapters.length === 0) {
    return "无活动物理网卡";
  }
  return status.activeAdapters
    .map(
      (adapter) =>
        `${adapter.name}（IPv4 ${formatDnsServers(adapter.ipv4Servers)}，IPv6 ${formatDnsServers(adapter.ipv6Servers)}）`,
    )
    .join("；");
}

function formatBackupDnsAdapters(status: WindowsSystemDnsStatus): string {
  if (status.backupAdapters.length === 0) {
    return "无历史备份";
  }
  return status.backupAdapters
    .map(
      (adapter) =>
        `${adapter.name}（IPv4 ${formatDnsServers(adapter.ipv4Servers)}，IPv6 ${formatDnsServers(adapter.ipv6Servers)}）`,
    )
    .join("；");
}

function closeDnsFallbackDialog(): void {
  if (dnsFallbackDialog.open) {
    dnsFallbackDialog.close();
  }
}

function requireWindowsSystemDnsStatus(value: unknown): WindowsSystemDnsStatus {
  if (!value || typeof value !== "object") {
    throw new Error("Windows 系统 DNS 状态接口返回了空结果");
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
    throw new Error("Windows 系统 DNS 状态接口返回格式无效");
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
    throw new Error("Windows 系统服务状态接口返回了空结果");
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
    throw new Error("Windows 系统服务状态接口返回格式无效");
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
  dataStorageSizeElement.textContent = `当前占用 ${formatBytes(info.total_bytes)}（数据库 ${formatBytes(info.database_bytes)}，过滤器数据 ${formatBytes(info.filter_cache_bytes)}）`;
  dataStorageStateElement.textContent = info.is_default ? "默认目录" : "自定义目录";
  dataStorageStateElement.classList.toggle("custom", !info.is_default);

  const pending = hasPendingStorageSelection();
  dataStoragePending.classList.toggle("hidden", !pending);
  if (!pending) {
    dataStoragePendingText.textContent = "";
    migrateDataStorageButton.textContent = "迁移并重启";
  } else if (!selectedStorageTarget) {
    dataStoragePendingText.textContent = storageSelectionError
      ? "所选目录不可用"
      : "正在检查所选目录…";
    migrateDataStorageButton.textContent = "检查目录中…";
  } else if (selectedStorageTarget.action === "use_existing") {
    dataStoragePendingText.textContent = `检测到现有数据 ${formatBytes(selectedStorageTarget.total_bytes)}（数据库 ${formatBytes(selectedStorageTarget.database_bytes)}，过滤器数据 ${formatBytes(selectedStorageTarget.filter_cache_bytes)}）`;
    migrateDataStorageButton.textContent = "使用现有数据并重启";
  } else {
    dataStoragePendingText.textContent = `重启后迁移到：${displayPath}`;
    migrateDataStorageButton.textContent = "迁移并重启";
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
    showMessage("配置尚未从 DNS 服务加载，已阻止保存以保护原配置", true);
    return;
  }
  await runStatusAction(() => saveConfigOnly(), "配置已保存");
}

async function saveConfigOnly(): Promise<RuntimeStatus> {
  const config = collectConfig();
  const previousStatisticsRetentionHours = currentStatisticsRetentionHours;
  currentStatisticsRetentionHours = config.statistics_retention_hours;
  try {
    const status = await saveConfigCommand(config);
    savedConfigFingerprint = configFingerprint(config);
    configDirty = false;
    updateConfigSaveState();
    return status;
  } catch (error) {
    currentStatisticsRetentionHours = previousStatisticsRetentionHours;
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
    dns_cache_enabled: dnsCacheEnabledInput.checked,
    dns_cache_size: Number(dnsCacheSizeInput.value || 0),
    dns_cache_min_ttl: Number(dnsCacheMinTtlInput.value || 0),
    dns_cache_max_ttl: Number(dnsCacheMaxTtlInput.value || 0),
    dns_cache_optimistic: dnsCacheOptimisticInput.checked,
    dns_cache_prefetch_enabled: dnsCachePrefetchEnabledInput.checked,
    dns_cache_prefetch_hit_threshold: Number(dnsCachePrefetchHitThresholdInput.value || 10),
    runtime_watchdog_enabled: runtimeWatchdogEnabledInput.checked,
    runtime_watchdog_interval_seconds: Number(runtimeWatchdogIntervalInput.value || 0),
    blocking_mode: selectedRadioValue(blockingModeInputs, "null_ip") as BlockingMode,
    blocking_response_ttl: Number(blockingResponseTtlInput.value || 0),
    blocking_custom_ipv4: blockingCustomIpv4Input.value.trim(),
    blocking_custom_ipv6: blockingCustomIpv6Input.value.trim(),
    rebinding_protection_enabled: rebindingProtectionEnabledInput.checked,
    rebinding_allowed_domains: rebindingAllowedDomainsInput.value,
    cname_cloaking_enabled: cnameCloakingEnabledInput.checked,
    dns_rewrites: dnsRewritesInput.value,
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
    ? "配置不可用"
    : configDirty
      ? "有未保存的更改"
      : "所有更改已保存";
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
    return;
  }

  const started = performance.now();
  let succeeded = false;
  refreshInFlight = true;
  setRefreshButtonState(options.button, true);
  try {
    const renderDashboard = activeView === "dashboard";
    const status = await getStatus(options.auto !== true, renderDashboard);
    if (options.auto && isContentScrolling) {
      queuedAutoRefresh = true;
      return;
    }
    renderStatus(status, { renderDashboard });
    if (renderDashboard) {
      lastDashboardRefreshAt = performance.now();
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
  }
}
function scheduleQueryLogSearch(): void {
  if (queryLogSearchComposing) {
    return;
  }

  window.clearTimeout(queryLogSearchTimer);
  queryLogSearchTimer = window.setTimeout(() => {
    queryLogPage = 1;
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
    const requestedFilter = queryLogFilterInput.value as QueryLogFilter;
    const requestedSearch = queryLogSearchInput.value.trim();
    const requestedPage = queryLogPage;
    const page = await getQueryLogs({
      filter: requestedFilter,
      search: requestedSearch,
      page: requestedPage,
      pageSize: QUERY_LOG_PAGE_SIZE,
    });
    if (options.auto && isContentScrolling) {
      queuedAutoRefresh = true;
      return;
    }
    if (
      requestedFilter !== queryLogFilterInput.value ||
      requestedSearch !== queryLogSearchInput.value.trim() ||
      requestedPage !== queryLogPage
    ) {
      queryLogRefreshQueued = true;
      return;
    }
    queryLogPage = page.page;
    queryLogTotal = page.total;
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
  updateContextNavigation(view);
  document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
    const isFilterGroup =
      button.dataset.navGroup === "filters" && (view === "filters" || view === "custom");
    const isSettingsGroup =
      button.dataset.navGroup === "settings" &&
      (view === "settings" || view === "dns" || view === "security" || view === "diagnostics");
    button.classList.toggle(
      "active",
      button.dataset.view === view || isFilterGroup || isSettingsGroup,
    );
  });
  document.querySelectorAll<HTMLElement>("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
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
    showMessage("请输入要诊断的域名", true);
    return;
  }
  runDiagnosticButton.classList.add("loading");
  runDiagnosticButton.textContent = "诊断中";
  runDiagnosticButton.disabled = true;
  diagnosticResults.innerHTML = `
    <div class="diagnostic-empty loading-state">
      <strong>正在并行测试上游…</strong>
      <span>不可用的服务器最多等待 3 秒。</span>
    </div>
  `;
  try {
    const report = await runDnsDiagnostic(domain, diagnosticQueryTypeInput.value);
    renderDiagnosticReport(report);
  } catch (error) {
    diagnosticResults.innerHTML = `
      <div class="diagnostic-empty error-state">
        <strong>诊断失败</strong>
        <span>${escapeHtml(String(error))}</span>
      </div>
    `;
    showMessage(String(error), true);
  } finally {
    runDiagnosticButton.classList.remove("loading");
    runDiagnosticButton.textContent = "开始诊断";
    runDiagnosticButton.disabled = false;
  }
}

function renderDiagnosticReport(report: DnsDiagnosticReport): void {
  const localLabels: Record<DnsDiagnosticReport["local_status"], string> = {
    allowed: "本地判定：允许",
    blocked: "本地判定：已拦截",
    rewrite: "本地判定：DNS 重写",
    paused: "本地判定：保护已暂停",
    stopped: "本地判定：服务未运行",
  };
  const upstreamRows = report.upstreams.length > 0
    ? report.upstreams.map((result) => {
        const answers = result.answers.length > 0
          ? result.answers
              .map((answer) => `${dnsQueryTypeLabel(answer.record_type)} ${answer.value}`)
              .join(" · ")
          : result.success
            ? "响应中没有可展示的记录"
            : result.error || "上游无响应";
        return `
          <div class="diagnostic-upstream ${result.success ? "success" : "failed"}">
            <i aria-hidden="true"></i>
            <div>
              <strong title="${escapeHtml(result.upstream)}">${escapeHtml(result.upstream)}</strong>
              <span title="${escapeHtml(answers)}">${escapeHtml(answers)}</span>
            </div>
            <div class="diagnostic-upstream-meta">
              <strong>${result.success ? `${dnsResponseCodeShortLabel(result.response_code)}${result.authenticated_data ? " · DNSSEC" : ""}` : "失败"}</strong>
              <span>${result.latency_ms === null ? "-" : formatElapsedMs(result.latency_ms)}</span>
            </div>
          </div>
        `;
      }).join("")
    : `<div class="diagnostic-empty"><strong>没有已配置的上游</strong></div>`;
  diagnosticResults.innerHTML = `
    <section class="diagnostic-local ${report.local_status}">
      <div>
        <span>${escapeHtml(report.domain)} · ${escapeHtml(report.query_type)}</span>
        <strong>${localLabels[report.local_status]}</strong>
      </div>
      <p>${escapeHtml(report.local_detail)}</p>
    </section>
    <section class="diagnostic-upstream-list">
      <div class="diagnostic-result-heading">
        <h3>上游测试</h3>
        <span>${report.upstreams.filter((result) => result.success).length}/${report.upstreams.length} 个可用</span>
      </div>
      ${upstreamRows}
    </section>
  `;
}

function dnsResponseCodeShortLabel(code: number | null): string {
  if (code === null) {
    return "已响应";
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
    filtersBody.innerHTML = `<div class="empty-row">暂无远程清单</div>`;
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
  const hasUnsupportedIgnoredRules =
    filter.ignored_regex_count + filter.ignored_unsupported_count + filter.ignored_invalid_count > 0;
  const statusText = filter.last_error
    ? "更新失败"
    : filter.last_updated
      ? hasUnsupportedIgnoredRules
        ? "部分忽略"
        : "已更新"
      : "未更新";
  const statusClass = filter.last_error
    ? "danger"
    : filter.last_updated
      ? hasUnsupportedIgnoredRules
        ? "warning"
        : "ok"
      : "muted";
  const ruleSummary = formatFilterRuleSummary(filter);

  return `
    <div class="filter-item" data-id="${escapeHtml(filter.id)}">
      <div class="filter-summary">
        <label class="switch" title="启用清单">
          <input class="filter-enabled" data-field="enabled" type="checkbox" ${filter.enabled ? "checked" : ""} />
        </label>
        <div class="filter-meta">
          <strong>${escapeHtml(filter.name || "未命名清单")}</strong>
          <span class="url-line" title="${escapeHtml(filter.url)}">${escapeHtml(filter.url || "尚未填写清单网址")}</span>
        </div>
        <span class="rule-count" title="${escapeHtml(ruleSummary)}">${formatCount(filter.rule_count)}</span>
        <span class="update-time">${formatTime(filter.last_updated)}</span>
        <span class="state-tag ${statusClass}" title="${escapeHtml(filter.last_error ?? "")}">${statusText}</span>
        <div class="row-actions">
          <button data-action="edit" type="button">${isEditing ? "收起" : "编辑"}</button>
          <button data-action="remove" type="button">删除</button>
        </div>
      </div>
      ${
        isEditing
          ? `
            <div class="filter-edit">
              <label class="field">
                <span>名称</span>
                <input data-field="name" value="${escapeHtml(filter.name)}" spellcheck="false" />
              </label>
              <label class="field">
                <span>清单网址</span>
                <input data-field="url" value="${escapeHtml(filter.url)}" spellcheck="false" />
              </label>
              <small class="filter-rule-detail">${escapeHtml(ruleSummary)}</small>
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
  renderSparkline(
    "#query_sparkline",
    buildDailyTrafficSeries(status.stats.traffic, "queries"),
  );
  renderSparkline(
    "#blocked_sparkline",
    buildDailyTrafficSeries(status.stats.traffic, "blocked"),
  );
  renderRankTable("#query_rank", status.stats.query_domains ?? {}, status.stats.queries);
  renderRankTable("#blocked_rank", status.stats.blocked_domains ?? {}, status.stats.blocked);
  renderRankTable(
    "#client_rank",
    status.stats.client_requests ?? {},
    status.stats.queries,
    formatClientRankLabel,
  );
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
      `<div class="security-event-empty">暂无安全事件</div>`,
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
  const eventLabel = event.event_type === "rate_limited" ? "触发限速" : "访问拒绝";
  const clientLabel = clientDisplayName(event.client_ip) ?? event.client_ip;
  const detail = `${event.protocol.toUpperCase()} · ${event.reason}`;
  const detailTitle =
    event.count > 1
      ? `${detail}；首次：${formatLogDate(event.first_seen_at)} ${formatLogTime(event.first_seen_at)}`
      : detail;
  return `
    <div class="security-event-row ${event.event_type}">
      <div>
        <strong>${escapeHtml(formatLogTime(event.last_seen_at))}</strong>
        <span>${escapeHtml(formatLogDate(event.last_seen_at))}</span>
      </div>
      <div>
        <strong title="${escapeHtml(event.client_ip)}">${escapeHtml(clientLabel)}</strong>
        <span>${escapeHtml(event.client_ip)}</span>
      </div>
      <div>
        <strong>${eventLabel}</strong>
        <span title="${escapeHtml(detailTitle)}">${escapeHtml(detail)}</span>
      </div>
      <strong class="security-event-count">${escapeHtml(formatCount(event.count))}</strong>
    </div>
  `;
}

function formatFilterRuleSummary(filter: FilterSubscription): string {
  const ignoredParts = [
    filter.ignored_comment_count > 0 ? `空行/注释 ${formatCount(filter.ignored_comment_count)}` : "",
    filter.ignored_regex_count > 0 ? `正则 ${formatCount(filter.ignored_regex_count)}` : "",
    filter.ignored_unsupported_count > 0
      ? `高级修饰符 ${formatCount(filter.ignored_unsupported_count)}`
      : "",
    filter.ignored_invalid_count > 0 ? `非法域名 ${formatCount(filter.ignored_invalid_count)}` : "",
  ].filter(Boolean);

  const ignoredText =
    filter.ignored_rule_count > 0
      ? `，忽略 ${formatCount(filter.ignored_rule_count)}（${ignoredParts.join("，") || "未分类"}）`
      : "";

  return `有效 ${formatCount(filter.rule_count)}，黑名单 ${formatCount(filter.block_rule_count)}，白名单 ${formatCount(filter.allow_rule_count)}${ignoredText}`;
}

function renderQueryLogs(page: QueryLogPage): void {
  renderQueryLogPagination(page);

  if (!currentQueryLogEnabled) {
    setHtmlIfChanged(queryLogBody, `<div class="query-log-empty">查询日志未启用，请在设置中开启日志配置。</div>`);
    return;
  }

  if (page.records.length === 0) {
    const hasSearch = queryLogSearchInput.value.trim().length > 0 || queryLogFilterInput.value !== "all";
    setHtmlIfChanged(
      queryLogBody,
      `<div class="query-log-empty">${hasSearch ? "没有匹配的查询记录" : "暂无查询记录"}</div>`,
    );
    return;
  }

  const html = page.records.map(renderQueryLogRow).join("");
  setHtmlIfChanged(queryLogBody, html);
}

function renderQueryLogRow(record: QueryLogRecord): string {
  const status = queryLogStatus(record);
  const rowClass = record.failed ? " failed" : record.blocked ? " blocked" : "";
  const detailText = queryLogResponseDetail(record);
  const detail = escapeHtml(detailText);
  const measuredDuration = record.processing_duration_ms ?? record.upstream_duration_ms;
  const duration = measuredDuration !== null ? formatElapsedMs(measuredDuration) : "";
  const requestMeta = [
    dnsQueryTypeLabel(record.query_type),
    record.transport?.toUpperCase() ?? "协议未记录",
  ];
  if (record.query_class !== null && record.query_class !== 1) {
    requestMeta.push(dnsQueryClassLabel(record.query_class));
  }
  const requestDetailPopover = renderQueryLogRequestDetail(record);
  const responseDetailPopover = renderQueryLogResponseDetail(record, status.label);

  return `
    <div class="query-log-row${rowClass}">
      <div class="log-time">
        <strong>${escapeHtml(formatLogTime(record.timestamp))}</strong>
        <span>${escapeHtml(formatLogDate(record.timestamp))}</span>
      </div>
      <div class="log-request">
        <div class="log-detail-anchor">
          <button class="log-detail-trigger" type="button" aria-label="查看请求详情">
            ${renderLogEyeIcon(status.className)}
          </button>
          ${requestDetailPopover}
        </div>
        <div class="log-request-content">
          <strong title="${escapeHtml(record.domain)}">${escapeHtml(record.domain)}</strong>
          <div class="log-request-meta">
            <span>${escapeHtml(requestMeta.join(" · "))}</span>
            <div class="log-rule-actions">
              <button data-log-rule-action="${record.blocked ? "allow" : "block"}" data-domain="${escapeHtml(record.domain)}" type="button">${record.blocked ? "放行" : "拦截"}</button>
              <button data-log-rule-action="rewrite" data-domain="${escapeHtml(record.domain)}" type="button">重写</button>
            </div>
          </div>
        </div>
      </div>
      <div class="log-response">
        <div class="log-response-layout">
          <div class="log-detail-anchor log-response-detail-anchor">
            <button class="log-detail-trigger" type="button" aria-label="查看响应详情">
              ${renderLogQuestionIcon()}
            </button>
            ${responseDetailPopover}
          </div>
          <div class="log-response-summary">
            <strong class="${status.className}">${status.label}</strong>
            <span title="${detail}">${detail}</span>
            ${duration ? `<small>${duration}</small>` : ""}
          </div>
        </div>
      </div>
      <div class="log-client">
        <strong>${escapeHtml(clientDisplayName(record.client_ip) ?? record.client_ip ?? "-")}</strong>
        <span>${escapeHtml(record.client_ip || "未知客户端")}</span>
      </div>
    </div>
  `;
}

function renderLogEyeIcon(className: string): string {
  return `
    <svg class="log-eye-icon ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M2.75 12c1.95-3.25 5.2-5.25 9.25-5.25s7.3 2 9.25 5.25c-1.95 3.25-5.2 5.25-9.25 5.25S4.7 15.25 2.75 12Z"></path>
      <circle cx="12" cy="12" r="2.75"></circle>
      <path d="M4.75 19.25 19.25 4.75"></path>
    </svg>
  `;
}

function renderLogQuestionIcon(): string {
  return `
    <svg class="log-question-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="8.75"></circle>
      <path d="M9.7 9.35a2.45 2.45 0 0 1 4.7.95c0 1.9-2.4 2.1-2.4 3.65"></path>
      <path d="M12 17.25h.01"></path>
    </svg>
  `;
}

function renderQueryLogRequestDetail(record: QueryLogRecord): string {
  const rows = [
    ["时间", formatLogTime(record.timestamp)],
    ["日期", formatLogDate(record.timestamp)],
    ["域名", record.domain],
    ["查询类型", dnsQueryTypeDetail(record.query_type)],
    ["查询类别", dnsQueryClassLabel(record.query_class)],
    ["传输协议", record.transport?.toUpperCase() ?? "旧日志未记录"],
    ["客户端", formatClientLabel(record.client_ip)],
  ];

  return renderLogDetailPopover("请求详情", rows);
}

function renderQueryLogResponseDetail(record: QueryLogRecord, statusLabel: string): string {
  const rows = [
    ["状态", statusLabel],
    ["响应来源", queryLogResponseSourceLabel(record)],
  ];
  const response = record.response;

  if (response) {
    rows.push(
      ["响应代码", dnsResponseCodeLabel(response.code)],
      ["响应记录", `${formatCount(response.answer_count)} 条`],
    );
  } else {
    rows.push(["响应代码", record.failed ? "无响应" : "旧日志未记录"]);
  }

  if (record.upstream_server) {
    rows.push(["上游服务器", record.upstream_server]);
  }

  if (record.upstream_duration_ms !== null) {
    rows.push(["上游耗时", formatElapsedMs(record.upstream_duration_ms)]);
  }

  if (record.processing_duration_ms !== null) {
    rows.push(["总处理耗时", formatElapsedMs(record.processing_duration_ms)]);
  }

  if (response?.truncated) {
    rows.push(["截断响应", "是（TC 标志）"]);
  }

  if (record.error) {
    rows.push([record.failed ? "错误" : "说明", record.error]);
  }

  if (record.blocked) {
    rows.push(
      ["命中规则", record.matched_rule ?? "旧日志未记录"],
      ["来源清单", record.rule_source ?? "旧日志未记录"],
      ["规则类型", record.rule_type ?? "旧日志未记录"],
      ["important 覆盖", record.important_overrode ? "是" : "否"],
      ["allowlist", record.allowlist_rule ?? "无"],
    );
  }

  return renderLogDetailPopover("响应详情", rows, renderQueryLogResponseAnswers(record));
}

function renderLogDetailPopover(
  title: string,
  rows: string[][],
  extraContent = "",
): string {
  return `
    <div class="log-detail-popover${extraContent ? " log-response-popover" : ""}" role="tooltip">
      <strong>${escapeHtml(title)}</strong>
      <dl>
        ${rows
          .map(
            ([label, value]) => `
              <div>
                <dt>${escapeHtml(label)}</dt>
                <dd title="${escapeHtml(value)}">${escapeHtml(value)}</dd>
              </div>
            `,
          )
          .join("")}
      </dl>
      ${extraContent}
    </div>
  `;
}

function renderQueryLogResponseAnswers(record: QueryLogRecord): string {
  const response = record.response;
  if (!response || response.answer_count === 0) {
    return "";
  }

  const omitted = Math.max(0, response.answer_count - response.answers.length);
  const records = response.answers
    .map(
      (answer) => `
        <div class="log-response-answer">
          <span>${escapeHtml(dnsQueryTypeLabel(answer.record_type))}</span>
          <code title="${escapeHtml(answer.value)}">${escapeHtml(answer.value)}</code>
          <small>TTL ${formatCount(answer.ttl)} 秒</small>
        </div>
      `,
    )
    .join("");

  return `
    <section class="log-response-answers">
      <strong>响应记录</strong>
      <div class="log-response-answer-list">
        ${records || `<p>响应记录内容无法解析</p>`}
      </div>
      ${omitted > 0 ? `<p>另有 ${formatCount(omitted)} 条记录未写入日志摘要</p>` : ""}
    </section>
  `;
}

function dnsResponseCodeLabel(code: number): string {
  const labels: Record<number, string> = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
  };
  return `${labels[code] ?? "RCODE"}（${code}）`;
}

function renderQueryLogPagination(page: QueryLogPage): void {
  const totalPages = totalQueryLogPages(page.total);
  const start = page.total === 0 ? 0 : (page.page - 1) * page.page_size + 1;
  const end = Math.min(page.total, page.page * page.page_size);
  queryLogPageInfo.textContent =
    page.total === 0
      ? "0 条记录"
      : `${formatCount(start)}-${formatCount(end)} / ${formatCount(page.total)} 条`;
  queryLogPrevButton.disabled = page.page <= 1 || queryLogRefreshInFlight;
  queryLogNextButton.disabled = page.page >= totalPages || queryLogRefreshInFlight;
}

function totalQueryLogPages(total = queryLogTotal): number {
  return Math.max(1, Math.ceil(total / QUERY_LOG_PAGE_SIZE));
}

function queryLogStatus(record: QueryLogRecord): { label: string; className: string } {
  if (record.failed) {
    return { label: "失败", className: "failed" };
  }
  if (record.blocked) {
    return { label: "已拦截", className: "blocked" };
  }
  if (queryLogResponseSource(record) === "refused") {
    return { label: "已拒绝", className: "refused" };
  }
  return { label: "已处理", className: "processed" };
}

type ResolvedQueryResponseSource =
  | "upstream"
  | "cache"
  | "rewrite"
  | "blocked"
  | "refused"
  | "local";

function queryLogResponseSource(record: QueryLogRecord): ResolvedQueryResponseSource {
  if (record.response_source) {
    return record.response_source;
  }
  if (record.blocked) {
    return "blocked";
  }
  if (record.error?.includes("ANY 查询")) {
    return "refused";
  }
  if (record.upstream_server) {
    return "upstream";
  }
  if (record.upstream_duration_ms === 0) {
    return "cache";
  }
  return "local";
}

function queryLogResponseSourceLabel(record: QueryLogRecord): string {
  switch (queryLogResponseSource(record)) {
    case "upstream":
      return "上游 DNS";
    case "cache":
      return "DNS 缓存";
    case "rewrite":
      return "本地 DNS 重写";
    case "blocked":
      return "过滤器";
    case "refused":
      return "本地拒绝";
    default:
      return "本地响应（旧日志未记录来源）";
  }
}

function queryLogResponseDetail(record: QueryLogRecord): string {
  if (record.failed && record.error) {
    return record.error;
  }
  switch (queryLogResponseSource(record)) {
    case "upstream":
      return record.upstream_server ? `上游：${record.upstream_server}` : "上游 DNS 解析";
    case "cache":
      return "DNS 缓存命中";
    case "rewrite":
      return "本地 DNS 重写";
    case "blocked":
      return record.rule_source ? `过滤器：${record.rule_source}` : "过滤器拦截";
    case "refused":
      return record.error ?? "本地拒绝响应";
    default:
      return "本地响应（旧日志）";
  }
}

function dnsQueryTypeLabel(queryType: number | null): string {
  if (queryType === null) {
    return "类型未记录";
  }
  return DNS_QUERY_TYPE_LABELS[queryType] ?? `TYPE${queryType}`;
}

function dnsQueryTypeDetail(queryType: number | null): string {
  if (queryType === null) {
    return "旧日志未记录";
  }
  return `${dnsQueryTypeLabel(queryType)}（${queryType}）`;
}

function dnsQueryClassLabel(queryClass: number | null): string {
  if (queryClass === null) {
    return "旧日志未记录";
  }
  const labels: Record<number, string> = {
    1: "IN（互联网）",
    3: "CH（Chaos）",
    4: "HS（Hesiod）",
    255: "ANY（任意类别）",
  };
  return labels[queryClass] ?? `CLASS${queryClass}`;
}

const DNS_QUERY_TYPE_LABELS: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  41: "OPT",
  43: "DS",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  52: "TLSA",
  64: "SVCB",
  65: "HTTPS",
  255: "ANY",
};

function setQueryLogFilterValue(value: QueryLogFilter): void {
  const options = queryLogFilterMenu.querySelectorAll<HTMLButtonElement>("[data-filter]");
  let label = "所有查询记录";

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
  return clientNameMap.get(ip) ?? (ip === "127.0.0.1" || ip === "::1" ? "本机" : null);
}

function formatClientLabel(ip: string | null): string {
  if (!ip) {
    return "未知客户端";
  }
  const name = clientDisplayName(ip);
  return name ? `${name}（${ip}）` : ip;
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
    throw new Error(`GitHub Release 请求失败（HTTP ${response.status}）`);
  }

  const release = (await response.json()) as GitHubRelease;
  const releaseVersion = normalizeVersion(release.tag_name);
  if (!releaseVersion) {
    throw new Error("GitHub Release 缺少版本号");
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
        `读取更新信息失败，${Math.round(delayMs / 1_000)} 秒后重试（${attempt}/${CHECK_RETRY_DELAYS_MS.length}）：${formatUpdateError(error)}`,
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
  const content = formatReleaseNotes(notes) || "此版本暂未提供更新说明。";
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
    () => check({ timeout: CHECK_TIMEOUT_MS }),
    CHECK_RETRY_DELAYS_MS,
    (attempt, delayMs, error) => {
      setUpdateStatus(
        "info",
        `检查更新失败，${Math.round(delayMs / 1_000)} 秒后重试（${attempt}/${CHECK_RETRY_DELAYS_MS.length}）：${formatUpdateError(error)}`,
      );
    },
  );
}

async function downloadAndInstallWithRetry(): Promise<void> {
  await retryWithBackoff(
    async (attempt) => {
      const candidate = await check({ timeout: CHECK_TIMEOUT_MS });
      if (!candidate) {
        throw new Error("重新检查时未发现可安装的新版本");
      }

      pendingUpdate = candidate;
      manualDownloadUrl = resolveManualDownloadUrl(candidate);
      let downloaded = 0;
      let total = 0;
      const prefix =
        attempt > 1 ? `第 ${attempt}/${DOWNLOAD_RETRY_DELAYS_MS.length + 1} 次下载：` : "";

      try {
        await candidate.downloadAndInstall(
          (event) => {
            if (event.event === "Started") {
              downloaded = 0;
              total = event.data.contentLength ?? 0;
              setUpdateStatus("info", `${prefix}开始下载更新...`);
            } else if (event.event === "Progress") {
              downloaded += event.data.chunkLength;
              const percent = total ? Math.round((downloaded / total) * 100) : 0;
              setUpdateStatus("info", `${prefix}下载中... ${percent}%`);
            } else if (event.event === "Finished") {
              setUpdateStatus("info", `${prefix}下载完成，正在安装...`);
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
        `下载更新失败，${Math.round(delayMs / 1_000)} 秒后重试（${attempt}/${DOWNLOAD_RETRY_DELAYS_MS.length}）：${formatUpdateError(error)}`,
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
  if (currentStatisticsRetentionHours !== 0) {
    const days = Math.max(1, Math.ceil(currentStatisticsRetentionHours / 24));
    label = `最近 ${days} 天`;
  } else if (summaryStartedAt && summaryEndedAt) {
    const start = new Date(summaryStartedAt * 1000);
    const end = new Date(summaryEndedAt * 1000);
    const days = Math.max(1, Math.floor((end.getTime() - start.getTime()) / 86_400_000) + 1);
    if (days < 32) {
      label = `累计汇总 ${days} 天`;
    } else {
      const months = Math.max(
        1,
        (end.getFullYear() - start.getFullYear()) * 12 + end.getMonth() - start.getMonth() + 1,
      );
      label = `累计汇总 ${months} 个月`;
    }
  } else {
    label = "暂无汇总数据";
  }
  query("#query_rank_window").textContent = label;
  query("#blocked_rank_window").textContent = label;
  query("#client_rank_window").textContent = label;
  query("#blocklist_rank_window").textContent = label;
  query("#upstream_rank_window").textContent = label;
  query("#upstream_latency_window").textContent = label;
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
    ? "保护运行中"
    : state === "paused"
      ? "过滤已暂停"
      : state === "error"
        ? "运行异常"
        : "服务已停止";
  runtimeStatusButton.className = `runtime-status-trigger ${state}`;
  runtimeStatusLabel.textContent = label;
  runtimeStatusDetail.textContent = state === "paused"
    ? `DNS 仍在运行，黑名单过滤将在${formatPauseRemaining(status.protection_paused_until)}后自动恢复。`
    : state === "running"
      ? `正在监听 ${status.listen_addr}，可临时暂停黑名单过滤。`
      : state === "error"
        ? status.error || "DNS 运行时出现异常"
        : "请先启动 DNS 服务，再使用临时暂停。";

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
    return "稍后";
  }
  const seconds = Math.max(0, deadline - Math.floor(Date.now() / 1000));
  if (seconds >= 3600) {
    return `${Math.ceil(seconds / 3600)} 小时`;
  }
  return `${Math.max(1, Math.ceil(seconds / 60))} 分钟`;
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
        ? "过滤保护已恢复"
        : `过滤保护已暂停 ${formatPauseRemaining(status.protection_paused_until)}`,
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
    setHtmlIfChanged(container, `<div class="empty-rank">暂无请求数据</div>`);
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
    setHtmlIfChanged(container, `<div class="empty-rank">暂无上游请求数据</div>`);
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
    setHtmlIfChanged(container, `<div class="empty-rank">暂无上游响应时间数据</div>`);
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

function setFilterUpdating(updating: boolean): void {
  updateFiltersButton.classList.toggle("loading", updating);
  updateFiltersButton.textContent = updating ? "更新中" : "检查更新";
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
  cancelFilterUpdateButton.textContent = "取消更新";
  filterUpdateProgressElement.classList.toggle("hidden", !updating);
  if (updating) {
    filterUpdateProgressElement.textContent = "正在准备更新…";
  }
}

function updateFilterProxyControls(): void {
  const mode = filterProxyModeInput.value as FilterProxyMode;
  filterProxyUrlField.classList.toggle("hidden", mode !== "custom");
  filterProxyUrlInput.disabled = mode !== "custom";

  if (mode === "direct") {
    filterProxyStatus.textContent = "后台将直接连接，不使用任何系统或环境代理。";
    return;
  }
  if (mode === "custom") {
    filterProxyStatus.textContent = "后台服务将使用这里填写的 HTTP/HTTPS 代理地址。";
    return;
  }

  const proxy = detectedSystemProxy ?? savedSystemProxyUrl;
  filterProxyStatus.textContent = proxy
    ? `已同步当前用户的系统代理：${proxy}`
    : "当前未检测到系统代理；后台将按系统默认网络直接连接。";
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
    ? " · 正在取消"
    : ` · 成功 ${progress.updated} · 失败 ${progress.failed}`;
  filterUpdateProgressElement.textContent = `已处理 ${progress.completed}/${progress.total}${suffix}`;
  cancelFilterUpdateButton.disabled = progress.cancel_requested || !progress.running;
  cancelFilterUpdateButton.textContent = progress.cancel_requested ? "正在取消" : "取消更新";
}

function setQueryLogLoading(loading: boolean, background = false): void {
  queryLogRefreshButton.classList.toggle("loading", loading);
  if (background) {
    return;
  }
  queryLogRefreshButton.disabled = loading;
  queryLogFilterInput.disabled = loading;
  queryLogFilterButton.disabled = loading;
  if (loading) {
    closeQueryLogFilter();
  }
  queryLogPrevButton.disabled = loading || queryLogPage <= 1;
  queryLogNextButton.disabled = loading || queryLogPage >= totalQueryLogPages();
}

function waitForPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}


function showMessage(value: string, isError: boolean): void {
  clearTimeout(messageTimer);

  // 移除已有的消息
  document.querySelectorAll(".message").forEach((el) => el.remove());

  if (value.length === 0) return;

  const el = document.createElement("div");
  el.className = isError ? "message error" : "message";
  el.innerHTML = `<span class="msg-text">${escapeHtml(value)}</span>`;
  document.body.appendChild(el);

  const dismiss = () => {
    el.classList.add("fade-out");
    el.addEventListener("transitionend", () => el.remove(), { once: true });
  };

  if (!isError) {
    messageTimer = window.setTimeout(dismiss, 3000);
  } else {
    // 错误消息 8 秒后自动消失
    messageTimer = window.setTimeout(dismiss, 8000);
  }
}

void bootstrapApplication().catch((error) => {
  console.error("应用启动失败", error);
  showMessage(`应用启动失败：${String(error)}`, true);
  logLoadTime("前端启动失败", frontendStartedAt, String(error));
});
