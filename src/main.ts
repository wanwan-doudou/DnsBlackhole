import { getVersion } from "@tauri-apps/api/app";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import {
  clearDnsCache as clearDnsCacheCommand,
  clearFilterCache as clearFilterCacheCommand,
  getConfig,
  getQueryLogs,
  getStatus,
  saveConfig as saveConfigCommand,
  startDns,
  stopDns,
  updateFilters as updateFiltersCommand,
} from "./api";
import appIconUrl from "./app-icon.png";
import { buildTrafficSeries, renderSparkline, runtimeWindowHours } from "./charts";
import { query } from "./dom";
import {
  escapeHtml,
  formatCount,
  formatDuration,
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
  FilterSubscription,
  QueryLogFilter,
  QueryLogPage,
  QueryLogRecord,
  RefreshOptions,
  RenderStatusOptions,
  RuntimeStatus,
  SecurityEvent,
  UpstreamLatencyStat,
  UpstreamMode,
  UpstreamRequestStat,
  ViewName,
} from "./types";
import "./style.css";

let messageTimer = 0;
let updateStatusTimer = 0;
let lastStatusErrorKey: string | null = null;
const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("缺少应用挂载节点");
}

app.innerHTML = renderAppTemplate(appIconUrl);

let activeView: ViewName = "dashboard";
let filtersState: FilterSubscription[] = [];
let editingFilterIds = new Set<string>();
let currentQueryLogEnabled = true;
let currentQueryLogRetentionHours = 90 * 24;
let lastStatus: RuntimeStatus | null = null;
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
let currentConfigSchemaVersion = 2;
let clientNameMap = new Map<string, string>();

const RELEASES_URL = "https://github.com/wanwan-doudou/DnsBlackhole/releases";
const QUERY_LOG_PAGE_SIZE = 50;
const QUERY_LOG_SEARCH_DEBOUNCE_MS = 800;
const CHECK_RETRY_DELAYS_MS = [800, 2_000, 5_000];
const DOWNLOAD_RETRY_DELAYS_MS = [1_000, 2_500, 5_000];
const CHECK_TIMEOUT_MS = 20_000;
const DOWNLOAD_TIMEOUT_MS = 180_000;

const contentElement = query<HTMLDivElement>(".content");
const enabledInput = query<HTMLInputElement>("#enabled");
const launchAtStartupInput = query<HTMLInputElement>("#launch_at_startup");
const useFiltersInput = query<HTMLInputElement>("#use_filters");
const upstreamInput = query<HTMLTextAreaElement>("#upstream_dns");
const fallbackInput = query<HTMLTextAreaElement>("#fallback_dns");
const bootstrapInput = query<HTMLTextAreaElement>("#bootstrap_dns");
const listenHostInput = query<HTMLInputElement>("#listen_host");
const listenPortInput = query<HTMLInputElement>("#listen_port");
const listenIpv6Input = query<HTMLInputElement>("#listen_ipv6");
const allowedClientsInput = query<HTMLTextAreaElement>("#allowed_clients");
const blockedClientsInput = query<HTMLTextAreaElement>("#blocked_clients");
const rateLimitPerSecondInput = query<HTMLInputElement>("#rate_limit_per_second");
const refuseAnyInput = query<HTMLInputElement>("#refuse_any");
const filterUpdateIntervalInput = query<HTMLSelectElement>("#filter_update_interval");
const filterMaxSizeInput = query<HTMLInputElement>("#filter_max_size_mb");
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
const dnsCacheEnabledInput = query<HTMLInputElement>("#dns_cache_enabled");
const dnsCacheSizeInput = query<HTMLInputElement>("#dns_cache_size");
const dnsCacheMinTtlInput = query<HTMLInputElement>("#dns_cache_min_ttl");
const dnsCacheMaxTtlInput = query<HTMLInputElement>("#dns_cache_max_ttl");
const dnsCacheOptimisticInput = query<HTMLInputElement>("#dns_cache_optimistic");
const runtimeWatchdogEnabledInput = query<HTMLInputElement>("#runtime_watchdog_enabled");
const runtimeWatchdogIntervalInput = query<HTMLInputElement>("#runtime_watchdog_interval_seconds");
const blockingModeInputs = Array.from(
  document.querySelectorAll<HTMLInputElement>('input[name="blocking_mode"]'),
);
const blockingCustomFields = query<HTMLDivElement>("#blocking_custom_fields");
const blockingCustomIpv4Input = query<HTMLInputElement>("#blocking_custom_ipv4");
const blockingCustomIpv6Input = query<HTMLInputElement>("#blocking_custom_ipv6");
const dnsRewritesInput = query<HTMLTextAreaElement>("#dns_rewrites");
const clientNamesInput = query<HTMLTextAreaElement>("#client_names");
const queryLogIgnoredInput = query<HTMLTextAreaElement>("#query_log_ignored_domains");
const blacklistInput = query<HTMLTextAreaElement>("#blacklist");
const filtersTable = query<HTMLDivElement>(".filters-table");
const filtersBody = query<HTMLDivElement>("#filters_body");
const saveButton = query<HTMLButtonElement>("#save_btn");
const saveSettingsButton = query<HTMLButtonElement>("#save_settings_btn");
const saveSecurityButton = query<HTMLButtonElement>("#save_security_btn");
const saveCustomButton = query<HTMLButtonElement>("#save_custom_btn");
const startButton = query<HTMLButtonElement>("#start_btn");
const stopButton = query<HTMLButtonElement>("#stop_btn");
const addFilterButton = query<HTMLButtonElement>("#add_filter_btn");
const updateFiltersButton = query<HTMLButtonElement>("#update_filters_btn");
const clearDnsCacheButton = query<HTMLButtonElement>("#clear_dns_cache_btn");
const clearFilterCacheButton = query<HTMLButtonElement>("#clear_filter_cache_btn");
const appVersionElement = query<HTMLElement>("#app_version");
const checkUpdateButton = query<HTMLButtonElement>("#check_update_btn");
const installUpdateButton = query<HTMLButtonElement>("#install_update_btn");
const manualDownloadButton = query<HTMLButtonElement>("#manual_download_btn");
const updateStatusElement = query<HTMLElement>("#update_status");
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
const securityAccessDenied = query<HTMLElement>("#security_access_denied");
const securityRateLimited = query<HTMLElement>("#security_rate_limited");
const securityDroppedUdp = query<HTMLElement>("#security_dropped_udp");
const securityRefusedAny = query<HTMLElement>("#security_refused_any");
const securityEventBody = query<HTMLDivElement>("#security_event_body");

document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    // 有 data-nav-group 的按钮只作为下拉触发器，不直接导航
    if (button.dataset.navGroup) {
      return;
    }
    const view = button.dataset.view as ViewName | undefined;
    if (view) {
      setActiveView(view);
      // 点击下拉菜单项后关闭所有下拉框
      closeAllDropdowns();
    }
  });
});

// 下拉菜单控制：点击触发，同时只显示一个
const navMenus = document.querySelectorAll<HTMLDivElement>(".nav-menu");

function closeAllDropdowns(): void {
  navMenus.forEach((m) => m.classList.remove("open"));
}

function closeQueryLogFilter(): void {
  queryLogFilterMenu.classList.remove("open");
  queryLogFilterButton.setAttribute("aria-expanded", "false");
}

navMenus.forEach((menu) => {
  const trigger = menu.querySelector<HTMLButtonElement>(".nav-item");
  if (!trigger) return;
  trigger.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = menu.classList.contains("open");
    closeAllDropdowns();
    if (!isOpen) {
      menu.classList.add("open");
    }
  });
});

// 点击页面其他区域时关闭下拉框
document.addEventListener("click", (e) => {
  const target = e.target as HTMLElement;
  if (!target.closest(".nav-dropdown")) {
    closeAllDropdowns();
  }
  if (!target.closest(".query-log-filter")) {
    closeQueryLogFilter();
  }
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
  closeAllDropdowns();
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
dnsCacheEnabledInput.addEventListener("change", updateDnsCacheControls);
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

saveButton.addEventListener("click", async () => {
  await saveConfig();
});

saveSettingsButton.addEventListener("click", async () => {
  await saveConfig();
});

saveSecurityButton.addEventListener("click", async () => {
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
});

updateFiltersButton.addEventListener("click", async () => {
  setFilterUpdating(true);
  setBusy(true);
  try {
    await waitForPaint();
    const result = await updateFiltersCommand(collectConfig());
    renderStatus(result.status);
    showMessage(result.message, result.failed > 0);
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    setBusy(false);
    setFilterUpdating(false);
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
    "这会删除已下载的远程黑名单缓存，并重载当前过滤规则。配置、查询日志和统计数据不会删除。清理后需要重新检查更新才能恢复远程黑名单缓存。是否继续？",
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
    await loadConfig();
  } catch (error) {
    showMessage(String(error), true);
    await refreshStatus();
  } finally {
    clearFilterCacheButton.classList.remove("loading");
    setBusy(false);
  }
});

checkUpdateButton.addEventListener("click", async () => {
  checkUpdateButton.disabled = true;
  checkUpdateButton.classList.add("loading");
  checkUpdateButton.textContent = "检查中";
  setUpdateStatus("info", "正在检查更新...");
  installUpdateButton.classList.add("hidden");
  manualDownloadButton.classList.add("hidden");
  pendingUpdate = null;
  manualDownloadUrl = "";

  try {
    pendingUpdate = await checkForUpdateWithRetry();
    if (pendingUpdate) {
      manualDownloadUrl = resolveManualDownloadUrl(pendingUpdate);
      const notes = pendingUpdate.body ? `\n${pendingUpdate.body}` : "";
      setUpdateStatus("ok", `发现新版本 v${pendingUpdate.version}${notes}`);
      installUpdateButton.classList.remove("hidden");
      installUpdateButton.disabled = false;
      manualDownloadButton.classList.remove("hidden");
      manualDownloadButton.disabled = false;
    } else {
      setUpdateStatus("ok", `已是最新版本 v${await getVersion()}`, 3500);
    }
  } catch (error) {
    console.error("检查更新失败", error);
    setUpdateStatus("err", `检查更新失败：${formatUpdateError(error)}`);
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
  }
  if (target.dataset.action === "edit") {
    editingFilterIds = toggleEditing(editingFilterIds, id);
    renderFilters();
  }
});

void getVersion().then((version) => {
  appVersionElement.textContent = version;
});

await loadConfig();
void listen<FilterSubscription[]>("filters-updated", ({ payload }) => {
  syncFilterUpdateMetadata(payload);
}).catch((error) => {
  console.error("监听过滤器更新失败", error);
});
await refreshStatus();
setActiveView(activeView);
window.setInterval(() => {
  // 窗口不可见（最小化 / 切到托盘）时跳过轮询，避免无谓的 IPC 与重渲染
  if (document.hidden) {
    return;
  }
  if (activeView === "logs") {
    void refreshQueryLogs({ auto: true });
    return;
  }
  void refreshStatus({ auto: true });
}, 5000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    if (activeView === "logs") {
      void refreshQueryLogs({ auto: true });
    } else {
      void refreshStatus({ auto: true });
    }
  }
});

async function loadConfig(): Promise<void> {
  try {
    const config = await getConfig();
    currentConfigSchemaVersion = config.schema_version;
    enabledInput.checked = config.enabled;
    launchAtStartupInput.checked = config.launch_at_startup;
    useFiltersInput.checked = config.use_filters;
    upstreamInput.value = config.upstream_dns;
    fallbackInput.value = config.fallback_dns;
    bootstrapInput.value = config.bootstrap_dns;
    listenHostInput.value = config.listen_host;
    listenPortInput.value = String(config.listen_port);
    listenIpv6Input.checked = config.listen_ipv6;
    allowedClientsInput.value = config.allowed_clients;
    blockedClientsInput.value = config.blocked_clients;
    rateLimitPerSecondInput.value = String(config.rate_limit_per_second);
    refuseAnyInput.checked = config.refuse_any;
    filterUpdateIntervalInput.value = String(config.filter_update_interval_hours);
    filterMaxSizeInput.value = String(config.filter_max_size_mb);
    allowInsecureHttpInput.checked = config.allow_insecure_http;
    setRadioValue(upstreamModeInputs, config.upstream_mode);
    queryLogEnabledInput.checked = config.query_log_enabled;
    anonymizeClientIpInput.checked = config.anonymize_client_ip;
    setRetentionValue(config.query_log_retention_hours);
    dnsCacheEnabledInput.checked = config.dns_cache_enabled;
    dnsCacheSizeInput.value = String(config.dns_cache_size);
    dnsCacheMinTtlInput.value = String(config.dns_cache_min_ttl);
    dnsCacheMaxTtlInput.value = String(config.dns_cache_max_ttl);
    dnsCacheOptimisticInput.checked = config.dns_cache_optimistic;
    runtimeWatchdogEnabledInput.checked = config.runtime_watchdog_enabled;
    runtimeWatchdogIntervalInput.value = String(config.runtime_watchdog_interval_seconds);
    setRadioValue(blockingModeInputs, config.blocking_mode);
    blockingCustomIpv4Input.value = config.blocking_custom_ipv4;
    blockingCustomIpv6Input.value = config.blocking_custom_ipv6;
    dnsRewritesInput.value = config.dns_rewrites;
    clientNamesInput.value = config.client_names;
    queryLogIgnoredInput.value = config.query_log_ignored_domains;
    clientNameMap = parseClientNames(config.client_names);
    currentQueryLogEnabled = config.query_log_enabled;
    currentQueryLogRetentionHours = config.query_log_retention_hours;
    renderRetentionWindow();
    updateLogControls();
    updateDnsCacheControls();
    updateRuntimeWatchdogControls();
    updateBlockingModeControls();
    blacklistInput.value = config.blacklist;
    filtersState = config.filters;
    renderFilters();
  } catch (error) {
    showMessage(String(error), true);
  }
}

async function saveConfig(): Promise<void> {
  await runStatusAction(() => saveConfigOnly(), "配置已保存");
}

async function saveConfigOnly(): Promise<RuntimeStatus> {
  return saveConfigCommand(collectConfig());
}

function collectConfig(): AppConfig {
  return {
    schema_version: currentConfigSchemaVersion,
    enabled: enabledInput.checked,
    launch_at_startup: launchAtStartupInput.checked,
    use_filters: useFiltersInput.checked,
    upstream_dns: upstreamInput.value.trim(),
    fallback_dns: fallbackInput.value.trim(),
    bootstrap_dns: bootstrapInput.value.trim(),
    upstream_mode: selectedRadioValue(upstreamModeInputs, "load_balance") as UpstreamMode,
    allowed_clients: allowedClientsInput.value.trim(),
    blocked_clients: blockedClientsInput.value.trim(),
    rate_limit_per_second: Number(rateLimitPerSecondInput.value || 0),
    refuse_any: refuseAnyInput.checked,
    filter_update_interval_hours: Number(filterUpdateIntervalInput.value),
    filter_max_size_mb: Number(filterMaxSizeInput.value || 50),
    allow_insecure_http: allowInsecureHttpInput.checked,
    query_log_enabled: queryLogEnabledInput.checked,
    anonymize_client_ip: anonymizeClientIpInput.checked,
    query_log_retention_hours: selectedRetentionHours(),
    dns_cache_enabled: dnsCacheEnabledInput.checked,
    dns_cache_size: Number(dnsCacheSizeInput.value || 0),
    dns_cache_min_ttl: Number(dnsCacheMinTtlInput.value || 0),
    dns_cache_max_ttl: Number(dnsCacheMaxTtlInput.value || 0),
    dns_cache_optimistic: dnsCacheOptimisticInput.checked,
    runtime_watchdog_enabled: runtimeWatchdogEnabledInput.checked,
    runtime_watchdog_interval_seconds: Number(runtimeWatchdogIntervalInput.value || 0),
    blocking_mode: selectedRadioValue(blockingModeInputs, "null_ip") as BlockingMode,
    blocking_custom_ipv4: blockingCustomIpv4Input.value.trim(),
    blocking_custom_ipv6: blockingCustomIpv6Input.value.trim(),
    dns_rewrites: dnsRewritesInput.value,
    client_names: clientNamesInput.value,
    query_log_ignored_domains: queryLogIgnoredInput.value,
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

async function refreshStatus(options: RefreshOptions = {}): Promise<void> {
  if (options.auto && activeView === "dashboard" && isContentScrolling) {
    queuedAutoRefresh = true;
    return;
  }
  if (refreshInFlight) {
    return;
  }

  refreshInFlight = true;
  setRefreshButtonState(options.button, true);
  try {
    const status = await getStatus(options.auto !== true);
    renderStatus(status, { renderDashboard: activeView === "dashboard" });
  } catch (error) {
    showMessage(String(error), true);
  } finally {
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
  if (queryLogRefreshInFlight) {
    queryLogRefreshQueued = true;
    return;
  }

  queryLogRefreshInFlight = true;
  setRefreshButtonState(options.button, true);
  setQueryLogLoading(true);
  try {
    const requestedFilter = queryLogFilterInput.value as QueryLogFilter;
    const requestedSearch = queryLogSearchInput.value.trim();
    const page = await getQueryLogs({
      filter: requestedFilter,
      search: requestedSearch,
      page: queryLogPage,
      pageSize: QUERY_LOG_PAGE_SIZE,
    });
    if (
      requestedFilter !== queryLogFilterInput.value ||
      requestedSearch !== queryLogSearchInput.value.trim()
    ) {
      queryLogRefreshQueued = true;
      return;
    }
    queryLogPage = page.page;
    queryLogTotal = page.total;
    renderQueryLogs(page);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    queryLogRefreshInFlight = false;
    setQueryLogLoading(false);
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
  activeView = view;
  showMessage("", false);
  document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
    const isFilterGroup =
      button.dataset.navGroup === "filters" && (view === "filters" || view === "custom");
    const isSettingsGroup =
      button.dataset.navGroup === "settings" &&
      (view === "settings" || view === "dns" || view === "security");
    button.classList.toggle(
      "active",
      button.dataset.view === view || isFilterGroup || isSettingsGroup,
    );
  });
  document.querySelectorAll<HTMLElement>("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
  if (view === "dashboard" && lastStatus) {
    renderStatus(lastStatus, { renderDashboard: true });
  }
  if (view === "logs") {
    void refreshQueryLogs();
  }
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
  filtersState = filtersState.map((filter) => {
    const updated = updatedById.get(filter.id);
    if (!updated) {
      return filter;
    }
    return {
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
  });
  renderFilters();
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
  lastStatus = status;
  const renderDashboard = options.renderDashboard ?? true;

  const lastError = status.error ?? status.stats.last_error;
  const statusErrorKey = status.error
    ? `runtime:${status.error}`
    : lastError
      ? `dns:${status.stats.failed}:${lastError}`
      : null;
  if (lastError && statusErrorKey !== lastStatusErrorKey) {
    showMessage(lastError, true);
  }
  lastStatusErrorKey = statusErrorKey;
  renderSecurityEvents(status);

  if (!renderDashboard) {
    return;
  }

  setTextIfChanged(query("#queries"), formatCount(status.stats.queries));
  setTextIfChanged(query("#blocked"), formatCount(status.stats.blocked));
  setTextIfChanged(query("#block_rate"), formatRate(status.stats.blocked, status.stats.queries));
  const trafficWindowHours = currentQueryLogEnabled
    ? currentQueryLogRetentionHours
    : runtimeWindowHours(status.stats.started_at);
  renderSparkline("#query_sparkline", buildTrafficSeries(status.stats.traffic, "queries", trafficWindowHours));
  renderSparkline("#blocked_sparkline", buildTrafficSeries(status.stats.traffic, "blocked", trafficWindowHours));
  renderRankTable("#query_rank", status.stats.query_domains ?? {}, status.stats.queries);
  renderRankTable("#blocked_rank", status.stats.blocked_domains ?? {}, status.stats.blocked);
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
  const rowClass = record.blocked ? " blocked" : record.failed ? " failed" : "";
  const detailText = record.error
    ? record.error
    : record.upstream_server
      ? `上游：${record.upstream_server}`
      : "本地响应";
  const detail = escapeHtml(detailText);
  const duration = record.upstream_duration_ms !== null
    ? `${formatCount(record.upstream_duration_ms)} 毫秒`
    : "";
  const detailPopover = renderQueryLogDetail(record, status.label, detailText, duration);

  return `
    <div class="query-log-row${rowClass}">
      <div class="log-time">
        <strong>${escapeHtml(formatLogTime(record.timestamp))}</strong>
        <span>${escapeHtml(formatLogDate(record.timestamp))}</span>
      </div>
      <div class="log-request">
        <div class="log-detail-anchor">
          <button class="log-detail-trigger" type="button" aria-label="查看请求详情">
            ${renderLogEyeIcon(record.blocked ? "blocked" : "processed")}
          </button>
          ${detailPopover}
        </div>
        <div>
          <strong title="${escapeHtml(record.domain)}">${escapeHtml(record.domain)}</strong>
          <span>类型：标准 DNS</span>
        </div>
      </div>
      <div class="log-response">
        <strong class="${status.className}">${status.label}</strong>
        <span title="${detail}">${detail}</span>
        ${duration ? `<small>${duration}</small>` : ""}
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

function renderQueryLogDetail(
  record: QueryLogRecord,
  statusLabel: string,
  detail: string,
  duration: string,
): string {
  const rows = [
    ["时间", formatLogTime(record.timestamp)],
    ["日期", formatLogDate(record.timestamp)],
    ["域名", record.domain],
    ["类型", "标准 DNS"],
    ["响应", statusLabel],
    ["客户端", formatClientLabel(record.client_ip)],
    ["详情", detail],
  ];

  if (duration) {
    rows.push(["耗时", duration]);
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

  return `
    <div class="log-detail-popover" role="tooltip">
      <strong>请求详情</strong>
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
    </div>
  `;
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
  if (record.blocked) {
    return { label: "已拦截", className: "blocked" };
  }
  if (record.failed) {
    return { label: "失败", className: "failed" };
  }
  return { label: "已处理", className: "processed" };
}

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

  anchor.classList.remove("show-above");
  const contentRect = contentElement.getBoundingClientRect();
  const anchorRect = anchor.getBoundingClientRect();
  const bottomLimit = Math.min(window.innerHeight, contentRect.bottom) - 12;
  const topLimit = Math.max(0, contentRect.top) + 12;
  const spaceBelow = bottomLimit - anchorRect.bottom;
  const spaceAbove = anchorRect.top - topLimit;
  const shouldShowAbove = spaceBelow < popover.offsetHeight + 16 && spaceAbove > spaceBelow;

  anchor.classList.toggle("show-above", shouldShowAbove);
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

function updateLogControls(): void {
  const enabled = queryLogEnabledInput.checked;
  anonymizeClientIpInput.disabled = !enabled;

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

function updateDnsCacheControls(): void {
  const enabled = dnsCacheEnabledInput.checked;
  dnsCacheSizeInput.disabled = !enabled;
  dnsCacheMinTtlInput.disabled = !enabled;
  dnsCacheMaxTtlInput.disabled = !enabled;
  dnsCacheOptimisticInput.disabled = !enabled;
  clearDnsCacheButton.disabled = !enabled;
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

function resolveManualDownloadUrl(update: Update): string {
  const platforms = update.rawJson.platforms;
  if (platforms && typeof platforms === "object" && !Array.isArray(platforms)) {
    const platformMap = platforms as Record<string, unknown>;
    const currentPlatformUrl = extractUrl(platformMap["windows-x86_64"]);
    if (currentPlatformUrl) {
      return currentPlatformUrl;
    }

    for (const platform of Object.values(platformMap)) {
      const platformUrl = extractUrl(platform);
      if (platformUrl) {
        return platformUrl;
      }
    }
  }

  const directUrl = extractUrl(update.rawJson);
  return directUrl ?? `${RELEASES_URL}/tag/v${update.version}`;
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

function renderRetentionWindow(): void {
  const label = currentQueryLogEnabled
    ? `最近 ${formatDuration(currentQueryLogRetentionHours)}`
    : "本次运行";
  query("#query_rank_window").textContent = label;
  query("#blocked_rank_window").textContent = label;
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
}

function renderRankTable(
  selector: string,
  counts: Record<string, number>,
  total: number,
): void {
  const container = query<HTMLDivElement>(selector);
  const rows = Object.entries(counts)
    .filter(([domain, count]) => domain.length > 0 && count > 0)
    .sort((a, b) => b[1] - a[1] || compareRankLabel(a[0], b[0]))
    .slice(0, 8);

  if (rows.length === 0) {
    setHtmlIfChanged(container, `<div class="empty-rank">暂无请求数据</div>`);
    return;
  }

  const maxCount = rows[0]?.[1] ?? 1;
  const html = rows
    .map(([domain, count]) => {
      const barWidth = maxCount > 0 ? Math.max((count / maxCount) * 100, 2) : 0;
      const percent = total > 0 ? count / total : 0;

      return `
        <div class="rank-row">
          <div class="rank-domain" title="${escapeHtml(domain)}">
            <span>${escapeHtml(domain)}</span>
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
    .slice(0, 8);

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
    .slice(0, 8);

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
}

function markContentScrolling(): void {
  if (activeView !== "dashboard") {
    return;
  }

  isContentScrolling = true;
  if (scrollIdleTimer !== undefined) {
    window.clearTimeout(scrollIdleTimer);
  }

  scrollIdleTimer = window.setTimeout(() => {
    isContentScrolling = false;
    if (queuedAutoRefresh) {
      queuedAutoRefresh = false;
      void refreshStatus({ auto: true });
    }
  }, 180);
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
  filtersTable.classList.toggle("is-updating", updating);
}

function setQueryLogLoading(loading: boolean): void {
  queryLogRefreshButton.classList.toggle("loading", loading);
  queryLogRefreshButton.disabled = loading;
  queryLogFilterInput.disabled = loading;
  queryLogFilterButton.disabled = loading;
  if (loading) {
    closeQueryLogFilter();
  }
  queryLogPrevButton.disabled = loading || queryLogPage <= 1;
  queryLogNextButton.disabled = loading || queryLogPage >= totalQueryLogPages();
  queryLogBody.classList.toggle("is-loading", loading);
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
