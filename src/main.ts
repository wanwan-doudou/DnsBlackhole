import { getVersion } from "@tauri-apps/api/app";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import {
  clearDnsCache as clearDnsCacheCommand,
  clearFilterCache as clearFilterCacheCommand,
  getConfig,
  getMacosServiceStatus,
  getWindowsServiceStatus,
  getStorageInfo,
  getQueryLogs,
  getStatus,
  saveConfig as saveConfigCommand,
  requestDataMigration,
  installMacosService,
  installWindowsService,
  openMacosServiceSettings,
  startDns,
  stopDns,
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
  formatDuration,
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
  FilterSubscription,
  MacosServiceState,
  MacosServiceStatus,
  QueryLogFilter,
  QueryLogPage,
  QueryLogRecord,
  RefreshOptions,
  RenderStatusOptions,
  RuntimeStatus,
  SecurityEvent,
  StorageInfo,
  UpstreamLatencyStat,
  UpstreamMode,
  UpstreamRequestStat,
  ViewName,
  WindowsServiceState,
  WindowsServiceStatus,
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
let currentStorageInfo: StorageInfo | null = null;
let selectedDataStoragePath = "";
let configLoaded = false;
const isMacOS = navigator.userAgent.includes("Macintosh");
const isWindows = navigator.userAgent.includes("Windows");
let currentMacosServiceStatus: MacosServiceStatus | null = null;
let currentWindowsServiceStatus: WindowsServiceStatus | null = null;

const RELEASES_URL = "https://github.com/wanwan-doudou/DnsBlackhole/releases";
const RELEASES_API_URL =
  "https://api.github.com/repos/wanwan-doudou/DnsBlackhole/releases";
const QUERY_LOG_PAGE_SIZE = 50;
const QUERY_LOG_SEARCH_DEBOUNCE_MS = 800;
// 排行卡片渲染上限：超出可视高度的部分在卡片内滚动查看
const RANK_ROW_LIMIT = 50;
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
const configSaveButtons = [
  saveButton,
  saveSettingsButton,
  saveSecurityButton,
  saveCustomButton,
];
configSaveButtons.forEach((button) => {
  button.disabled = true;
});
const startButton = query<HTMLButtonElement>("#start_btn");
const stopButton = query<HTMLButtonElement>("#stop_btn");
const addFilterButton = query<HTMLButtonElement>("#add_filter_btn");
const updateFiltersButton = query<HTMLButtonElement>("#update_filters_btn");
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
      selectedDataStoragePath = selected;
      renderStorageInfo(currentStorageInfo);
    }
  } catch (error) {
    showMessage(`选择数据目录失败：${String(error)}`, true);
  }
});

resetDataStorageButton.addEventListener("click", () => {
  if (!currentStorageInfo) {
    return;
  }
  selectedDataStoragePath = currentStorageInfo.default_path;
  renderStorageInfo(currentStorageInfo);
});

migrateDataStorageButton.addEventListener("click", async () => {
  if (!currentStorageInfo || !hasPendingStorageSelection()) {
    return;
  }
  const targetPath = selectedDataStoragePath;
  const confirmed = window.confirm(
    `应用将重启并把数据库与过滤器缓存迁移到：\n${targetPath}\n\n目标数据验证成功后才会清理原目录。是否继续？`,
  );
  if (!confirmed) {
    return;
  }

  setBusy(true);
  migrateDataStorageButton.classList.add("loading");
  try {
    await requestDataMigration(targetPath);
    showMessage("迁移任务已保存，正在重启应用…", false);
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
        "后台服务已注册但暂未响应，可能仍在启动，将自动重试连接；若持续无响应请重启 Mac 后再试",
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

installWindowsServiceButton.addEventListener("click", async () => {
  installWindowsServiceButton.disabled = true;
  installWindowsServiceButton.classList.add("loading");
  try {
    const status = requireWindowsServiceStatus(await installWindowsService());
    renderWindowsServiceStatus(status);
    if (status.running && !status.needsRepair) {
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
    "卸载 Windows DNS 系统服务后，127.0.0.1/::1 将不再提供 DNS；若网卡仍指向本机 DNS，解析可能立即失败。是否继续？",
  );
  if (!confirmed) {
    return;
  }
  uninstallWindowsServiceButton.disabled = true;
  uninstallWindowsServiceButton.classList.add("loading");
  try {
    const status = requireWindowsServiceStatus(await uninstallWindowsService());
    renderWindowsServiceStatus(status);
    showMessage("Windows DNS 系统服务已卸载，数据和配置未删除", false);
  } catch (error) {
    showMessage(String(error), true);
  } finally {
    uninstallWindowsServiceButton.disabled = false;
    uninstallWindowsServiceButton.classList.remove("loading");
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

const initialWindowsServiceStatus = await loadWindowsServiceStatus();
await loadMacosServiceStatus();
const windowsCoreReady =
  !isWindows ||
  ((initialWindowsServiceStatus?.running ?? false) &&
    !(initialWindowsServiceStatus?.needsRepair ?? false));
const configReady = await loadConfig();
await loadStorageInfo();
if (!windowsCoreReady && !configReady) {
  activeView = "settings";
}
void listen<FilterSubscription[]>("filters-updated", ({ payload }) => {
  syncFilterUpdateMetadata(payload);
}).catch((error) => {
  console.error("监听过滤器更新失败", error);
});
if (configReady) {
  await refreshStatus();
}
setActiveView(activeView);
window.setInterval(() => {
  // 窗口不可见（最小化 / 切到托盘）时跳过轮询，避免无谓的 IPC 与重渲染
  if (document.hidden) {
    return;
  }
  // 服务待批准或暂未响应时持续复查：daemon 启动慢或用户刚在系统设置中批准，
  // 状态恢复后自动重新加载数据，避免用户被引导去反复“修复”。
  if (
    currentMacosServiceStatus?.requiresApproval ||
    currentMacosServiceStatus?.needsRepair ||
    (isWindows &&
      (!currentWindowsServiceStatus || currentWindowsServiceStatus.needsRepair))
  ) {
    void loadMacosServiceStatus();
    void loadWindowsServiceStatus();
  }
  if (activeView === "logs") {
    void refreshQueryLogs({ auto: true });
    return;
  }
  if (activeView === "dashboard" || activeView === "security") {
    void refreshStatus({ auto: true });
  }
}, 5000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    if (activeView === "logs") {
      void refreshQueryLogs({ auto: true });
    } else if (activeView === "dashboard" || activeView === "security") {
      void refreshStatus({ auto: true });
    }
    // 用户可能刚从系统设置批准完服务回来，切回窗口时同步最新授权状态
    if (currentMacosServiceStatus?.requiresApproval) {
      void loadMacosServiceStatus();
    }
    if (
      isWindows &&
      (!currentWindowsServiceStatus || currentWindowsServiceStatus.needsRepair)
    ) {
      void loadWindowsServiceStatus();
    }
  }
});

async function loadConfig(): Promise<boolean> {
  try {
    const config = await getConfig();
    if (!config || typeof config.schema_version !== "number") {
      throw new Error("DNS 服务返回了空配置或配置格式无效");
    }
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
    configLoaded = true;
    configSaveButtons.forEach((button) => {
      button.disabled = false;
    });
    return true;
  } catch (error) {
    configLoaded = false;
    configSaveButtons.forEach((button) => {
      button.disabled = true;
    });
    showMessage(String(error), true);
    return false;
  }
}

async function loadStorageInfo(): Promise<void> {
  try {
    currentStorageInfo = await getStorageInfo();
    selectedDataStoragePath = currentStorageInfo.pending_path ?? currentStorageInfo.current_path;
    renderStorageInfo(currentStorageInfo);
  } catch (error) {
    dataStorageError.textContent = String(error);
    dataStorageError.classList.remove("hidden");
  }
}

const MACOS_SERVICE_STATE_TEXT: Record<MacosServiceState, string> = {
  not_registered: "后台服务尚未安装。安装并授权后，DNS 才能监听 53 端口。",
  enabled: "后台服务已启用，DNS 可以监听 53 端口。",
  requires_approval: "等待批准：请在“系统设置 → 通用 → 登录项与扩展”中允许 DnsBlackhole。",
  not_found: "未找到后台服务，可能已被系统移除，请重新安装。",
  unknown: "后台服务状态未知，可尝试“安装或修复”。",
};

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
    if (status.enabled && !status.needsRepair && !wasReady) {
      await refreshAfterBackgroundServiceEnabled();
    }
  } catch (error) {
    currentMacosServiceStatus = null;
    macosServiceStatusElement.textContent = `读取后台服务状态失败：${String(error)}`;
  }
}

async function refreshAfterBackgroundServiceEnabled(): Promise<void> {
  // 系统服务启动后 IPC 可能稍晚创建，短暂等待再同步完整状态。
  await new Promise((resolve) => window.setTimeout(resolve, 400));
  await loadConfig();
  await loadStorageInfo();
  await refreshStatus();
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
    ? "后台服务已启用但暂未响应，可能正在启动，将自动重试连接；持续无响应时点击“安装或修复”。"
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
  windowsServiceSection.classList.remove("hidden");
  try {
    const wasReady =
      (currentWindowsServiceStatus?.running ?? false) &&
      !(currentWindowsServiceStatus?.needsRepair ?? false);
    const status = requireWindowsServiceStatus(await getWindowsServiceStatus());
    renderWindowsServiceStatus(status);
    if (status.running && !status.needsRepair && !wasReady) {
      await refreshAfterBackgroundServiceEnabled();
    }
    return status;
  } catch (error) {
    currentWindowsServiceStatus = null;
    windowsServiceStatusElement.textContent = `读取 Windows 系统服务状态失败：${String(error)}`;
    return null;
  }
}

function renderWindowsServiceStatus(status: WindowsServiceStatus): void {
  currentWindowsServiceStatus = status;
  const ready = status.running && !status.needsRepair;
  windowsServiceSection.classList.toggle("is-ready", ready);
  windowsServiceSection.classList.toggle("needs-repair", status.needsRepair);
  const stateText = WINDOWS_SERVICE_STATE_TEXT[status.state];
  const versionText = status.serviceVersion ? ` 当前服务版本 v${status.serviceVersion}。` : "";
  windowsServiceStatusElement.textContent =
    status.running && status.needsRepair
      ? "系统服务已启动但 IPC 无响应或版本不一致，请点击“安装或修复”。"
      : `${stateText}${versionText}`;
  uninstallWindowsServiceButton.disabled = !status.installed;
}

function requireWindowsServiceStatus(value: unknown): WindowsServiceStatus {
  if (!value || typeof value !== "object") {
    throw new Error("Windows 系统服务状态接口返回了空结果");
  }
  const status = value as Partial<WindowsServiceStatus>;
  if (
    typeof status.state !== "string" ||
    !(status.state in WINDOWS_SERVICE_STATE_TEXT) ||
    typeof status.installed !== "boolean" ||
    typeof status.running !== "boolean" ||
    typeof status.expectedVersion !== "string" ||
    typeof status.needsRepair !== "boolean"
  ) {
    throw new Error("Windows 系统服务状态接口返回格式无效");
  }
  return status as WindowsServiceStatus;
}

function renderStorageInfo(info: StorageInfo): void {
  const displayPath = selectedDataStoragePath || info.current_path;
  dataStoragePathInput.value = displayPath;
  dataStorageSizeElement.textContent = `当前占用 ${formatBytes(info.total_bytes)}（数据库 ${formatBytes(info.database_bytes)}，过滤器缓存 ${formatBytes(info.filter_cache_bytes)}）`;
  dataStorageStateElement.textContent = info.is_default ? "默认目录" : "自定义目录";
  dataStorageStateElement.classList.toggle("custom", !info.is_default);

  const pending = hasPendingStorageSelection();
  dataStoragePending.classList.toggle("hidden", !pending);
  dataStoragePendingText.textContent = pending
    ? `重启后迁移到：${displayPath}`
    : "";
  migrateDataStorageButton.disabled = !pending;
  resetDataStorageButton.disabled = info.is_default && !pending;

  dataStorageError.textContent = info.migration_error ?? "";
  dataStorageError.classList.toggle("hidden", !info.migration_error);
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
    const renderDashboard = activeView === "dashboard";
    const status = await getStatus(options.auto !== true, renderDashboard);
    renderStatus(status, { renderDashboard });
  } catch (error) {
    // 自动轮询会撞上后台服务重启或等待批准的窗口，瞬态错误只记录不打扰用户
    if (options.auto) {
      console.error("自动刷新状态失败", error);
    } else {
      showMessage(String(error), true);
    }
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
  if (view === "dashboard" && viewChanged) {
    void refreshStatus({ auto: true });
  }
  if (view === "logs") {
    void refreshQueryLogs();
  }
  if (view === "security") {
    void refreshStatus({ auto: true });
  }
  if (view === "settings" && viewChanged) {
    void loadMacosServiceStatus();
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
  const renderDashboard = options.renderDashboard ?? true;

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

  if (!renderDashboard) {
    return;
  }

  setTextIfChanged(query("#queries"), formatCount(status.stats.queries));
  setTextIfChanged(query("#blocked"), formatCount(status.stats.blocked));
  setTextIfChanged(query("#block_rate"), formatRate(status.stats.blocked, status.stats.queries));
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
        <div>
          <strong title="${escapeHtml(record.domain)}">${escapeHtml(record.domain)}</strong>
          <span>${escapeHtml(requestMeta.join(" · "))}</span>
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
  return notes
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

function renderRetentionWindow(): void {
  const label = currentQueryLogEnabled
    ? `最近 ${formatDuration(currentQueryLogRetentionHours)}`
    : "本次运行";
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
