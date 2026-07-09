import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import appIconUrl from "./app-icon.png";
import "./style.css";

type ViewName = "dashboard" | "dns" | "filters" | "custom" | "logs" | "settings";
type QueryLogFilter = "all" | "processed" | "blocked" | "failed";

type FilterSubscription = {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  rule_count: number;
  last_updated: number | null;
  last_error: string | null;
};

type UpstreamMode = "load_balance" | "parallel_requests" | "fastest_addr";

type AppConfig = {
  enabled: boolean;
  use_filters: boolean;
  listen_host: string;
  listen_port: number;
  upstream_dns: string;
  upstream_mode: UpstreamMode;
  filter_update_interval_hours: number;
  query_log_enabled: boolean;
  anonymize_client_ip: boolean;
  launch_at_startup: boolean;
  query_log_retention_hours: number;
  dns_cache_enabled: boolean;
  dns_cache_size: number;
  dns_cache_min_ttl: number;
  dns_cache_max_ttl: number;
  dns_cache_optimistic: boolean;
  filters: FilterSubscription[];
  blacklist: string;
};

type RuleSummary = {
  block_rules: number;
  allow_rules: number;
  ignored_rules: number;
};

type TrafficBucket = {
  minute: number;
  queries: number;
  blocked: number;
};

type UpstreamRequestStat = {
  upstream: string;
  requests: number;
};

type UpstreamLatencyStat = {
  upstream: string;
  avg_ms: number;
};

type DnsStats = {
  started_at: number | null;
  queries: number;
  blocked: number;
  forwarded: number;
  failed: number;
  last_query: string | null;
  last_blocked: string | null;
  last_error: string | null;
  query_domains?: Record<string, number>;
  blocked_domains?: Record<string, number>;
  traffic?: TrafficBucket[];
  upstream_requests?: UpstreamRequestStat[];
  upstream_avg_latency?: UpstreamLatencyStat[];
};

type RuntimeStatus = {
  running: boolean;
  listen_addr: string;
  upstream_dns: string;
  summary: RuleSummary;
  stats: DnsStats;
  error: string | null;
};

type QueryLogRecord = {
  id: number;
  timestamp: number;
  domain: string;
  client_ip: string | null;
  blocked: boolean;
  forwarded: boolean;
  failed: boolean;
  upstream_server: string | null;
  upstream_duration_ms: number | null;
  error: string | null;
};

type QueryLogPage = {
  records: QueryLogRecord[];
  total: number;
  page: number;
  page_size: number;
};

type FilterUpdateResult = {
  status: RuntimeStatus;
  updated: number;
  failed: number;
  message: string;
};

type FilterCacheClearResult = {
  status: RuntimeStatus;
  removed_files: number;
  removed_bytes: number;
  message: string;
};

type RefreshOptions = {
  auto?: boolean;
  button?: HTMLButtonElement;
};

type RenderStatusOptions = {
  renderDashboard?: boolean;
};

type HistoryPoint = {
  index: number;
  value: number;
  label: string;
};

type ChartPoint = HistoryPoint & {
  x: number;
  y: number;
};

let messageTimer = 0;
let updateStatusTimer = 0;
const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("缺少应用挂载节点");
}

app.innerHTML = `
  <div class="app-shell">
    <header class="app-header">
      <div class="header-inner">
        <div class="brand">
          <img class="brand-mark" src="${appIconUrl}" alt="DnsBlackhole" />
          <div>
            <h1>DnsBlackhole</h1>
            <span>DNS sinkhole</span>
          </div>
        </div>

        <nav class="module-nav" aria-label="模块">
          <button class="nav-item active" data-view="dashboard" type="button">仪表盘</button>
          <div class="nav-menu">
            <button class="nav-item" data-view="settings" data-nav-group="settings" type="button">设置</button>
            <div class="nav-dropdown" role="menu">
              <button data-view="settings" type="button" role="menuitem">常规设置</button>
              <button data-view="dns" type="button" role="menuitem">DNS 设置</button>
            </div>
          </div>
          <div class="nav-menu">
            <button class="nav-item" data-view="filters" data-nav-group="filters" type="button">过滤器</button>
            <div class="nav-dropdown" role="menu">
              <button data-view="filters" type="button" role="menuitem">DNS 黑名单</button>
              <button data-view="custom" type="button" role="menuitem">自定义过滤规则</button>
            </div>
          </div>
          <button class="nav-item" data-view="logs" type="button">查询日志</button>
        </nav>
      </div>
    </header>

    <main class="content">
      <section class="view active" data-view-panel="dashboard">
        <div class="dashboard-summary" aria-label="统计趋势">
          <article class="spark-card">
            <div class="spark-box">
              <strong id="queries">0</strong>
              <svg class="sparkline" data-tooltip="query_spark_tooltip" viewBox="0 0 260 78" preserveAspectRatio="none" aria-hidden="true">
                <defs>
                  <linearGradient id="query_spark_gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#7f7f7f" stop-opacity="0.82"></stop>
                    <stop offset="64%" stop-color="#7f7f7f" stop-opacity="0.6"></stop>
                    <stop offset="92%" stop-color="#7f7f7f" stop-opacity="0.16"></stop>
                    <stop offset="100%" stop-color="#7f7f7f" stop-opacity="0"></stop>
                  </linearGradient>
                </defs>
                <line class="spark-baseline" x1="0" y1="72" x2="260" y2="72"></line>
                <path class="spark-area" fill="url(#query_spark_gradient)" d=""></path>
                <path class="spark-line" id="query_sparkline" d=""></path>
                <line class="spark-guide hidden" x1="0" y1="8" x2="0" y2="72"></line>
                <circle class="spark-point hidden" cx="0" cy="72" r="3"></circle>
              </svg>
              <div class="spark-tooltip hidden" id="query_spark_tooltip"></div>
            </div>
            <span>DNS 查询</span>
          </article>

          <article class="spark-card blocked-spark">
            <div class="spark-box">
              <strong id="blocked">0</strong>
              <small id="block_rate">0%</small>
              <svg class="sparkline" data-tooltip="blocked_spark_tooltip" viewBox="0 0 260 78" preserveAspectRatio="none" aria-hidden="true">
                <defs>
                  <linearGradient id="blocked_spark_gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#f67247" stop-opacity="0.82"></stop>
                    <stop offset="64%" stop-color="#f67247" stop-opacity="0.6"></stop>
                    <stop offset="92%" stop-color="#f67247" stop-opacity="0.16"></stop>
                    <stop offset="100%" stop-color="#f67247" stop-opacity="0"></stop>
                  </linearGradient>
                </defs>
                <line class="spark-baseline" x1="0" y1="72" x2="260" y2="72"></line>
                <path class="spark-area" fill="url(#blocked_spark_gradient)" d=""></path>
                <path class="spark-line" id="blocked_sparkline" d=""></path>
                <line class="spark-guide hidden" x1="0" y1="8" x2="0" y2="72"></line>
                <circle class="spark-point hidden" cx="0" cy="72" r="3"></circle>
              </svg>
              <div class="spark-tooltip hidden" id="blocked_spark_tooltip"></div>
            </div>
            <span>已被过滤器拦截</span>
          </article>
        </div>

        <div class="dashboard-rank-grid">
          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>请求域名排行</h2>
                <span id="query_rank_window">最近 90 天</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table">
              <div class="rank-head">
                <span>域名</span>
                <span>请求数</span>
              </div>
              <div class="rank-body" id="query_rank"></div>
            </div>
          </section>

          <section class="panel rank-panel blocked-rank">
            <div class="rank-title">
              <div>
                <h2>被拦截域名排行</h2>
                <span id="blocked_rank_window">最近 90 天</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table">
              <div class="rank-head">
                <span>域名</span>
                <span>请求数</span>
              </div>
              <div class="rank-body" id="blocked_rank"></div>
            </div>
          </section>
        </div>

        <div class="dashboard-rank-grid upstream-rank-grid">
          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>经常请求的上游服务器</h2>
                <span id="upstream_rank_window">最近 90 天</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table">
              <div class="rank-head">
                <span>上游服务器</span>
                <span>请求数</span>
              </div>
              <div class="rank-body" id="upstream_rank"></div>
            </div>
          </section>

          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>上游服务器的平均响应时间</h2>
                <span id="upstream_latency_window">最近 90 天</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table">
              <div class="rank-head">
                <span>上游服务器</span>
                <span>响应时间</span>
              </div>
              <div class="rank-body" id="upstream_latency_rank"></div>
            </div>
          </section>
        </div>

      </section>

      <section class="view query-log-view" data-view-panel="logs">
        <div class="query-log-toolbar">
          <div class="query-log-title">
            <h2>查询日志</h2>
            <button class="ghost-icon-button" id="query_log_refresh_btn" type="button" title="刷新查询日志">↻</button>
          </div>
          <label class="query-log-search">
            <span aria-hidden="true">⌕</span>
            <input id="query_log_search" autocomplete="off" spellcheck="false" placeholder="域名或客户端" />
          </label>
          <div class="query-log-filter" id="query_log_filter_menu">
            <button class="query-log-filter-trigger" id="query_log_filter_button" type="button" aria-haspopup="listbox" aria-expanded="false">
              <span id="query_log_filter_label">所有查询记录</span>
              <i aria-hidden="true"></i>
            </button>
            <div class="query-log-filter-options" role="listbox" aria-label="查询日志筛选">
              <button class="active" data-filter="all" type="button" role="option" aria-selected="true">所有查询记录</button>
              <button data-filter="processed" type="button" role="option" aria-selected="false">已处理</button>
              <button data-filter="blocked" type="button" role="option" aria-selected="false">已过滤</button>
              <button data-filter="failed" type="button" role="option" aria-selected="false">失败</button>
            </div>
            <select id="query_log_filter" aria-hidden="true" tabindex="-1">
              <option value="all">所有查询记录</option>
              <option value="processed">已处理</option>
              <option value="blocked">已过滤</option>
              <option value="failed">失败</option>
            </select>
          </div>
        </div>

        <section class="query-log-panel">
          <div class="query-log-head">
            <span>时间</span>
            <span>请求</span>
            <span>响应</span>
            <span>客户端</span>
          </div>
          <div class="query-log-body" id="query_log_body"></div>
          <div class="query-log-pagination">
            <span id="query_log_page_info">0 条记录</span>
            <div class="button-group">
              <button id="query_log_prev_btn" type="button">上一页</button>
              <button id="query_log_next_btn" type="button">下一页</button>
            </div>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="dns">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>DNS 设置</h2>
            <div class="button-group">
              <button class="primary" id="save_btn" type="button">保存</button>
              <button id="start_btn" type="button">启动</button>
              <button id="stop_btn" type="button">停止</button>
            </div>
          </div>

          <div class="settings-stack">
            <section class="settings-section">
              <h3>上游 DNS</h3>
              <div class="dns-settings">
                <label class="field upstream-field">
                  <span>上游 DNS 服务器</span>
                  <textarea id="upstream_dns" autocomplete="off" spellcheck="false"></textarea>
                </label>
                <div class="listen-settings">
                  <label class="field">
                    <span>监听地址</span>
                    <input id="listen_host" autocomplete="off" spellcheck="false" placeholder="127.0.0.1" />
                  </label>
                  <label class="field compact-field">
                    <span>端口</span>
                    <input id="listen_port" type="number" min="1" max="65535" step="1" />
                  </label>
                </div>
              </div>
              <div class="radio-stack upstream-mode">
                <label class="radio-row">
                  <input name="upstream_mode" type="radio" value="load_balance" />
                  <span>
                    <strong>负载均衡</strong>
                    <small>一次查询一台上游服务器，失败后尝试其它服务器。</small>
                  </span>
                </label>
                <label class="radio-row">
                  <input name="upstream_mode" type="radio" value="parallel_requests" />
                  <span>
                    <strong>并行请求</strong>
                    <small>同时查询所有上游服务器，并使用最先成功的响应。</small>
                  </span>
                </label>
                <label class="radio-row">
                  <input name="upstream_mode" type="radio" value="fastest_addr" />
                  <span>
                    <strong>最快的 IP 地址</strong>
                    <small>等待上游服务器响应，测速返回的 IP 地址，并优先采用最快的可用结果。</small>
                  </span>
                </label>
              </div>
            </section>

            <section class="settings-section dns-cache-section">
              <div class="section-heading">
                <h3>DNS 缓存配置</h3>
                <span>您可以在此处配置 DNS 缓存</span>
              </div>
              <label class="check-row">
                <input id="dns_cache_enabled" type="checkbox" />
                <span>
                  <strong>启用缓存</strong>
                  <small>在本地存储 DNS 响应，减少重复查询的上游请求延迟。</small>
                </span>
              </label>
              <div class="dns-cache-grid">
                <label class="field">
                  <span>缓存大小</span>
                  <small>DNS 缓存大小（单位：字节）</small>
                  <input id="dns_cache_size" type="number" min="1024" max="536870912" step="1024" />
                </label>
                <label class="field">
                  <span>覆盖最小 TTL 值</span>
                  <small>缓存 DNS 响应时，延长从上游服务器接收到的 TTL 值（秒）。</small>
                  <input id="dns_cache_min_ttl" type="number" min="0" max="604800" step="1" />
                </label>
                <label class="field">
                  <span>覆盖最大 TTL 值</span>
                  <small>设定 DNS 缓存条目的最大 TTL 值（秒）。</small>
                  <input id="dns_cache_max_ttl" type="number" min="0" max="604800" step="1" />
                </label>
              </div>
              <label class="check-row">
                <input id="dns_cache_optimistic" type="checkbox" />
                <span>
                  <strong>乐观缓存</strong>
                  <small>即使条目已过期，也先从缓存中响应，并在后台刷新它们。</small>
                </span>
              </label>
              <button id="clear_dns_cache_btn" type="button">清除缓存</button>
            </section>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="settings">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>设置</h2>
            <button class="primary" id="save_settings_btn" type="button">保存</button>
          </div>

          <div class="settings-stack">
            <section class="settings-section">
              <h3>常规设置</h3>
              <label class="check-row">
                <input id="use_filters" type="checkbox" />
                <span>
                  <strong>使用过滤器和 Hosts 文件以拦截指定域名</strong>
                  <small>你可以在 DNS 黑名单和自定义过滤规则中添加过滤规则。</small>
                </span>
              </label>
              <label class="field compact-select">
                <span>过滤器更新间隔</span>
                <select id="filter_update_interval">
                  <option value="6">6 小时</option>
                  <option value="12">12 小时</option>
                  <option value="24">24 小时</option>
                  <option value="72">3 天</option>
                  <option value="168">7 天</option>
                </select>
              </label>
              <label class="toggle-row">
                <input id="enabled" type="checkbox" />
                <span>启动时自动运行 DNS 服务</span>
              </label>
              <label class="toggle-row">
                <input id="launch_at_startup" type="checkbox" />
                <span>开机时启动应用</span>
              </label>
            </section>

            <section class="settings-section cache-maintenance-section">
              <div>
                <h3>磁盘缓存</h3>
                <p>清理已下载的远程黑名单缓存，不会删除配置、查询日志和统计数据。</p>
              </div>
              <button id="clear_filter_cache_btn" type="button">清理过滤器缓存</button>
            </section>

            <section class="settings-section">
              <h3>日志配置</h3>
              <label class="check-row">
                <input id="query_log_enabled" type="checkbox" />
                <span>
                  <strong>启用日志</strong>
                </span>
              </label>
              <label class="check-row inline-help-row">
                <input id="anonymize_client_ip" type="checkbox" />
                <span>
                  <strong>匿名化客户端 IP</strong>
                  <small>不要在日志和统计信息中保存客户端的完整 IP 地址。</small>
                </span>
              </label>
              <div class="retention-settings">
                <span class="retention-title">查询日志保留时间</span>
                <div class="retention-options">
                  <label><input name="query_log_retention" type="radio" value="24" /> 24 小时</label>
                  <label><input name="query_log_retention" type="radio" value="168" /> 7 天</label>
                  <label><input name="query_log_retention" type="radio" value="720" /> 30 天</label>
                  <label><input name="query_log_retention" type="radio" value="2160" /> 90 天</label>
                  <label><input name="query_log_retention" type="radio" value="4320" /> 180 天</label>
                  <label><input name="query_log_retention" type="radio" value="8640" /> 360 天</label>
                  <label><input name="query_log_retention" type="radio" value="custom" /> 自定义</label>
                </div>
                <label class="field custom-retention-field" id="custom_retention_field">
                  <span>自定义保留时间（小时）</span>
                  <input id="query_log_retention_custom" type="number" min="1" max="8760" step="1" placeholder="例如 120" />
                </label>
              </div>
            </section>

            <section class="settings-section about-section">
              <h3>关于与更新</h3>
              <div class="about-row">
                <span class="about-version">DnsBlackhole v<span id="app_version">-</span></span>
                <div class="button-group update-actions">
                  <button id="check_update_btn" type="button">检查更新</button>
                  <button class="primary hidden" id="install_update_btn" type="button">下载并安装</button>
                  <button class="hidden" id="manual_download_btn" type="button">浏览器下载</button>
                </div>
              </div>
              <div class="update-status hidden" id="update_status"></div>
            </section>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="filters">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>DNS 黑名单</h2>
            <div class="button-group">
              <button id="add_filter_btn" type="button">添加黑名单</button>
              <button class="primary" id="update_filters_btn" type="button">检查更新</button>
            </div>
          </div>
          <div class="filters-table">
            <div class="filters-head">
              <span>启用</span>
              <span>名称</span>
              <span>规则数</span>
              <span>上次更新</span>
              <span>状态</span>
              <span>操作</span>
            </div>
            <div id="filters_body" class="filters-body"></div>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="custom">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>自定义过滤规则</h2>
            <button class="primary" id="save_custom_btn" type="button">保存</button>
          </div>
          <textarea id="blacklist" spellcheck="false"></textarea>
        </section>
      </section>
    </main>
  </div>
`;

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

const RELEASES_URL = "https://github.com/wanwan-doudou/DnsBlackhole/releases";
const QUERY_LOG_PAGE_SIZE = 50;
const QUERY_LOG_SEARCH_DEBOUNCE_MS = 800;
const CHECK_RETRY_DELAYS_MS = [800, 2_000, 5_000];
const DOWNLOAD_RETRY_DELAYS_MS = [1_000, 2_500, 5_000];
const CHECK_TIMEOUT_MS = 20_000;
const DOWNLOAD_TIMEOUT_MS = 180_000;

// 缓存 Intl 格式化器：构造开销较大，仪表盘每 5 秒刷新会高频调用（sparkline 标签单轮达数十次），复用可避免重复创建
const countFormatter = new Intl.NumberFormat("zh-CN");
const percentFormatter = new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 });
const filterTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});
const sparkDateFormatter = new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit" });
const sparkTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});
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

const contentElement = query<HTMLDivElement>(".content");
const enabledInput = query<HTMLInputElement>("#enabled");
const launchAtStartupInput = query<HTMLInputElement>("#launch_at_startup");
const useFiltersInput = query<HTMLInputElement>("#use_filters");
const upstreamInput = query<HTMLTextAreaElement>("#upstream_dns");
const listenHostInput = query<HTMLInputElement>("#listen_host");
const listenPortInput = query<HTMLInputElement>("#listen_port");
const filterUpdateIntervalInput = query<HTMLSelectElement>("#filter_update_interval");
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
const blacklistInput = query<HTMLTextAreaElement>("#blacklist");
const filtersTable = query<HTMLDivElement>(".filters-table");
const filtersBody = query<HTMLDivElement>("#filters_body");
const saveButton = query<HTMLButtonElement>("#save_btn");
const saveSettingsButton = query<HTMLButtonElement>("#save_settings_btn");
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

saveCustomButton.addEventListener("click", async () => {
  await saveConfig();
});

startButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    await saveConfigOnly();
    const status = await invoke<RuntimeStatus>("start_dns");
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
  await runStatusAction(() => invoke<RuntimeStatus>("stop_dns"), "DNS 服务已停止");
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
    const result = await invoke<FilterUpdateResult>("update_filters", { config: collectConfig() });
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
    const status = await invoke<RuntimeStatus>("clear_dns_cache");
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
    const result = await invoke<FilterCacheClearResult>("clear_filter_cache");
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
    const config = await invoke<AppConfig>("get_config");
    enabledInput.checked = config.enabled;
    launchAtStartupInput.checked = config.launch_at_startup;
    useFiltersInput.checked = config.use_filters;
    upstreamInput.value = config.upstream_dns;
    listenHostInput.value = config.listen_host;
    listenPortInput.value = String(config.listen_port);
    filterUpdateIntervalInput.value = String(config.filter_update_interval_hours);
    setRadioValue(upstreamModeInputs, config.upstream_mode);
    queryLogEnabledInput.checked = config.query_log_enabled;
    anonymizeClientIpInput.checked = config.anonymize_client_ip;
    setRetentionValue(config.query_log_retention_hours);
    dnsCacheEnabledInput.checked = config.dns_cache_enabled;
    dnsCacheSizeInput.value = String(config.dns_cache_size);
    dnsCacheMinTtlInput.value = String(config.dns_cache_min_ttl);
    dnsCacheMaxTtlInput.value = String(config.dns_cache_max_ttl);
    dnsCacheOptimisticInput.checked = config.dns_cache_optimistic;
    currentQueryLogEnabled = config.query_log_enabled;
    currentQueryLogRetentionHours = config.query_log_retention_hours;
    renderRetentionWindow();
    updateLogControls();
    updateDnsCacheControls();
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
  return invoke<RuntimeStatus>("save_config", { config: collectConfig() });
}

function collectConfig(): AppConfig {
  return {
    enabled: enabledInput.checked,
    launch_at_startup: launchAtStartupInput.checked,
    use_filters: useFiltersInput.checked,
    upstream_dns: upstreamInput.value.trim(),
    upstream_mode: selectedRadioValue(upstreamModeInputs, "load_balance") as UpstreamMode,
    filter_update_interval_hours: Number(filterUpdateIntervalInput.value),
    query_log_enabled: queryLogEnabledInput.checked,
    anonymize_client_ip: anonymizeClientIpInput.checked,
    query_log_retention_hours: selectedRetentionHours(),
    dns_cache_enabled: dnsCacheEnabledInput.checked,
    dns_cache_size: Number(dnsCacheSizeInput.value || 0),
    dns_cache_min_ttl: Number(dnsCacheMinTtlInput.value || 0),
    dns_cache_max_ttl: Number(dnsCacheMaxTtlInput.value || 0),
    dns_cache_optimistic: dnsCacheOptimisticInput.checked,
    listen_host: listenHostInput.value.trim(),
    listen_port: Number(listenPortInput.value),
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
    const status = await invoke<RuntimeStatus>("get_status", { force: options.auto !== true });
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
    const page = await invoke<QueryLogPage>("get_query_logs", {
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
      button.dataset.navGroup === "settings" && (view === "settings" || view === "dns");
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

function renderFilter(filter: FilterSubscription): string {
  const isEditing = editingFilterIds.has(filter.id);
  const statusText = filter.last_error ? "更新失败" : filter.last_updated ? "已更新" : "未更新";
  const statusClass = filter.last_error ? "danger" : filter.last_updated ? "ok" : "muted";

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
        <span class="rule-count">${formatCount(filter.rule_count)}</span>
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
  if (lastError) {
    showMessage(lastError, true);
  }

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
        <strong>${escapeHtml(record.client_ip || "-")}</strong>
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
    ["客户端", record.client_ip || "未知客户端"],
    ["详情", detail],
  ];

  if (duration) {
    rows.push(["耗时", duration]);
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

function buildTrafficSeries(
  buckets: TrafficBucket[] | undefined,
  field: "queries" | "blocked",
  windowHours: number,
): HistoryPoint[] {
  const pointCount = 48;
  const latestMinute = Math.floor(Date.now() / 60000);
  const windowMinutes = Math.max(pointCount, Math.ceil(windowHours * 60));
  const bucketMinutes = Math.max(1, Math.ceil(windowMinutes / pointCount));
  const firstMinute = latestMinute - bucketMinutes * pointCount + 1;
  const values = Array.from({ length: pointCount }, (_, index) => {
    const minute = firstMinute + index * bucketMinutes;
    return {
      index,
      value: 0,
      label: formatSparkBucketLabel(minute, bucketMinutes),
    };
  });

  for (const bucket of buckets ?? []) {
    const index = Math.floor((bucket.minute - firstMinute) / bucketMinutes);
    if (index >= 0 && index < pointCount) {
      values[index].value += bucket[field];
    }
  }

  return values;
}

function renderSparkline(selector: string, series: HistoryPoint[]): void {
  const line = query<SVGPathElement>(selector);
  const svg = line.ownerSVGElement;
  if (!svg) {
    return;
  }

  const area = svg.querySelector<SVGPathElement>(".spark-area");
  if (!area) {
    return;
  }

  const width = 260;
  const baseline = 72;
  const top = 8;
  const maxValue = Math.max(...series.map((point) => point.value), 1);
  const coords = series.map<ChartPoint>((point, index) => {
    const x = series.length === 1 ? width : (index / (series.length - 1)) * width;
    const y = baseline - (point.value / maxValue) * (baseline - top);
    return { ...point, x, y };
  });
  const linePath = buildMonotonePath(coords);
  const areaPath = buildAreaPath(coords, baseline);

  if (line.getAttribute("d") !== linePath) {
    line.setAttribute("d", linePath);
  }
  if (area.getAttribute("d") !== areaPath) {
    area.setAttribute("d", areaPath);
  }

  bindSparklineHover(svg, coords, width);
}

function buildAreaPath(points: ChartPoint[], baseline: number): string {
  const linePath = buildMonotonePath(points);
  if (!linePath || points.length === 0) {
    return "";
  }

  const first = points[0];
  const last = points[points.length - 1];
  return `${linePath} L ${last.x.toFixed(1)} ${baseline.toFixed(1)} L ${first.x.toFixed(1)} ${baseline.toFixed(1)} Z`;
}

function buildMonotonePath(points: ChartPoint[]): string {
  if (points.length === 0) {
    return "";
  }
  if (points.length === 1) {
    const point = points[0];
    return `M ${point.x.toFixed(1)} ${point.y.toFixed(1)}`;
  }

  const slopes = points.slice(0, -1).map((point, index) => {
    const next = points[index + 1];
    return (next.y - point.y) / (next.x - point.x || 1);
  });
  const tangents = points.map((_, index) => {
    if (index === 0) {
      return slopes[0];
    }
    if (index === points.length - 1) {
      return slopes[slopes.length - 1];
    }

    const prev = slopes[index - 1];
    const next = slopes[index];
    return prev * next <= 0 ? 0 : (prev + next) / 2;
  });

  let path = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    const dx = next.x - current.x;
    const cp1x = current.x + dx / 3;
    const cp1y = current.y + (tangents[index] * dx) / 3;
    const cp2x = next.x - dx / 3;
    const cp2y = next.y - (tangents[index + 1] * dx) / 3;
    path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${next.x.toFixed(1)} ${next.y.toFixed(1)}`;
  }

  return path;
}

function bindSparklineHover(svg: SVGSVGElement, coords: ChartPoint[], width: number): void {
  const guide = svg.querySelector<SVGLineElement>(".spark-guide");
  const point = svg.querySelector<SVGCircleElement>(".spark-point");
  const tooltipId = svg.dataset.tooltip;
  const tooltip = tooltipId ? query<HTMLDivElement>(`#${tooltipId}`) : null;
  if (!guide || !point || !tooltip) {
    return;
  }

  const hideTooltip = () => {
    guide.classList.add("hidden");
    point.classList.add("hidden");
    tooltip.classList.add("hidden");
  };

  svg.onpointerleave = hideTooltip;
  svg.onpointermove = (event) => {
    if (coords.length === 0) {
      hideTooltip();
      return;
    }

    const rect = svg.getBoundingClientRect();
    const relativeX = clamp(((event.clientX - rect.left) / rect.width) * width, 0, width);
    const nearest = coords.reduce((best, current) =>
      Math.abs(current.x - relativeX) < Math.abs(best.x - relativeX) ? current : best,
    );

    guide.setAttribute("x1", nearest.x.toFixed(1));
    guide.setAttribute("x2", nearest.x.toFixed(1));
    point.setAttribute("cx", nearest.x.toFixed(1));
    point.setAttribute("cy", nearest.y.toFixed(1));
    tooltip.innerHTML = `<strong>${formatCount(nearest.value)}</strong><span>${escapeHtml(nearest.label)}</span>`;

    // 先显示再测量：.hidden 为 display:none 时取不到 tooltip 的真实尺寸
    guide.classList.remove("hidden");
    point.classList.remove("hidden");
    tooltip.classList.remove("hidden");

    const host = svg.parentElement;
    const hostRect = host?.getBoundingClientRect();
    if (!hostRect) {
      return;
    }
    const svgRect = svg.getBoundingClientRect();
    const pointLeft = svgRect.left - hostRect.left + (nearest.x / width) * svgRect.width;
    const pointTop = svgRect.top - hostRect.top + (nearest.y / 78) * svgRect.height;

    // tooltip 位于 overflow:hidden 的卡片内，按其真实尺寸把锚点收敛到卡片范围内，避免溢出被裁切。
    // CSS transform 为 translate(-50%, -105%)：水平相对锚点居中，垂直向上偏移自身高度的 105%
    const margin = 8;
    const halfWidth = tooltip.offsetWidth / 2;
    const tooltipHeight = tooltip.offsetHeight;
    const minLeft = halfWidth + margin;
    const maxLeft = Math.max(minLeft, hostRect.width - halfWidth - margin);
    const minTop = tooltipHeight * 1.05 + margin;
    const maxTop = Math.max(minTop, hostRect.height - tooltipHeight * 0.05 - margin);
    tooltip.style.left = `${clamp(pointLeft, minLeft, maxLeft)}px`;
    tooltip.style.top = `${clamp(pointTop, minTop, maxTop)}px`;
  };
}

function runtimeWindowHours(startedAt: number | null): number {
  if (!startedAt) {
    return 1;
  }
  const elapsedSeconds = Math.max(60, Date.now() / 1000 - startedAt);
  return Math.max(1, Math.ceil(elapsedSeconds / 3600));
}

function formatSparkBucketLabel(minute: number, bucketMinutes: number): string {
  const start = new Date(minute * 60000);
  const end = new Date((minute + bucketMinutes - 1) * 60000);

  if (bucketMinutes >= 24 * 60) {
    const startLabel = sparkDateFormatter.format(start);
    const endLabel = sparkDateFormatter.format(end);
    return startLabel === endLabel ? startLabel : `${startLabel} - ${endLabel}`;
  }

  const startLabel = sparkTimeFormatter.format(start);
  const endLabel = sparkTimeFormatter.format(end);
  return startLabel === endLabel ? startLabel : `${startLabel} - ${endLabel}`;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
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


function formatCount(value: number): string {
  return countFormatter.format(value);
}

function formatRate(blocked: number, queries: number): string {
  if (queries === 0) {
    return "0%";
  }
  return `${Math.round((blocked / queries) * 100)}%`;
}

function formatPercent(value: number): string {
  return `${percentFormatter.format(value * 100)}%`;
}

function formatDuration(hours: number): string {
  if (hours % (24 * 30) === 0) {
    return `${hours / (24 * 30)} 个月`;
  }
  if (hours % 24 === 0) {
    return `${hours / 24} 天`;
  }
  return `${hours} 小时`;
}

function formatTime(value: number | null): string {
  if (!value) {
    return "-";
  }
  return filterTimeFormatter.format(new Date(value * 1000));
}

function formatLogTime(value: number): string {
  return logTimeFormatter.format(new Date(value * 1000));
}

function formatLogDate(value: number): string {
  return logDateFormatter.format(new Date(value * 1000));
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function query<T extends Element = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`找不到元素：${selector}`);
  }
  return element;
}
