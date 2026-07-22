export type ViewName =
  | "dashboard"
  | "dns"
  | "security"
  | "filters"
  | "custom"
  | "logs"
  | "about"
  | "settings";
export type QueryLogFilter = "all" | "processed" | "blocked" | "failed";

export type MacosServiceState =
  | "not_registered"
  | "enabled"
  | "requires_approval"
  | "not_found"
  | "unknown";

export type MacosServiceStatus = {
  state: MacosServiceState;
  enabled: boolean;
  requiresApproval: boolean;
  expectedVersion: string;
  serviceVersion: string | null;
  needsRepair: boolean;
};

export type WindowsServiceState =
  | "not_installed"
  | "stopped"
  | "start_pending"
  | "stop_pending"
  | "running"
  | "continue_pending"
  | "pause_pending"
  | "paused";

export type WindowsServiceStatus = {
  state: WindowsServiceState;
  installed: boolean;
  running: boolean;
  ready: boolean;
  ipcReady: boolean;
  expectedVersion: string;
  serviceVersion: string | null;
  needsRepair: boolean;
  diagnostic: string | null;
};

export type FilterSubscription = {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  rule_count: number;
  block_rule_count: number;
  allow_rule_count: number;
  ignored_rule_count: number;
  ignored_comment_count: number;
  ignored_regex_count: number;
  ignored_unsupported_count: number;
  ignored_invalid_count: number;
  last_updated: number | null;
  last_error: string | null;
};

export type UpstreamMode = "load_balance" | "parallel_requests" | "fastest_addr";

export type BlockingMode = "null_ip" | "nxdomain" | "refused" | "custom_ip";

export type FilterProxyMode = "system" | "direct" | "custom";

export type AppConfig = {
  schema_version: number;
  enabled: boolean;
  use_filters: boolean;
  listen_host: string;
  listen_port: number;
  listen_ipv6: boolean;
  upstream_dns: string;
  fallback_dns: string;
  bootstrap_dns: string;
  upstream_mode: UpstreamMode;
  allowed_clients: string;
  blocked_clients: string;
  rate_limit_per_second: number;
  refuse_any: boolean;
  filter_update_interval_hours: number;
  filter_max_size_mb: number;
  filter_proxy_mode: FilterProxyMode;
  filter_proxy_url: string;
  filter_system_proxy_url: string;
  allow_insecure_http: boolean;
  query_log_enabled: boolean;
  anonymize_client_ip: boolean;
  launch_at_startup: boolean;
  query_log_retention_hours: number;
  dns_cache_enabled: boolean;
  dns_cache_size: number;
  dns_cache_min_ttl: number;
  dns_cache_max_ttl: number;
  dns_cache_optimistic: boolean;
  runtime_watchdog_enabled: boolean;
  runtime_watchdog_interval_seconds: number;
  blocking_mode: BlockingMode;
  blocking_custom_ipv4: string;
  blocking_custom_ipv6: string;
  dns_rewrites: string;
  client_names: string;
  query_log_ignored_domains: string;
  filters: FilterSubscription[];
  blacklist: string;
};

export type RuleSummary = {
  block_rules: number;
  allow_rules: number;
  ignored_rules: number;
  ignored_comment_rules: number;
  ignored_regex_rules: number;
  ignored_unsupported_rules: number;
  ignored_invalid_rules: number;
};

export type TrafficBucket = {
  minute: number;
  queries: number;
  blocked: number;
};

export type UpstreamRequestStat = {
  upstream: string;
  requests: number;
};

export type UpstreamLatencyStat = {
  upstream: string;
  avg_ms: number;
};

export type DnsStats = {
  started_at: number | null;
  dashboard_started_at?: number | null;
  dashboard_ended_at?: number | null;
  queries: number;
  blocked: number;
  forwarded: number;
  failed: number;
  access_denied_total: number;
  rate_limited_total: number;
  refused_any_total: number;
  dropped_udp_total: number;
  security_events: SecurityEvent[];
  last_query: string | null;
  last_blocked: string | null;
  last_error: string | null;
  query_domains?: Record<string, number>;
  blocked_domains?: Record<string, number>;
  client_requests?: Record<string, number>;
  blocklist_hits?: Record<string, number>;
  traffic?: TrafficBucket[];
  upstream_requests?: UpstreamRequestStat[];
  upstream_avg_latency?: UpstreamLatencyStat[];
};

export type SecurityEvent = {
  event_type: "access_denied" | "rate_limited";
  protocol: "udp" | "tcp";
  client_ip: string;
  reason: string;
  first_seen_at: number;
  last_seen_at: number;
  count: number;
};

export type RuntimeStatus = {
  running: boolean;
  listen_addr: string;
  upstream_dns: string;
  summary: RuleSummary;
  stats: DnsStats;
  error: string | null;
};

export type QueryLogResponseAnswer = {
  record_type: number;
  value: string;
  ttl: number;
};

export type QueryLogResponseSummary = {
  code: number;
  answer_count: number;
  answers: QueryLogResponseAnswer[];
  truncated: boolean;
};

export type QueryLogRecord = {
  id: number;
  timestamp: number;
  domain: string;
  query_type: number | null;
  query_class: number | null;
  transport: "udp" | "tcp" | null;
  response_source: "upstream" | "cache" | "rewrite" | "blocked" | "refused" | null;
  response: QueryLogResponseSummary | null;
  client_ip: string | null;
  blocked: boolean;
  forwarded: boolean;
  failed: boolean;
  upstream_server: string | null;
  upstream_duration_ms: number | null;
  processing_duration_ms: number | null;
  error: string | null;
  matched_rule: string | null;
  rule_source: string | null;
  rule_type: string | null;
  important_overrode: boolean;
  allowlist_rule: string | null;
};

export type QueryLogPage = {
  records: QueryLogRecord[];
  total: number;
  page: number;
  page_size: number;
};

export type FilterUpdateResult = {
  status: RuntimeStatus;
  updated: number;
  failed: number;
  cancelled: number;
  message: string;
};

export type FilterUpdateProgress = {
  running: boolean;
  total: number;
  completed: number;
  updated: number;
  failed: number;
  cancel_requested: boolean;
};

export type FilterCacheClearResult = {
  status: RuntimeStatus;
  removed_files: number;
  removed_bytes: number;
  message: string;
};

export type StorageInfo = {
  current_path: string;
  default_path: string;
  pending_path: string | null;
  migration_error: string | null;
  is_default: boolean;
  database_bytes: number;
  filter_cache_bytes: number;
  total_bytes: number;
};

export type RefreshOptions = {
  auto?: boolean;
  button?: HTMLButtonElement;
};

export type RenderStatusOptions = {
  renderDashboard?: boolean;
};

export type HistoryPoint = {
  index: number;
  value: number;
  label: string;
};

export type ChartPoint = HistoryPoint & {
  x: number;
  y: number;
};
