export type ViewName =
  | "dashboard"
  | "dns"
  | "security"
  | "filters"
  | "custom"
  | "logs"
  | "diagnostics"
  | "settings";
export type QueryLogFilter = "all" | "processed" | "blocked" | "failed";

export type FilterSubscription = {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  rule_count: number;
  last_updated: number | null;
  last_error: string | null;
};

export type UpstreamMode = "load_balance" | "parallel_requests" | "fastest_addr";

export type AppConfig = {
  schema_version: number;
  enabled: boolean;
  use_filters: boolean;
  listen_host: string;
  listen_port: number;
  upstream_dns: string;
  fallback_dns: string;
  bootstrap_dns: string;
  upstream_mode: UpstreamMode;
  allowed_clients: string;
  blocked_clients: string;
  rate_limit_per_second: number;
  refuse_any: boolean;
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
  diagnostics_domain: string;
  runtime_watchdog_enabled: boolean;
  runtime_watchdog_interval_seconds: number;
  filters: FilterSubscription[];
  blacklist: string;
};

export type RuleSummary = {
  block_rules: number;
  allow_rules: number;
  ignored_rules: number;
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

export type RuntimeStatus = {
  running: boolean;
  listen_addr: string;
  upstream_dns: string;
  summary: RuleSummary;
  stats: DnsStats;
  error: string | null;
};

export type QueryLogRecord = {
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
  message: string;
};

export type FilterCacheClearResult = {
  status: RuntimeStatus;
  removed_files: number;
  removed_bytes: number;
  message: string;
};

export type DnsProbeResult = {
  ok: boolean;
  duration_ms: number | null;
  rcode: number | null;
  answers: number | null;
  error: string | null;
};

export type DnsDiagnosticsResult = {
  domain: string;
  listen_addr: string;
  udp: DnsProbeResult;
  tcp: DnsProbeResult;
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
