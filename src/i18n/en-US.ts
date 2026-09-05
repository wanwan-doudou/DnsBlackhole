/**
 * 英文字典：键是中文原文，值是译文。
 *
 * 中文文案有改动时，这里的键也要同步改，否则该条会回退成中文。
 */
export const enUS: Record<string, string> = {
  // ---------- 顶部导航与运行状态 ----------
  "过滤保护控制": "Filtering controls",
  "模块": "Sections",
  "设置分类": "Settings categories",
  "过滤器分类": "Filter categories",
  "正在连接": "Connecting",
  "正在读取 DNS 运行状态…": "Reading DNS service status…",
  "暂停 5 分钟": "Pause for 5 minutes",
  "暂停 30 分钟": "Pause for 30 minutes",
  "暂停 1 小时": "Pause for 1 hour",
  "立即恢复过滤": "Resume filtering now",
  "仪表盘": "Dashboard",
  "设置": "Settings",
  "过滤器": "Filters",
  "查询日志": "Query log",
  "关于": "About",
  "常规与运行": "General",
  "DNS 设置": "DNS settings",
  "安全防护": "Security",
  "DNS 诊断": "DNS diagnostics",
  "DNS 黑名单": "Blocklists",
  "自定义规则与重写": "Custom rules & rewrites",

  // ---------- 仪表盘 ----------
  "DNS 使用概览": "DNS overview",
  "点击客户端可直接查看该设备的查询日志。": "Select a client to jump straight to its query log.",
  "统计范围": "Range",
  "按保留设置": "Follow retention setting",
  "最近 24 小时": "Last 24 hours",
  "最近 7 天": "Last 7 days",
  "最近 30 天": "Last 30 days",
  "全部历史": "All time",
  "统计趋势": "Trend",
  "DNS 查询": "DNS queries",
  "已拦截查询": "Blocked queries",
  "请求域名排行": "Top queried domains",
  "暂无汇总数据": "No aggregated data yet",
  "域名": "Domain",
  "请求数": "Queries",
  "被拦截域名排行": "Top blocked domains",
  "客户端排行": "Top clients",
  "客户端": "Client",
  "拦截率": "Block rate",
  "DNS 黑名单排行": "Top blocklists",
  "黑名单": "Blocklist",
  "拦截数": "Blocked",
  "经常请求的上游服务器": "Most used upstreams",
  "上游服务器": "Upstream",
  "上游服务器的平均响应时间": "Average upstream response time",
  "响应时间": "Response time",

  // ---------- 查询日志 ----------
  "刷新": "Refresh",
  "刷新查询日志": "Refresh query log",
  "搜索域名或客户端": "Search domain or client",
  "查询日志状态筛选": "Query log status filter",
  "例如 夜间失败查询": "e.g. Failed queries at night",
  "DNS 查询日志": "DNS query log",
  "关闭": "Close",
  "暂停实时刷新": "Pause live refresh",
  "导出当前筛选": "Export current view",
  "所有查询记录": "All queries",
  "已处理": "Processed",
  "已过滤": "Filtered",
  "失败": "Failed",
  "更多筛选": "More filters",
  "时间范围": "Time range",
  "按日志保留设置": "Follow log retention",
  "最近 1 小时": "Last hour",
  "响应来源": "Response source",
  "全部来源": "All sources",
  "DNS 缓存": "DNS cache",
  "DNS 重写": "DNS rewrite",
  "过滤规则": "Filter rule",
  "拒绝响应": "Refused",
  "查询类型": "Query type",
  "全部类型": "All types",
  "其他类型": "Other types",
  "排序方式": "Sort by",
  "最新优先": "Newest first",
  "最早优先": "Oldest first",
  "最慢优先": "Slowest first",
  "保存的视图": "Saved views",
  "选择已保存视图": "Select a saved view",
  "视图名称": "View name",
  "保存当前": "Save current",
  "删除": "Delete",
  "重置筛选": "Reset filters",
  "时间": "Time",
  "请求": "Request",
  "响应": "Response",
  "0 条记录": "0 records",
  "上一页": "Previous",
  "下一页": "Next",
  "查询日志快捷操作": "Query log quick actions",
  "添加 DNS 重写": "Add DNS rewrite",
  "域名：": "Domain:",
  "重写目标 IP": "Target IP",
  "填写有效的 IPv4 或 IPv6 地址；保存后会立即热更新，无需重启 DNS。":
    "Enter a valid IPv4 or IPv6 address. Saving applies immediately without restarting DNS.",
  "取消": "Cancel",
  "保存重写": "Save rewrite",

  // ---------- 通用操作 ----------
  "正在读取配置": "Loading configuration",
  "保存更改": "Save changes",
  "启动": "Start",
  "停止": "Stop",
  "自定义": "Custom",

  // ---------- DNS 设置 ----------
  "上游 DNS": "Upstream DNS",
  "上游 DNS 服务器": "Upstream DNS servers",
  "每行一个上游：普通 DNS、https://（DoH）、tls://（DoT）或 quic://（DoQ）。DoT / DoQ 必须填写证书对应的主机名。":
    "One upstream per line: plain DNS, https:// (DoH), tls:// (DoT) or quic:// (DoQ). DoT and DoQ must use the hostname the certificate was issued for.",
  "IPv4 监听地址": "IPv4 listen address",
  "端口": "Port",
  "监听 IPv6": "Listen on IPv6",
  "开启后额外绑定 [::]:同一端口，同时接受 IPv4 与 IPv6 DNS 请求。":
    "Also binds [::] on the same port so both IPv4 and IPv6 queries are accepted.",
  "Fallback DNS 服务器": "Fallback DNS servers",
  "所有上游服务器都失败时重试的后备 DNS，语法与上游相同。留空则禁用。":
    "Retried when every upstream fails. Same syntax as upstreams. Leave empty to disable.",
  "Bootstrap DNS 服务器": "Bootstrap DNS servers",
  "用于解析 DoH 和域名形式上游自身的地址，并同时查询 IPv4/IPv6；只支持普通 IP 地址 DNS。":
    "Resolves the addresses of DoH and hostname upstreams, querying IPv4 and IPv6 in parallel. Plain IP servers only.",
  "验证 DNSSEC": "Validate DNSSEC",
  "请求 DNSSEC 记录并要求上游执行验证；验证失败的 SERVFAIL 响应会被拒绝。建议搭配可信的 DoH、DoT 或 DoQ 上游。":
    "Requests DNSSEC records and asks the upstream to validate them. SERVFAIL responses from failed validation are rejected. Best paired with a trusted DoH, DoT or DoQ upstream.",
  "负载均衡": "Load balance",
  "一次查询一台上游服务器，失败后尝试其它服务器。":
    "Queries one upstream at a time and falls back to the others on failure.",
  "并行请求": "Parallel requests",
  "优先查询一个上游；25 毫秒内未成功时并发查询其余上游，并使用最先成功的响应。":
    "Queries one upstream first; if it has not answered within 25 ms the rest are queried in parallel and the first success wins.",
  "最快的 IP 地址": "Fastest IP address",
  "等待上游服务器响应，测速返回的 IP 地址，并优先采用最快的可用结果。":
    "Collects upstream answers, probes the returned addresses and prefers the fastest reachable result.",
  "DNS 分流与客户端上游策略": "Split DNS and per-client upstreams",
  "匹配后只使用指定上游，不回退到全局服务器。客户端策略优先于域名分流；保存后会安全重启 DNS 运行时。":
    "A match uses only the listed upstreams and never falls back to the global servers. Client rules take priority over domain rules. Saving restarts the DNS runtime safely.",
  "域名分流": "Domain routing",
  "每行“域名模式 =&gt; 上游”。使用 *.example.com 同时匹配主域和子域；多个上游用逗号分隔。":
    "One \"domain pattern =&gt; upstream\" per line. Use *.example.com to match the domain and its subdomains; separate multiple upstreams with commas.",
  "客户端上游策略": "Client upstream rules",
  "每行“IP/CIDR =&gt; 上游”。更精确的网段优先，可让指定设备或网段使用独立 DNS。":
    "One \"IP/CIDR =&gt; upstream\" per line. The most specific network wins, letting chosen devices or subnets use their own DNS.",

  // ---------- 拦截方式 ----------
  "拦截响应方式": "Blocking mode",
  "命中黑名单时返回给客户端的响应类型，保存后立即生效，无需重启服务。":
    "What clients receive when a query is blocked. Applies immediately without restarting the service.",
  "零地址（默认）": "Null address (default)",
  "A 返回 0.0.0.0，AAAA 返回 ::，兼容性最好。":
    "Answers 0.0.0.0 for A and :: for AAAA. The most compatible option.",
  "返回“域名不存在”，部分应用对此的处理更干脆。":
    "Answers \"domain does not exist\", which some applications handle more decisively.",
  "返回“拒绝服务”，客户端会更快放弃重试。":
    "Answers \"refused\", so clients give up retrying sooner.",
  "自定义 IP": "Custom IP",
  "返回指定 IP，可指向局域网内的提示页面服务器。":
    "Answers a fixed address, for example a notice page on your LAN.",
  "拦截响应 TTL": "Blocked response TTL",
  "客户端缓存零地址、自定义 IP 或 NXDOMAIN 拦截结果的秒数；0 表示不缓存。":
    "How many seconds clients may cache a null-address, custom-IP or NXDOMAIN block. 0 disables caching.",
  "自定义 IPv4": "Custom IPv4",
  "自定义 IPv6（可选）": "Custom IPv6 (optional)",

  // ---------- 缓存 ----------
  "DNS 缓存配置": "DNS cache",
  "您可以在此处配置 DNS 缓存": "Configure the local DNS response cache here.",
  "启用缓存": "Enable cache",
  "在本地存储 DNS 响应，减少重复查询的上游请求延迟。":
    "Stores DNS answers locally so repeated queries skip the upstream round trip.",
  "缓存大小": "Cache size",
  "DNS 缓存大小（单位：字节）": "DNS cache size (bytes)",
  "覆盖最小 TTL 值": "Override minimum TTL",
  "缓存 DNS 响应时，延长从上游服务器接收到的 TTL 值（秒）。":
    "Extends the TTL received from upstream when caching an answer (seconds).",
  "覆盖最大 TTL 值": "Override maximum TTL",
  "设定 DNS 缓存条目的最大 TTL 值（秒）。": "Caps the TTL of cached entries (seconds).",
  "乐观缓存": "Optimistic caching",
  "条目过期后可在限定时间内先响应缓存，并在后台刷新。":
    "Serves an expired entry for a limited time while refreshing it in the background.",
  "最大陈旧时间": "Maximum staleness",
  "乐观缓存最多可继续使用过期响应的时间，范围 60–604800 秒。":
    "How long an expired answer may still be served, between 60 and 604800 seconds.",
  "热门域名预取": "Prefetch popular domains",
  "高频条目接近过期时在后台提前刷新，减少客户端遇到冷缓存的概率；同一条目只允许一个刷新任务。":
    "Refreshes frequently used entries shortly before they expire so clients rarely hit a cold cache. Only one refresh runs per entry.",
  "预取命中阈值": "Prefetch hit threshold",
  "条目至少命中多少次后才允许预取，范围 2–10000。":
    "How many hits an entry needs before it is eligible for prefetching, between 2 and 10000.",
  "清除缓存": "Clear cache",
  "运行状态": "Runtime",
  "本次 DNS 服务运行期间的内存缓存指标": "In-memory cache metrics for the current service run",
  "命中率": "Hit rate",
  "命中 / 未命中": "Hits / misses",
  "过期应答": "Stale answers",
  "后台刷新（成功 / 失败）": "Background refresh (ok / failed)",
  "热门预取（成功 / 失败）": "Prefetch (ok / failed)",
  "淘汰条目": "Evicted entries",
  "当前条目": "Entries",
  "当前占用": "Memory used",

  // ---------- 诊断 ----------
  "DNS 诊断中心": "DNS diagnostics",
  "检查本地过滤判定，并并行测试每个已配置上游的响应、延迟与返回记录。":
    "Shows the local filtering decision and tests every configured upstream in parallel for response, latency and returned records.",
  "开始诊断": "Run diagnostics",
  "测试域名": "Domain to test",
  "模拟客户端（可选）": "Simulated client (optional)",
  "填写 IPv4 或 IPv6，可验证该设备是否命中过滤绕过策略。":
    "Enter an IPv4 or IPv6 address to check which filtering policy that device would match.",
  "尚未运行诊断": "No diagnostics run yet",
  "输入域名后开始测试；不会修改配置，也不会写入查询日志。":
    "Enter a domain to start. Nothing is written to the configuration or the query log.",
  "A（IPv4）": "A (IPv4)",
  "AAAA（IPv6）": "AAAA (IPv6)",

  // ---------- 安全防护 ----------
  "客户端访问控制": "Client access control",
  "限制可使用此 DNS 服务的客户端，避免成为开放递归 DNS。":
    "Restrict which clients may use this resolver so it never becomes an open recursive DNS.",
  "允许客户端": "Allowed clients",
  "每行一个 IP 或 CIDR。留空时允许所有未被拒绝的客户端。":
    "One IP or CIDR per line. When empty, every client that is not denied is allowed.",
  "拒绝客户端": "Denied clients",
  "每行一个 IP 或 CIDR。拒绝列表优先于允许列表。":
    "One IP or CIDR per line. The deny list takes priority over the allow list.",
  "客户端名称": "Client names",
  "每行一条“IP 名称”，例如 192.168.1.23 客厅电视。查询日志会用名称代替 IP 展示。":
    "One \"IP name\" pair per line, e.g. 192.168.1.23 Living room TV. The query log shows the name instead of the address.",
  "192.168.1.23 客厅电视": "192.168.1.23 Living room TV",
  "客户端过滤策略": "Client filtering rules",
  "每行一条“IP/CIDR =&gt; 策略组 [@ 周期 时间]”，最长 CIDR 优先。周期使用 mon-sun 或 daily，支持跨午夜时段。":
    "One \"IP/CIDR =&gt; policy [@ days time]\" per line; the longest CIDR wins. Use mon-sun or daily for the schedule; ranges may cross midnight.",
  "自定义策略组": "Policy groups",
  "格式：名称 =&gt; filter|bypass, safe_search, block:服务|服务。可用服务见右侧说明。":
    "Format: name =&gt; filter|bypass, safe_search, block:service|service. Available services are listed on the right.",
  "家庭组启用安全搜索": "Enable safe search for the family group",
  "为 Google、Bing、DuckDuckGo 和 YouTube 返回强制安全模式重定向。":
    "Redirects Google, Bing, DuckDuckGo and YouTube to their enforced safe-mode hosts.",
  "家庭组拦截服务": "Services blocked for the family group",
  "逗号或换行分隔：youtube、tiktok、instagram、facebook、x、reddit、twitch、discord、steam、epic、roblox。":
    "Separate with commas or new lines: youtube, tiktok, instagram, facebook, x, reddit, twitch, discord, steam, epic, roblox.",
  "查询防护": "Query protection",
  "降低异常流量和 DNS 放大攻击风险。": "Reduces abusive traffic and DNS amplification risk.",
  "每客户端限速": "Per-client rate limit",
  "持续每秒允许的 DNS 查询数；默认 2000 并可容纳约 10 秒短时突发，适合路由器汇聚多台设备，0 表示关闭限速。":
    "Sustained queries per second per client. The default of 2000 absorbs bursts of about 10 seconds, which suits a router aggregating many devices. 0 disables the limit.",
  "拒绝 ANY 查询": "Refuse ANY queries",
  "减少 DNS 放大攻击面，家庭网关场景通常应开启。":
    "Shrinks the amplification attack surface. Usually worth enabling on a home gateway.",
  "响应安全防护": "Response protection",
  "检查上游返回的地址和 CNAME 链，阻止恶意域名绕过过滤器或访问局域网资源。":
    "Inspects upstream addresses and CNAME chains to stop hostile domains from bypassing filters or reaching LAN resources.",
  "公共域名返回私有、回环、链路本地或组播地址时改为拦截响应；域名分流上游自动视为可信。":
    "Blocks public domains that resolve to private, loopback, link-local or multicast addresses. Domain-routed upstreams are trusted automatically.",
  "CNAME cloaking 检测": "CNAME cloaking detection",
  "解析响应中的 CNAME 目标，并用当前黑白名单再次判定，阻止首方别名隐藏被拦截域名。":
    "Re-checks CNAME targets against the current block and allow lists so first-party aliases cannot hide a blocked domain.",
  "Rebinding 可信域名": "Rebinding-trusted domains",
  "每行一个域名；同时信任它的子域名。用于确实需要返回局域网地址的内部服务。":
    "One domain per line, subdomains included. For internal services that legitimately resolve to LAN addresses.",

  // ---------- 安全事件 ----------
  "安全事件": "Security events",
  "UDP 拒绝仍保持静默丢弃；这里展示拒绝与限速情况，最多保留最近 200 条聚合事件。事件会落盘保存，重启后仍可查看。":
    "Denied UDP queries are still dropped silently. This lists denials and rate limiting, keeping the 200 most recent aggregated events. Events are stored on disk and survive a restart.",
  "访问拒绝": "Access denied",
  "限速触发": "Rate limited",
  "UDP 静默丢弃": "UDP dropped silently",
  "ANY 拒绝": "ANY refused",
  "Rebinding 拦截": "Rebinding blocked",
  "CNAME cloaking 拦截": "CNAME cloaking blocked",
  "最近安全事件": "Recent security events",
  "最近发生": "Last seen",
  "来源客户端": "Client",
  "事件": "Event",
  "次数": "Count",
  "暂无安全事件": "No security events yet",
  "安全事件保留时间": "Security event retention",
  "超过保留期的历史事件会在后台维护时清理。":
    "Events older than the retention window are removed during background maintenance.",
  "最近 90 天": "Last 90 days",
  "最近 365 天": "Last 365 days",
  "清除历史事件": "Clear history",
  "立即删除已落盘的全部安全事件，不影响统计和查询日志。":
    "Deletes every stored security event immediately. Statistics and query logs are untouched.",
  "清除安全事件": "Clear security events",
  "容量保护": "Capacity safeguards",
  "展示本次服务运行期间因内部队列或连接上限触发的降级；正常情况下都应为 0。":
    "Degradations caused by internal queue or connection limits during this run. All of these should normally be 0.",
  "DNS 工作队列丢弃": "DNS work queue drops",
  "日志持久化丢弃": "Log persistence drops",
  "上游任务池降级": "Upstream task pool rejections",
  "TCP 连接拒绝": "TCP connections refused",

  // ---------- 过滤器下载安全 ----------
  "过滤器下载安全": "Filter download safety",
  "限制远程黑名单下载行为，降低异常响应和中间人篡改风险。":
    "Constrains how remote blocklists are downloaded, limiting exposure to malformed responses and tampering.",
  "单个过滤器最大大小（MB）": "Maximum size per filter (MB)",
  "按解压后的实际读取大小限制，超过后立即中断下载。":
    "Measured after decompression. The download aborts as soon as the limit is exceeded.",
  "下载代理": "Download proxy",
  "自动读取当前用户的系统代理，并交给后台服务使用。":
    "Reads the current user's system proxy and hands it to the background service.",
  "跟随系统代理": "Use system proxy",
  "直接连接": "Direct connection",
  "自定义代理": "Custom proxy",
  "自定义代理地址": "Custom proxy address",
  "支持 HTTP/HTTPS 代理，例如 http://127.0.0.1:7897。":
    "HTTP and HTTPS proxies are supported, e.g. http://127.0.0.1:7897.",
  "允许不安全 HTTP": "Allow insecure HTTP",
  "允许 HTTP 黑名单订阅和 HTTP DoH。仅在可信内网或临时迁移时使用。":
    "Permits HTTP blocklist subscriptions and HTTP DoH. Use only on a trusted network or during a temporary migration.",

  // ---------- 常规设置 ----------
  "管理启动行为、后台服务、数据与隐私。":
    "Startup behaviour, background service, data and privacy.",
  "常规设置": "General",
  "拦截总开关、过滤器更新频率与启动方式。":
    "Blocking switch, filter refresh frequency and startup behaviour.",
  "使用过滤器和 Hosts 文件以拦截指定域名":
    "Use filters and hosts files to block domains",
  "你可以在 DNS 黑名单和自定义过滤规则中添加过滤规则。":
    "Add rules under Blocklists and Custom rules.",
  "过滤器更新间隔": "Filter update interval",
  "6 小时": "6 hours",
  "12 小时": "12 hours",
  "24 小时": "24 hours",
  "3 天": "3 days",
  "7 天": "7 days",
  "启动时自动运行 DNS 服务": "Start the DNS service automatically",
  "开机时启动应用": "Launch the app at sign-in",

  // ---------- 界面偏好 ----------
  "界面": "Appearance",
  "界面偏好立即生效，保存在本机，不属于需要保存的 DNS 配置。":
    "Appearance settings apply immediately and are stored on this device. They are not part of the DNS configuration you save.",
  "主题": "Theme",
  "跟随系统会随 Windows 的浅色/深色设置自动切换。":
    "Following the system tracks the Windows light and dark setting.",
  "跟随系统": "Follow system",
  "浅色": "Light",
  "深色": "Dark",
  "界面语言": "Language",
  "切换语言会重新载入界面。": "Changing the language reloads the interface.",
  "简体中文": "简体中文",

  // ---------- 运行监控与后台服务 ----------
  "运行监控": "Health monitoring",
  "DNS 服务意外停止时自动拉起，避免本机解析中断。":
    "Brings the DNS service back up if it stops unexpectedly, so name resolution keeps working.",
  "自动恢复 DNS 服务": "Restart the DNS service automatically",
  "检测到服务未运行或内部线程异常时自动重启 DNS 服务。":
    "Restarts the DNS service when it stops running or an internal thread fails.",
  "检查间隔（秒）": "Check interval (seconds)",
  "Windows DNS 系统服务": "Windows DNS system service",
  "正在读取系统服务状态…": "Reading system service status…",
  "DNS 核心由 Windows 服务控制管理器在开机阶段自动启动；关闭 GUI、尚未登录或 Clash 稍后启动都不会中断本机 DNS。":
    "The DNS core is started at boot by the Windows Service Control Manager, so closing the window, not having signed in yet, or another tool starting later will not interrupt local DNS.",
  "安装或修复": "Install or repair",
  "卸载服务": "Uninstall service",
  "系统 DNS": "System DNS",
  "正在读取系统 DNS 状态…": "Reading system DNS status…",
  "会按有线、无线网卡分别保存原始 DNS；切换网络后可将当前活动网卡同步纳入接管。":
    "Original DNS settings are saved per wired and wireless adapter. After switching networks the active adapter can be brought under management too.",
  "接管 DNS": "Take over DNS",
  "恢复 DNS": "Restore DNS",
  "解除本机 DNS": "Release local DNS",
  "当前没有原 DNS 备份，请选择解除后使用的 DNS。只会修改仍指向 127.0.0.1 或 ::1 的设置。":
    "No original DNS backup exists. Choose what to use after releasing. Only adapters still pointing at 127.0.0.1 or ::1 are changed.",
  "按接管前配置恢复（推荐）": "Restore the pre-takeover settings (recommended)",
  "保留接管前的自动获取或手动 DNS 设置":
    "Keeps whatever automatic or manual DNS was configured before takeover",
  "自动获取（DHCP）": "Obtain automatically (DHCP)",
  "适合 IP 也由 DHCP 分配的网络；静态 IP 建议使用自定义 DNS":
    "Suitable when the address also comes from DHCP. With a static IP, prefer a custom DNS",
  "8.8.8.8 / 8.8.4.4，并配置 IPv6": "8.8.8.8 / 8.8.4.4, with IPv6 configured",
  "自定义 DNS": "Custom DNS",
  "填写希望在解除接管后使用的 DNS 服务器地址":
    "Enter the DNS servers to use after releasing",
  "IPv6 DNS（可选）": "IPv6 DNS (optional)",
  "确认解除": "Confirm release",
  "macOS DNS 后台服务": "macOS DNS background service",
  "正在读取后台服务状态…": "Reading background service status…",
  "正式版通过系统后台服务监听 UDP/TCP 53。首次安装需要管理员在“系统设置 → 通用 → 登录项与扩展”中批准。":
    "Release builds listen on UDP/TCP 53 through a system background service. The first install must be approved by an administrator under System Settings → General → Login Items & Extensions.",
  "打开系统设置": "Open System Settings",

  // ---------- 监控接口 ----------
  "只读监控接口": "Read-only monitoring API",
  "向本机监控工具提供": "Exposes",
  "和 Prometheus": "and Prometheus",
  "；不会暴露域名或客户端明细。": "to local monitoring tools. No domains or client details are exposed.",
  "启用 REST 与 Prometheus": "Enable REST and Prometheus",
  "默认仅监听 127.0.0.1；监听局域网地址时必须设置至少 16 个字符的令牌。":
    "Binds to 127.0.0.1 by default. Listening on a LAN address requires a token of at least 16 characters.",
  "监听地址": "Listen address",
  "访问令牌（可选）": "Access token (optional)",
  "本机监听可留空": "Optional when listening locally",

  // ---------- 数据存储 ----------
  "数据存储": "Data storage",
  "数据存储路径": "Data directory",
  "查询日志、统计数据库和过滤器数据会保存在此目录。可迁移到空目录，也可在重装系统后安全使用保留的现有数据。":
    "Query logs, the statistics database and filter data live in this directory. It can be moved to an empty folder, or an existing folder can be reused safely after reinstalling.",
  "选择目录": "Choose folder",
  "恢复默认": "Reset to default",
  "正在读取占用空间…": "Reading disk usage…",
  "迁移并重启": "Migrate and restart",
  "磁盘缓存": "Disk cache",
  "清理可重新生成的规则编译缓存，不会删除远程黑名单、当前生效规则、配置、查询日志和统计数据。":
    "Clears the regenerable compiled-rule cache. Remote blocklists, active rules, configuration, query logs and statistics are kept.",
  "清理缓存": "Clear cache",
  "备份与诊断": "Backup and diagnostics",
  "导出或恢复完整配置；诊断文件会隐藏域名、客户端地址、规则、代理和上游等隐私内容。":
    "Export or restore the full configuration. Diagnostic files omit domains, client addresses, rules, proxies and upstreams.",
  "导出配置": "Export configuration",
  "恢复配置": "Restore configuration",
  "导出脱敏诊断": "Export redacted diagnostics",

  // ---------- 日志与统计配置 ----------
  "日志配置": "Query log",
  "启用日志": "Enable query log",
  "匿名化客户端 IP": "Anonymise client IPs",
  "持久化查询日志和统计中仅保存匿名化后的客户端 IP；运行期安全事件仍会显示来源 IP。":
    "Stored query logs and statistics keep only anonymised client addresses. Security events still show the source address while the service runs.",
  "查询日志保留时间": "Query log retention",
  "30 天": "30 days",
  "90 天": "90 days",
  "180 天": "180 days",
  "360 天": "360 days",
  "自定义保留时间（小时）": "Custom retention (hours)",
  "例如 120": "e.g. 120",
  "日志忽略域名": "Domains excluded from the log",
  "每行一个域名，自动包含其子域名。命中的查询不会写入查询日志。":
    "One domain per line, subdomains included. Matching queries are not written to the query log.",
  "清除查询日志": "Clear query log",
  "统计配置": "Statistics",
  "启用统计数据": "Enable statistics",
  "按小时聚合查询趋势、域名、客户端、上游和黑名单命中，不保存完整 DNS 响应。":
    "Aggregates trends, domains, clients, upstreams and blocklist hits by hour. Full DNS responses are not stored.",
  "统计数据保留时间": "Statistics retention",
  "365 天": "365 days",
  "永久": "Forever",
  "自定义保留时间（天）": "Custom retention (days)",
  "统计忽略域名": "Domains excluded from statistics",
  "每行一个域名，自动包含其子域名。适合排除 NAS 心跳、探活等高频噪音，不影响查询日志。":
    "One domain per line, subdomains included. Useful for excluding NAS heartbeats and health checks. The query log is unaffected.",
  "清除统计数据": "Clear statistics",

  // ---------- 关于 ----------
  "版本、运行环境与支持信息。": "Version, runtime environment and support details.",
  "轻量的本地 DNS 转发与域名拦截工具。":
    "A lightweight local DNS forwarder and domain blocker.",
  "配置、过滤规则和查询数据保存在你的设备上，无需注册账户。":
    "Configuration, filter rules and query data stay on your device. No account required.",
  "应用特性": "Highlights",
  "本地优先": "Local first",
  "后台系统服务": "System background service",
  "开源透明": "Open source",
  "独立守护 DNS": "Keeps DNS running on its own",
  "关闭界面后，系统服务仍可持续保护本机。":
    "The system service keeps protecting this machine after the window is closed.",
  "版本与运行环境": "Version and environment",
  "提交问题时，可复制这些不包含域名和客户端信息的摘要。":
    "Copy this summary when reporting an issue. It contains no domains or client details.",
  "复制支持信息": "Copy support info",
  "应用版本": "App version",
  "运行平台": "Platform",
  "正在识别…": "Detecting…",
  "后台服务": "Background service",
  "正在读取…": "Loading…",
  "DNS 核心": "DNS core",
  "软件更新": "Updates",
  "检查稳定版本并查看本次变更；安装前会先完成下载验证。":
    "Checks for stable releases and shows what changed. Downloads are verified before installing.",
  "检查更新": "Check for updates",
  "帮助与项目": "Help and project",
  "文档和反馈会在系统浏览器中打开。":
    "Documentation and feedback links open in your system browser.",
  "获取帮助": "Get help",
  "使用文档": "Documentation",
  "了解安装、DNS 接管与过滤规则":
    "Installation, DNS takeover and filter rules",
  "报告问题": "Report an issue",
  "提交故障信息或功能建议": "Send a bug report or feature request",
  "项目信息": "Project",
  "项目源码": "Source code",
  "更新记录": "Release notes",
  "版本与变更": "Versions and changes",
  "开源许可": "Licence",
  "DnsBlackhole 是基于 MIT License 发布的开源项目。":
    "DnsBlackhole is open source under the MIT License.",
  "发现新版本": "Update available",
  "本次更新内容": "What's new",
  "稍后": "Later",
  "浏览器下载": "Download in browser",
  "下载并安装": "Download and install",
  "取消更新": "Cancel update",

  // ---------- 过滤器与自定义规则 ----------
  "远程黑名单": "Remote blocklists",
  "添加黑名单": "Add blocklist",
  "启用": "Enabled",
  "名称": "Name",
  "规则数": "Rules",
  "上次更新": "Last updated",
  "状态": "Status",
  "操作": "Actions",
  "自定义过滤规则": "Custom filter rules",
  "等待读取规则": "Waiting for rules",
  "在自定义规则中查找": "Search custom rules",
  "查找规则，按 Enter 跳到下一处": "Search rules, press Enter for the next match",
  "每行一条“域名 IP”本地记录，优先于黑名单生效。用 *.域名 匹配整个子域，同一域名可以分别写一行 IPv4 和一行 IPv6。":
    "One \"domain IP\" record per line, applied before blocklists. Use *.domain to match a whole subtree; write IPv4 and IPv6 for the same domain on separate lines.",
  "合并系统 hosts 文件": "Merge the system hosts file",
  "把本机 hosts 文件中的记录并入上面的重写表。上面显式写出的记录优先；修改 hosts 后需要再保存一次配置才会重新读取。":
    "Merges this machine's hosts file into the rewrite table above. Records written above take priority. After editing hosts, save the configuration again to reload it.",

  // ---------- 占位与示例 ----------
  "例如 192.168.1.10": "e.g. 192.168.1.10",
  "例如 192.168.1.100": "e.g. 192.168.1.100",
  "例如 fd00::1": "e.g. fd00::1",
  "例如 1.1.1.1, 1.0.0.1": "e.g. 1.1.1.1, 1.0.0.1",
  "例如 2606:4700:4700::1111": "e.g. 2606:4700:4700::1111",

  // ---------- 运行状态与平台 ----------
  "缺少应用挂载节点": "Application mount point is missing",
  "当前桌面平台": "This desktop platform",
  "已连接{p0}": "Connected{p0}",
  "需要修复{p0}": "Needs repair{p0}",
  "尚未安装": "Not installed",
  "已启用{p0}": "Enabled{p0}",
  "需要处理": "Needs attention",
  "当前平台无需系统服务": "No system service is needed on this platform",
  "保护已暂停": "Protection paused",
  "保护运行中": "Protection active",
  "当前未运行": "Not running",
  "运行平台：{p0}": "Platform: {p0}",
  "后台服务：{p0}": "Background service: {p0}",
  "DNS 核心：{p0}": "DNS core: {p0}",
  "系统 DNS：{p0}": "System DNS: {p0}",
  "配置架构：v{p0}": "Config schema: v{p0}",
  "未知": "Unknown",
  "不适用": "Not applicable",
  "已接管": "Managed",
  "接管状态异常": "Takeover state is inconsistent",
  "未接管": "Not managed",
  "过滤已暂停": "Filtering paused",
  "运行异常": "Runtime error",
  "服务已停止": "Service stopped",
  "DNS 仍在运行，黑名单过滤将在{p0}后自动恢复。":
    "DNS is still running. Blocklist filtering resumes automatically in {p0}.",
  "正在监听 {p0}，可临时暂停黑名单过滤。":
    "Listening on {p0}. Blocklist filtering can be paused temporarily.",
  "DNS 运行时出现异常": "The DNS runtime hit an error",
  "请先启动 DNS 服务，再使用临时暂停。": "Start the DNS service before pausing filtering.",
  "片刻": "a moment",
  "{p0} 小时": "{p0} h",
  "{p0} 分钟": "{p0} min",
  "{p0} 天": "{p0} d",
  "{p0} 个月": "{p0} mo",
  "{p0} 毫秒": "{p0} ms",
  "过滤保护已恢复": "Filtering resumed",
  "过滤保护已暂停 {p0}": "Filtering paused for {p0}",

  // ---------- 剪贴板与链接 ----------
  "当前系统不允许写入剪贴板": "This system does not allow writing to the clipboard",
  "无法打开{p0}。请重试，或复制链接后在浏览器中打开。":
    "Could not open {p0}. Try again, or copy the link and open it in your browser.",
  "重试": "Retry",
  "复制链接": "Copy link",
  "{p0}链接已复制": "{p0} link copied",
  "已复制": "Copied",
  "支持信息已复制，不包含域名、客户端或访问令牌":
    "Support info copied. It contains no domains, clients or tokens.",
  "复制支持信息失败：{p0}": "Could not copy support info: {p0}",
  "问题反馈": "Feedback",
  "请选择": "Select",
  "刷新仪表盘": "Refresh dashboard",

  // ---------- 查询日志操作 ----------
  "已保存查询视图“{p0}”": "Saved view \"{p0}\"",
  "查询视图已保存": "View saved",
  "删除查询视图“{p0}”？": "Delete the view \"{p0}\"?",
  "已删除查询视图“{p0}”": "Deleted view \"{p0}\"",
  "视图名称需要 1-40 个字符": "View names must be 1-40 characters",
  "最多保存 {p0} 个查询视图": "You can save at most {p0} views",
  "请先保存当前配置更改，再从查询日志添加规则":
    "Save your configuration changes before adding rules from the query log",
  "请填写 DNS 重写目标 IP": "Enter a target IP for the DNS rewrite",
  "恢复实时刷新": "Resume live refresh",
  "导出的 CSV 会包含当前筛选中的域名和客户端地址，请妥善保管。是否继续？":
    "The exported CSV contains the domains and client addresses in the current view. Keep it safe. Continue?",
  "准备导出…": "Preparing export…",
  "导出 {p0}/{p1}": "Exporting {p0}/{p1}",
  "已导出最近 {p0} 条；当前筛选共 {p1} 条，请缩小筛选范围以导出其余记录":
    "Exported the {p0} most recent of {p1} matching records. Narrow the filter to export the rest.",
  "已导出 {p0} 条查询日志": "Exported {p0} log entries",
  "已启用 {p0} 个高级筛选": "{p0} advanced filters active",
  "更多筛选，已启用 {p0} 个条件": "More filters, {p0} active",
  "<option value=\"\">选择已保存视图</option>": "<option value=\"\">Select a saved view</option>",
  "{p0}-{p1} / {p2} 条": "{p0}-{p1} of {p2}",
  "没有匹配的查询记录": "No matching queries",
  "暂无查询记录": "No queries yet",
  "<div class=\"query-log-empty\">查询日志未启用，请在设置中开启日志配置。</div>":
    "<div class=\"query-log-empty\">The query log is disabled. Enable it under Settings.</div>",
  "<div class=\"query-log-empty\">{p0}</div>": "<div class=\"query-log-empty\">{p0}</div>",

  // ---------- 配置保存与备份 ----------
  "导出中…": "Exporting…",
  "恢复中…": "Restoring…",
  "配置尚未加载，无法导出": "The configuration has not loaded yet, so it cannot be exported",
  "配置备份已导出": "Configuration backup exported",
  "恢复配置会覆盖当前未保存的更改，是否继续？":
    "Restoring will overwrite your unsaved changes. Continue?",
  "配置已校验、迁移并恢复": "Configuration validated, migrated and restored",
  "配置尚未加载，无法导出诊断信息":
    "The configuration has not loaded yet, so diagnostics cannot be exported",
  "脱敏诊断信息已导出": "Redacted diagnostics exported",
  "配置尚未从 DNS 服务加载，已阻止保存以保护原配置":
    "The configuration has not been loaded from the DNS service. Saving was blocked to protect the existing settings.",
  "配置已保存": "Configuration saved",
  "配置不可用": "Configuration unavailable",
  "有未保存的更改": "Unsaved changes",
  "所有更改已保存": "All changes saved",
  "导出 DnsBlackhole 配置": "Export DnsBlackhole configuration",
  "JSON 配置": "JSON configuration",
  "选择 DnsBlackhole 配置备份": "Choose a DnsBlackhole configuration backup",
  "导出脱敏诊断信息": "Export redacted diagnostics",
  "JSON 诊断信息": "JSON diagnostics",
  "导出查询日志": "Export query log",
  "CSV 表格": "CSV spreadsheet",
  "DNS 服务返回了空配置或配置格式无效":
    "The DNS service returned an empty or malformed configuration",

  // ---------- 服务控制 ----------
  "DNS 服务已启动": "DNS service started",
  "DNS 服务已停止": "DNS service stopped",
  "新黑名单": "New blocklist",
  "正在取消": "Cancelling",
  "DNS 缓存已清除": "DNS cache cleared",
  "这会删除可重新生成的规则编译缓存。已下载的远程黑名单和当前生效规则不会删除；下次启动或规则变更时会自动重新生成缓存。是否继续？":
    "This deletes the regenerable compiled-rule cache. Downloaded blocklists and the active rules are kept, and the cache is rebuilt on the next start or rule change. Continue?",
  "这会永久删除全部查询日志，但不会删除统计数据和配置。清除后，新查询仍会继续记录。是否继续？":
    "This permanently deletes every query log entry. Statistics and configuration are kept, and new queries are still recorded. Continue?",
  "查询日志已清除，统计数据未受影响": "Query log cleared. Statistics were not affected.",
  "这会永久删除全部累计统计、趋势和排行，但不会删除查询日志和配置。清除后将从新的 DNS 查询重新统计。是否继续？":
    "This permanently deletes all accumulated statistics, trends and rankings. Query logs and configuration are kept, and counting restarts from the next query. Continue?",
  "统计数据已清除，查询日志未受影响": "Statistics cleared. The query log was not affected.",
  "这会永久删除已落盘的全部安全事件历史，但不会影响统计数据和查询日志。是否继续？":
    "This permanently deletes the stored security event history. Statistics and query logs are not affected. Continue?",
  "安全事件已清除": "Security events cleared",

  // ---------- 数据目录 ----------
  "选择 DnsBlackhole 数据存储目录": "Choose the DnsBlackhole data directory",
  "选择数据目录失败：{p0}": "Could not choose a data directory: {p0}",
  "现有数据接管任务已保存，正在重启应用…": "Adoption of the existing data is queued. Restarting…",
  "迁移任务已保存，正在重启应用…": "Migration queued. Restarting…",
  "当前占用 {p0}（数据库 {p1}，过滤器数据 {p2}）":
    "Using {p0} ({p1} database, {p2} filter data)",
  "默认目录": "Default directory",
  "自定义目录": "Custom directory",
  "所选目录不可用": "The selected directory is not usable",
  "正在检查所选目录…": "Checking the selected directory…",
  "检查目录中…": "Checking…",
  "检测到现有数据 {p0}（数据库 {p1}，过滤器数据 {p2}）":
    "Existing data found: {p0} ({p1} database, {p2} filter data)",
  "使用现有数据并重启": "Use existing data and restart",
  "重启后迁移到：{p0}": "Will migrate to {p0} after restart",

  // ---------- 更新 ----------
  "检查中": "Checking",
  "正在检查更新...": "Checking for updates…",
  "发现新版本 v{p0}": "Version v{p0} is available",
  "已是最新版本 v{p0}": "You are on the latest version, v{p0}",
  "当前平台暂无自动更新包，请前往 GitHub Releases 手动下载":
    "No automatic update package for this platform. Download it from GitHub Releases.",
  "检查更新失败：{p0}": "Update check failed: {p0}",
  "安装完成，即将重启应用...": "Installed. Restarting the app…",
  "更新失败：{p0}{p1}": "Update failed: {p0}{p1}",
  "GitHub Release 请求失败（HTTP {p0}）": "GitHub Release request failed (HTTP {p0})",
  "GitHub Release 缺少版本号": "The GitHub release has no version number",
  "读取更新信息失败，{p0} 秒后重试（{p1}/{p2}）：{p3}":
    "Could not read update info, retrying in {p0}s ({p1}/{p2}): {p3}",
  "此版本暂未提供更新说明。": "No release notes are available for this version.",
  "检查更新失败，{p0} 秒后重试（{p1}/{p2}）：{p3}":
    "Update check failed, retrying in {p0}s ({p1}/{p2}): {p3}",
  "重新检查时未发现可安装的新版本": "The recheck found no installable update",
  "第 {p0}/{p1} 次下载：": "Download attempt {p0}/{p1}: ",
  "开始下载更新...": "Downloading update…",
  "下载中... {p0}%": "Downloading… {p0}%",
  "下载完成，正在安装...": "Download complete, installing…",
  "下载更新失败，{p0} 秒后重试（{p1}/{p2}）：{p3}":
    "Download failed, retrying in {p0}s ({p1}/{p2}): {p3}",
  "正在准备更新…": "Preparing update…",

  // ---------- macOS 后台服务 ----------
  "请在“系统设置 → 通用 → 登录项与扩展”中批准 DnsBlackhole 后台服务":
    "Approve the DnsBlackhole background service under System Settings → General → Login Items & Extensions",
  "macOS DNS 后台服务已启用": "The macOS DNS background service is enabled",
  "后台服务已注册但暂未响应，请稍后重新进入本页检查；若持续无响应请重启 Mac 后再试":
    "The background service is registered but not responding yet. Revisit this page shortly; if it stays unresponsive, restart your Mac.",
  "卸载后台服务后，DNS 将无法监听 53 端口，局域网设备的 DNS 查询会立即失败。是否继续卸载？":
    "Without the background service, DNS cannot listen on port 53 and LAN devices will fail to resolve immediately. Uninstall anyway?",
  "macOS DNS 后台服务已卸载": "The macOS DNS background service was uninstalled",
  "后台服务尚未安装。安装并授权后，DNS 才能监听 53 端口。":
    "The background service is not installed. DNS can only listen on port 53 once it is installed and approved.",
  "后台服务已启用，DNS 可以监听 53 端口。":
    "The background service is enabled and DNS can listen on port 53.",
  "等待批准：请在“系统设置 → 通用 → 登录项与扩展”中允许 DnsBlackhole。":
    "Waiting for approval: allow DnsBlackhole under System Settings → General → Login Items & Extensions.",
  "未找到后台服务，可能已被系统移除，请重新安装。":
    "The background service was not found. It may have been removed by the system; install it again.",
  "后台服务状态未知，可尝试“安装或修复”。":
    "The background service status is unknown. Try \"Install or repair\".",
  "读取后台服务状态失败：{p0}": "Could not read the background service status: {p0}",
  " 当前服务版本 v{p0}。": " Service version v{p0}.",
  "后台服务已启用但暂未响应，可稍后重新进入本页检查；持续无响应时点击“安装或修复”。":
    "The background service is enabled but not responding. Revisit this page shortly, or use \"Install or repair\" if it stays unresponsive.",

  // ---------- Windows 系统服务 ----------
  "Windows DNS 系统服务已安装并启动": "The Windows DNS system service was installed and started",
  "系统服务已注册但暂未就绪，请稍候重试；详情可查看服务日志":
    "The system service is registered but not ready yet. Try again shortly; see the service log for details.",
  "卸载 Windows DNS 系统服务后，127.0.0.1/::1 将不再提供 DNS；若系统 DNS 已接管，会先自动恢复原 DNS。是否继续？":
    "Without the Windows DNS system service, 127.0.0.1 and ::1 will no longer answer DNS. If system DNS is managed, the original settings are restored first. Continue?",
  "Windows DNS 系统服务已卸载，原 DNS 已恢复，数据和配置未删除":
    "The Windows DNS system service was uninstalled and the original DNS restored. Data and configuration were kept.",
  "系统服务尚未安装，DNS 核心无法在开机阶段自动启动。":
    "The system service is not installed, so the DNS core cannot start at boot.",
  "系统服务已停止，可点击“安装或修复”恢复。":
    "The system service is stopped. Use \"Install or repair\" to bring it back.",
  "系统服务正在启动，请稍候…": "The system service is starting…",
  "系统服务正在停止，请稍候…": "The system service is stopping…",
  "系统服务正在运行，DNS 核心不依赖 GUI。":
    "The system service is running. The DNS core does not depend on the window being open.",
  "系统服务正在恢复运行，请稍候…": "The system service is resuming…",
  "系统服务正在暂停，请稍候…": "The system service is pausing…",
  "系统服务已暂停，可点击“安装或修复”恢复。":
    "The system service is paused. Use \"Install or repair\" to resume it.",
  "无有效状态": "No valid status",
  "连续读取 Windows 系统服务状态失败：{p0}":
    "Repeatedly failed to read the Windows system service status: {p0}",
  "正在等待 Windows 系统服务响应…": "Waiting for the Windows system service…",
  "系统服务版本不一致（当前 {p0}，需要 {p1}），请点击“安装或修复”。":
    "System service version mismatch (found {p0}, expected {p1}). Use \"Install or repair\".",
  "系统服务已运行，但 IPC 连续无响应，请点击“安装或修复”。":
    "The system service is running but its IPC keeps timing out. Use \"Install or repair\".",
  "系统服务正在完成启动并建立通信，请稍候…":
    "The system service is finishing startup and establishing communication…",
  "请先安装并启动 Windows DNS 系统服务":
    "Install and start the Windows DNS system service first",
  "Windows 系统服务状态接口返回了空结果":
    "The Windows system service status API returned an empty result",
  "Windows 系统服务状态接口返回格式无效":
    "The Windows system service status API returned a malformed result",

  // ---------- 系统 DNS 接管 ----------
  "读取系统 DNS 状态失败：{p0}": "Could not read the system DNS status: {p0}",
  "、": ", ",
  "；": "; ",
  "已接管当前活动网卡：{p0}。": "Active adapters now managed: {p0}.",
  "当前 DNS 均指向 127.0.0.1 / ::1。接管前配置：{p0}。":
    "All adapters point at 127.0.0.1 / ::1. Settings before takeover: {p0}.",
  "当前活动网卡尚未全部接管：{p0}。": "Some active adapters are not managed yet: {p0}.",
  "已保留 DNS 接管备份，但当前没有活动的物理网卡。":
    "A DNS backup is kept, but there is no active physical adapter right now.",
  "当前配置：{p0}。历史恢复配置：{p1}。可同步接管当前网卡，或选择恢复方式。":
    "Current settings: {p0}. Saved restore settings: {p1}. You can bring the current adapters under management, or choose how to restore.",
  "检测到 {p0} 使用本机 DNS，但没有原配置备份。":
    "{p0} uses the local DNS but has no saved original settings.",
  "当前配置：{p0}。请选择自动获取、公共 DNS 或自定义 DNS 来解除。":
    "Current settings: {p0}. Choose DHCP, a public DNS or a custom DNS to release.",
  "尚未接管，当前活动网卡：{p0}。": "Not managed. Active adapters: {p0}.",
  "尚未接管，当前未检测到已连接的物理网卡。":
    "Not managed. No connected physical adapter was detected.",
  "当前配置：{p0}。接管时会按网卡分别保存这些设置。":
    "Current settings: {p0}. These are saved per adapter when taking over.",
  "连接有线或无线网络后，可将其 DNS 指向 DnsBlackhole。":
    "Connect a wired or wireless network to point its DNS at DnsBlackhole.",
  "同步接管": "Bring under management",
  "系统服务就绪后会读取当前活动网卡及每张网卡的 DNS 恢复配置。":
    "Once the system service is ready, the active adapters and their saved DNS settings are read.",
  "选择恢复后的 DNS": "Choose the DNS to restore",
  "“按接管前配置恢复”只还原仍指向本机 DNS 的部分，保留你后来在 Windows 中做的修改；选择其他方式则会将历史备份中的网卡设置为所选 DNS。":
    "\"Restore the pre-takeover settings\" only reverts adapters still pointing at the local DNS, keeping any later changes you made in Windows. The other options set every previously backed-up adapter to the DNS you choose.",
  "确认恢复": "Confirm restore",
  "自动获取": "Automatic (DHCP)",
  "无活动物理网卡": "No active physical adapter",
  "{p0}（IPv4 {p1}，IPv6 {p2}）": "{p0} (IPv4 {p1}, IPv6 {p2})",
  "无历史备份": "No saved backup",
  "Windows 系统 DNS 状态接口返回了空结果":
    "The Windows system DNS status API returned an empty result",
  "Windows 系统 DNS 状态接口返回格式无效":
    "The Windows system DNS status API returned a malformed result",
  "当前活动网卡已同步接管": "The active adapters are now managed",
  "系统 DNS 已接管，所有 DNS 查询将交给 DnsBlackhole":
    "System DNS is now managed. All queries go through DnsBlackhole.",
  "系统 DNS 备份已保存，但接管状态需要检查":
    "The system DNS backup was saved, but the takeover state needs checking",
  "请至少填写一个自定义 DNS 服务器地址": "Enter at least one custom DNS server address",
  "已恢复仍由 DnsBlackhole 接管的 DNS；在 Windows 中另行修改的配置保持不变":
    "Restored the adapters still managed by DnsBlackhole. Settings you changed in Windows were left alone.",
  "已恢复为所选外部 DNS": "Restored to the selected external DNS",
  "已解除本机 DNS，现在可以重新接管并保存该恢复配置":
    "Local DNS released. You can take over again and save this as the restore point.",

  // ---------- 诊断结果 ----------
  "请输入要诊断的域名": "Enter a domain to diagnose",
  "诊断中": "Running",
  "正在并行测试上游…": "Testing upstreams in parallel…",
  "不可用的服务器最多等待 3 秒。": "Unreachable servers time out after 3 seconds.",
  "诊断失败": "Diagnostics failed",
  "本地判定：允许": "Local decision: allowed",
  "本地判定：已拦截": "Local decision: blocked",
  "本地判定：客户端已绕过": "Local decision: client bypasses filtering",
  "本地判定：DNS 重写": "Local decision: DNS rewrite",
  "本地判定：保护已暂停": "Local decision: protection paused",
  "本地判定：服务未运行": "Local decision: service not running",
  "模拟客户端": "Simulated client",
  "客户端策略": "Client policy",
  "绕过过滤{p0}": "Bypasses filtering{p0}",
  "正常过滤{p0}": "Filtered normally{p0}",
  "命中规则": "Matched rule",
  "规则来源": "Rule source",
  "规则类型": "Rule type",
  "被覆盖的允许规则": "Overridden allow rule",
  "响应中没有可展示的记录": "The response has no records to show",
  "上游无响应": "No response from upstream",
  "<div class=\"diagnostic-empty\"><strong>没有已配置的上游</strong></div>":
    "<div class=\"diagnostic-empty\"><strong>No upstreams configured</strong></div>",
  "该重要规则覆盖了一条允许规则。": "This important rule overrode an allow rule.",
  "上游测试": "Upstream tests",
  "个可用": "available",
  "已响应": "Responded",

  // ---------- 过滤器列表 ----------
  "<div class=\"empty-row\" role=\"row\"><span role=\"cell\">暂无远程清单</span></div>":
    "<div class=\"empty-row\" role=\"row\"><span role=\"cell\">No remote blocklists yet</span></div>",
  "未命名清单": "Untitled blocklist",
  "更新失败": "Update failed",
  "部分忽略": "Partially ignored",
  "已更新": "Updated",
  "未更新": "Not updated",
  "启用清单": "Enable blocklist",
  "启用黑名单 {p0}": "Enable blocklist {p0}",
  "尚未填写清单网址": "No blocklist URL yet",
  "收起黑名单 {p0}": "Collapse blocklist {p0}",
  "编辑黑名单 {p0}": "Edit blocklist {p0}",
  "收起": "Collapse",
  "编辑": "Edit",
  "删除黑名单 {p0}": "Delete blocklist {p0}",
  "清单网址": "Blocklist URL",
  "更新中": "Updating",
  "成功 {p0} · 失败 {p1}": "{p0} ok · {p1} failed",
  "已处理 {p0}/{p1}{p2}": "Processed {p0}/{p1}{p2}",
  "后台将直接连接，不使用任何系统或环境代理。":
    "The background service connects directly, ignoring any system or environment proxy.",
  "后台服务将使用这里填写的 HTTP/HTTPS 代理地址。":
    "The background service uses the HTTP/HTTPS proxy address entered here.",
  "已同步当前用户的系统代理：{p0}": "Synced this user's system proxy: {p0}",
  "当前未检测到系统代理；后台将按系统默认网络直接连接。":
    "No system proxy detected. The background service connects over the default network.",

  // ---------- 安全事件与仪表盘 ----------
  "<div class=\"security-event-empty\" role=\"row\"><span role=\"cell\">暂无安全事件</span></div>":
    "<div class=\"security-event-empty\" role=\"row\"><span role=\"cell\">No security events yet</span></div>",
  "触发限速": "Rate limited",
  "{p0}；首次：{p1} {p2}": "{p0}; first seen: {p1} {p2}",
  "暂无请求数据": "No query data yet",
  "暂无客户端数据": "No client data yet",
  "暂无上游请求数据": "No upstream request data yet",
  "暂无上游响应时间数据": "No upstream latency data yet",
  "查看 {p0} 的查询日志": "View the query log for {p0}",
  "最近 {p0} 小时": "Last {p0} hours",
  "最近 {p0} 天": "Last {p0} days",
  "累计汇总 {p0} 天": "{p0} days accumulated",
  "累计汇总 {p0} 个月": "{p0} months accumulated",
  "本机": "This machine",
  "未知客户端": "Unknown client",
  "{p0}（{p1}）": "{p0} ({p1})",

  // ---------- 规则编辑器 ----------
  "空行/注释 {p0}": "{p0} blank/comment",
  "正则 {p0}": "{p0} regex",
  "高级修饰符 {p0}": "{p0} advanced modifier",
  "非法域名 {p0}": "{p0} invalid domain",
  "，忽略 {p0}（{p1}）": ", {p0} ignored ({p1})",
  "未分类": "uncategorised",
  "有效 {p0}，黑名单 {p1}，白名单 {p2}{p3}":
    "{p0} active, {p1} blocking, {p2} allowing{p3}",
  "{p0} 条拦截": "{p0} blocking",
  "{p0} 条允许": "{p0} allowing",
  "{p0} 条 badfilter": "{p0} badfilter",
  "{p0} 条需处理": "{p0} need attention",
  "格式检查通过": "Syntax check passed",
  "没有发现无效或不受支持的规则。": "No invalid or unsupported rules were found.",
  "第 {p0} 行：{p1}": "Line {p0}: {p1}",

  // ---------- 查询日志明细 ----------
  "传输协议": "Transport",
  "上游耗时(ms)": "Upstream time (ms)",
  "总耗时(ms)": "Total time (ms)",
  "响应代码": "Response code",
  "响应记录": "Answers",
  "错误": "Error",
  "已拦截": "Blocked",
  "协议未记录": "Protocol not recorded",
  "查看请求详情": "Show request details",
  "放行": "Allow",
  "拦截": "Block",
  "重写": "Rewrite",
  "查看响应详情": "Show response details",
  "请求详情": "Request details",
  "日期": "Date",
  "查询类别": "Class",
  "旧日志未记录": "Not recorded in older logs",
  "{p0} 条": "{p0}",
  "无响应": "No response",
  "上游耗时": "Upstream time",
  "总处理耗时": "Total time",
  "截断响应": "Truncated",
  "是（TC 标志）": "Yes (TC flag)",
  "说明": "Detail",
  "来源清单": "Source list",
  "important 覆盖": "important override",
  "是": "Yes",
  "否": "No",
  "无": "None",
  "响应详情": "Response details",
  "TTL {p0} 秒": "TTL {p0}s",
  "响应记录内容无法解析": "The answer could not be decoded",
  "另有 {p0} 条记录未写入日志摘要": "{p0} more records were not stored in the log summary",
  "已拒绝": "Refused",
  "本地 DNS 重写": "Local DNS rewrite",
  "本地拒绝": "Refused locally",
  "本地响应（旧日志未记录来源）": "Answered locally (source not recorded in older logs)",
  "上游：{p0}": "Upstream: {p0}",
  "上游 DNS 解析": "Resolved upstream",
  "DNS 缓存命中": "Cache hit",
  "过滤器：{p0}": "Filter: {p0}",
  "过滤器拦截": "Blocked by filter",
  "本地拒绝响应": "Refused locally",
  "本地响应（旧日志）": "Answered locally (older log)",
  "类型未记录": "Type not recorded",
  "IN（互联网）": "IN (Internet)",
  "CH（Chaos）": "CH (Chaos)",
  "HS（Hesiod）": "HS (Hesiod)",
  "ANY（任意类别）": "ANY (any class)",

  // ---------- 其它提示 ----------
  "{p0}失败，请稍后重试。": "{p0} failed. Try again shortly.",
  "关闭错误提示": "Dismiss error",
  "应用启动失败：{p0}": "The app failed to start: {p0}",

  // ---------- 含换行的多行提示 ----------
  "检测到现有 DnsBlackhole 数据：\n{p0}\n\n应用将验证并备份该数据库，然后切换使用此目录。现有目录和当前目录都不会被删除。是否继续？":
    "Existing DnsBlackhole data found:\n{p0}\n\nThe app will validate and back up that database, then switch to this directory. Neither the existing nor the current directory is deleted. Continue?",
  "应用将重启并把数据库与过滤器缓存迁移到：\n{p0}\n\n目标数据验证成功后才会清理原目录。是否继续？":
    "The app will restart and migrate the database and filter cache to:\n{p0}\n\nThe old directory is cleaned up only after the new data validates. Continue?",
  "\n可重试，或点击“浏览器下载”手动安装。":
    "\nTry again, or use \"Download in browser\" to install manually.",
  "打开浏览器失败：{p0}\n下载地址：{p1}": "Could not open the browser: {p0}\nDownload URL: {p1}",
  "同步后，当前活动的有线或无线网卡会使用 127.0.0.1 和 ::1。每张网卡现有的自动获取或手动 DNS 都会分别保存；已在 Windows 中改过的配置会作为新的恢复配置。是否继续？":
    "The active wired or wireless adapters will use 127.0.0.1 and ::1. Each adapter's current DHCP or manual DNS is saved separately, and anything you changed in Windows becomes the new restore point. Continue?",
  "接管后，当前已连接的物理网卡将只使用 127.0.0.1 和 ::1 作为 DNS，不设置公共备用 DNS。每张网卡的原 DNS（包括自动获取）会先分别保存，可随时恢复。是否继续？":
    "Connected physical adapters will use only 127.0.0.1 and ::1 for DNS, with no public fallback. Each adapter's original DNS (including DHCP) is saved first and can be restored at any time. Continue?",

  // ---------- 规则检查 ----------
  "另有 {p0} 条未展开，请先修复上面的规则。": "{p0} more are hidden. Fix the rules above first.",
  "正在检查规则…": "Checking rules…",
  "规则检查失败：{p0}": "Rule check failed: {p0}",
  "没有找到匹配规则": "No matching rule found",
};
