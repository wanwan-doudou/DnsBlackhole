export function renderAppTemplate(appIconUrl: string): string {
  return `
  <div class="app-shell">
    <header class="app-header">
      <div class="header-inner">
        <div class="brand">
          <img class="brand-mark" src="${appIconUrl}" alt="DnsBlackhole" />
          <div>
            <h1>DnsBlackhole</h1>
            <span>DNS sinkhole</span>
          </div>
          <div class="header-runtime" id="header_runtime">
            <button class="runtime-status-trigger connecting" id="runtime_status_btn" type="button" aria-haspopup="menu" aria-expanded="false">
              <i aria-hidden="true"></i>
              <span id="runtime_status_label">正在连接</span>
              <b aria-hidden="true"></b>
            </button>
            <div class="runtime-status-menu" id="runtime_status_menu" role="menu" aria-label="过滤保护控制">
              <strong id="runtime_status_detail">正在读取 DNS 运行状态…</strong>
              <button data-protection-action="pause" data-duration="300" type="button" role="menuitem">暂停 5 分钟</button>
              <button data-protection-action="pause" data-duration="1800" type="button" role="menuitem">暂停 30 分钟</button>
              <button data-protection-action="pause" data-duration="3600" type="button" role="menuitem">暂停 1 小时</button>
              <button class="resume-action" data-protection-action="resume" type="button" role="menuitem">立即恢复过滤</button>
            </div>
          </div>
        </div>

        <nav class="module-nav" aria-label="模块">
          <button class="nav-item active" data-view="dashboard" type="button">仪表盘</button>
          <button class="nav-item" data-view="settings" data-nav-group="settings" type="button">设置</button>
          <button class="nav-item" data-view="filters" data-nav-group="filters" type="button">过滤器</button>
          <button class="nav-item" data-view="logs" type="button">查询日志</button>
          <button class="nav-item" data-view="about" type="button">关于</button>
        </nav>
      </div>

      <div class="context-nav" id="context_nav">
        <nav class="context-nav-inner" data-context-group="settings" aria-label="设置分类">
          <button data-view="settings" type="button">常规与运行</button>
          <button data-view="dns" type="button">DNS 设置</button>
          <button data-view="security" type="button">安全防护</button>
          <button data-view="diagnostics" type="button">DNS 诊断</button>
        </nav>
        <nav class="context-nav-inner" data-context-group="filters" aria-label="过滤器分类">
          <button data-view="filters" type="button">DNS 黑名单</button>
          <button data-view="custom" type="button">自定义规则与重写</button>
        </nav>
      </div>
    </header>

    <main class="content">
      <section class="view active" data-view-panel="dashboard">
        <div class="dashboard-controls">
          <div>
            <h2>DNS 使用概览</h2>
            <span>点击客户端可直接查看该设备的查询日志。</span>
          </div>
          <label class="dashboard-range-field">
            <span>统计范围</span>
            <select id="dashboard_statistics_range">
              <option value="configured">按保留设置</option>
              <option value="24">最近 24 小时</option>
              <option value="168">最近 7 天</option>
              <option value="720">最近 30 天</option>
              <option value="0">全部历史</option>
            </select>
          </label>
        </div>
        <div class="dashboard-summary" aria-label="统计趋势">
          <article class="spark-card">
            <div class="spark-box">
              <span class="spark-caption">DNS 查询</span>
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
          </article>

          <article class="spark-card blocked-spark">
            <div class="spark-box">
              <span class="spark-caption">已拦截查询</span>
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
          </article>
        </div>

        <div class="dashboard-rank-grid">
          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>请求域名排行</h2>
                <span id="query_rank_window">暂无汇总数据</span>
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
                <span id="blocked_rank_window">暂无汇总数据</span>
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

        <div class="dashboard-rank-grid">
          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>客户端排行</h2>
                <span id="client_rank_window">暂无汇总数据</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table client-rank-table">
              <div class="rank-head client-rank-head">
                <span>客户端</span>
                <span>请求数</span>
                <span>拦截率</span>
              </div>
              <div class="rank-body" id="client_rank"></div>
            </div>
          </section>

          <section class="panel rank-panel blocked-rank">
            <div class="rank-title">
              <div>
                <h2>DNS 黑名单排行</h2>
                <span id="blocklist_rank_window">暂无汇总数据</span>
              </div>
              <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
            </div>
            <div class="rank-table">
              <div class="rank-head">
                <span>黑名单</span>
                <span>拦截数</span>
              </div>
              <div class="rank-body" id="blocklist_rank"></div>
            </div>
          </section>
        </div>

        <div class="dashboard-rank-grid upstream-rank-grid">
          <section class="panel rank-panel">
            <div class="rank-title">
              <div>
                <h2>经常请求的上游服务器</h2>
                <span id="upstream_rank_window">暂无汇总数据</span>
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
                <span id="upstream_latency_window">暂无汇总数据</span>
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
            <button class="query-log-tool-button" id="query_log_pause_btn" type="button">暂停实时刷新</button>
            <button class="query-log-tool-button" id="query_log_export_btn" type="button">导出当前筛选</button>
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

        <dialog class="update-dialog query-rule-dialog" id="query_rule_dialog">
          <form class="update-dialog-panel" method="dialog" id="query_rule_form">
            <div class="update-dialog-header">
              <div>
                <span class="update-dialog-kicker">查询日志快捷操作</span>
                <h3>添加 DNS 重写</h3>
              </div>
              <button class="update-dialog-close" id="query_rule_dialog_close_btn" type="button" aria-label="关闭">×</button>
            </div>
            <div class="update-dialog-body">
              <p class="query-rule-domain">域名：<strong id="query_rule_domain">-</strong></p>
              <label class="field">
                <span>重写目标 IP</span>
                <small>填写有效的 IPv4 或 IPv6 地址；保存后会立即热更新，无需重启 DNS。</small>
                <input id="query_rule_target" autocomplete="off" spellcheck="false" placeholder="例如 192.168.1.10" />
              </label>
            </div>
            <div class="update-dialog-footer">
              <button id="query_rule_dialog_cancel_btn" type="button">取消</button>
              <button class="primary" id="query_rule_dialog_confirm_btn" type="submit">保存重写</button>
            </div>
          </form>
        </dialog>
      </section>

      <section class="view" data-view-panel="dns">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>DNS 设置</h2>
            <div class="button-group">
              <span class="save-state-label" aria-live="polite">正在读取配置</span>
              <button class="primary" id="save_btn" type="button">保存更改</button>
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
                  <small>每行一个上游：普通 DNS、https://（DoH）、tls://（DoT）或 quic://（DoQ）。DoT / DoQ 必须填写证书对应的主机名。</small>
                  <textarea id="upstream_dns" autocomplete="off" spellcheck="false"></textarea>
                </label>
                <div class="listen-settings">
                  <label class="field">
                    <span>IPv4 监听地址</span>
                    <input id="listen_host" autocomplete="off" spellcheck="false" placeholder="0.0.0.0" />
                  </label>
                  <label class="field compact-field">
                    <span>端口</span>
                    <input id="listen_port" type="number" min="1" max="65535" step="1" />
                  </label>
                  <label class="check-row ipv6-listen-row">
                    <input id="listen_ipv6" type="checkbox" />
                    <span>
                      <strong>监听 IPv6</strong>
                      <small>开启后额外绑定 [::]:同一端口，同时接受 IPv4 与 IPv6 DNS 请求。</small>
                    </span>
                  </label>
                </div>
              </div>
              <div class="upstream-extra-grid">
                <label class="field upstream-extra-field">
                  <span>Fallback DNS 服务器</span>
                  <small>所有上游服务器都失败时重试的后备 DNS，语法与上游相同。留空则禁用。</small>
                  <textarea id="fallback_dns" autocomplete="off" spellcheck="false" placeholder="114.114.114.114"></textarea>
                </label>
                <label class="field upstream-extra-field">
                  <span>Bootstrap DNS 服务器</span>
                  <small>用于解析 DoH 和域名形式上游自身的地址，并同时查询 IPv4/IPv6；只支持普通 IP 地址 DNS。</small>
                  <textarea id="bootstrap_dns" autocomplete="off" spellcheck="false" placeholder="223.5.5.5"></textarea>
                </label>
              </div>
              <label class="check-row dnssec-row">
                <input id="dnssec_enabled" type="checkbox" />
                <span>
                  <strong>验证 DNSSEC</strong>
                  <small>请求 DNSSEC 记录并要求上游执行验证；验证失败的 SERVFAIL 响应会被拒绝。建议搭配可信的 DoH、DoT 或 DoQ 上游。</small>
                </span>
              </label>
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
                    <small>优先查询一个上游；25 毫秒内未成功时并发查询其余上游，并使用最先成功的响应。</small>
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

            <section class="settings-section upstream-routing-section">
              <div class="section-heading">
                <h3>DNS 分流与客户端上游策略</h3>
                <span>匹配后只使用指定上游，不回退到全局服务器。客户端策略优先于域名分流；保存后会安全重启 DNS 运行时。</span>
              </div>
              <div class="upstream-routing-grid">
                <label class="field">
                  <span>域名分流</span>
                  <small>每行“域名模式 => 上游”。使用 *.example.com 同时匹配主域和子域；多个上游用逗号分隔。</small>
                  <textarea id="domain_upstream_rules" autocomplete="off" spellcheck="false" placeholder="*.home.arpa => 192.168.1.1&#10;example.com => https://dns.example/dns-query, 1.1.1.1"></textarea>
                </label>
                <label class="field">
                  <span>客户端上游策略</span>
                  <small>每行“IP/CIDR => 上游”。更精确的网段优先，可让指定设备或网段使用独立 DNS。</small>
                  <textarea id="client_upstream_rules" autocomplete="off" spellcheck="false" placeholder="192.168.1.20 => 223.5.5.5&#10;192.168.2.0/24 => https://doh.pub/dns-query"></textarea>
                </label>
              </div>
            </section>

            <section class="settings-section blocking-mode-section">
              <div class="section-heading">
                <h3>拦截响应方式</h3>
                <span>命中黑名单时返回给客户端的响应类型，保存后立即生效，无需重启服务。</span>
              </div>
              <div class="radio-stack">
                <label class="radio-row">
                  <input name="blocking_mode" type="radio" value="null_ip" />
                  <span>
                    <strong>零地址（默认）</strong>
                    <small>A 返回 0.0.0.0，AAAA 返回 ::，兼容性最好。</small>
                  </span>
                </label>
                <label class="radio-row">
                  <input name="blocking_mode" type="radio" value="nxdomain" />
                  <span>
                    <strong>NXDOMAIN</strong>
                    <small>返回“域名不存在”，部分应用对此的处理更干脆。</small>
                  </span>
                </label>
                <label class="radio-row">
                  <input name="blocking_mode" type="radio" value="refused" />
                  <span>
                    <strong>REFUSED</strong>
                    <small>返回“拒绝服务”，客户端会更快放弃重试。</small>
                  </span>
                </label>
                <label class="radio-row">
                  <input name="blocking_mode" type="radio" value="custom_ip" />
                  <span>
                    <strong>自定义 IP</strong>
                    <small>返回指定 IP，可指向局域网内的提示页面服务器。</small>
                  </span>
                </label>
              </div>
              <div class="dns-cache-grid">
                <label class="field">
                  <span>拦截响应 TTL</span>
                  <small>客户端缓存零地址、自定义 IP 或 NXDOMAIN 拦截结果的秒数；0 表示不缓存。</small>
                  <input id="blocking_response_ttl" type="number" min="0" max="604800" step="1" />
                </label>
              </div>
              <div class="blocking-custom-grid" id="blocking_custom_fields">
                <label class="field">
                  <span>自定义 IPv4</span>
                  <input id="blocking_custom_ipv4" autocomplete="off" spellcheck="false" placeholder="例如 192.168.1.100" />
                </label>
                <label class="field">
                  <span>自定义 IPv6（可选）</span>
                  <input id="blocking_custom_ipv6" autocomplete="off" spellcheck="false" placeholder="例如 fd00::1" />
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
              <label class="check-row">
                <input id="dns_cache_prefetch_enabled" type="checkbox" />
                <span>
                  <strong>热门域名预取</strong>
                  <small>高频条目接近过期时在后台提前刷新，减少客户端遇到冷缓存的概率；同一条目只允许一个刷新任务。</small>
                </span>
              </label>
              <div class="dns-cache-grid">
                <label class="field">
                  <span>预取命中阈值</span>
                  <small>条目至少命中多少次后才允许预取，范围 2–10000。</small>
                  <input id="dns_cache_prefetch_hit_threshold" type="number" min="2" max="10000" step="1" />
                </label>
              </div>
              <button id="clear_dns_cache_btn" type="button">清除缓存</button>
              <div class="cache-runtime-summary">
                <div class="cache-runtime-heading">
                  <div>
                    <h4>运行状态</h4>
                    <span>本次 DNS 服务运行期间的内存缓存指标</span>
                  </div>
                  <button class="icon-button" data-refresh-dashboard type="button" title="刷新">↻</button>
                </div>
                <div class="security-stat-grid cache-stat-grid">
                  <div class="security-stat-card"><span>命中率</span><strong id="cache_hit_rate">0%</strong></div>
                  <div class="security-stat-card"><span>命中 / 未命中</span><strong id="cache_hit_miss">0 / 0</strong></div>
                  <div class="security-stat-card"><span>过期应答</span><strong id="cache_stale_hits">0</strong></div>
                  <div class="security-stat-card"><span>后台刷新（成功 / 失败）</span><strong id="cache_refreshes">0 / 0</strong></div>
                  <div class="security-stat-card"><span>热门预取（成功 / 失败）</span><strong id="cache_prefetches">0 / 0</strong></div>
                  <div class="security-stat-card"><span>淘汰条目</span><strong id="cache_evictions">0</strong></div>
                  <div class="security-stat-card"><span>当前条目</span><strong id="cache_entries">0</strong></div>
                  <div class="security-stat-card"><span>当前占用</span><strong id="cache_bytes">0 B</strong></div>
                </div>
              </div>
            </section>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="diagnostics">
        <section class="panel module-panel diagnostic-panel">
          <div class="panel-title with-actions">
            <div>
              <h2>DNS 诊断中心</h2>
              <p>检查本地过滤判定，并并行测试每个已配置上游的响应、延迟与返回记录。</p>
            </div>
            <button class="primary" id="run_diagnostic_btn" type="button">开始诊断</button>
          </div>
          <div class="diagnostic-form">
            <label class="field">
              <span>测试域名</span>
              <input id="diagnostic_domain" autocomplete="off" spellcheck="false" value="example.com" placeholder="example.com" />
            </label>
            <label class="field compact-select">
              <span>查询类型</span>
              <select id="diagnostic_query_type">
                <option value="A">A（IPv4）</option>
                <option value="AAAA">AAAA（IPv6）</option>
                <option value="HTTPS">HTTPS</option>
                <option value="TXT">TXT</option>
              </select>
            </label>
            <label class="field">
              <span>模拟客户端（可选）</span>
              <input id="diagnostic_client_ip" autocomplete="off" spellcheck="false" placeholder="192.168.1.23" />
              <small>填写 IPv4 或 IPv6，可验证该设备是否命中过滤绕过策略。</small>
            </label>
          </div>
          <div class="diagnostic-results" id="diagnostic_results">
            <div class="diagnostic-empty">
              <strong>尚未运行诊断</strong>
              <span>输入域名后开始测试；不会修改配置，也不会写入查询日志。</span>
            </div>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="security">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>安全防护</h2>
            <div class="button-group">
              <span class="save-state-label" aria-live="polite">正在读取配置</span>
              <button class="primary" id="save_security_btn" type="button">保存更改</button>
            </div>
          </div>

          <div class="settings-stack">
            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>客户端访问控制</h3>
                <span>限制可使用此 DNS 服务的客户端，避免成为开放递归 DNS。</span>
              </div>
              <div class="dns-security-grid">
                <label class="field access-list-field">
                  <span>允许客户端</span>
                  <small>每行一个 IP 或 CIDR。留空时允许所有未被拒绝的客户端。</small>
                  <textarea id="allowed_clients" autocomplete="off" spellcheck="false"></textarea>
                </label>
                <label class="field access-list-field">
                  <span>拒绝客户端</span>
                  <small>每行一个 IP 或 CIDR。拒绝列表优先于允许列表。</small>
                  <textarea id="blocked_clients" autocomplete="off" spellcheck="false"></textarea>
                </label>
              </div>
              <label class="field access-list-field client-names-field">
                <span>客户端名称</span>
                <small>每行一条“IP 名称”，例如 192.168.1.23 客厅电视。查询日志会用名称代替 IP 展示。</small>
                <textarea id="client_names" autocomplete="off" spellcheck="false" placeholder="192.168.1.23 客厅电视"></textarea>
              </label>
              <label class="field access-list-field client-names-field">
                <span>客户端过滤策略</span>
                <small>每行一条“IP/CIDR =&gt; filter|bypass”，最长 CIDR 优先。bypass 仅跳过过滤规则与响应保护，仍执行访问控制和 DNS 重写。</small>
                <textarea id="client_filtering_rules" autocomplete="off" spellcheck="false" placeholder="192.168.1.50 =&gt; bypass&#10;192.168.1.0/24 =&gt; filter"></textarea>
              </label>
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>查询防护</h3>
                <span>降低异常流量和 DNS 放大攻击风险。</span>
              </div>
              <div class="dns-security-options">
                <label class="field">
                  <span>每客户端限速</span>
                  <small>持续每秒允许的 DNS 查询数；默认 2000 并可容纳约 10 秒短时突发，适合路由器汇聚多台设备，0 表示关闭限速。</small>
                  <input id="rate_limit_per_second" type="number" min="0" max="100000" step="1" />
                </label>
                <label class="check-row">
                  <input id="refuse_any" type="checkbox" />
                  <span>
                    <strong>拒绝 ANY 查询</strong>
                    <small>减少 DNS 放大攻击面，家庭网关场景通常应开启。</small>
                  </span>
                </label>
              </div>
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>响应安全防护</h3>
                <span>检查上游返回的地址和 CNAME 链，阻止恶意域名绕过过滤器或访问局域网资源。</span>
              </div>
              <div class="dns-security-options">
                <label class="check-row">
                  <input id="rebinding_protection_enabled" type="checkbox" />
                  <span>
                    <strong>DNS Rebinding Protection</strong>
                    <small>公共域名返回私有、回环、链路本地或组播地址时改为拦截响应；域名分流上游自动视为可信。</small>
                  </span>
                </label>
                <label class="check-row">
                  <input id="cname_cloaking_enabled" type="checkbox" />
                  <span>
                    <strong>CNAME cloaking 检测</strong>
                    <small>解析响应中的 CNAME 目标，并用当前黑白名单再次判定，阻止首方别名隐藏被拦截域名。</small>
                  </span>
                </label>
              </div>
              <label class="field access-list-field">
                <span>Rebinding 可信域名</span>
                <small>每行一个域名；同时信任它的子域名。用于确实需要返回局域网地址的内部服务。</small>
                <textarea id="rebinding_allowed_domains" autocomplete="off" spellcheck="false" placeholder="home.arpa&#10;router.example.com"></textarea>
              </label>
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>安全事件</h3>
                <span>UDP 拒绝仍保持静默丢弃；这里展示本次运行期间的拒绝与限速情况，最多保留最近 200 条聚合事件。</span>
              </div>
              <div class="security-stat-grid">
                <div class="security-stat-card">
                  <span>访问拒绝</span>
                  <strong id="security_access_denied">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>限速触发</span>
                  <strong id="security_rate_limited">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>UDP 静默丢弃</span>
                  <strong id="security_dropped_udp">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>ANY 拒绝</span>
                  <strong id="security_refused_any">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>Rebinding 拦截</span>
                  <strong id="security_rebinding_blocked">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>CNAME cloaking 拦截</span>
                  <strong id="security_cname_blocked">0</strong>
                </div>
              </div>
              <div class="security-event-table">
                <div class="security-event-head">
                  <span>最近发生</span>
                  <span>来源客户端</span>
                  <span>事件</span>
                  <span>次数</span>
                </div>
                <div class="security-event-body" id="security_event_body">
                  <div class="security-event-empty">暂无安全事件</div>
                </div>
              </div>
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>容量保护</h3>
                <span>展示本次服务运行期间因内部队列或连接上限触发的降级；正常情况下都应为 0。</span>
              </div>
              <div class="security-stat-grid">
                <div class="security-stat-card">
                  <span>DNS 工作队列丢弃</span>
                  <strong id="worker_queue_dropped">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>日志持久化丢弃</span>
                  <strong id="persistence_queue_dropped">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>上游任务池降级</span>
                  <strong id="upstream_task_queue_rejected">0</strong>
                </div>
                <div class="security-stat-card">
                  <span>TCP 连接拒绝</span>
                  <strong id="tcp_connection_rejected">0</strong>
                </div>
              </div>
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>过滤器下载安全</h3>
                <span>限制远程黑名单下载行为，降低异常响应和中间人篡改风险。</span>
              </div>
              <div class="dns-security-options">
                <label class="field">
                  <span>单个过滤器最大大小（MB）</span>
                  <small>按解压后的实际读取大小限制，超过后立即中断下载。</small>
                  <input id="filter_max_size_mb" type="number" min="1" max="256" step="1" />
                </label>
                <div class="field">
                  <span>下载代理</span>
                  <small id="filter_proxy_status">自动读取当前用户的系统代理，并交给后台服务使用。</small>
                  <select id="filter_proxy_mode">
                    <option value="system">跟随系统代理</option>
                    <option value="direct">直接连接</option>
                    <option value="custom">自定义代理</option>
                  </select>
                </div>
                <label class="field filter-proxy-url-field" id="filter_proxy_url_field">
                  <span>自定义代理地址</span>
                  <small>支持 HTTP/HTTPS 代理，例如 http://127.0.0.1:7897。</small>
                  <input id="filter_proxy_url" type="url" placeholder="http://127.0.0.1:7897" spellcheck="false" />
                </label>
                <label class="check-row warning-check-row">
                  <input id="allow_insecure_http" type="checkbox" />
                  <span>
                    <strong>允许不安全 HTTP</strong>
                    <small>允许 HTTP 黑名单订阅和 HTTP DoH。仅在可信内网或临时迁移时使用。</small>
                  </span>
                </label>
              </div>
            </section>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="settings">
        <section class="panel module-panel settings-overview-panel">
          <div class="panel-title with-actions">
            <div>
              <h2>常规与运行</h2>
              <p class="panel-subtitle">管理启动行为、后台服务、数据与隐私。</p>
            </div>
            <div class="button-group">
              <span class="save-state-label" aria-live="polite">正在读取配置</span>
              <button class="primary" id="save_settings_btn" type="button">保存更改</button>
            </div>
          </div>

          <div class="settings-stack settings-overview-grid">
            <section class="settings-section settings-section-first-row">
              <h3>常规设置</h3>
              <label class="check-row">
                <input id="use_filters" type="checkbox" />
                <span>
                  <strong>使用过滤器和 Hosts 文件以拦截指定域名</strong>
                  <small>你可以在 DNS 黑名单和自定义过滤规则中添加过滤规则。</small>
                </span>
              </label>
              <div class="field compact-select">
                <span>过滤器更新间隔</span>
                <select id="filter_update_interval">
                  <option value="6">6 小时</option>
                  <option value="12">12 小时</option>
                  <option value="24">24 小时</option>
                  <option value="72">3 天</option>
                  <option value="168">7 天</option>
                </select>
              </div>
              <label class="toggle-row">
                <input id="enabled" type="checkbox" />
                <span>启动时自动运行 DNS 服务</span>
              </label>
              <label class="toggle-row">
                <input id="launch_at_startup" type="checkbox" />
                <span>开机时启动应用</span>
              </label>
            </section>

            <section class="settings-section settings-section-first-row settings-section-right runtime-watchdog-section">
              <div class="section-heading">
                <h3>运行监控</h3>
              </div>
              <div class="runtime-watchdog-grid">
                <label class="check-row">
                  <input id="runtime_watchdog_enabled" type="checkbox" />
                  <span>
                    <strong>自动恢复 DNS 服务</strong>
                    <small>检测到服务未运行或内部线程异常时自动重启 DNS 服务。</small>
                  </span>
                </label>
                <label class="field">
                  <span>检查间隔（秒）</span>
                  <input id="runtime_watchdog_interval_seconds" type="number" min="10" max="3600" step="1" />
                </label>
              </div>
            </section>

            <section class="settings-section background-service-section hidden" id="windows_service_section">
              <div>
                <h3>Windows DNS 系统服务</h3>
                <p id="windows_service_status">正在读取系统服务状态…</p>
                <small>DNS 核心由 Windows 服务控制管理器在开机阶段自动启动；关闭 GUI、尚未登录或 Clash 稍后启动都不会中断本机 DNS。</small>
              </div>
              <div class="button-group background-service-actions">
                <button class="primary" id="install_windows_service_btn" type="button">安装或修复</button>
                <button id="uninstall_windows_service_btn" type="button">卸载服务</button>
              </div>
            </section>

            <section class="settings-section settings-section-right background-service-section hidden" id="windows_system_dns_section">
              <div>
                <h3>系统 DNS</h3>
                <p id="windows_system_dns_status">正在读取系统 DNS 状态…</p>
                <small id="windows_system_dns_detail">会按有线、无线网卡分别保存原始 DNS；切换网络后可将当前活动网卡同步纳入接管。</small>
              </div>
              <div class="button-group background-service-actions">
                <button class="primary" id="take_over_windows_system_dns_btn" type="button">接管 DNS</button>
                <button id="restore_windows_system_dns_btn" type="button">恢复 DNS</button>
              </div>
            </section>

            <dialog class="update-dialog dns-fallback-dialog" id="dns_fallback_dialog">
              <div class="update-dialog-panel">
                <div class="update-dialog-header">
                  <div>
                    <span class="update-dialog-kicker">系统 DNS</span>
                    <h3 id="dns_fallback_dialog_title">解除本机 DNS</h3>
                  </div>
                  <button class="update-dialog-close" id="dns_fallback_dialog_close_btn" type="button" aria-label="关闭">×</button>
                </div>
                <div class="update-dialog-body">
                  <p class="dns-fallback-intro" id="dns_fallback_dialog_intro">当前没有原 DNS 备份，请选择解除后使用的 DNS。只会修改仍指向 127.0.0.1 或 ::1 的设置。</p>
                  <div class="dns-fallback-options">
                    <label class="dns-fallback-option hidden" id="dns_restore_original_option">
                      <input type="radio" name="dns_fallback" value="original" />
                      <span><strong>按接管前配置恢复（推荐）</strong><small id="dns_restore_original_detail">保留接管前的自动获取或手动 DNS 设置</small></span>
                    </label>
                    <label class="dns-fallback-option">
                      <input type="radio" name="dns_fallback" value="automatic" />
                      <span><strong>自动获取（DHCP）</strong><small>适合 IP 也由 DHCP 分配的网络；静态 IP 建议使用自定义 DNS</small></span>
                    </label>
                    <label class="dns-fallback-option">
                      <input type="radio" name="dns_fallback" value="dns114" />
                      <span><strong>114DNS</strong><small>114.114.114.114 / 114.114.115.115</small></span>
                    </label>
                    <label class="dns-fallback-option">
                      <input type="radio" name="dns_fallback" value="google" />
                      <span><strong>Google DNS</strong><small>8.8.8.8 / 8.8.4.4，并配置 IPv6</small></span>
                    </label>
                    <div class="dns-fallback-option dns-fallback-custom-option" id="dns_fallback_custom_option">
                      <label>
                        <input type="radio" name="dns_fallback" value="custom" />
                        <span><strong>自定义 DNS</strong><small>填写希望在解除接管后使用的 DNS 服务器地址</small></span>
                      </label>
                      <div class="dns-custom-fields">
                        <label class="field">
                          <span>IPv4 DNS</span>
                          <input id="dns_custom_ipv4" type="text" inputmode="decimal" placeholder="例如 1.1.1.1, 1.0.0.1" />
                        </label>
                        <label class="field">
                          <span>IPv6 DNS（可选）</span>
                          <input id="dns_custom_ipv6" type="text" placeholder="例如 2606:4700:4700::1111" />
                        </label>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="update-dialog-footer">
                  <button id="dns_fallback_dialog_cancel_btn" type="button">取消</button>
                  <button class="primary" id="dns_fallback_dialog_confirm_btn" type="button">确认解除</button>
                </div>
              </div>
            </dialog>

            <section class="settings-section settings-section-wide background-service-section hidden" id="macos_service_section">
              <div>
                <h3>macOS DNS 后台服务</h3>
                <p id="macos_service_status">正在读取后台服务状态…</p>
                <small>正式版通过系统后台服务监听 UDP/TCP 53。首次安装需要管理员在“系统设置 → 通用 → 登录项与扩展”中批准。</small>
              </div>
              <div class="button-group background-service-actions">
                <button class="primary" id="install_macos_service_btn" type="button">安装或修复</button>
                <button class="hidden" id="open_macos_service_settings_btn" type="button">打开系统设置</button>
                <button id="uninstall_macos_service_btn" type="button">卸载服务</button>
              </div>
            </section>

            <section class="settings-section data-storage-section settings-section-wide">
              <div class="section-heading">
                <h3>数据存储</h3>
                <span>查询日志、统计数据库和过滤器数据会保存在此目录。可迁移到空目录，也可在重装系统后安全使用保留的现有数据。</span>
              </div>
              <div class="data-storage-path-row">
                <input id="data_storage_path" type="text" readonly aria-label="数据存储路径" />
                <div class="button-group data-storage-actions">
                  <button id="choose_data_storage_btn" type="button">选择目录</button>
                  <button id="reset_data_storage_btn" type="button">恢复默认</button>
                </div>
              </div>
              <div class="data-storage-meta">
                <span id="data_storage_size">正在读取占用空间…</span>
                <span id="data_storage_state"></span>
              </div>
              <div class="data-storage-pending hidden" id="data_storage_pending">
                <span id="data_storage_pending_text"></span>
                <button class="primary" id="migrate_data_storage_btn" type="button">迁移并重启</button>
              </div>
              <div class="data-storage-error hidden" id="data_storage_error"></div>
            </section>

            <section class="settings-section cache-maintenance-section settings-section-wide">
              <div>
                <h3>磁盘缓存</h3>
                <p>清理可重新生成的规则编译缓存，不会删除远程黑名单、当前生效规则、配置、查询日志和统计数据。</p>
              </div>
              <button id="clear_filter_cache_btn" type="button">清理缓存</button>
            </section>

            <section class="settings-section config-transfer-section settings-section-wide">
              <div>
                <h3>备份与诊断</h3>
                <p>导出或恢复完整配置；诊断文件会隐藏域名、客户端地址、规则、代理和上游等隐私内容。</p>
              </div>
              <div class="button-group config-transfer-actions">
                <button id="export_config_btn" type="button">导出配置</button>
                <button id="import_config_btn" type="button">恢复配置</button>
                <button id="export_diagnostic_btn" type="button">导出脱敏诊断</button>
              </div>
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
                  <small>持久化查询日志和统计中仅保存匿名化后的客户端 IP；运行期安全事件仍会显示来源 IP。</small>
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
              <label class="field log-ignore-field">
                <span>日志忽略域名</span>
                <small>每行一个域名，自动包含其子域名。命中的查询不会写入查询日志。</small>
                <textarea id="query_log_ignored_domains" autocomplete="off" spellcheck="false" placeholder="example.com"></textarea>
              </label>
              <div class="button-group persistence-actions">
                <button id="clear_query_logs_btn" type="button">清除查询日志</button>
              </div>
            </section>

            <section class="settings-section settings-section-right">
              <h3>统计配置</h3>
              <label class="check-row">
                <input id="statistics_enabled" type="checkbox" />
                <span>
                  <strong>启用统计数据</strong>
                  <small>按小时聚合查询趋势、域名、客户端、上游和黑名单命中，不保存完整 DNS 响应。</small>
                </span>
              </label>
              <div class="retention-settings">
                <span class="retention-title">统计数据保留时间</span>
                <div class="retention-options">
                  <label><input name="statistics_retention" type="radio" value="24" /> 24 小时</label>
                  <label><input name="statistics_retention" type="radio" value="168" /> 7 天</label>
                  <label><input name="statistics_retention" type="radio" value="720" /> 30 天</label>
                  <label><input name="statistics_retention" type="radio" value="2160" /> 90 天</label>
                  <label><input name="statistics_retention" type="radio" value="4320" /> 180 天</label>
                  <label><input name="statistics_retention" type="radio" value="8760" /> 365 天</label>
                  <label><input name="statistics_retention" type="radio" value="forever" /> 永久</label>
                  <label><input name="statistics_retention" type="radio" value="custom" /> 自定义</label>
                </div>
                <label class="field custom-retention-field" id="statistics_custom_retention_field">
                  <span>自定义保留时间（天）</span>
                  <input id="statistics_retention_custom" type="number" min="1" max="365" step="1" placeholder="例如 120" />
                </label>
              </div>
              <label class="field log-ignore-field">
                <span>统计忽略域名</span>
                <small>每行一个域名，自动包含其子域名。适合排除 NAS 心跳、探活等高频噪音，不影响查询日志。</small>
                <textarea id="statistics_ignored_domains" autocomplete="off" spellcheck="false" placeholder="example.com"></textarea>
              </label>
              <div class="button-group persistence-actions">
                <button id="clear_statistics_btn" type="button">清除统计数据</button>
              </div>
            </section>

          </div>
        </section>
      </section>

      <section class="view about-view" data-view-panel="about">
        <section class="panel module-panel about-panel">
          <div class="panel-title">
            <h2>关于</h2>
          </div>

          <div class="about-hero">
            <img class="about-app-mark" src="${appIconUrl}" alt="" />
            <div class="about-intro">
              <h3>DnsBlackhole</h3>
              <p>轻量的本地 DNS 转发与域名拦截工具。</p>
              <div class="about-capabilities" aria-label="应用特性">
                <span>DNS 转发</span>
                <span>域名拦截</span>
                <span>Windows / macOS</span>
              </div>
            </div>
          </div>

          <section class="about-update-section" aria-labelledby="about_update_title">
            <div class="about-update-row">
              <div>
                <h3 id="about_update_title">软件更新</h3>
                <p>当前版本：<strong class="about-version">v<span id="app_version">-</span></strong></p>
              </div>
              <div class="button-group update-actions">
                <button class="primary" id="check_update_btn" type="button">检查更新</button>
              </div>
            </div>
            <div class="update-status hidden" id="update_status"></div>
          </section>

          <div class="about-links-grid" aria-label="项目相关链接">
            <button class="about-link-card" data-about-link="repository" type="button">
              <span class="about-link-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M9 18H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h4M15 4h4a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-4M8 12h8M13 9l3 3-3 3" /></svg>
              </span>
              <span class="about-link-copy">
                <strong>项目主页</strong>
                <small>查看源码与使用文档</small>
              </span>
              <span class="about-link-arrow" aria-hidden="true">›</span>
            </button>
            <button class="about-link-card" data-about-link="releases" type="button">
              <span class="about-link-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M6 3h9l3 3v15H6zM14 3v4h4M9 12h6M9 16h6" /></svg>
              </span>
              <span class="about-link-copy">
                <strong>更新记录</strong>
                <small>查看历史版本与变更</small>
              </span>
              <span class="about-link-arrow" aria-hidden="true">›</span>
            </button>
            <button class="about-link-card" data-about-link="issues" type="button">
              <span class="about-link-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M4 5h16v12H8l-4 4zM8 9h8M8 13h5" /></svg>
              </span>
              <span class="about-link-copy">
                <strong>意见反馈</strong>
                <small>报告问题或提出建议</small>
              </span>
              <span class="about-link-arrow" aria-hidden="true">›</span>
            </button>
            <button class="about-link-card" data-about-link="license" type="button">
              <span class="about-link-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8.1 7 10 4.2-1.9 7-5.4 7-10V6zM9 12l2 2 4-4" /></svg>
              </span>
              <span class="about-link-copy">
                <strong>开源许可</strong>
                <small>基于 MIT License 发布</small>
              </span>
              <span class="about-link-arrow" aria-hidden="true">›</span>
            </button>
          </div>

          <dialog class="update-dialog" id="update_dialog">
            <div class="update-dialog-panel">
              <div class="update-dialog-header">
                <div>
                  <span class="update-dialog-kicker">软件更新</span>
                  <h3>发现新版本</h3>
                </div>
                <button class="update-dialog-close" id="update_dialog_close_btn" type="button" aria-label="关闭">×</button>
              </div>
              <div class="update-dialog-body">
                <div class="update-version-change">
                  <span>v<span id="update_current_version">-</span></span>
                  <span aria-hidden="true">→</span>
                  <strong id="update_release_version">v-</strong>
                </div>
                <div class="update-release-notes">
                  <div class="update-release-notes-title">本次更新内容</div>
                  <div class="update-release-notes-body" id="update_release_notes_body"></div>
                </div>
              </div>
              <div class="update-dialog-footer">
                <button id="update_dialog_later_btn" type="button">稍后</button>
                <button id="manual_download_btn" type="button">浏览器下载</button>
                <button class="primary" id="install_update_btn" type="button">下载并安装</button>
              </div>
            </div>
          </dialog>
        </section>
      </section>

      <section class="view" data-view-panel="filters">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>DNS 黑名单</h2>
            <div class="button-group">
              <span class="filter-update-progress hidden" id="filter_update_progress" role="status"></span>
              <span class="save-state-label" aria-live="polite">正在读取配置</span>
              <button id="save_filters_btn" type="button">保存更改</button>
              <button id="add_filter_btn" type="button">添加黑名单</button>
              <button class="hidden" id="cancel_filter_update_btn" type="button">取消更新</button>
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
            <div class="button-group">
              <span class="save-state-label" aria-live="polite">正在读取配置</span>
              <button class="primary" id="save_custom_btn" type="button">保存更改</button>
            </div>
          </div>
          <div class="rule-editor-toolbar">
            <span id="rule_analysis_summary" aria-live="polite">等待读取规则</span>
            <label class="field rule-search-field">
              <span class="sr-only">在自定义规则中查找</span>
              <input id="custom_rule_search" type="search" autocomplete="off" spellcheck="false" placeholder="查找规则，按 Enter 跳到下一处" />
            </label>
          </div>
          <div class="rule-editor-shell">
            <pre id="rule_line_numbers" aria-hidden="true">1</pre>
            <textarea id="blacklist" spellcheck="false" aria-label="自定义过滤规则"></textarea>
          </div>
          <div class="rule-diagnostics" id="rule_diagnostics" aria-live="polite"></div>

          <section class="settings-section dns-rewrites-section">
            <div class="section-heading">
              <h3>DNS 重写</h3>
              <span>每行一条“域名 IP”本地记录，优先于黑名单生效。用 *.域名 匹配整个子域，同一域名可以分别写一行 IPv4 和一行 IPv6。</span>
            </div>
            <textarea id="dns_rewrites" spellcheck="false" placeholder="nas.lan 192.168.1.10&#10;*.home.lan 192.168.1.1"></textarea>
          </section>
        </section>
      </section>
    </main>
  </div>
`;
}
