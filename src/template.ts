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
        </div>

        <nav class="module-nav" aria-label="模块">
          <button class="nav-item active" data-view="dashboard" type="button">仪表盘</button>
          <div class="nav-menu">
            <button class="nav-item" data-view="settings" data-nav-group="settings" type="button">设置</button>
            <div class="nav-dropdown" role="menu">
              <button data-view="settings" type="button" role="menuitem">常规设置</button>
              <button data-view="dns" type="button" role="menuitem">DNS 设置</button>
              <button data-view="security" type="button" role="menuitem">安全防护</button>
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
            <span class="spark-caption"><span>DNS 查询</span><small>最近 15 天 · 每日</small></span>
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
            <span class="spark-caption"><span>已被过滤器拦截</span><small>最近 15 天 · 每日</small></span>
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
              <button id="clear_dns_cache_btn" type="button">清除缓存</button>
            </section>
          </div>
        </section>
      </section>

      <section class="view" data-view-panel="security">
        <section class="panel module-panel">
          <div class="panel-title with-actions">
            <h2>安全防护</h2>
            <button class="primary" id="save_security_btn" type="button">保存</button>
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
            </section>

            <section class="settings-section dns-security-section">
              <div class="section-heading">
                <h3>查询防护</h3>
                <span>降低异常流量和 DNS 放大攻击风险。</span>
              </div>
              <div class="dns-security-options">
                <label class="field">
                  <span>每客户端限速</span>
                  <small>每秒允许的 DNS 查询数，0 表示关闭限速。</small>
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
                <h3>过滤器下载安全</h3>
                <span>限制远程黑名单下载行为，降低异常响应和中间人篡改风险。</span>
              </div>
              <div class="dns-security-options">
                <label class="field">
                  <span>单个过滤器最大大小（MB）</span>
                  <small>按解压后的实际读取大小限制，超过后立即中断下载。</small>
                  <input id="filter_max_size_mb" type="number" min="1" max="256" step="1" />
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

            <section class="settings-section runtime-watchdog-section">
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

            <section class="settings-section data-storage-section">
              <div class="section-heading">
                <h3>数据存储</h3>
                <span>查询日志、统计数据库和过滤器缓存会保存在此目录。迁移在重启后执行，失败时继续使用原目录。</span>
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
                  <small>持久化查询日志中仅保存匿名化后的客户端 IP；运行期安全事件仍会显示来源 IP。</small>
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
                <small>每行一个域名，自动包含其子域名。命中的查询不会写入日志和统计，可用于过滤 NAS 心跳等高频噪音。</small>
                <textarea id="query_log_ignored_domains" autocomplete="off" spellcheck="false" placeholder="example.com"></textarea>
              </label>
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
