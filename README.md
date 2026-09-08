# DnsBlackhole

轻量的本地 DNS 转发与域名拦截工具，使用 Tauri 2、TypeScript 和 Rust 构建。

[下载最新版](https://github.com/wanwan-doudou/DnsBlackhole/releases/latest) · [查看发布记录](https://github.com/wanwan-doudou/DnsBlackhole/releases) · [MIT License](LICENSE)

DnsBlackhole 可以运行在 Windows 或 macOS 主机上，通过远程黑名单、自定义规则和 DNS 重写过滤广告、跟踪及指定域名，同时提供查询日志、统计、客户端访问控制和 DNS 缓存。它是一个带图形界面的本地转发器，不是完整的权威 DNS 或递归解析器。

> 当前 GitHub Release 同时提供 Windows x64 的 NSIS/MSI 安装包和 macOS Universal DMG。

## 安装

1. 打开 [最新 Release](https://github.com/wanwan-doudou/DnsBlackhole/releases/latest)。
2. Windows 普通用户下载 `DnsBlackhole_<版本>_x64-setup.exe`；需要 MSI 部署时下载 `DnsBlackhole_<版本>_x64_en-US.msi`。
3. macOS 用户下载 `DnsBlackhole_<版本>_universal.dmg`，将应用拖入“应用程序”文件夹；首次启动后，在“设置”中安装后台 DNS 服务，并按系统提示批准后台项目。
4. 启动应用，在“DNS 黑名单”中检查更新，下载已启用的远程清单。
5. 将本机、路由器或局域网设备的 DNS 地址指向运行 DnsBlackhole 的主机。

Windows 版本支持在“关于”中检查、下载并安装带签名的新版本。

## 快速开始

默认配置会启动 DNS 服务，并监听：

- IPv4：`0.0.0.0:53`
- IPv6：`[::]:53`

首次使用建议按以下顺序检查：

1. 在“DNS 设置”确认监听地址、上游 DNS、Fallback DNS 和 Bootstrap DNS。
2. 在“安全防护”确认允许客户端网段，不要把递归 DNS 暴露给公网。
3. 在“DNS 黑名单”更新远程清单，按需增删订阅。
4. 使用“自定义过滤规则”添加本地规则，或使用“DNS 重写”配置局域网域名。
5. 启动服务后，在仪表盘和查询日志中确认请求已进入 DnsBlackhole。

如果只服务本机，请将 IPv4 监听地址改为 `127.0.0.1`，并把 IPv6 监听地址改为 `::1` 或直接关闭 IPv6 监听。家庭网关场景应保留或进一步收紧默认允许客户端列表，并确认防火墙没有将 `53/udp`、`53/tcp` 暴露到公网。

## 核心能力

### DNS 上游

- 上游、Fallback 上游均支持普通 UDP DNS、DoH、DoT 和 DoQ，每行配置一个服务器。
- 域名形式的上游主机名会先通过 Bootstrap DNS 并行查询 A/AAAA，保留多个地址用于故障回退。
- 单个域名上游暂时无法解析不会阻止整个 DNS 服务启动；端点失败后会等待退避时间并重新解析。
- 可按查询域名或客户端 IP/CIDR 配置独立上游；客户端策略优先于域名分流。
- 可请求上游执行 DNSSEC 验证并检查 AD/SERVFAIL 结果；建议搭配可信的加密 DNS 上游。
- 支持三种请求模式：
  - 负载均衡：每次选择一台上游，失败后尝试其他服务器。
  - 并行请求：同时请求所有上游，采用最先成功的响应。
  - 最快的 IP 地址：收集上游响应并探测结果地址，优先返回可达性更好的结果。

支持的上游格式：

| 类型 | 示例 |
| --- | --- |
| UDP DNS IP | `223.5.5.5` |
| UDP DNS IP 与端口 | `223.5.5.5:53`、`[2400:3200::1]:53` |
| UDP DNS 域名 | `dns.example.com`、`dns.example.com:53` |
| DoH | `https://dns.alidns.com/dns-query` |
| DoT | `tls://dns.example.com`、`tls://dns.example.com:853` |
| DoQ | `quic://dns.example.com`、`quic://dns.example.com:853` |

Bootstrap DNS 只接受 IP 或 `IP:端口`，不能填写域名或 DoH 地址，避免解析自身时形成依赖循环。

### 过滤与重写

- 默认包含五条订阅：AdGuard DNS filter、AdBlock DNS Filters、HaGeZi Threat Intelligence Feeds、HaGeZi NSFW 和 HaGeZi Gambling，全部取自上游仓库官方标注的原始地址，不使用任何加速镜像。
- 可添加、启用、停用、更新和删除远程清单；自动更新失败时采用指数退避，并保留上一版有效缓存。
- 支持本地自定义规则、allowlist、`important`、`badfilter`、DNS 类型限制和 `denyallow`。
- 支持 DNS 重写，格式为 `域名 IP`；`*.example.org` 可匹配子域，优先于黑名单生效。
- 规则可用 `$dnsrewrite` 直接指定应答，覆盖全局拦截方式；查询类型与重写记录类型不一致时返回空 NOERROR。
- 可选把系统 hosts 文件并入 DNS 重写表；界面里显式写出的重写优先，修改 hosts 后需重新保存配置才会读取。
- 支持零地址、NXDOMAIN、REFUSED 和自定义 IP 四种拦截响应。
- 拦截响应 TTL 可配置；NXDOMAIN 会携带同 TTL 的 SOA 负缓存信息，减少客户端对同一被拦域名的重复查询。
- 支持按客户端分配命名策略组、周期计划、家庭安全搜索及常用服务分类拦截。
- “安全防护”提供客户端策略表单：填写 IP/CIDR、选择策略组和时间段即可生成上述规则文本，仪表盘客户端排行也能直接跳转编辑；原有的文本编辑入口保留。
- 规则、清单、重写、拦截方式和日志忽略域名保存后热替换，不重启服务、不清空 DNS 缓存。

### 查询、统计与缓存

- 查询日志支持按时间、处理状态、响应来源和查询类型组合筛选，可切换排序并保存常用查询视图。
- 查询日志搜索使用增量索引与稳定游标分页，大规模日志下仍可连续翻页和导出当前筛选结果。
- 拦截详情显示命中规则、来源清单、规则类型、`important` 覆盖和 allowlist 信息。
- 支持客户端名称映射、日志忽略域名、日志保留时间及客户端 IP 匿名化。
- 仪表盘展示查询趋势、拦截率、域名排行、客户端排行、DNS 黑名单排行、上游请求排行、平均响应时间和缓存命中/刷新/淘汰指标。
- DNS 响应缓存支持容量、最小/最大 TTL、有最大陈旧时间保护的乐观缓存、热门域名过期前预取和手动清理。
- 可清理远程过滤器磁盘缓存，不影响配置、查询日志和统计数据库。
- 查询日志、统计数据库和过滤器数据可迁移到自定义目录，并在重装后接管保留的现有数据。

### 界面

- 支持浅色、深色和跟随系统三种主题；配色基于统一的设计令牌，深色下的正文对比度达到 WCAG AA。
- 界面语言支持简体中文和 English，默认跟随系统；主题与语言保存在本机，立即生效，不属于需要保存的 DNS 配置。
- 托盘菜单文案跟随界面语言。

### 安全与运行维护

- 允许/拒绝客户端列表支持单个 IP 和 CIDR，拒绝列表优先。
- 默认允许回环、私有 IPv4、ULA IPv6 和链路本地 IPv6 网段。
- 默认每客户端限制为每秒 2000 次查询，并拒绝 ANY 查询。
- DNS Rebinding Protection 会拦截公共域名返回的私有、回环、链路本地和组播地址；可信域名及域名分流上游可安全豁免。
- CNAME cloaking 检测会对响应别名目标再次执行现有黑白名单判定。
- 私有、回环、链路本地地址的反向解析（`in-addr.arpa` / `ip6.arpa`）默认由本地返回带 SOA 的 NXDOMAIN，不向上游转发，避免把内网网段逐个泄漏给公共 DNS；部分区域名（如 `168.192.in-addr.arpa`）同样拦截，而 `192.in-addr.arpa` 这类还覆盖公网地址的短前缀会照常转发。需要内网 DNS 解析反查时，用“域名分流上游”把对应区域指向内网服务器即可放行，也可以在“安全防护”里整体关闭。
- UDP 访问拒绝和限速请求会静默丢弃；TCP 会尝试返回 `REFUSED`。
- “安全防护”页面展示访问拒绝、限速、UDP 丢弃和 ANY 拒绝统计，并保留最近 200 条聚合事件。事件会落盘保存，重启后仍可查看，保留时间可配置，也可一键清除。
- 远程清单和 DoH 默认只允许 HTTPS；HTTP 必须在安全防护中显式开启。
- 单个远程清单默认限制为解压后 200 MB，超限立即中断并保留旧缓存。
- 支持运行状态监控与异常自动恢复、系统托盘、开机启动和关闭窗口后后台运行。
- 可选启用只读 REST 与 Prometheus 监控接口；默认仅监听本机，且不暴露域名或客户端明细。

## 默认安全策略

| 项目 | 默认值 |
| --- | --- |
| 监听 | `0.0.0.0:53` 与 `[::]:53` |
| 允许客户端 | `127.0.0.0/8`、`::1/128`、RFC 1918、`fc00::/7`、`fe80::/10` |
| 每客户端限速 | 持续 2000 次/秒，允许约 10 秒短时突发 |
| ANY 查询 | 拒绝 |
| 不安全 HTTP | 禁止 |
| 单个远程清单上限 | 200 MB |
| DNS 缓存 | 启用，16 MB，最小 TTL 60 秒，最大 TTL 24 小时，启用乐观缓存与热门域名预取 |
| 响应安全 | 启用 DNS Rebinding Protection 与 CNAME cloaking 检测 |
| 私有地址反查 | 本地返回 NXDOMAIN，不向上游转发 |
| 拦截响应 TTL | 60 秒 |
| 查询日志 | 启用，默认保留 90 天 |

这些默认值适合受信任的本机或家庭局域网，但不能替代主机和路由器防火墙。

## 规则语法

当前支持常见 AdGuard Home 规则子集，规则会编译为 exact/suffix 集合以保持查询性能。

| 写法 | 处理方式 |
| --- | --- |
| `||example.org^` | 拦截域名及其子域名 |
| `@@||example.org^` | 放行域名及其子域名，优先级高于普通拦截 |
| `0.0.0.0 example.org`、`127.0.0.1 example.org` | hosts 风格黑名单，仅拦截该域名 |
| `*.example.org` | 拦截域名及其子域名 |
| `example.org` | 仅拦截该域名 |
| `$important` | 提高规则优先级；重要放行规则优先于重要拦截规则 |
| `$badfilter` | 禁用文本和其他修饰符完全匹配的目标规则 |
| `$dnstype=A|AAAA`、`$dnstype=~AAAA` | 按 DNS question 类型包含或排除匹配 |
| `$denyallow=safe.example.org` | 匹配父域时排除指定域名及其子域名 |
| `$dnsrewrite=1.2.3.4`、`$dnsrewrite=NXDOMAIN` | 按规则给出自定义应答，短写法支持 IP、CNAME 目标和 RCODE |
| `$dnsrewrite=NOERROR;TXT;hello` | 完整写法，支持 A、AAAA、CNAME、TXT、MX、SRV、PTR 和各 RCODE |
| 空行、`#` 注释、`!` 注释 | 忽略并计入注释/空行统计 |
| `/regex/` | 暂不支持，忽略并计入正则统计 |
| 其他未知 `$` 高级修饰符 | 暂不支持，整条忽略并计入高级修饰符统计 |
| 非法域名或包含路径的模式 | 忽略并计入非法域名统计 |

远程清单更新后，界面会显示有效规则数、allowlist 数量、忽略规则数量和忽略原因。

## 协议与当前边界

- 客户端侧支持 UDP DNS 和 TCP DNS；上游支持 UDP DNS、HTTP/HTTPS DoH、DoT 和 DoQ，HTTP 默认禁用。
- DNSSEC 当前依赖上游验证：启用后会请求 DNSSEC 记录并检查上游返回的验证结果，不在本地执行完整签名链验证。
- DNS 请求必须且只能包含一个 question，暂不支持压缩格式的 question。
- EDNS0 会解析 UDP 响应大小和 DNSSEC DO 位。Padding、TCP Keepalive 可在移除 OPT 后进入缓存与重复请求合并，命中时按当前请求重建空 OPT；DNS Cookie 需要客户端校验响应，和 ECS 等会改变应答内容的选项及未知选项一样，不参与缓存。
- 缓存不按客户端声明的 UDP 大小分键（同一问题的应答内容与之无关），出站尺寸按每个客户端单独截断；但“是否使用 EDNS”仍然分键，因为 RFC 6891 要求请求没有 OPT 时响应也不能带 OPT。
- 开启 IPv6 双监听时，IPv4 地址由“监听地址”指定，IPv6 地址由“IPv6 监听地址”单独指定，可填 `::`、`::1` 或某个本机 IPv6 地址；从旧版本升级时该字段保持原有的 `::` 行为。
- 黑名单命中时，A/AAAA 会按配置生成响应；其他记录类型在零地址或无匹配重写时返回无答案的 NOERROR。

## 测试 DNS

不修改系统 DNS 时，可以直接从本机回环地址测试：

```powershell
nslookup -port=53 example.com 127.0.0.1
nslookup -port=53 example-blocked.local 127.0.0.1
```

安装了 `dig` 时也可以使用：

```bash
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 53 example-blocked.local
```

在 Windows 上监听 `53` 端口通常不需要管理员权限。启动失败时，应先检查端口是否被其他 DNS 服务占用、是否被防火墙拦截，以及地址是否被系统保留。macOS/Linux 上监听低端口通常需要管理员权限或对应 capability。Windows 的 `5353` 常被 mDNS 占用，因此不作为默认端口。

## 本地开发

需要 Node.js、pnpm、Rust 工具链以及 Tauri 2 对应的系统构建依赖。

```bash
pnpm install
pnpm tauri:dev
```

开发版使用独立的应用标识和数据目录，并且不会写入系统开机自启项。开机自启请通过安装后的生产版本验证，避免系统登录时启动依赖 Vite 服务的 debug 可执行文件。

生产构建：

```bash
pnpm tauri build
```

低成本验证：

```bash
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml
```

### 性能基准

DNS 热路径（规则编译、规则匹配、报文解析与拦截应答、缓存读写）有一套 criterion 基准：

```bash
cargo bench --manifest-path src-tauri/Cargo.toml --features bench --bench dns_hot_path
```

对比改动前后用 `--save-baseline` 和 `--baseline`。CI 只做编译检查——共享构建机的噪声太大，跑不出可信的性能门禁，实际对比需要在固定机器上进行。

## 发布维护

项目使用 `tauri-plugin-updater` 和 Tauri updater 签名。维护者发布新版本时：

1. 同步更新 `package.json`、`src-tauri/Cargo.toml`、`src-tauri/Cargo.lock` 和 `src-tauri/tauri.conf.json` 中的版本号。
2. 完成前端构建、Rust 测试和 Clippy 检查。
3. 在 Windows 执行 `./scripts/release.ps1`，生成签名的 NSIS、MSI 安装包与 `latest.json`。
4. 推送 `main` 并等待 macOS CI 完成，下载 `DnsBlackhole-macos-universal-release` artifact。
5. 创建一个 `v<版本号>` GitHub Release，统一上传 NSIS、MSI、Windows `latest.json`，以及 macOS artifact 中的 Universal DMG、`.app.tar.gz`、`.sig` 和 `latest-darwin-universal.json`。

更新私钥位于维护者机器的 `%USERPROFILE%\.tauri\dnsblackhole.key`。macOS CI 需要把同一私钥配置为 `TAURI_SIGNING_PRIVATE_KEY` Secret；如果私钥有密码，再配置 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`。未配置私钥时 CI 仍会生成 DMG，但不会生成自动更新产物。私钥丢失后，旧版本将无法验证后续自动更新，必须妥善离线备份且不得提交到仓库。

## License

本项目采用 [MIT License](LICENSE)。
