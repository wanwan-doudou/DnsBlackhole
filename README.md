# DnsBlackhole

基于 Tauri 2 + TypeScript + Rust 的本地 DNS 黑名单工具。

## 功能

- 配置上游 DNS，每行一个服务器，支持 UDP DNS 和 DoH：
  - `https://dns.alidns.com/dns-query`
  - `https://doh.pub/dns-query`
  - `223.5.5.5`
  - `119.29.29.29`
- 支持三种上游请求模式：
  - 负载均衡：一次查询一台上游服务器，失败后尝试其它服务器
  - 并行请求：同时查询所有上游服务器，使用最先成功的响应
  - 最快的 IP 地址：等待多个上游响应并探测返回 IP，优先使用最快结果
- 像 AdGuard Home 一样管理远程 DNS 黑名单清单
- 默认内置三条清单：
  - AdGuard DNS filter
  - AdAway Default Blocklist
  - AdBlock DNS Filters
- 支持添加、启用、停用、删除清单，可手动检查更新，也会按设置的间隔自动更新（失败时指数退避）
- 支持本地自定义规则
- 支持 DNS 重写：每行一条 `域名 IP` 本地记录，`*.域名` 匹配子域，优先于黑名单生效
- 支持拦截响应方式选择：零地址（默认）、NXDOMAIN、REFUSED、自定义 IP
- 规则、清单、重写、拦截方式、日志忽略等过滤类配置支持热替换，保存后立即生效，不重启服务、不清空 DNS 缓存
- 支持查询日志，可按已处理、已过滤、失败筛选，并按域名或客户端搜索
- 支持客户端名称映射（`IP 名称`），查询日志用设备名代替 IP 展示
- 支持日志忽略域名清单，命中的查询不写入日志和统计
- 支持仪表盘统计，包括查询趋势、拦截率、请求域名排行、被拦截域名排行、上游请求排行和上游平均响应时间
- 支持日志保留时间配置和客户端 IP 匿名化
- 支持 DNS 响应缓存，可配置缓存大小、最小/最大 TTL、乐观缓存，并可手动清除缓存
- 默认监听 `0.0.0.0:53`，默认只允许本机、私有 IPv4 网段和常见内网 IPv6 网段客户端访问
- 默认只允许 HTTPS 远程清单和 HTTPS DoH；HTTP 需要在安全防护中显式开启
- 远程清单下载按解压后的实际读取大小限制，默认单个清单最大 50 MB，失败时保留上一版缓存
- 支持系统托盘，关闭窗口后保持后台运行，可从托盘显示窗口或退出
- 支持应用内检查更新与签名安装更新

## 规则语法

当前支持常见 AdGuard Home 子集，规则会编译为 exact/suffix 集合以保持查询性能。

| 写法 | 处理方式 |
| --- | --- |
| `||example.org^` | 拦截域名及其子域名 |
| `@@||example.org^` | 放行域名及其子域名，优先级高于拦截 |
| `0.0.0.0 example.org`、`127.0.0.1 example.org` | hosts 风格黑名单，仅拦截该域名 |
| `*.example.org` | 拦截域名及其子域名 |
| `example.org` | 仅拦截该域名 |
| 空行、`#` 注释、`!` 注释 | 忽略并计入注释/空行统计 |
| `/regex/` | 不支持，忽略并计入正则统计 |
| 带 `$` 高级修饰符的规则 | 不支持，忽略并计入高级修饰符统计 |
| 非法域名或包含路径/通配符的模式 | 忽略并计入非法域名统计 |

远程清单更新后，界面会显示有效规则数、白名单数量、忽略规则数量和忽略原因。

## 协议边界

- 监听侧支持 UDP DNS 和 TCP DNS；上游支持 UDP DNS 和 HTTPS DoH。
- 不做 DNSSEC 验证。
- DNS 请求必须且只能包含 1 个 question；暂不支持压缩格式的 question。
- EDNS0/OPT 记录不会在本地规则逻辑中主动解释；上游响应会按原始响应转发或缓存。
- 默认拒绝 ANY 查询，以降低 DNS 放大攻击面。
- 黑名单命中时的响应由拦截方式决定：默认零地址（A 返回 `0.0.0.0`，AAAA 返回 `::`，其它类型返回无答案的 NOERROR），也可选 NXDOMAIN、REFUSED 或自定义 IP。
- DNS 重写命中时按记录的 IP 版本应答（A 对 IPv4、AAAA 对 IPv6），没有对应版本记录或其它类型返回无答案的 NOERROR。

## 开发

```bash
pnpm install
pnpm tauri dev
pnpm tauri build
```

低成本验证：

```bash
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml
```

## 测试 DNS

默认监听 `0.0.0.0:53`，但默认访问控制只允许本机和私有网络客户端访问。不需要修改系统 DNS 时，可以直接从本机回环地址测试：

```bash
nslookup -port=53 example.com 127.0.0.1
nslookup -port=53 example-blocked.local 127.0.0.1
```

如果安装了 `dig`，也可以使用：

```bash
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 53 example-blocked.local
```

如果只想服务本机，请把监听地址改为 `127.0.0.1`。如果部署到家庭网关，请确认防火墙不会把 `53/udp` 和 `53/tcp` 暴露到公网，并保留或收紧默认允许客户端列表。

在 Windows 上监听 `53` 端口本身通常不需要管理员权限；如果启动失败，更常见原因是端口已被其它 DNS 服务占用、防火墙拦截，或地址被系统保留。macOS/Linux 上监听 `53` 这类低端口通常仍需要管理员权限或对应 capability。Windows 上 `5353` 常被 mDNS 占用，因此不再作为默认监听端口。

## 发布

应用内置基于 `tauri-plugin-updater` 的检查更新（设置 → 关于与更新）。发版流程：

1. 更新 `src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml`、`package.json` 三处版本号。
2. 执行 `.\scripts\release.ps1`。
3. 创建 GitHub Release（tag `v<版本号>`），上传脚本输出的 `setup.exe`、`msi` 和 `latest.json`。

更新签名私钥位于 `%USERPROFILE%\.tauri\dnsblackhole.key`，丢失后旧版本将无法验证新版本更新，务必备份。
