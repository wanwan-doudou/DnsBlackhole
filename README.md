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
- 支持添加、启用、停用、删除清单，并手动检查更新
- 支持本地自定义规则
- 支持查询日志，可按已处理、已过滤、失败筛选，并按域名或客户端搜索
- 支持仪表盘统计，包括查询趋势、拦截率、请求域名排行、被拦截域名排行、上游请求排行和上游平均响应时间
- 支持日志保留时间配置和客户端 IP 匿名化
- 支持 DNS 响应缓存，可配置缓存大小、最小/最大 TTL、乐观缓存，并可手动清除缓存
- 默认监听 `127.0.0.1:53`
- 支持系统托盘，关闭窗口后保持后台运行，可从托盘显示窗口或退出
- 支持应用内检查更新与签名安装更新

## 规则语法

当前支持常见 AdGuard Home 子集：

- `||example.org^`：拦截域名及其子域名
- `@@||example.org^`：放行域名及其子域名
- `0.0.0.0 example.org`、`127.0.0.1 example.org`：hosts 风格黑名单
- `*.example.org`：拦截域名及其子域名
- `example.org`：仅拦截该域名

规则会忽略空行、`#` 注释和 `!` 注释。当前不支持正则规则；`$dnstype` 等高级修饰符会被忽略，只使用 `$` 前面的域名模式。

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

默认监听 `127.0.0.1:53`，不需要修改系统 DNS 就可以直接测试：

```bash
nslookup -port=53 example.com 127.0.0.1
nslookup -port=53 example-blocked.local 127.0.0.1
```

如果安装了 `dig`，也可以使用：

```bash
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 53 example-blocked.local
```

在 Windows 上监听 `53` 端口本身通常不需要管理员权限；如果启动失败，更常见原因是端口已被其它 DNS 服务占用、防火墙拦截，或地址被系统保留。macOS/Linux 上监听 `53` 这类低端口通常仍需要管理员权限或对应 capability。Windows 上 `5353` 常被 mDNS 占用，因此不再作为默认监听端口。

## 发布

应用内置基于 `tauri-plugin-updater` 的检查更新（设置 → 关于与更新）。发版流程：

1. 更新 `src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml`、`package.json` 三处版本号。
2. 执行 `.\scripts\release.ps1`。
3. 创建 GitHub Release（tag `v<版本号>`），上传脚本输出的 `setup.exe`、`msi` 和 `latest.json`。

更新签名私钥位于 `%USERPROFILE%\.tauri\dnsblackhole.key`，丢失后旧版本将无法验证新版本更新，务必备份。
