# DnsBlackhole

基于 Tauri 2 + TypeScript + Rust 的本地 DNS 黑名单工具。

## 功能

- 配置上游 DNS，每行一个服务器，支持 UDP DNS 和 DoH：
  - `https://dns.alidns.com/dns-query`
  - `https://doh.pub/dns-query`
  - `223.5.5.5`
  - `119.29.29.29`
- 像 AdGuard Home 一样管理远程 DNS 黑名单清单
- 默认内置三条清单：
  - AdGuard DNS filter
  - AdAway Default Blocklist
  - AdBlock DNS Filters
- 支持添加、启用、停用、删除清单，并手动检查更新
- 支持本地自定义规则
- 默认监听 `127.0.0.1:1053`

## 规则语法

当前支持常见 AdGuard Home 子集：

- `||example.org^`：拦截域名及其子域名
- `@@||example.org^`：放行域名及其子域名
- `0.0.0.0 example.org`、`127.0.0.1 example.org`：hosts 风格黑名单
- `example.org`：仅拦截该域名

更复杂的正则、`$dnstype` 等高级语法暂未实现。

## 开发

```bash
pnpm install
pnpm tauri dev
pnpm tauri build
```

监听 `53` 端口通常需要管理员权限。Windows 上 `5353` 常被 mDNS 占用，开发和日常测试建议先使用默认的 `1053`。
