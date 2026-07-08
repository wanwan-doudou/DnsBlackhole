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
- 支持应用内检查更新与签名安装更新

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

## 发布

应用内置基于 `tauri-plugin-updater` 的检查更新（设置 → 关于与更新）。发版流程：

1. 更新 `src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml`、`package.json` 三处版本号。
2. 执行 `.\scripts\release.ps1`。
3. 创建 GitHub Release（tag `v<版本号>`），上传脚本输出的 `setup.exe`、`msi` 和 `latest.json`。

更新签名私钥位于 `%USERPROFILE%\.tauri\dnsblackhole.key`，丢失后旧版本将无法验证新版本更新，务必备份。
