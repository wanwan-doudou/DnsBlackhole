# Docker 部署

v0.2.5 的 Docker 镜像直接封装 Server 版 headless binary 和同一套内嵌 Web 管理后台。容器只运行一个固定 uid/gid `10001:10001` 的非 root 进程，不使用 `privileged` 或 `NET_ADMIN`。官方 Linux amd64 镜像发布在 `ghcr.io/wanwan-doudou/dnsblackhole`。

正式部署建议检出对应的版本 tag，让同版本 Compose 拉取不可变版本标签；不要从持续变化的分支部署，也不要在生产环境固定 `latest`：

```bash
git clone https://github.com/wanwan-doudou/DnsBlackhole.git
cd DnsBlackhole
git fetch --tags
git checkout v0.2.5
docker compose pull
docker compose up -d --no-build
```

仓库中的 Dockerfile 保留为源码构建回退。确实需要自行构建时，显式改成本地镜像名，避免覆盖 Compose 的官方镜像引用：

```bash
export DNSBLACKHOLE_IMAGE=dnsblackhole:0.2.5
docker compose build --pull
docker compose up -d --no-build
```

## bridge 模式

先确保宿主的 TCP/UDP 53 与 TCP 3000 可用，再执行：

```bash
docker compose pull
docker compose up -d --no-build
docker compose ps
docker compose logs dnsblackhole
```

自行构建且所在网络不能直连 Docker Hub 时，可在构建命令中通过 `NODE_IMAGE`、`RUST_IMAGE` 和 `RUNTIME_IMAGE` build arg 指向可信的 Docker Official Images 镜像仓库；正式 Dockerfile 默认仍使用 Docker Hub。

默认显式绑定宿主的 IPv4 与 IPv6 所有地址。只想绑定指定地址时，在同一命令前设置 `DNSBLACKHOLE_BIND_ADDRESS` 和 `DNSBLACKHOLE_BIND_ADDRESS_V6`，例如：

```bash
DNSBLACKHOLE_BIND_ADDRESS=192.168.1.10 \
DNSBLACKHOLE_BIND_ADDRESS_V6=fd00::10 \
docker compose up -d --no-build
```

宿主没有可用 IPv6 时，可删除 Compose 中三个 `host_ip: "${DNSBLACKHOLE_BIND_ADDRESS_V6:-::}"` 端口项。

浏览器可直接打开 `http://<宿主地址>:3000`。v0.2.5 暂不内置 Web 登录，任何能访问
3000 端口的客户端都能修改 DNS 配置；只应绑定可信内网地址，跨越不可信网络时必须由
反向代理提供 HTTPS 和身份认证。

## 首次配置

需要在新数据卷中应用一份导出的完整配置时，可以使用 `compose.init.yaml`：

```bash
# 从另一套 DnsBlackhole 导出的完整配置放到这里
cp /path/to/exported-config.json docker/bootstrap-config.json

docker compose pull
docker compose -f compose.yaml -f compose.init.yaml up -d --no-build
```

`bootstrap-config` 只在数据卷中尚无 SQLite 数据库时应用；已有数据库时只记录忽略原因，
不覆盖运行配置。不需要导入配置时直接使用基础 `compose.yaml`。

## Linux host network 模式

host 模式通常更容易保留局域网客户端的真实源地址，但会直接占用宿主的 53 和 3000 端口：

```bash
docker compose -f compose.host.yaml pull
docker compose -f compose.host.yaml up -d --no-build
```

宿主原先若有 systemd-resolved stub 或其它 DNS 服务监听 53，必须先由管理员妥善释放。对于使用 systemd-resolved 的宿主，可由管理员关闭 stub listener，并让宿主继续读取 resolved 的非 stub 运行时结果：

```bash
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/disable-stub-for-dnsblackhole-container.conf
sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

这属于宿主部署配置，不由容器自动执行。移除 host 模式后，应按宿主原先的 DNS 管理方式恢复该 drop-in 与 `/etc/resolv.conf`；DnsBlackhole 容器不会停用、修改或恢复这些宿主设置。

VPN/TUN 软件可能安装针对目标端口 53 的策略路由，从而在 bridge DNAT 之后、进入容器 bridge 之前截走 DNS 包。遇到“3000 可访问但 bridge 的 53 超时”时，应先检查宿主 `ip rule`；为对应 bridge 网段添加可信排除规则，或改用 host network，不能在容器里申请 `NET_ADMIN` 绕过宿主策略。

## 数据、健康检查与停止

- SQLite、配置与过滤器缓存保存在命名卷 `dnsblackhole-data`。
- `/run/dnsblackhole` 是带 uid/gid 的 tmpfs，只保存运行时 Unix socket。
- 根文件系统只读；镜像健康检查调用自身的 `healthcheck` 子命令，不依赖 curl 或 shell。
- `docker compose down` 删除容器但保留命名卷；只有显式加 `--volumes` 才会删除数据。
- 容器收到 SIGTERM 后会优雅停止 DNS runtime 并关闭数据库。容器从不声称能够恢复宿主 DNS；如果宿主或路由器已把 DNS 指向该容器，停止前应先把客户端 DNS 改回其它可用解析器。

查看状态与配置：

```bash
docker compose exec dnsblackhole dnsblackhole-service status --json
docker compose exec dnsblackhole dnsblackhole-service config export -
```

## 升级

先把客户端 DNS 临时切到其它可用解析器，再检出新的正式 tag、拉取对应镜像并替换容器：

```bash
git fetch --tags
git checkout v<新版本>
docker compose pull
docker compose up -d --no-build
docker compose ps
```

Compose 会替换容器但继续挂载 `dnsblackhole-data`，配置、查询日志和统计数据会保留。确认 Web、DNS 查询和 healthcheck 正常后再把客户端 DNS 切回。不要使用 `docker compose down --volumes`，该命令会删除数据卷。
