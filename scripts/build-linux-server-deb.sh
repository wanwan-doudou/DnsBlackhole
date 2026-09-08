#!/usr/bin/env bash
set -euo pipefail

# Ubuntu Server DEB：只装 headless 服务 + 内嵌 Web 管理后台 + systemd unit + 维护脚本，
# 不依赖 GTK/WebKitGTK。Tauri 的 deb bundler 只会打桌面应用，所以 Server 包用 dpkg-deb 单独打。
# 桌面包与本包声明同一个 dnsblackhole-dns-service，并互相 Conflicts，不能同时安装；
# 切换包时 /var/lib/dnsblackhole 里的数据保持不动。

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

target="${CARGO_BUILD_TARGET:-x86_64-unknown-linux-gnu}"
case "${target}" in
  x86_64-unknown-linux-gnu) deb_arch="amd64" ;;
  *)
    echo "Server DEB 首版只支持 x86_64-unknown-linux-gnu，收到：${target}" >&2
    exit 1
    ;;
esac

version="$(python3 - <<'PY'
import json, pathlib
print(json.loads(pathlib.Path("src-tauri/tauri.conf.json").read_text(encoding="utf-8"))["version"])
PY
)"

if [[ ! -f dist/index.html ]]; then
  echo "缺少 dist/index.html，请先执行 pnpm build" >&2
  exit 1
fi

echo "==> 编译 headless 服务（web-admin 特性）"
cargo build \
  --manifest-path src-tauri/Cargo.toml \
  --locked \
  --release \
  --bin dnsblackhole-service \
  --no-default-features \
  --features web-admin \
  --target "${target}"

binary="src-tauri/target/${target}/release/dnsblackhole-service"

echo "==> 断言产物不链接 GUI 库"
offenders="$(ldd "${binary}" | grep -iE 'webkit2gtk|libgtk-3|libgdk-3|appindicator' || true)"
if [[ -n "${offenders}" ]]; then
  echo "headless 服务意外链接了 GUI 库：" >&2
  echo "${offenders}" >&2
  exit 1
fi

staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT

# mktemp -d 给的是 0700，且 install -d 只设最后一级的权限；包里的目录权限会被 dpkg
# 应用到真实目录上，所以每一级都要显式设成 0755，别把 / 或 /usr 的权限带歪。
chmod 0755 "${staging}"
install -d -m 0755   "${staging}/DEBIAN"   "${staging}/usr"   "${staging}/usr/lib"   "${staging}/usr/lib/dnsblackhole"   "${staging}/usr/lib/systemd"   "${staging}/usr/lib/systemd/system"
install -m 0755 "${binary}" "${staging}/usr/lib/dnsblackhole/dnsblackhole-service"
install -m 0644 src-tauri/packages/linux/dnsblackhole.service \
  "${staging}/usr/lib/systemd/system/dnsblackhole.service"

# 维护脚本与桌面包共用同一份，避免两套生命周期语义
for script in postinst prerm postrm; do
  install -m 0755 "src-tauri/packages/linux/${script}.sh" "${staging}/DEBIAN/${script}"
done

installed_size="$(du -sk "${staging}/usr" | cut -f1)"

cat > "${staging}/DEBIAN/control" <<CONTROL
Package: dnsblackhole-server
Version: ${version}
Section: net
Priority: optional
Architecture: ${deb_arch}
Maintainer: DnsBlackhole Maintainers <noreply@dnsblackhole.local>
Installed-Size: ${installed_size}
Depends: systemd
Provides: dnsblackhole-dns-service
Conflicts: dnsblackhole
Replaces: dnsblackhole
Description: DnsBlackhole DNS 过滤服务（无图形界面）
 以 systemd 服务形式运行的 DNS 过滤与拦截核心，自带同源的 Web 管理后台，
 默认监听 0.0.0.0:3000，不依赖 GTK 或 WebKitGTK。
 本版不内置 Web 登录，请只在可信内网开放 3000 端口。
 安装后服务自动启动，但不会自动接管宿主 DNS，需要在 Web 后台或用
 sudo dnsblackhole-cli system-dns takeover 显式发起。
CONTROL

# 包里不带 conffiles：数据目录与运行时状态由 systemd 的 StateDirectory 和 postinst 创建

output_dir="dist-linux"
install -d -m 0755 "${output_dir}"
package="${output_dir}/dnsblackhole-server_${version}_${deb_arch}.deb"

echo "==> 打包 ${package}"
dpkg-deb --root-owner-group --build "${staging}" "${package}" >/dev/null

echo "==> 包内容"
dpkg-deb --contents "${package}"
echo "==> 控制信息"
dpkg-deb --info "${package}"
echo "已生成 ${package}"
