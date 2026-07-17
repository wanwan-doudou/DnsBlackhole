#!/usr/bin/env bash
set -euo pipefail

# tauri-build 在编译 sidecar 自身时也会校验 externalBin 文件存在，
# 首次构建前先创建空占位完成自举，构建成功后会被真实产物覆盖
ensure_placeholder() {
  local path="src-tauri/binaries/dnsblackhole-service-$1"
  if [[ ! -f "${path}" ]]; then
    touch "${path}"
  fi
}

build_service() {
  local target="$1"
  ensure_placeholder "${target}"
  cargo build \
    --manifest-path src-tauri/Cargo.toml \
    --release \
    --bin dnsblackhole-service \
    --features macos-service \
    --target "${target}"
}

# daemon 由 launchd 直接拉起，macOS 26 的启动约束要求它与容器应用使用同一签名身份，
# 且标识符必须跨版本稳定——链接器 ad-hoc 签名生成的哈希后缀名不满足要求。
# 必须先签 helper 再由 Tauri 签外层 .app，外层资源封装才会记录最终的 helper 签名。
sign_service() {
  local path="$1"
  local identity="${APPLE_SIGNING_IDENTITY:-}"
  if [[ -z "${identity}" || "${identity}" == "-" ]]; then
    return 0
  fi
  codesign --force --options runtime --timestamp=none \
    --identifier com.dnsblackhole.app.service \
    --sign "${identity}" \
    "${path}"
  codesign --verify --strict "${path}"
}

target="${TAURI_ENV_TARGET_TRIPLE:-${CARGO_BUILD_TARGET:-}}"
if [[ -z "${target}" ]]; then
  target="$(rustc -vV | awk '/^host:/ { print $2 }')"
fi

mkdir -p src-tauri/binaries

case "${target}" in
  aarch64-apple-darwin|x86_64-apple-darwin)
    build_service "${target}"
    cp \
      "src-tauri/target/${target}/release/dnsblackhole-service" \
      "src-tauri/binaries/dnsblackhole-service-${target}"
    sign_service "src-tauri/binaries/dnsblackhole-service-${target}"
    ;;
  universal-apple-darwin)
    # Tauri universal 构建要求 sidecar 也是双架构，分别编译后用 lipo 合成
    build_service aarch64-apple-darwin
    build_service x86_64-apple-darwin
    lipo -create \
      src-tauri/target/aarch64-apple-darwin/release/dnsblackhole-service \
      src-tauri/target/x86_64-apple-darwin/release/dnsblackhole-service \
      -output src-tauri/binaries/dnsblackhole-service-universal-apple-darwin
    lipo -info src-tauri/binaries/dnsblackhole-service-universal-apple-darwin
    sign_service src-tauri/binaries/dnsblackhole-service-universal-apple-darwin
    ;;
  *)
    echo "不支持的 macOS 构建目标：${target}" >&2
    exit 1
    ;;
esac
