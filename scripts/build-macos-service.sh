#!/usr/bin/env bash
set -euo pipefail

build_service() {
  local target="$1"
  cargo build \
    --manifest-path src-tauri/Cargo.toml \
    --release \
    --bin dnsblackhole-service \
    --target "${target}"
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
    ;;
  *)
    echo "不支持的 macOS 构建目标：${target}" >&2
    exit 1
    ;;
esac
