#!/bin/sh
# DnsBlackhole Debian prerm
#
# 这里是唯一还能同时用到"服务二进制存在"和"接管状态尚未丢失"的时机：
# postrm purge 阶段二进制已被删除，离线恢复也就跑不了了。
set -e

restore_offline() {
  # daemon 起不来时的兜底。服务仍可连接时该命令会自己拒绝，所以放在 stop 之后。
  if [ -x /usr/lib/dnsblackhole/dnsblackhole-service ]; then
    /usr/lib/dnsblackhole/dnsblackhole-service system-dns restore --offline || true
  fi
}

case "$1" in
  upgrade|deconfigure)
    # 升级/降级：停服务会走 daemon 自身的恢复路径，恢复实际 DNS 但保留 desired，
    # 新版本启动后重新接管。这里不清除接管意图。
    if [ -d /run/systemd/system ]; then
      systemctl stop dnsblackhole.service || true
    fi
    if [ -x /usr/lib/dnsblackhole/dnsblackhole-service ]; then
      /usr/lib/dnsblackhole/dnsblackhole-service system-dns restore --offline --keep-desired || true
    fi
    ;;

  remove)
    # 卸载：先趁服务还活着走在线事务恢复并清除 desired，避免重装后又自动接管
    if [ -x /usr/lib/dnsblackhole/dnsblackhole-service ]; then
      /usr/lib/dnsblackhole/dnsblackhole-service system-dns restore || true
    fi
    if [ -d /run/systemd/system ]; then
      systemctl stop dnsblackhole.service || true
      systemctl disable dnsblackhole.service || true
    fi
    restore_offline
    ;;

  failed-upgrade)
    ;;
esac

exit 0
