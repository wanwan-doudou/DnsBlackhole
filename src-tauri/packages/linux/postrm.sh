#!/bin/sh
# DnsBlackhole Debian postrm
#
# 不删除 /var/lib/dnsblackhole：purge 也不静默清掉查询历史与配置，
# 显式清理命令写在 README 的 Linux 卸载说明里。
set -e

case "$1" in
  remove|purge)
    rm -f /usr/bin/dnsblackhole-cli
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
      systemctl reset-failed dnsblackhole.service 2>/dev/null || true
    fi
    ;;
esac

exit 0
