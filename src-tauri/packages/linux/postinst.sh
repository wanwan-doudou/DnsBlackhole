#!/bin/sh
# DnsBlackhole Debian postinst
#
# 全新安装只让服务就绪，绝不自动接管系统 DNS——接管意图只由
# /var/lib/dnsblackhole/system-dns-state.json 里的事务状态决定，由用户显式发起。
# 升级时服务重启后会按已保存的 desired 重新核验并接管。
set -e

case "$1" in
  configure)
    chmod 0755 /usr/lib/dnsblackhole/dnsblackhole-service 2>/dev/null || true
    # 本机管理 CLI 只是指向同一个可执行文件的薄入口
    ln -sf /usr/lib/dnsblackhole/dnsblackhole-service /usr/bin/dnsblackhole-cli
    install -d -m 0700 /var/lib/dnsblackhole

    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
      systemctl enable dnsblackhole.service || true
      systemctl restart dnsblackhole.service || true
    fi
    ;;

  abort-upgrade|abort-remove|abort-deconfigure)
    # 幂等：回滚路径只需保证服务能起来，接管状态由 daemon 自己核对
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
      systemctl restart dnsblackhole.service || true
    fi
    ;;
esac

exit 0
