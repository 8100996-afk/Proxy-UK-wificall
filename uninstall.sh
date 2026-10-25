#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "请使用 sudo ./uninstall.sh"; exit 1; fi
read -rp "确认卸载 Proxy UK WiFi Call？输入 DELETE: " answer
[[ $answer == DELETE ]] || exit 1
systemctl disable --now proxy-panel.service proxy-panel-rate-limiter.service proxy-panel-health.timer proxy-panel-traffic.timer wifi-call-health.timer 2>/dev/null || true
rm -f /etc/systemd/system/proxy-panel*.service /etc/systemd/system/proxy-panel*.timer /etc/systemd/system/wifi-call-health.* /etc/sudoers.d/proxy-panel
rm -rf /opt/proxy-panel
read -rp "同时永久删除数据库和全部订阅数据？输入 YES: " purge
[[ $purge == YES ]] && rm -rf /var/lib/proxy-panel /etc/proxy-panel.env
systemctl daemon-reload
echo "卸载完成"

