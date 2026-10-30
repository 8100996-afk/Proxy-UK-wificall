#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "请使用 sudo ./update.sh"; exit 1; fi
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
set -a; source /etc/proxy-panel.env; set +a
install -d -o root -g root -m 0700 /var/backups/proxy-panel
rsync -a --delete --exclude='.git' --exclude='venv' --exclude='__pycache__' "$PROJECT_DIR/" /opt/proxy-panel/
chown -R root:root /opt/proxy-panel
/opt/proxy-panel/venv/bin/pip install -r /opt/proxy-panel/requirements.txt
for unit in /opt/proxy-panel/deploy/*.service /opt/proxy-panel/deploy/*.timer; do install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"; done
sed -e "s/__PANEL_DOMAIN__/$PANEL_DOMAIN/g" -e "s/__SUB_DOMAIN__/$SUB_DOMAIN/g" -e "s/__NODE_DOMAIN__/$NODE_DOMAIN/g" /opt/proxy-panel/deploy/Caddyfile > /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now proxy-panel-backup.timer
cd /opt/proxy-panel
sudo --preserve-env -u proxy-panel /opt/proxy-panel/venv/bin/python -c 'from proxy_panel.core import init_db,rebuild_xray; init_db(); rebuild_xray()'
systemctl restart proxy-panel proxy-panel-rate-limiter caddy
echo "更新完成"

