#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "请使用 root 运行：sudo ./install.sh"
  exit 1
fi

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
read -rp "后台域名（如 panel.example.com）: " PANEL_DOMAIN
read -rp "订阅域名（如 sub.example.com）: " SUB_DOMAIN
read -rp "节点域名（如 node.example.com）: " NODE_DOMAIN
read -rsp "后台管理员密码（留空自动生成）: " ADMIN_PASSWORD
echo

for value in "$PANEL_DOMAIN" "$SUB_DOMAIN" "$NODE_DOMAIN"; do
  if [[ ! $value =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    echo "域名格式不正确：$value"
    exit 1
  fi
done

if [[ -z $ADMIN_PASSWORD ]]; then
  ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y caddy curl ca-certificates rsync python3 python3-venv sudo sqlite3 ike-scan openssl

if [[ ! -x /usr/local/bin/xray ]]; then
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
fi

id proxy-panel >/dev/null 2>&1 || useradd --system --home /opt/proxy-panel --shell /usr/sbin/nologin proxy-panel
install -d -o proxy-panel -g proxy-panel -m 0750 /var/lib/proxy-panel
install -d -o root -g proxy-panel -m 0775 /usr/local/etc/xray
install -d -o root -g root -m 0755 /opt/proxy-panel
rsync -a --delete --exclude='.git' --exclude='venv' --exclude='__pycache__' "$PROJECT_DIR/" /opt/proxy-panel/
chown -R root:root /opt/proxy-panel

python3 -m venv /opt/proxy-panel/venv
/opt/proxy-panel/venv/bin/pip install --upgrade pip
/opt/proxy-panel/venv/bin/pip install -r /opt/proxy-panel/requirements.txt

FERNET_KEY=$(/opt/proxy-panel/venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
SESSION_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD_HASH=$(ADMIN_PASSWORD="$ADMIN_PASSWORD" /opt/proxy-panel/venv/bin/python -c 'import os; from werkzeug.security import generate_password_hash; print(generate_password_hash(os.environ["ADMIN_PASSWORD"]))')

install -m 0600 /dev/null /etc/proxy-panel.env
{
  echo "PANEL_DOMAIN=$PANEL_DOMAIN"
  echo "SUB_DOMAIN=$SUB_DOMAIN"
  echo "NODE_DOMAIN=$NODE_DOMAIN"
  echo "SUB_BASE_URL=https://$SUB_DOMAIN"
  echo "PANEL_DATA_DIR=/var/lib/proxy-panel"
  echo "XRAY_CONFIG=/usr/local/etc/xray/config.json"
  echo "SESSION_SECRET=$SESSION_SECRET"
  echo "FERNET_KEY=$FERNET_KEY"
  echo "ADMIN_PASSWORD_HASH=$ADMIN_PASSWORD_HASH"
} > /etc/proxy-panel.env

for unit in /opt/proxy-panel/deploy/*.service /opt/proxy-panel/deploy/*.timer; do
  install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
install -o root -g root -m 0440 /opt/proxy-panel/deploy/proxy-panel.sudoers /etc/sudoers.d/proxy-panel
visudo -cf /etc/sudoers.d/proxy-panel
install -o root -g root -m 0644 /opt/proxy-panel/deploy/99-proxy-performance.conf /etc/sysctl.d/99-proxy-performance.conf
sysctl --system >/dev/null

sed -e "s/__PANEL_DOMAIN__/$PANEL_DOMAIN/g" -e "s/__SUB_DOMAIN__/$SUB_DOMAIN/g" -e "s/__NODE_DOMAIN__/$NODE_DOMAIN/g" /opt/proxy-panel/deploy/Caddyfile > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable --now xray caddy proxy-panel-rate-limiter.service proxy-panel.service
systemctl enable --now proxy-panel-health.timer proxy-panel-traffic.timer wifi-call-health.timer

set -a
source /etc/proxy-panel.env
set +a
cd /opt/proxy-panel
sudo --preserve-env -u proxy-panel /opt/proxy-panel/venv/bin/python -c 'from proxy_panel.core import init_db,rebuild_xray; init_db(); rebuild_xray()'
systemctl restart proxy-panel caddy

echo
echo "安装完成"
echo "后台：https://$PANEL_DOMAIN"
echo "兑换：https://$SUB_DOMAIN/redeem"
echo "管理员密码：$ADMIN_PASSWORD"
echo "请妥善保存密码，并确保三个域名的 DNS 已指向本机。"

