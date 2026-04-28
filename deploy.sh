#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/ios-rule"
APP_USER="iosrule"

apt update
apt install -y python3 python3-venv python3-pip nginx curl ufw

id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -m -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR"
cp -r . "$APP_DIR/"
cd "$APP_DIR"

python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

mkdir -p data static/cert static/config
[ -f .env ] || cp .env.example .env
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

cp deploy/ios-rule.service /etc/systemd/system/ios-rule.service
systemctl daemon-reload
systemctl enable ios-rule
systemctl restart ios-rule

echo "部署完成。下一步：编辑 $APP_DIR/.env 后执行 systemctl restart ios-rule"
