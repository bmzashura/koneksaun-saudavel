#!/bin/bash
# Koneksaun Saudavel Full Setup
# Run as: sudo ./setup.sh
# Installs DNS, Web, and Gateway services as ks-user.
#
# Usage on fresh VM:
#   git clone https://github.com/bmzashura/koneksaun-saudavel.git
#   cd koneksaun-saudavel
#   sudo ./deploy/setup.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

KS_USER="ks-user"
APP_DIR="/opt/ks/koneksaun-saudavel"
VENV_PY="${APP_DIR}/venv/bin/python3"
DNS_SVC="/etc/systemd/system/ks-dns.service"
WEB_SVC="/etc/systemd/system/ks-web.service"
GATEWAY_SVC="/etc/systemd/system/ks-gateway.service"

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [ "$EUID" -ne 0 ]; then
    error "Run as: sudo $0"
    exit 1
fi

# Detect source dir — when run via sudo as bmz user,
# HOME=/root so we need explicit path
if [ -d "/home/bmz/koneksaun-saudavel" ]; then
    SRC_DIR="/home/bmz/koneksaun-saudavel"
elif [ -d "${HOME}/koneksaun-saudavel" ]; then
    SRC_DIR="${HOME}/koneksaun-saudavel"
else
    error "Source directory not found"
    exit 1
fi

log "Source: ${SRC_DIR}"
log "Target: ${APP_DIR}"

log "Creating service user '${KS_USER}'..."
if id "$KS_USER" &>/dev/null; then
    log "User ${KS_USER} already exists"
else
    useradd -r -s /usr/sbin/nologin "$KS_USER"
    log "User ${KS_USER} created"
fi

log "Copying application to ${APP_DIR}..."
mkdir -p /opt/ks
rm -rf "${APP_DIR}"
cp -r "${SRC_DIR}" "${APP_DIR}"

log "Creating blocklists subdirectory and moving blocklist files..."
mkdir -p "${APP_DIR}/db/blocklists"
mv "${APP_DIR}"/db/ads.txt "${APP_DIR}"/db/blocklists/ 2>/dev/null || true
mv "${APP_DIR}"/db/porn.txt "${APP_DIR}"/db/blocklists/ 2>/dev/null || true
mv "${APP_DIR}"/db/gambling.txt "${APP_DIR}"/db/blocklists/ 2>/dev/null || true
mv "${APP_DIR}"/db/other.txt "${APP_DIR}"/db/blocklists/ 2>/dev/null || true

log "Creating Python virtual environment..."
cd "${APP_DIR}"
python3 -m venv venv

log "Installing Python dependencies..."
/opt/ks/koneksaun-saudavel/venv/bin/pip install -q -r requirements.txt

log "Initializing database..."
/opt/ks/koneksaun-saudavel/venv/bin/python -c "from app.database import init_db; init_db('db/koneksaun.db')"

log "Creating default admin user..."
/opt/ks/koneksaun-saudavel/venv/bin/python - << 'PYEOF'
import sys
sys.path.insert(0, '/opt/ks/koneksaun-saudavel')
import sqlite3
from app.auth import hash_password

conn = sqlite3.connect('/opt/ks/koneksaun-saudavel/db/koneksaun.db')
cur = conn.cursor()
existing = cur.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
if existing:
    print('admin user already exists — skipping')
else:
    pw_hash, _ = hash_password('admin123')
    cur.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ('admin', pw_hash, 'admin'))
    conn.commit()
    print('admin user created')
conn.close()
PYEOF

log "Setting ownership to ${KS_USER}..."
chown -R "${KS_USER}:${KS_USER}" "${APP_DIR}"

log "Installing ks-dns.service..."
cat > "$DNS_SVC" << EOF
[Unit]
Description=Koneksaun Saudavel DNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${KS_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${VENV_PY} app/dns_server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ks-dns
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

log "Installing ks-web.service..."
cat > "$WEB_SVC" << EOF
[Unit]
Description=Koneksaun Saudavel Web Application
After=network.target

[Service]
Type=simple
User=${KS_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${VENV_PY} -m flask run --host=0.0.0.0 --port=8080
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ks-web

[Install]
WantedBy=multi-user.target
EOF

log "Installing ks-gateway.service (port 80)..."
cat > "$GATEWAY_SVC" << EOF
[Unit]
Description=Koneksaun Saudavel Blocked Domain Gateway
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${VENV_PY} gateway.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ks-gateway

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

log "Enabling and starting services..."
systemctl enable --now ks-dns
systemctl enable --now ks-web
systemctl enable --now ks-gateway

sleep 4

log ""
log "=== Status ==="
for svc in ks-dns ks-web ks-gateway; do
    if systemctl is-active --quiet $svc; then
        echo -e "  $svc: ${GREEN}running${NC} ✅"
    else
        echo -e "  $svc: ${RED}FAILED${NC} ❌"
        journalctl -u $svc -n 5 --no-pager
    fi
done

log ""
log "Ports:"
ss -tlnp | grep -E ':53|:8080|:80' | while read line; do echo "  $line"; done

log ""
log "Services:"
log "  DNS:     sudo systemctl status ks-dns"
log "  Web:     sudo systemctl status ks-web"
log "  Gateway: sudo systemctl status ks-gateway"
log ""
log "Logs:"
log "  DNS:     sudo journalctl -u ks-dns -f"
log "  Web:     sudo journalctl -u ks-web -f"
log "  Gateway: sudo journalctl -u ks-gateway -f"
