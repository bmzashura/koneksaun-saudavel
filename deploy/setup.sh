#!/bin/bash
# Koneksaun Saudavel Full Setup
# Run as: sudo ./setup.sh
# Installs DNS and Web services as ks-user.
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

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [ "$EUID" -ne 0 ]; then
    error "Run as: sudo $0"
    exit 1
fi

# Detect source dir — support multiple deployment paths
if [ -d "/home/ks-user/koneksaun-saudavel" ]; then
    SRC_DIR="/home/ks-user/koneksaun-saudavel"
elif [ -d "/home/bmz/koneksaun-saudavel" ]; then
    SRC_DIR="/home/bmz/koneksaun-saudavel"
elif [ -d "${HOME}/koneksaun-saudavel" ]; then
    SRC_DIR="${HOME}/koneksaun-saudavel"
elif [ -d "$(dirname "$(readlink -f "$0")")/.." ]; then
    SRC_DIR="$(dirname "$(readlink -f "$0")")/.."
else
    error "Source directory not found"
    error "Clone project first: git clone https://github.com/bmzashura/koneksaun-saudavel.git"
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

log "Installing python3-venv package..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
APT_PKG="python3-venv"
if command -v python3.14 &>/dev/null; then
    APT_PKG="python3.14-venv"
elif command -v python3.13 &>/dev/null; then
    APT_PKG="python3.13-venv"
elif command -v python3.12 &>/dev/null; then
    APT_PKG="python3.12-venv"
fi
log "Using apt package: ${APT_PKG}"
apt-get install -y "${APT_PKG}" > /dev/null 2>&1

log "Creating Python virtual environment..."
cd "${APP_DIR}"
python3 -m venv venv

log "Installing Python dependencies..."
/opt/ks/koneksaun-saudavel/venv/bin/pip install -q -r requirements.txt

log "Initializing database..."
/opt/ks/koneksaun-saudavel/venv/bin/python -c "from app.database import init_db; init_db('db/koneksaun.db')"
        log "Running migrations..."
        if [ -f "${APP_DIR}/db/koneksaun.db" ]; then
            bash "${SRC_DIR}/deploy/migrate_add_status.sh" 2>/dev/null || true
            sqlite3 "${APP_DIR}/db/koneksaun.db" < "${SRC_DIR}/deploy/migrate_add_whois_cache.sql" 2>/dev/null || true
        fi

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

log "Setting ownership and executable permission..."
chown -R "${KS_USER}:${KS_USER}" "${APP_DIR}"
chmod +x "${APP_DIR}/deploy/setup.sh" 2>/dev/null || true
chmod +x "${APP_DIR}/app/dns_server.py" 2>/dev/null || true
chmod +x "${APP_DIR}/gateway.py" 2>/dev/null || true
chmod -R u+rw "${APP_DIR}/db" 2>/dev/null || true

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

log "Enabling and starting services..."
systemctl enable --now ks-dns
systemctl enable --now ks-web

sleep 4

log ""
log "=== Status ==="
for svc in ks-dns ks-web; do
    if systemctl is-active --quiet $svc; then
        echo -e "  $svc: ${GREEN}running${NC} ✅"
    else
        echo -e "  $svc: ${RED}FAILED${NC} ❌"
        journalctl -u $svc -n 5 --no-pager
    fi
done

log ""
log "Ports:"
ss -tlnp | grep -E ':53|:8080' | while read line; do echo "  $line"; done

log ""
log "Services:"
log "  DNS:  sudo systemctl status ks-dns"
log "  Web:  sudo systemctl status ks-web"
log ""
log "Logs:"
log "  DNS:  sudo journalctl -u ks-dns -f"
log "  Web:  sudo journalctl -u ks-web -f"
