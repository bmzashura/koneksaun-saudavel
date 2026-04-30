#!/bin/bash
# Koneksaun Saudavel Full Setup
# Run as: sudo ./setup.sh
# Installs both DNS and Web services as ks-user (same user for inter-process signaling)

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

KS_USER="ks-user"
APP_DIR="/opt/ks/koneksaun-saudavel"
SRC_DIR="${HOME}/koneksaun-saudavel"
VENV_PY="${APP_DIR}/venv/bin/python3"
DNS_SVC="/etc/systemd/system/ks-dns.service"
WEB_SVC="/etc/systemd/system/ks-web.service"

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [ "$EUID" -ne 0 ]; then
    error "Run as: sudo $0"
    exit 1
fi

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

log "Setting ownership to ${KS_USER}..."
chown -R "${KS_USER}:${KS_USER}" "${APP_DIR}"

log "Fixing ${APP_DIR}/dns.pid path in dns_server.py and reports.py..."
sed -i 's|PID_FILE = Path(__file__).parent.parent / "dns.pid"|PID_FILE = Path("/opt/ks/koneksaun-saudavel/dns.pid")|' "${APP_DIR}/app/dns_server.py"
sed -i 's|pid_file = Path(__file__).parent.parent / "dns.pid"|pid_file = Path("/opt/ks/koneksaun-saudavel/dns.pid")|' "${APP_DIR}/app/reports.py"

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

systemctl daemon-reload

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
log ""
log "User ${KS_USER} created and running both services."
log "dns.pid owned by ${KS_USER} → SIGUSR1 signaling works between DNS and Web."
