#!/bin/bash
# Koneksaun Saudavel DNS Service Setup
# Run as: sudo ./setup-dns.sh
# This installs the DNS server as a systemd service.
# Works on: Ubuntu 20.04+, Debian 11+, Raspberry Pi OS

set -e

SERVICE_NAME="ks-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
APP_DIR="${HOME}/koneksaun-saudavel"
VENV_PYTHON="${APP_DIR}/venv/bin/python"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Check root
if [ "$EUID" -ne 0 ]; then
    error "Run as: sudo $0"
    exit 1
fi

# Check venv exists
if [ ! -f "$VENV_PYTHON" ]; then
    error "Virtualenv not found at ${VENV_PYTHON}"
    error "Run installer.sh first, or run: python3 -m venv ${APP_DIR}/venv"
    exit 1
fi

# Check app exists
if [ ! -f "${APP_DIR}/app/dns_server.py" ]; then
    error "dns_server.py not found at ${APP_DIR}/app/dns_server.py"
    exit 1
fi

log "Installing ${SERVICE_NAME} systemd service..."

# Create systemd unit
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Koneksaun Saudavel DNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${VENV_PYTHON} app/dns_server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

# Wait for startup
sleep 3

# Verify
if systemctl is-active --quiet ${SERVICE_NAME}; then
    log "${SERVICE_NAME} is running ✅"
    systemctl status ${SERVICE_NAME} --no-pager | grep -E 'Active:|Main PID:'
else
    error "${SERVICE_NAME} failed to start"
    journalctl -u ${SERVICE_NAME} -n 10 --no-pager
    exit 1
fi

log ""
log "DNS Server: ${SERVICE_NAME}"
log "Status:      sudo systemctl status ${SERVICE_NAME}"
log "Logs:        sudo journalctl -u ${SERVICE_NAME} -f"
log "Restart:     sudo systemctl restart ${SERVICE_NAME}"
log "Stop:        sudo systemctl stop ${SERVICE_NAME}"
log "Uninstall:   sudo ./uninstall-dns.sh"
