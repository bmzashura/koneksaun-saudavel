#!/bin/bash
# Koneksaun Saudavel DNS Service Removal
# Run as: sudo ./uninstall-dns.sh

set -e

SERVICE_NAME="ks-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as: sudo $0"
    exit 1
fi

echo "[INFO] Stopping ${SERVICE_NAME}..."
systemctl stop ${SERVICE_NAME} 2>/dev/null || true
systemctl disable ${SERVICE_NAME} 2>/dev/null || true

if [ -f "$SERVICE_FILE" ]; then
    echo "[INFO] Removing $SERVICE_FILE..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
fi

echo "[INFO] ${SERVICE_NAME} removed."
