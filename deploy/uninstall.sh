#!/bin/bash
# Koneksaun Saudavel Full Service Removal (DNS, Web, Gateway)
# Run as: sudo bash deploy/uninstall.sh

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as: sudo $0"
    exit 1
fi

SERVICES=("ks-dns" "ks-web" "ks-gateway")

for SVC in "${SERVICES[@]}"; do
    SVC_FILE="/etc/systemd/system/${SVC}.service"
    if systemctl list-unit-files | grep -q "${SVC}.service"; then
        echo "[INFO] Stopping and disabling ${SVC}..."
        systemctl stop "${SVC}" 2>/dev/null || true
        systemctl disable "${SVC}" 2>/dev/null || true
    fi
    if [ -f "$SVC_FILE" ]; then
        echo "[INFO] Removing ${SVC_FILE}..."
        rm -f "$SVC_FILE"
    fi
done

systemctl daemon-reload
echo "[INFO] Koneksaun Saudavel services stopped and removed successfully."
