#!/bin/bash
# ==============================================================================
# CTS ZERO TRUST ENGINE - VPN WATCHER SCRIPT
# ==============================================================================

FLAG_FILE="/opt/docker/CTS_Engine/config/reload.flag"
WG_CONTAINER="cts_wireguard_gateway"

echo "[CTS-WATCHER] Starting watcher on $FLAG_FILE..."

while true; do
    if [ -f "$FLAG_FILE" ]; then
        echo "[CTS-WATCHER] Reload flag detected! Restarting WireGuard container..."
        docker restart "$WG_CONTAINER"
        rm -f "$FLAG_FILE"
        echo "[CTS-WATCHER] Reload complete. Flag cleared."
    fi
    sleep 5
done