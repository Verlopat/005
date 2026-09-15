#!/usr/bin/env bash
# Tears down the network and removes generated crypto material and
# channel artifacts, so network-up.sh can be re-run cleanly.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(dirname "$HERE")"
cd "$NETWORK_DIR"

echo "[*] Stopping and removing containers/volumes ..."
docker compose -f docker-compose.yaml down --volumes

echo "[*] Removing generated crypto material and channel artifacts ..."
rm -rf crypto-config network-artifacts

echo "[ok] Network torn down."
