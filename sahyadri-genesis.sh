#!/bin/bash
# Sahyadri Archival Node — Full IBD, retain all history
set -euo pipefail

echo "---------------------------------------------------"
echo " Starting Sahyadri Archival Node (Full IBD)"
echo "---------------------------------------------------"
echo " gRPC: :27113"
echo " Borsh RPC: :27110"
echo " JSON RPC: :27112"
echo " P2P: :26111"
echo " Mode: Archival — full chain history retained"
echo "---------------------------------------------------"

APPDIR="${SAHYADRI_APPDIR:-$HOME/.sahyadri}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_BIN="$SCRIPT_DIR/target/release/sahyadrid"

source "$(dirname "$0")/rpc-setup.sh" "$@"

exec "$NODE_BIN" \
 --appdir "$APPDIR" \
 --archival \
 "${RPC_FLAGS[@]}" \
 --enable-flash-tx \
 --nodnsseed \
 --disable-upnp \
 --rpclisten-borsh=127.0.0.1:27110 \
 --rpclisten-json=127.0.0.1:27112 \
 --rpclisten=127.0.0.1:27113
