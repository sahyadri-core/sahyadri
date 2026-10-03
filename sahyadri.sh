#!/bin/bash
# Sahyadri Node Startup — Default (SyncWave fast bootstrap)
#
# On first run with an empty data directory, this script attempts to
# bootstrap from a seed peer using SyncWave. If the seed is unreachable
# or SyncWave fails, the node falls back to full IBD from genesis.

echo "---------------------------------------------------"
echo " Starting Sahyadri Node (SyncWave bootstrap)"
echo "---------------------------------------------------"
echo " gRPC:       :27113"
echo " Borsh RPC:  :27110"
echo " JSON RPC:   :27112"
echo " P2P:        :26111"
echo " Mode:       Fast bootstrap via SyncWave"
echo "---------------------------------------------------"

# Seed peer URL — override with SAHYADRI_SEED env var
SEED="${SAHYADRI_SEED:-grpc://seed.sahyadri.io:27113}"

# Data directory — if empty, use SyncWave; else regular startup
APPDIR="${SAHYADRI_APPDIR:-$HOME/.sahyadri}"

NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

if [ -d "$APPDIR/sahyadri-mainnet/datadir" ] && [ "$(ls -A "$APPDIR/sahyadri-mainnet/datadir" 2>/dev/null)" ]; then
    echo " Existing data directory found — starting normally"
    SYNC_FLAG=""
else
    echo " Fresh data directory — will attempt SyncWave from: $SEED"
    SYNC_FLAG="--sync-wave $SEED"
fi

$NODE_BIN \
  --appdir "$APPDIR" \
  $SYNC_FLAG \
  --nodnsseed \
  --disable-upnp \
  --enable-unsynced-mining \
  --enable-flash-tx \
  --rpclisten-borsh=0.0.0.0:27110 \
  --rpclisten-json=0.0.0.0:27112 \
  --rpclisten=0.0.0.0:27113
