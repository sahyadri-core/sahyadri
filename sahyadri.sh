#!/bin/bash
# Sahyadri Node Startup — Default (SyncWave fast bootstrap)
#
# Fresh-data bootstrap flow:
#   1. Start archival node (sahyadri-genesis.sh), mine blocks
#   2. Get tip hash: sahyadri-cli get_block_hash $(sahyadri-cli get_block_count)
#   3. On new node: export SAHYADRI_SEED=<archival_grpc_url>
#                   export SAHYADRI_CHECKPOINT_HASH=<tip_hash>
#   4. Run ./sahyadri.sh — SyncWave bootstraps in ~2s
#
# Security (C-03, SZR-2026-1108 §5.3):
#   - SAHYADRI_CHECKPOINT_HASH is REQUIRED when SEED is set.
#   - SAHYADRI_CHECKPOINT_ROOT is optional but recommended
#     (get_block(<hash>).header.accountCommitment on archival node).
#   - SAHYADRI_SYNC_INSECURE=1 disables all anchoring — LOCAL TESTING ONLY.

set -euo pipefail

echo "---------------------------------------------------"
echo " Starting Sahyadri Node (SyncWave bootstrap)"
echo "---------------------------------------------------"
echo " gRPC:       :27113"
echo " Borsh RPC:  :27110"
echo " JSON RPC:   :27112"
echo " P2P:        :26111"
echo "---------------------------------------------------"

SEED="${SAHYADRI_SEED:-}"
CHECKPOINT="${SAHYADRI_CHECKPOINT_HASH:-}"
CHECKPOINT_ROOT="${SAHYADRI_CHECKPOINT_ROOT:-}"
INSECURE="${SAHYADRI_SYNC_INSECURE:-0}"
APPDIR="${SAHYADRI_APPDIR:-$HOME/.sahyadri}"

NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

SYNC_FLAGS=()

if [ -n "$SEED" ] && [ ! -d "$APPDIR/sahyadri-mainnet/datadir" ]; then
    echo " Fresh data directory — SyncWave from: $SEED"

    if [ -n "$CHECKPOINT" ]; then
        echo " Checkpoint hash: $CHECKPOINT"
        SYNC_FLAGS+=(--sync-wave "$SEED" --sync-wave-checkpoint "$CHECKPOINT")
        if [ -n "$CHECKPOINT_ROOT" ]; then
            echo " Checkpoint root: $CHECKPOINT_ROOT"
            # Passed via env to daemon; documented here for operator
        fi
    elif [ "$INSECURE" = "1" ] || [ "$INSECURE" = "true" ]; then
        echo ""
        echo " ⚠️  WARNING: SAHYADRI_SYNC_INSECURE=1"
        echo " ⚠️  Checkpoint anchoring DISABLED — malicious seed can inject state."
        echo " ⚠️  Use only for local testing."
        echo ""
        SYNC_FLAGS+=(--sync-wave "$SEED")
    else
        echo ""
        echo " ❌ ERROR: SAHYADRI_SEED is set but SAHYADRI_CHECKPOINT_HASH is missing."
        echo ""
        echo " Get the checkpoint hash from your archival node:"
        echo "   sahyadri-cli get_block_hash \$(sahyadri-cli get_block_count)"
        echo ""
        echo " Then: export SAHYADRI_CHECKPOINT_HASH=<hash>"
        echo ""
        echo " For local testing only: export SAHYADRI_SYNC_INSECURE=1"
        echo ""
        exit 1
    fi
else
    echo " Starting normally (no SyncWave — dir exists or no seed set)"
fi

# Export CHECKPOINT_ROOT so daemon.rs picks it up
if [ -n "$CHECKPOINT_ROOT" ]; then
    export SAHYADRI_CHECKPOINT_ROOT="$CHECKPOINT_ROOT"
fi
if [ "$INSECURE" = "1" ] || [ "$INSECURE" = "true" ]; then
    export SAHYADRI_SYNC_INSECURE=1
fi

# NOTE: --enable-unsynced-mining REMOVED pending audit P1 (M-10).
# Flash (--enable-flash-tx) re-enabled: C-02.5 wires validate_flash_batch
# into BOTH verify_block_state and commit_virtual_state, so committed
# roots and live state stay in sync across all flash outcomes.

exec "$NODE_BIN" \
  --appdir "$APPDIR" \
  "${SYNC_FLAGS[@]}" \
  --enable-flash-tx \
  --nodnsseed \
  --disable-upnp \
  --rpclisten-borsh=127.0.0.1:27110 \
  --rpclisten-json=127.0.0.1:27112 \
  --rpclisten=127.0.0.1:27113
