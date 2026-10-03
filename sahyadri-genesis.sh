#!/bin/bash
# Sahyadri Archival Node Startup — Full IBD from Genesis
#
# Use this script to run a full archival node. It retains complete
# chain history and serves SyncWave snapshots for any checkpoint.
# No bootstrap; builds state from genesis.

echo "---------------------------------------------------"
echo " Starting Sahyadri Archival Node (Full IBD)"
echo "---------------------------------------------------"
echo " gRPC:       :27113"
echo " Borsh RPC:  :27110"
echo " JSON RPC:   :27112"
echo " P2P:        :26111"
echo " Mode:       Archival — full chain history retained"
echo "---------------------------------------------------"

NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

$NODE_BIN \
  --appdir "$HOME/.sahyadri" \
  --archival \
  --nodnsseed \
  --disable-upnp \
  --enable-unsynced-mining \
  --enable-flash-tx \
  --rpclisten-borsh=0.0.0.0:27110 \
  --rpclisten-json=0.0.0.0:27112 \
  --rpclisten=0.0.0.0:27113
