#!/bin/bash
# Sahyadri Node Startup Script - Solo mainnet (fresh account model)

echo "---------------------------------------------------"
echo " Starting Sahyadri Node (Mainnet Solo)"
echo "---------------------------------------------------"
echo " Borsh RPC:  :27110"
echo " JSON RPC:   :27112"
echo " gRPC:       :27113"
echo " P2P:        :26111"
echo " Account State:       ENABLED"
echo " Account Commitment:  ENABLED (SMT)"
echo " Flash Tx:            ENABLED"
echo " Solo Mining:         ENABLED"
echo "---------------------------------------------------"

NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

$NODE_BIN \
  --reset-db \
  --yes \
  --nodnsseed \
  --disable-upnp \
  --enable-unsynced-mining \
  --enable-flash-tx \
  --rpclisten-borsh=0.0.0.0:27110 \
  --rpclisten-json=0.0.0.0:27112 \
  --rpclisten=0.0.0.0:27113
