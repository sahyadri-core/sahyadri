#!/bin/bash
# Sahyadri Node Startup Script - All Protocols Enabled

echo "---------------------------------------------------"
echo " Starting Sahyadri Node (Layer 1 Network)"
echo "---------------------------------------------------"
echo " Borsh RPC:  :27110 (Raw Binary Protocol)"
echo " JSON RPC:   :27112 (HTTP JSON Protocol)"  
echo " gRPC:       :27113 (Protobuf/Tonic - FASTEST!)"
echo " P2P:        :26111 (Peer Connection)"
echo " Account State: ENABLED"
echo " Flash Tx:      ENABLED"
echo " Solo Mining:   ENABLED"
echo "---------------------------------------------------"

# Path to the binary 
NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

# Run the node WITH ALL 3 RPC PROTOCOLS
$NODE_BIN \
  --utxoindex \
  --enable-unsynced-mining \
  --enable-flash-tx \
  --rpclisten-borsh=0.0.0.0:27110 \
  --rpclisten-json=0.0.0.0:27112 \
  --rpclisten=0.0.0.0:27113
