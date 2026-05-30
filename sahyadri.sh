#!/bin/bash
# Sahyadri Node Startup Script - Unique Identity Version

echo "---------------------------------------------------"
echo " Starting Sahyadri Node (Layer 1 Network)"
echo " gRPC Port: 26110 (Miner)"
echo " wRPC Port: 27110 (CLI/Indexer)"
echo " P2P Port:  26111 (Node Connection)"
echo " Account State: ENABLED"
echo " Solo Mining: ENABLED"
echo "---------------------------------------------------"

# Path to the binary 
NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

# Run the node
$NODE_BIN --utxoindex --archival --rpclisten-borsh=0.0.0.0:27110 --rpclisten-json=0.0.0.0:27112
