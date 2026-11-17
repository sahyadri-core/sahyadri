#!/bin/bash
# Generates a self-signed TLS certificate for RPC.
# Usage: ./gen-rpc-cert.sh [network]   (default: mainnet)
NET="${1:-mainnet}"
DIR="$HOME/.sahyadri/sahyadri-${NET}/rpc"
mkdir -p "$DIR"

if [ -f "$DIR/rpc.cert" ] && [ -f "$DIR/rpc.key" ]; then
  echo "Cert already exists at $DIR/rpc.cert"
  exit 0
fi

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$DIR/rpc.key" \
  -out "$DIR/rpc.cert" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>&1

if [ $? -eq 0 ]; then
  echo "Done. Add to your .sh script for mainnet:"
  echo "  --rpccert=$DIR/rpc.cert --rpckey=$DIR/rpc.key --rpcauth=admin:CHANGE_THIS"
else
  echo "Failed. Is openssl installed?"
  exit 1
fi
