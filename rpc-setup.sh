#!/bin/bash
# Sourced by sahyadri.sh / sahyadri-genesis.sh. Builds RPC_FLAGS.
# Secure (TLS + password) is the DEFAULT. Use --no-auth for local demos only.
SECURE="${SAHYADRI_RPC_SECURE:-1}"
for a in "$@"; do [ "$a" = "--no-auth" ] && SECURE=0; done
RPC_DIR="${SAHYADRI_APPDIR:-$HOME/.sahyadri}/sahyadri-mainnet/rpc"
RPC_FLAGS=()

if [ "$SECURE" = "1" ]; then
  mkdir -p "$RPC_DIR"; chmod 700 "$RPC_DIR"

  if [ ! -f "$RPC_DIR/rpc.cert" ] || [ ! -f "$RPC_DIR/rpc.key" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -keyout "$RPC_DIR/rpc.key" -out "$RPC_DIR/rpc.cert" 2>/dev/null
    chmod 600 "$RPC_DIR/rpc.key"
    echo " Created RPC certificate."
  fi

  if [ ! -f "$RPC_DIR/rpc.auth" ]; then
    if [ -t 0 ]; then
      echo " First run: set a password for your node's RPC."
      echo " (Only your own wallet/miner/tools need it. Other nodes never use it.)"
      while true; do
        read -r -s -p " New RPC password (min 8 chars, Enter = generate random): " P1; echo
        if [ -z "$P1" ]; then P1="$(openssl rand -base64 24 | tr -d '=+/')"; echo " Generated a random password."; break; fi
        if [ "${#P1}" -lt 8 ]; then echo " Too short."; continue; fi
        read -r -s -p " Repeat password: " P2; echo
        if [ "$P1" = "$P2" ]; then break; else echo " Passwords do not match."; fi
      done
    else
      P1="$(openssl rand -base64 24 | tr -d '=+/')"   # non-interactive (systemd): auto-generate
    fi
    ( umask 077; printf 'admin:%s\n' "$P1" > "$RPC_DIR/rpc.auth" )
    echo " Password saved in: $RPC_DIR/rpc.auth (readable only by you)"
  fi

  RPC_FLAGS+=(--rpccert="$RPC_DIR/rpc.cert" --rpckey="$RPC_DIR/rpc.key" --rpcauth="$(cat "$RPC_DIR/rpc.auth")")
  echo " RPC: TLS + password ON  (username: admin, password file: $RPC_DIR/rpc.auth)"
else
  echo " RPC: loopback only, NO password (--no-auth). Local demos only."
fi
