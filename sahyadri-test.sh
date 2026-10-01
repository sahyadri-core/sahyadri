#!/bin/bash
NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

$NODE_BIN \
  --testnet \
  --disable-upnp \
  --enable-unsynced-mining \
  --enable-flash-tx \
  --rpclisten-borsh=0.0.0.0:27110 \
  --rpclisten-json=0.0.0.0:27112 \
  --rpclisten=0.0.0.0:27113
