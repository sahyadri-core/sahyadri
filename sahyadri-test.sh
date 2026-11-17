#!/bin/bash
NODE_BIN=~/sahyadri-final/sahyadri/target/release/sahyadrid

$NODE_BIN \
 --testnet \
 --disable-upnp \
 --enable-unsynced-mining \
 --enable-flash-tx \
 --rpclisten-borsh=127.0.0.1:27110 \
 --rpclisten-json=127.0.0.1:27112 \
 --rpclisten=127.0.0.1:27113
