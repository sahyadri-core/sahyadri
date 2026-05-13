<div align="center">
  <img src="https://www.sahyadri.io/img/IMG_3277.png" alt="Sahyadri Logo" width="200"/>
  <h1>Sahyadri on Rust</h1>
  <p><b>High-Performance PoW DAG | Web5 Native | Sovereign Infrastructure</b></p>
</div>

---

Welcome to the official Rust-based implementation of the **Sahyadri Layer 1 Protocol**. Sahyadri is a high-performance, Decentralized Web Node (DWN) integrated, Proof-of-Work (PoW) DAG network.

This repository contains the full-node software, designed for maximum throughput, low latency, and native Web5 sovereign identity integration. Built from the ground up in Rust, this node is optimized for the **Sahyadri Consensus**—delivering extreme scalability without sacrificing decentralization.

## Key Features
 * **High Throughput:** Engineered to handle up to 10,000+ TPS.
 * **Web5 Native:** Built-in support for Decentralized Identifiers (DIDs) and DWN synchronization.
 * **Sovereign Infrastructure:** 21 Million hard-capped supply with a fair-launch, no-premine model.
 * **Quantum Ready:** Future-proof architecture designed for post-quantum security transitions.
## The Genesis Phase
The Sahyadri network is currently in its **Bootstrap/Genesis Phase**. We invite developers, miners, and visionaries to join us in securing the world’s first Web5-native DAG.
> **Note:** Our network architecture is designed for 1-second finality. We are constantly optimizing the DAG topology to reach our 10,000 TPS milestone on consumer-grade hardware.
> 
## Web5 Identity Integration
Unlike traditional L1s, Sahyadri nodes are natively compatible with Decentralized Web Nodes (DWN). 
Every miner and user can link their on-chain CSM address with a W3C-compliant DID (Decentralized Identifier). 
This allows for secure, serverless messaging and data storage directly on the Sahyadri infrastructure.

## Installation
### Building from Source (Recommended)
Building from source ensures you are running the most optimized version for your specific hardware.
**Prerequisites (Linux/Ubuntu):**
```bash
sudo apt update && sudo apt install -y git build-essential cmake pkg-config libssl-dev

```
**Build Commands:**
```bash
# Clone the repository
git clone https://github.com/sahyadri-core/sahyadri.git
cd sahyadri

# Compile the node and miner
cargo build --release

```
##  Running the Node
### Start a Mainnet Node
To start a full-node and begin syncing with the Sahyadri DAG:
```bash
./target/release/sahyadrid --utxoindex

```
### Start a Testnet Node
For developers looking to test integrations or mining setups:
```bash
./target/release/sahyadrid --testnet

```
## Mining on Sahyadri
Sahyadri uses a memory-hard, ASIC-resistant PoW algorithm. To start mining with your CSM address:
```bash
cd sahyadri-miner
./target/release/sahyadri-miner -s 127.0.0.1 -p 26110 -a <YOUR_CSM_ADDRESS> --mine-when-not-synced

```
## wRPC & Integration
Sahyadri provides a high-performance **wRPC (WebSocket RPC)** interface for exchanges, wallets, and explorers.
 * **Default Port:** 26110
 * **Documentation:** Visit sahyadri.io/documentation for the full API reference.

## Contributing
We welcome contributions to the Sahyadri core! Whether it's optimizing the Rust codebase, improving the DAG consensus, or enhancing Web5 integration, your help is vital.
 1. Fork the repo.
 2. Create your feature branch (git checkout -b feature/amazing-feature).
 3. Commit your changes.
 4. Push to the branch.
 5. Open a Pull Request.

## 🔗 Official Links
 * **Website:** https://sahyadri.io
 * **Explorer:** explorer.sahyadri.io (upcoming)
 * **Wallet:** wallet.sahyadri.io (upcoming)
 * **Discord/Telegram:** 
[X: https://x.com/sahyadricore?s=21]
[Discord: https://discord.gg/Dz9NDUwWPe]
</details>
