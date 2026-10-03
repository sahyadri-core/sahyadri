[![CI](https://github.com/sahyadri-core/sahyadri/actions/workflows/ci.yml/badge.svg)](https://github.com/sahyadri-core/sahyadri/actions/workflows/ci.yml)
<div align="center">
  <img src="https://www.sahyadri.io/img/Sahyadri.PNG" alt="Sahyadri Logo" width="200"/>
  <h1>Sahyadri on Rust</h1>
  <p><b>High-Performance PoW DAG | Web5 Native | Sovereign Infrastructure | High TPS | Crest & Account Model | 21 Million Fixed Supply | Post-Quantum Signing</b></p>
</div>

---

Welcome to the official Rust implementation of the **Sahyadri Layer 1 Protocol**. Sahyadri is a high-performance, Decentralized Web Node (DWN) integrated, Proof-of-Work (PoW) DAG network with native post-quantum cryptography.

This repository contains the full-node software, designed for maximum throughput, low latency, and native Web5 sovereign identity integration.

## Key Features

- **High Throughput** — Engineered for 10,000+ TPS on consumer hardware
- **Deterministic Finality** — 1-second block time via Ashwa Consensus
- **Web5 Native** — Built-in support for W3C Decentralized Identifiers (DIDs) and DWN synchronization
- **Account + Crest Model** — Balance-based state with a Sparse Merkle Tree commitment in every block header
- **State Proofs** — Inclusion and exclusion proofs against the committed root, verifiable in under 1 ms
- **SyncWave Bootstrap** — Fresh nodes catch up to the network in seconds, not hours
- **Quantum Ready** — SHA3-256 hashing + ML-DSA-65 (Dilithium3) signatures + cSHAKE256 PoW
- **Sovereign Supply** — 21,000,000 CSM hard cap, no premine, fair launch

## The Genesis Phase

The Sahyadri network is currently in its **Bootstrap/Genesis Phase**. We invite developers, miners, and visionaries to join us in securing the world's first Web5-native DAG.

> **Note:** Network architecture is designed for 1-second finality. DAG topology optimization toward the 10,000 TPS milestone is ongoing.

## Installation

### Building from Source (Recommended)

Building from source ensures you are running the most optimized version for your hardware.

**Prerequisites (Linux/Ubuntu):**

```bash
sudo apt update && sudo apt install -y git build-essential cmake pkg-config libssl-dev
```

**Build:**

```bash
git clone https://github.com/sahyadri-core/sahyadri.git
cd sahyadri
cargo build --release
```

The build produces:

- `target/release/sahyadrid` — the full node
- `target/release/sahyadri-miner` — the mining client (in `sahyadri-miner/`)

## Running a Node

Sahyadri ships with two startup scripts. Choose the one that matches your role.

### Normal User — Fast Sync (Recommended)

```bash
./sahyadri.sh
```

This script:

- Detects whether you have existing chain data.
- **First run (empty data dir):** Attempts SyncWave bootstrap from a public seed — the node catches up to the network tip in seconds, not hours.
- **Subsequent runs:** Uses the local stores; no re-download.
- **Fallback:** If the seed is unreachable, the node falls back to ordinary IBD from genesis.

**Override the seed peer** (optional):

```bash
SAHYADRI_SEED=grpc://my-preferred-seed:27113 ./sahyadri.sh
```

**Default ports:**

| Service | Port |
|---|---|
| gRPC | 27113 |
| wRPC Borsh | 27110 |
| wRPC JSON | 27112 |
| P2P | 26111 |

### Archival Operator — Full History from Genesis

```bash
./sahyadri-genesis.sh
```

This script runs a **full archival node**:

- Retains the entire chain history (no pruning)
- Serves SyncWave snapshots for any historical checkpoint
- Is the backbone of the network — fresh nodes depend on archival nodes for fast bootstrap
- Storage grows over time (100 GB → TBs over years)

**Who should run this:**

- Seed node operators
- Block explorer / indexer backends
- Exchanges with audit requirements
- Anyone who wants to contribute to network resilience

**No permission is required.** Any operator can run an archival node. Three or more archival nodes on different continents provide the resilience the network needs.

### Testnet Node

For developers testing integrations on testnet:

```bash
./target/release/sahyadrid --testnet
```

Testnet uses port suffix conventions (`16210`–`16213`).

## Mining on Sahyadri

Sahyadri uses a memory-hard, ASIC-resistant PoW algorithm (**SahyadriX** — cSHAKE256 + 16 MB memory loop). Mining requires a running full node and a miner client.

**1. Start the node** (in one terminal):

```bash
./sahyadri.sh
```

**2. Start the miner** (in another terminal):

```bash
cd sahyadri-miner
./target/release/sahyadri-miner \
  -s 127.0.0.1 \
  -p 27113 \
  -a <YOUR_CSM_ADDRESS> \
  -t 1 \
  --mine-when-not-synced
```

| Flag | Meaning |
|---|---|
| `-s` | Node host (default: `127.0.0.1`) |
| `-p` | Node gRPC port (mainnet: `27113`, testnet: `16213`) |
| `-a` | Your CSM mining address |
| `-t` | Number of CPU miner threads |
| `--mine-when-not-synced` | Begin mining immediately, do not wait for full sync |

Rewards are credited to your CSM address at 95% of the block subsidy; 5% goes to the Sahyadri Treasury. Transaction fees are split 90% miner / 10% treasury.

## SyncWave — Fast Node Bootstrap

A fresh node does not need to replay the chain from genesis. SyncWave downloads a verified snapshot of account state at a recent checkpoint, cryptographically proves it against the checkpoint header's `account_commitment`, and resumes normal sync from there.

**Measured on a 2-node testnet:** ~10 ms bootstrap for a small state; production-scale networks project to seconds.

**CLI flags** (already applied by `sahyadri.sh` when needed):

```bash
sahyadrid \
  --sync-wave grpc://seed-node:27113 \
  --sync-wave-checkpoint <optional-block-hash>
```

Any full node serves SyncWave on its standard gRPC port. No special configuration is required on the serving side.

Full documentation: [docs.sahyadri.io/sync-wave](https://docs.sahyadri.io/sync-wave)

## State Proofs & Light Clients

Every block header commits to the entire account state through a 32-byte Sparse Merkle Tree root. Light clients can verify any account's balance against a trusted header without holding the full state.

**RPC:**

```bash
get_account_proof(
    address: Address,
    block_hash: Option<Hash>,   # defaults to current tip
)
```

Response contains an inclusion or exclusion proof. Verification is O(depth) hashes — under 1 ms on any device that can run SHA3.

Full documentation: [docs.sahyadri.io/state-proofs](https://docs.sahyadri.io/state-proofs)

## wRPC & Integration

Sahyadri provides a high-performance **wRPC (WebSocket RPC)** interface for exchanges, wallets, and explorers.

- **Borsh wRPC:** `27110`
- **JSON wRPC:** `27112`
- **gRPC:** `27113`
- **Full API reference:** [docs.sahyadri.io](https://docs.sahyadri.io)

## Web5 Identity Integration

Unlike traditional L1s, Sahyadri nodes are natively compatible with Decentralized Web Nodes (DWN). Every miner and user can link their on-chain CSM address with a W3C-compliant DID (Decentralized Identifier). This enables secure, serverless messaging and data storage directly on the Sahyadri infrastructure without state bloat.

Full documentation: [docs.sahyadri.io/did](https://docs.sahyadri.io/did)

## Contributing

We welcome contributions to the Sahyadri core — optimizing the Rust codebase, improving DAG consensus, or enhancing Web5 integration.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Official Links

- **Website:** https://sahyadri.io
- **Docs:** https://docs.sahyadri.io
- **API:** https://api.sahyadri.io
- **Blog:** https://blog.sahyadri.io
- **Explorer:** explorer.sahyadri.io
- **Wallet:** wallet.sahyadri.io *(upcoming)*
- **X (Twitter):** https://x.com/sahyadricore
- **Discord:** https://discord.gg/Dz9NDUwWPe
- **Telegram:** https://t.me/sahyadri
