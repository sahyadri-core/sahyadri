//! SyncWave bootstrap — fast node bootstrap from a peer's state.
//!
//! Reduces fresh-node startup from hours of full IBD to seconds:
//!   1. Connect to a seed peer (gRPC)
//!   2. Fetch SyncWaveMetadata (a few hundred bytes)
//!   3. Download all chunks, reassemble SyncWaveSnapshot
//!   4. Verify: rebuild SMT root locally, compare against checkpoint header
//!   5. Load into local stores (idempotent content-addressed inserts)
//!   6. Resume ordinary IBD from checkpoint forward
//!
//! SyncWave is UNTRUSTED. Any peer may serve; verification is local.

use std::time::Instant;

use sahyadri_consensus::model::sync_wave::SyncWaveExporter;
use sahyadri_consensus_core::api::ConsensusApi;
use sahyadri_consensus_core::model::sync_wave::{SyncWaveChunkWire, SyncWaveSnapshot};
use sahyadri_core::{debug, info};
use sahyadri_grpc_client::GrpcClient;
use sahyadri_hashes::Hash;
use sahyadri_rpc_core::api::rpc::RpcApi;

/// Configuration for a SyncWave bootstrap attempt.
#[derive(Debug, Clone)]
pub struct SyncWaveBootstrapConfig {
    /// Peer gRPC URL, e.g. `grpc://127.0.0.1:16110`.
    pub peer_url: String,
    /// Trusted checkpoint block hash. Required unless `insecure = true`.
    /// Verified against `metadata.block_hash` before any state is loaded.
    pub checkpoint_hash: Option<Hash>,
    /// Optional trusted account root for the checkpoint block. When set,
    /// `metadata.account_root` is verified to match before any state is loaded.
    /// Get it from the archival node's log line at checkpoint height, or from
    /// the checkpoint header returned by a trusted `get_block` RPC.
    pub checkpoint_root: Option<Hash>,
    /// Hard timeout for the entire bootstrap.
    pub timeout_secs: u64,
    /// C-03.2 (SZR-2026-1108 §5.3): bypass all checkpoint anchoring. A
    /// malicious seed in this mode controls the entire loaded ledger.
    /// Allowed only for local development / integration tests.
    pub insecure: bool,
}

impl Default for SyncWaveBootstrapConfig {
    fn default() -> Self {
        Self {
            peer_url: String::new(),
            checkpoint_hash: None,
            checkpoint_root: None,
            timeout_secs: 60,
            insecure: false,
        }
    }
}

#[derive(Debug)]
pub enum SyncWaveBootstrapError {
    Connect(String),
    Rpc(String),
    Timeout,
    Verify(String),
    Load(String),
    /// C-03.2: bootstrap attempted without a trusted checkpoint and without
    /// explicitly opting into insecure mode.
    CheckpointRequired,
    /// C-03.2: peer-supplied checkpoint metadata did not match the trusted
    /// checkpoint hash or trusted account root.
    CheckpointMismatch { expected: Hash, got: Hash },
}

impl std::fmt::Display for SyncWaveBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(s) => write!(f, "connect: {s}"),
            Self::Rpc(s) => write!(f, "rpc: {s}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Verify(s) => write!(f, "verify: {s}"),
            Self::Load(s) => write!(f, "load: {s}"),
            Self::CheckpointRequired => write!(
                f,
                "checkpoint required: pass --sync-wave-checkpoint or set \
                 SAHYADRI_CHECKPOINT_HASH (use SAHYADRI_SYNC_INSECURE=1 only for local testing)"
            ),
            Self::CheckpointMismatch { expected, got } => write!(
                f,
                "checkpoint mismatch: expected {expected}, peer sent {got}"
            ),
        }
    }
}

impl std::error::Error for SyncWaveBootstrapError {}

pub type Result<T> = std::result::Result<T, SyncWaveBootstrapError>;

/// Run a full SyncWave bootstrap against a single peer.
///
/// Returns the verified SyncWave on success — the caller may use it for
/// logging or further inspection. The consensus stores already hold the
/// loaded state by the time this returns.
pub async fn bootstrap_from_peer(
    config: SyncWaveBootstrapConfig,
    consensus: &dyn ConsensusApi,
) -> Result<SyncWaveSnapshot> {
    let t_start = Instant::now();

    // ─── 1. Connect ───
    info!("SyncWave: connecting to peer {}", config.peer_url);
    let client = GrpcClient::connect(config.peer_url.clone())
        .await
        .map_err(|e| SyncWaveBootstrapError::Connect(format!("{e:?}")))?;

    // ─── 2. Metadata ───
    info!("SyncWave: fetching checkpoint metadata");
    let metadata = client
        .get_sync_wave_metadata(config.checkpoint_hash)
        .await
        .map_err(|e| SyncWaveBootstrapError::Rpc(format!("metadata: {e:?}")))?;

    info!(
        "SyncWave: checkpoint block={} height={} smt_nodes={} accounts={} chunks={}",
        metadata.block_hash,
        metadata.block_height,
        metadata.total_smt_nodes,
        metadata.total_accounts,
        metadata.total_chunks
    );

    // ─── 2b. Enforce checkpoint anchoring (C-03.2, SZR-2026-1108 §5.3) ───
    if config.insecure {
        log::warn!(
            "SyncWave: INSECURE mode active — checkpoint hash NOT verified. \
             A malicious seed can inject arbitrary state. Use only for local testing."
        );
    } else {
        let expected_hash = config
            .checkpoint_hash
            .ok_or(SyncWaveBootstrapError::CheckpointRequired)?;
        if metadata.block_hash != expected_hash {
            return Err(SyncWaveBootstrapError::CheckpointMismatch {
                expected: expected_hash,
                got: metadata.block_hash,
            });
        }
        if let Some(expected_root) = config.checkpoint_root {
            if metadata.account_root != expected_root {
                return Err(SyncWaveBootstrapError::CheckpointMismatch {
                    expected: expected_root,
                    got: metadata.account_root,
                });
            }
        }
        log::info!("SyncWave: checkpoint hash verified ✓ (block={})", expected_hash);
        if config.checkpoint_root.is_some() {
            log::info!("SyncWave: account root verified ✓");
        }
    }

    // ─── 3. Download chunks ───
    info!("SyncWave: downloading {} chunks", metadata.total_chunks);
    let mut all_smt_nodes = Vec::with_capacity(metadata.total_smt_nodes as usize);
    let mut all_states = Vec::with_capacity(metadata.total_accounts as usize);
    let mut all_did_states = Vec::with_capacity(metadata.total_did_states as usize);

    for i in 0..metadata.total_chunks {
        let resp = client
            .download_sync_wave_chunk(metadata.block_hash, i)
            .await
            .map_err(|e| SyncWaveBootstrapError::Rpc(format!("chunk {i}: {e:?}")))?;

        let chunk: SyncWaveChunkWire = bincode::deserialize(&resp.data)
            .map_err(|e| SyncWaveBootstrapError::Rpc(format!("chunk {i} deser: {e:?}")))?;

        all_smt_nodes.extend(chunk.smt_nodes);
        all_states.extend(chunk.account_states);
        all_did_states.extend(chunk.did_states);

        if i % 8 == 0 || i + 1 == metadata.total_chunks {
            debug!(
                "SyncWave: {}/{} chunks ({} smt, {} states)",
                i + 1,
                metadata.total_chunks,
                all_smt_nodes.len(),
                all_states.len()
            );
        }
    }

    info!(
        "SyncWave: downloaded {} smt nodes, {} states in {:.2}s",
        all_smt_nodes.len(),
        all_states.len(),
        t_start.elapsed().as_secs_f64()
    );

    // ─── 4. Reassemble + verify ───
    // RPC metadata fields are hex-encoded; convert to core types.
    let core_metadata = sahyadri_consensus_core::model::sync_wave::SyncWaveMetadata {
        block_hash: metadata.block_hash,
        block_height: metadata.block_height,
        account_root: metadata.account_root,
        total_smt_nodes: metadata.total_smt_nodes,
        total_accounts: metadata.total_accounts,
        total_did_states: 0,
        chunk_size: metadata.chunk_size,
        total_chunks: metadata.total_chunks,
    };

    let snapshot = SyncWaveSnapshot {
        metadata: core_metadata,
        smt_nodes: all_smt_nodes,
        account_states: all_states,
        did_states: all_did_states,
    };

    info!("SyncWave: verifying snapshot against checkpoint root");
    SyncWaveExporter::verify(&snapshot)
        .map_err(|e| SyncWaveBootstrapError::Verify(format!("{e:?}")))?;

    // ─── 5. Load ───
    info!("SyncWave: loading into local stores");
    consensus
        .load_sync_wave(&snapshot)
        .map_err(|e| SyncWaveBootstrapError::Load(format!("{e:?}")))?;

    info!(
        "SyncWave: bootstrap complete in {:.2}s (checkpoint={} height={})",
        t_start.elapsed().as_secs_f64(),
        snapshot.metadata.block_hash,
        snapshot.metadata.block_height
    );

    Ok(snapshot)
}
