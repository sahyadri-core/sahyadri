//! Async proof-generation service for Sahyadri blocks.
//!
//! Decouples block acceptance (sub-second) from proof generation (10s–90s).
//!
//! # Phase 1 (current)
//!
//! This ships the channel and spawn scaffolding with a generic hash type,
//! so it compiles without pulling consensus-core or consensusmanager
//! internals. The daemon wires the channel; the task drains it.
//!
//! Phase 2 (next session) replaces the no-op drain with:
//!   1. fetch block + per-tx Dilithium proofs
//!   2. aggregate via `sahyadri_plonky3::aggregate_*`
//!   3. serialize `RecursionOutput`
//!   4. `session.async_verify_and_insert_block_proof(...)`
//!
//! Until Phase 2 lands, this crate has **no** consensus dependency.

use tokio::sync::mpsc::{Receiver, Sender};

/// Handle returned by `spawn`. Dropping it aborts the task.
pub struct ProofProverHandle {
    _join: tokio::task::JoinHandle<()>,
}

/// Spawn the proof-prover task.
///
/// `H` is the block-hash type as seen by the caller (typically
/// `sahyadri_consensus_core::blockhash::BlockHash`). We keep it generic
/// to avoid a hard dependency on consensus-core in Phase 1.
pub fn spawn<H>(mut rx: Receiver<H>, _tolerance_blue_score: u64) -> ProofProverHandle
where
    H: Send + std::fmt::Debug + 'static,
{
    let join = tokio::spawn(async move {
        while let Some(hash) = rx.recv().await {
            // Phase 1 no-op: log and continue.
            tracing::debug!(?hash, "proof_prover: received block hash");
        }
    });
    ProofProverHandle { _join: join }
}

/// Channel pair used by the daemon to hand block hashes to the prover.
pub struct ProofProverChannel<H> {
    pub tx: Sender<H>,
    pub handle: ProofProverHandle,
}

/// Convenience constructor: create a bounded channel and spawn the task.
pub fn channel<H>(capacity: usize, tolerance: u64) -> ProofProverChannel<H>
where
    H: Send + std::fmt::Debug + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    let handle = spawn(rx, tolerance);
    ProofProverChannel { tx, handle }
}
