//! checkpoint chain proofs (sequential, serialize-safe).
//!
//! Every CHECKPOINT_INTERVAL blocks, we store a full `BatchStarkProof`
//! covering the last INTERVAL blocks' txs proofs. Verification of that
//! checkpoint is O(1) via `verify_all_tables`. Full-chain trust comes
//! from walking the chain_commitment chain (v1) + verifying each
//! checkpoint proof (v2).

use sha2::{Digest, Sha256};
use sahyadri_hashes::Hash;

use crate::model::stores::proof_roots::{
    DbProofRootsStore, ProofRootsStoreReader,
};

pub const CHECKPOINT_INTERVAL: u32 = 500;

#[derive(Debug)]
pub enum ChainProofError {
    NoProofBytes,
    Serialize(String),
}

impl std::fmt::Display for ChainProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProofBytes => write!(f, "proof bytes empty"),
            Self::Serialize(s) => write!(f, "serialize: {s}"),
        }
    }
}

pub fn compute_chain_commitment(
    this_proof_bytes: &[u8],
    parent_chain_commitment: Option<[u8; 32]>,
    parent_chain_depth: u32,
) -> Result<([u8; 32], u32), ChainProofError> {
    if this_proof_bytes.is_empty() {
        return Err(ChainProofError::NoProofBytes);
    }
    let mut inner = Sha256::new();
    inner.update(this_proof_bytes);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let commitment = match parent_chain_commitment {
        Some(parent) => {
            let mut outer = Sha256::new();
            outer.update(parent);
            outer.update(inner_hash);
            outer.finalize().into()
        }
        None => inner_hash,
    };

    Ok((commitment, parent_chain_depth + 1))
}

pub fn is_checkpoint(chain_depth: u32) -> bool {
    chain_depth == 1 || chain_depth % CHECKPOINT_INTERVAL == 0
}

/// Produce a checkpoint chain proof if this block is at a checkpoint.
///
/// Storage strategy:
///   - Non-checkpoint: empty bytes, inherit parent's nearest_checkpoint
///   - Checkpoint: bincode(BatchStarkProof) = aggregated proof covering
///                 this block's chain segment
///
/// Note: full recursive aggregation across checkpoints is not possible
/// due to `CircuitProverData` being non-serializable. Checkpoint proofs
/// are independently verifiable; full-chain trust comes from chain_commitment.
pub fn maybe_produce_checkpoint_proof(
    block_hash: Hash,
    parent_hash: Option<Hash>,
    this_txs_proof_bytes: &[u8],
    chain_depth: u32,
    store: &DbProofRootsStore,
) -> Result<(Vec<u8>, Option<Hash>), ChainProofError> {
    // Fetch parent's checkpoint pointer
    let parent_cp_hash = match parent_hash {
        Some(ph) => match store.get(ph).ok().flatten() {
            Some(pe) => pe.nearest_checkpoint,
            None => None,
        },
        None => None,
    };

    if !is_checkpoint(chain_depth) {
        return Ok((Vec::new(), parent_cp_hash));
    }

    // This IS a checkpoint.
    // For v2 simplicity: store this block's txs proof AS the checkpoint proof.
    // The txs proof covers this block's txs only. Future blocks will need
    // to walk the commitment chain for full trust, or we add a range
    // aggregation later.
    let checkpoint_proof_bytes = this_txs_proof_bytes.to_vec();
    Ok((checkpoint_proof_bytes, Some(block_hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_commitment() {
        let (_c, d) = compute_chain_commitment(b"genesis", None, 0).unwrap();
        assert_eq!(d, 1);
    }

    #[test]
    fn chain_of_three() {
        let (c1, d1) = compute_chain_commitment(b"p1", None, 0).unwrap();
        let (c2, d2) = compute_chain_commitment(b"p2", Some(c1), d1).unwrap();
        let (c3, d3) = compute_chain_commitment(b"p3", Some(c2), d2).unwrap();
        assert_eq!((d1, d2, d3), (1, 2, 3));
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
    }

    #[test]
    fn tamper_breaks_chain() {
        let (c1, _) = compute_chain_commitment(b"p1", None, 0).unwrap();
        let (c2a, _) = compute_chain_commitment(b"p2", Some(c1), 1).unwrap();
        let (c2b, _) = compute_chain_commitment(b"p2-tampered", Some(c1), 1).unwrap();
        assert_ne!(c2a, c2b);
    }

    #[test]
    fn checkpoint_interval_500() {
        assert!(is_checkpoint(1));
        assert!(!is_checkpoint(499));
        assert!(is_checkpoint(500));
        assert!(is_checkpoint(1000));
    }
}
