//! chain commitment + recursive chain proofs (E v2).

use sha2::{Digest, Sha256};
use sahyadri_hashes::Hash;

use sahyadri_plonky3::smt_stark::chain_blob::{
    BatchStarkProof, ChainProofBlob, RecursionConfig,
};

use crate::model::stores::proof_roots::{DbProofRootsStore, ProofRootsStoreReader};

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

/// E v2: produce recursive chain proof for this block.
///
/// Skips gracefully for N=1 blocks (proof is not a BatchStarkProof).
pub fn maybe_produce_chain_proof(
    block_hash: Hash,
    parent_hash: Option<Hash>,
    this_txs_proof_bytes: &[u8],
    chain_depth: u32,
    chain_commitment: [u8; 32],
    store: &DbProofRootsStore,
) -> Result<(Vec<u8>, Option<Hash>), ChainProofError> {
    use sahyadri_plonky3::aggregate_cross::aggregate_two_chain_blobs;

    // Deserialize this block's txs proof. If it's not a BatchStarkProof
    // (e.g. N=1 case), skip chain proof silently — v1 chain_commitment
    // still provides tamper protection.
    let this_proof: BatchStarkProof<RecursionConfig> =
        match bincode::deserialize(this_txs_proof_bytes) {
            Ok(p) => p,
            Err(_) => return Ok((Vec::new(), None)),
        };

    let this_blob = ChainProofBlob {
        proof: this_proof,
        chain_depth,
        chain_commitment,
    };

    // Fetch parent chain proof if it exists
    let parent_blob = match parent_hash {
        Some(ph) => match store.get(ph).ok().flatten() {
            Some(pe) if !pe.chain_proof.is_empty() => Some(
                ChainProofBlob::from_bytes(&pe.chain_proof)
                    .map_err(|e| ChainProofError::Serialize(format!("parent blob: {e}")))?,
            ),
            _ => None,
        },
        None => None,
    };

    let combined = match parent_blob {
        Some(parent) => aggregate_two_chain_blobs(&parent, &this_blob)
            .map_err(|e| ChainProofError::Serialize(format!("aggregate: {e}")))?,
        None => this_blob, // Genesis
    };

    Ok((combined.to_bytes(), Some(block_hash)))
}

/// Mark the block's proof as ready (called after async proof lands).
pub fn mark_proof_ready(
    block_hash: Hash,
    store: &DbProofRootsStore,
) -> Result<(), ChainProofError> {
    if let Some(mut entry) = store.get(block_hash)
        .map_err(|e| ChainProofError::Serialize(format!("{e}")))?
    {
        entry.proof_pending = false;
        store.insert_sync(block_hash, &entry)
            .map_err(|e| ChainProofError::Serialize(format!("{e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_commitment() {
        let (c, d) = compute_chain_commitment(b"genesis", None, 0).unwrap();
        assert_eq!(d, 1);
        let _ = c;
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
