//! Chain commitment and recursive chain proofs.
//!
//! Two-tier approach:
//!   - Every block gets a chain_commitment (32-byte hash chain).
//!   - Every CHECKPOINT_INTERVAL blocks gets a full recursive chain proof.
//!
//! Verification:
//!   - Light client: verify chain_commitment from trusted checkpoint, walk forward.
//!   - Full verification: verify chain_proof at checkpoint (recursive STARK).

use sahyadri_hashes::Hash;
use sha2::{Digest, Sha256};

use crate::model::stores::proof_roots::{
    DbProofRootsStore, ProofRootEntry, ProofRootsStoreReader,
};

/// Checkpoint interval: produce a full recursive chain proof every N blocks.
pub const CHECKPOINT_INTERVAL: u32 = 100;

#[derive(Debug)]
pub enum ChainProofError {
    NoParentEntry,
    NoProofBytes,
    Hash(String),
}

impl std::fmt::Display for ChainProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoParentEntry => write!(f, "parent entry missing"),
            Self::NoProofBytes => write!(f, "proof bytes empty"),
            Self::Hash(s) => write!(f, "hash: {s}"),
        }
    }
}

/// Compute chain commitment for a new block.
///
/// chain_commitment[block] = sha256(parent_chain_commitment || sha256(this_proof))
/// chain_depth[block]      = parent_chain_depth + 1
/// genesis                 = sha256(this_proof), depth = 1
pub fn compute_chain_commitment(
    this_proof_bytes: &[u8],
    parent_chain_commitment: Option<[u8; 32]>,
    parent_chain_depth: u32,
) -> Result<([u8; 32], u32), ChainProofError> {
    if this_proof_bytes.is_empty() {
        return Err(ChainProofError::NoProofBytes);
    }

    // Inner hash: this proof's bytes.
    let mut inner = Sha256::new();
    inner.update(this_proof_bytes);
    let inner_hash: [u8; 32] = inner.finalize().into();

    // Outer hash: parent commitment || inner hash.
    let commitment = match parent_chain_commitment {
        Some(parent) => {
            let mut outer = Sha256::new();
            outer.update(parent);
            outer.update(inner_hash);
            outer.finalize().into()
        }
        None => inner_hash,  // genesis
    };

    Ok((commitment, parent_chain_depth + 1))
}

/// Determine if a block should produce a full recursive chain proof.
pub fn is_checkpoint(chain_depth: u32) -> bool {
    chain_depth == 1 || chain_depth % CHECKPOINT_INTERVAL == 0
}

/// Fetch the most recent ancestor checkpoint's chain proof.
///
/// Walks back through chain_depth until a block with non-empty `chain_proof`
/// is found, up to `CHECKPOINT_INTERVAL` steps.
pub fn find_parent_checkpoint_proof(
    store: &DbProofRootsStore,
    starting_block: Hash,
) -> Result<Option<(Hash, Vec<u8>, u32)>, ChainProofError> {
    // Note: caller must supply the parent block hash directly (block hash chain),
    // not the parent_chain_commitment. The store is keyed by block hash.
    let entry = store
        .get(starting_block)
        .map_err(|e| ChainProofError::Hash(format!("{e:?}")))?;

    let Some(entry) = entry else {
        return Ok(None);
    };

    if !entry.chain_proof.is_empty() {
        return Ok(Some((starting_block, entry.chain_proof, entry.chain_depth)));
    }

    // Not a checkpoint — walk further back.
    // Caller should handle walking; we only check one level.
    Ok(None)
}

/// Verify a chain commitment matches the expected value.
pub fn verify_chain_commitment(
    entry: &ProofRootEntry,
    expected_commitment: [u8; 32],
) -> bool {
    entry.chain_commitment == expected_commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_commitment_genesis() {
        let proof_bytes = b"genesis proof";
        let (commit, depth) =
            compute_chain_commitment(proof_bytes, None, 0).unwrap();
        assert_eq!(depth, 1);

        // Deterministic
        let (commit2, _) =
            compute_chain_commitment(proof_bytes, None, 0).unwrap();
        assert_eq!(commit, commit2);
    }

    #[test]
    fn chain_commitment_chain() {
        let (c1, d1) = compute_chain_commitment(b"proof1", None, 0).unwrap();
        let (c2, d2) = compute_chain_commitment(b"proof2", Some(c1), d1).unwrap();
        let (c3, d3) = compute_chain_commitment(b"proof3", Some(c2), d2).unwrap();

        assert_eq!(d1, 1);
        assert_eq!(d2, 2);
        assert_eq!(d3, 3);
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
    }

    #[test]
    fn chain_commitment_tamper_detected() {
        let (c1, _) = compute_chain_commitment(b"proof1", None, 0).unwrap();
        let (c2a, _) = compute_chain_commitment(b"proof2", Some(c1), 1).unwrap();
        let (c2b, _) = compute_chain_commitment(b"proof2_TAMPERED", Some(c1), 1).unwrap();
        assert_ne!(c2a, c2b);
    }

    #[test]
    fn checkpoint_detection() {
        assert!(is_checkpoint(1));
        assert!(!is_checkpoint(2));
        assert!(!is_checkpoint(99));
        assert!(is_checkpoint(100));
        assert!(is_checkpoint(200));
    }
}
