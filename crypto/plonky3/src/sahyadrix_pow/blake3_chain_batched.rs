//! Blake3 batched chain (Level 0c-3, iteration 1).
//!
//! Proves a chain of N Blake3 compressions:
//!   cv_0 -> block_0 -> cv_1 -> block_1 -> cv_2 -> ... -> cv_N
//!
//! Each step's output is the next step's chaining value.
//! Generates N STARK proofs, verifies all of them.
//!
//! Iteration 1: N=10 blocks (test scale).
//! Iteration 2+: N=100, N=1000, N=262144 (full memory fill).
//! Requires batching/recursive aggregation for N > 100.

use crate::sahyadrix_pow::blake3_block::blake3_compress_native;
use crate::sahyadrix_pow::blake3_prover::{prove_blake3_block, verify_blake3_block};
use crate::sahyadrix_pow::blake3_chain::{serialize_proof, deserialize_proof};

/// Compute a chain of N Blake3 compressions natively.
///
/// Returns all intermediate chaining values (cv_0 through cv_N).
pub fn compute_chain_n(
    cv_init: &[u8; 32],
    blocks: &[[u8; 64]],
) -> Vec<[u8; 32]> {
    let mut cvs = Vec::with_capacity(blocks.len() + 1);
    cvs.push(*cv_init);

    let mut current_cv = *cv_init;
    for block in blocks {
        let next_cv = blake3_compress_native(&current_cv, block, 0, 64, 0);
        cvs.push(next_cv);
        current_cv = next_cv;
    }

    cvs
}

/// Prove an N-block chain.
///
/// Returns N serialized proofs (one per block).
pub fn prove_chain_n(
    cv_init: &[u8; 32],
    blocks: &[[u8; 64]],
) -> Vec<Vec<u8>> {
    let cvs = compute_chain_n(cv_init, blocks);
    let mut proofs = Vec::with_capacity(blocks.len());

    for i in 0..blocks.len() {
        let cv_in = &cvs[i];
        let block = &blocks[i];
        let out = &cvs[i + 1];

        let proof = prove_blake3_block(cv_in, block, 0, 64, 0, out);
        proofs.push(serialize_proof(&proof));
    }

    proofs
}

/// Verify an N-block chain.
///
/// Verifies all N proofs, and checks each proof's output feeds the next's input.
pub fn verify_chain_n(
    proofs: &[Vec<u8>],
    cv_init: &[u8; 32],
    blocks: &[[u8; 64]],
) -> bool {
    if proofs.len() != blocks.len() {
        return false;
    }

    let cvs = compute_chain_n(cv_init, blocks);

    for i in 0..blocks.len() {
        let cv_in = &cvs[i];
        let block = &blocks[i];
        let out = &cvs[i + 1];

        let p = deserialize_proof(&proofs[i]);
        if !verify_blake3_block(&p, cv_in, block, 0, 64, 0, out) {
            return false;
        }
    }

    true
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_chain_5_native() {
        let cv_init = [0x00u8; 32];
        let blocks: Vec<[u8; 64]> = (0..5).map(|i| {
            let mut b = [0u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let cvs = compute_chain_n(&cv_init, &blocks);
        assert_eq!(cvs.len(), 6); // cv_0 ... cv_5
        assert_eq!(cvs[0], cv_init);

        // Manual verification
        let mut expected_cv = cv_init;
        for block in &blocks {
            expected_cv = blake3_compress_native(&expected_cv, block, 0, 64, 0);
        }
        assert_eq!(cvs[5], expected_cv);
    }

    #[test]
    fn chain_10_prove_verify() {
        let cv_init = [0x11u8; 32];
        let blocks: Vec<[u8; 64]> = (0..10).map(|i| {
            let mut b = [0x22u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let proofs = prove_chain_n(&cv_init, &blocks);
        assert_eq!(proofs.len(), 10);

        let ok = verify_chain_n(&proofs, &cv_init, &blocks);
        assert!(ok, "10-block chain should verify");
    }

    #[test]
    fn chain_rejects_wrong_block() {
        let cv_init = [0x33u8; 32];
        let blocks: Vec<[u8; 64]> = (0..5).map(|i| {
            let mut b = [0x44u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let proofs = prove_chain_n(&cv_init, &blocks);

        // Tamper: wrong block
        let mut wrong_blocks = blocks.clone();
        wrong_blocks[2][0] ^= 0xFF;

        let ok = verify_chain_n(&proofs, &cv_init, &wrong_blocks);
        assert!(!ok, "tampered block should fail");
    }

    #[test]
    fn chain_rejects_wrong_cv() {
        let cv_init = [0x55u8; 32];
        let blocks: Vec<[u8; 64]> = (0..5).map(|i| {
            let mut b = [0x66u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let proofs = prove_chain_n(&cv_init, &blocks);

        // Tamper: wrong initial cv
        let mut wrong_cv = cv_init;
        wrong_cv[0] ^= 0xFF;

        let ok = verify_chain_n(&proofs, &wrong_cv, &blocks);
        assert!(!ok, "tampered cv should fail");
    }
}
