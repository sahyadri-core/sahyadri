//! Blake3 chain recursive aggregation (Level 0c-5b, proper implementation).
//!
//! Same pattern as E v2 (chain_continuous_test.rs):
//!   1. Prove N single-block Blake3 STARKs
//!   2. aggregate_pair them into BatchStarkProof (level 1 recursion)
//!   3. Wrap in ChainProofBlob
//!   4. Recursive tree from there
//!
//! Uses existing aggregate::aggregate_pair and aggregate_cross::aggregate_two_chain_blobs.

use crate::aggregate::{aggregate_pair, AggregateError};
use crate::aggregate_cross::aggregate_two_chain_blobs;
use crate::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use crate::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};
use crate::smt_stark::chain_blob::ChainProofBlob;

/// Result of recursively proving an N-block Blake3 chain.
pub struct Blake3ChainRecursionProof {
    pub root: ChainProofBlob,
    pub num_blocks: usize,
    pub cv_init: [u8; 32],
    pub cv_final: [u8; 32],
}

/// Prove a Blake3 chain of N blocks via pairwise recursive aggregation.
///
/// Requires N to be a power of 2 (for clean binary tree).
/// Each level aggregates pairs: N → N/2 → N/4 → ... → 1.
pub fn prove_blake3_chain_recursive(
    cv_init: &[u8; 32],
    blocks: &[[u8; 64]],
) -> Result<Blake3ChainRecursionProof, AggregateError> {
    assert!(!blocks.is_empty(), "blocks cannot be empty");
    assert!(
        blocks.len().is_power_of_two(),
        "blocks.len() must be power of 2, got {}",
        blocks.len()
    );

    // Compute chain natively (for cvs)
    let mut cvs = Vec::with_capacity(blocks.len() + 1);
    cvs.push(*cv_init);
    let mut current_cv = *cv_init;
    for block in blocks {
        let next_cv = blake3_compress_native(&current_cv, block, 0, 64, 0);
        cvs.push(next_cv);
        current_cv = next_cv;
    }
    let cv_final = cvs[cvs.len() - 1];

    // Phase 1: Prove each block individually
    let mut proofs = Vec::with_capacity(blocks.len());
    let mut publics = Vec::with_capacity(blocks.len());
    for i in 0..blocks.len() {
        let cv_in = cvs[i];
        let out = cvs[i + 1];
        let proof = prove_blake3_block(&cv_in, &blocks[i], 0, 64, 0, &out);
        let pi = pack_public_inputs(&cv_in, &blocks[i], 0u64, 64u32, 0u32, &out);
        proofs.push(proof);
        publics.push(pi);
    }

    // Phase 2: Aggregate pairs into RecursionOutput (level 1)
    let air = Blake3BlockAir;
    let pairs = blocks.len() / 2;
    let mut level_1: Vec<ChainProofBlob> = Vec::with_capacity(pairs);

    for i in 0..pairs {
        let left = &proofs[i * 2];
        let right = &proofs[i * 2 + 1];
        let left_pi = &publics[i * 2];
        let right_pi = &publics[i * 2 + 1];

        let rec_output = aggregate_pair(left, left_pi, right, right_pi, &air)?;

        // Extract chain commitment from right block's output
        let right_block_idx = i * 2 + 1;
        let right_out_cv = cvs[right_block_idx + 1];
        let mut chain_commitment = [0u8; 32];
        chain_commitment.copy_from_slice(&right_out_cv);

        level_1.push(ChainProofBlob {
            proof: rec_output.0,  // BatchStarkProof — owned, no clone
            chain_depth: 2,
            chain_commitment,
        });
    }

    // Phase 3: Binary tree aggregation of blobs
    let mut current_level = level_1;
    while current_level.len() > 1 {
        let pairs = current_level.len() / 2;
        let mut next_level = Vec::with_capacity(pairs);

        for i in 0..pairs {
            let left = &current_level[i * 2];
            let right = &current_level[i * 2 + 1];
            let merged = aggregate_two_chain_blobs(left, right)?;
            next_level.push(merged);
        }

        current_level = next_level;
    }

    let root = current_level
        .into_iter()
        .next()
        .ok_or_else(|| AggregateError::Config("empty tree".into()))?;

    Ok(Blake3ChainRecursionProof {
        root,
        num_blocks: blocks.len(),
        cv_init: *cv_init,
        cv_final,
    })
}

/// Verify a Blake3 chain recursion proof (constant size, O(1) time).
pub fn verify_blake3_chain_recursive(
    proof: &Blake3ChainRecursionProof,
) -> Result<(), AggregateError> {
    proof
        .root
        .verify()
        .map_err(|e| AggregateError::Recursion(format!("root verify: {e}")))
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]  // Slow test — run with --ignored
    fn recursive_4_blocks() {
        let cv_init = [0x11u8; 32];
        let blocks: Vec<[u8; 64]> = (0..4).map(|i| {
            let mut b = [0x22u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let proof = prove_blake3_chain_recursive(&cv_init, &blocks)
            .expect("recursion should work");

        assert_eq!(proof.num_blocks, 4);
        assert_eq!(proof.cv_init, cv_init);

        verify_blake3_chain_recursive(&proof).expect("root should verify");

        println!("4 blocks recursively aggregated, root verified");
    }

    #[test]
    #[ignore]
    fn recursive_8_blocks() {
        let cv_init = [0x33u8; 32];
        let blocks: Vec<[u8; 64]> = (0..8).map(|i| {
            let mut b = [0x44u8; 64];
            b[0] = i as u8;
            b
        }).collect();

        let proof = prove_blake3_chain_recursive(&cv_init, &blocks)
            .expect("recursion should work");

        verify_blake3_chain_recursive(&proof).expect("root should verify");

        println!("8 blocks recursively aggregated, root verified");
    }
}
