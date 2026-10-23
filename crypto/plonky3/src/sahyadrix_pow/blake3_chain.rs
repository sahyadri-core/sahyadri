//! Blake3 chained compression (Level 0c, iteration 1).
//!
//! Proves that two consecutive Blake3 compressions form a valid chain:
//!   output_1 = compress(cv_1, block_1)
//!   output_2 = compress(output_1, block_2)
//!
//! This is the foundational structure for the 16 MB memory fill loop:
//! 262,144 blocks chained together, each output feeding the next input.
//!
//! Iteration 1 scope: 2-block chain via native + STARK proof.
//! Later iterations: recursive composition (prove chain of N blocks in one proof).

use crate::sahyadrix_pow::blake3_block::blake3_compress_native;
use crate::sahyadrix_pow::blake3_prover::{prove_blake3_block, verify_blake3_block};

/// Compute a chained pair of Blake3 compressions.
///
/// Input:
///   - cv0: initial chaining value (32 bytes)
///   - block0: first block (64 bytes)
///   - block1: second block (64 bytes)
///
/// Output:
///   - out0: output of first compression (becomes input cv for second)
///   - out1: output of second compression
///
/// Both out0 and out1 are proved correct via STARK.
pub fn compute_chain(
    cv0: &[u8; 32],
    block0: &[u8; 64],
    block1: &[u8; 64],
) -> ([u8; 32], [u8; 32]) {
    // First compression: cv0 x block0 -> out0
    let out0 = blake3_compress_native(cv0, block0, 0, 64, 0);

    // Second compression: out0 x block1 -> out1
    let out1 = blake3_compress_native(&out0, block1, 0, 64, 0);

    (out0, out1)
}

/// Prove a 2-block chain with two STARK proofs.
///
/// Returns (proof0, proof1) — both proofs together attest to the chain.
pub fn prove_chain_2(
    cv0: &[u8; 32],
    block0: &[u8; 64],
    block1: &[u8; 64],
) -> (Vec<u8>, Vec<u8>) {
    let (out0, out1) = compute_chain(cv0, block0, block1);

    // Proof for first compression
    let proof0 = serialize_proof(&prove_blake3_block(cv0, block0, 0, 64, 0, &out0));

    // Proof for second compression — uses out0 as chaining value
    let proof1 = serialize_proof(&prove_blake3_block(&out0, block1, 0, 64, 0, &out1));

    (proof0, proof1)
}

/// Verify a 2-block chain.
///
/// Verifies both proofs and checks that out0 (from proof0) matches
/// the chaining value used in proof1.
pub fn verify_chain_2(
    proof0: &[u8],
    proof1: &[u8],
    cv0: &[u8; 32],
    block0: &[u8; 64],
    block1: &[u8; 64],
) -> bool {
    let (out0, out1) = compute_chain(cv0, block0, block1);

    // Verify first proof
    let p0 = deserialize_proof(proof0);
    if !verify_blake3_block(&p0, cv0, block0, 0, 64, 0, &out0) {
        return false;
    }

    // Verify second proof — uses out0 as cv
    let p1 = deserialize_proof(proof1);
    if !verify_blake3_block(&p1, &out0, block1, 0, 64, 0, &out1) {
        return false;
    }

    true
}

// ═══════════════════════════════════════════════════════════════
// Serialization (proof <-> bytes)
// ═══════════════════════════════════════════════════════════════

use p3_uni_stark::Proof;
use crate::config::SahyadriStarkConfig;

pub fn serialize_proof(proof: &Proof<SahyadriStarkConfig>) -> Vec<u8> {
    bincode::serialize(proof).expect("proof serialize")
}

pub fn deserialize_proof(bytes: &[u8]) -> Proof<SahyadriStarkConfig> {
    bincode::deserialize(bytes).expect("proof deserialize")
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_chain_native() {
        let cv0 = [0u8; 32];
        let block0 = [1u8; 64];
        let block1 = [2u8; 64];

        let (out0, out1) = compute_chain(&cv0, &block0, &block1);

        // Manually verify via native
        assert_eq!(out0, blake3_compress_native(&cv0, &block0, 0, 64, 0));
        assert_eq!(out1, blake3_compress_native(&out0, &block1, 0, 64, 0));
    }

    #[test]
    fn chain_output_differs_from_single_block() {
        let cv0 = [0u8; 32];
        let block0 = [1u8; 64];
        let block1 = [2u8; 64];

        let (out0, out1) = compute_chain(&cv0, &block0, &block1);
        let single = blake3_compress_native(&cv0, &block0, 0, 64, 0);

        assert_eq!(out0, single);
        assert_ne!(out1, out0);
    }

    #[test]
    fn chain_prover_2_blocks() {
        let cv0 = [0x11u8; 32];
        let block0 = [0x22u8; 64];
        let block1 = [0x33u8; 64];

        let (proof0, proof1) = prove_chain_2(&cv0, &block0, &block1);
        let ok = verify_chain_2(&proof0, &proof1, &cv0, &block0, &block1);
        assert!(ok, "2-block chain should verify");
    }

    #[test]
    fn chain_rejects_wrong_cv() {
        let cv0 = [0x11u8; 32];
        let block0 = [0x22u8; 64];
        let block1 = [0x33u8; 64];

        let (proof0, proof1) = prove_chain_2(&cv0, &block0, &block1);

        // Wrong cv0 → should fail
        let mut wrong_cv = cv0;
        wrong_cv[0] ^= 0xFF;
        let ok = verify_chain_2(&proof0, &proof1, &wrong_cv, &block0, &block1);
        assert!(!ok, "wrong cv should fail");
    }
}
