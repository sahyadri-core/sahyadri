//! Blake3 compression STARK prover + verifier (Level 0b, iteration 3k-3).
//!
//! Uses the existing SahyadriStarkConfig (same as SMT proofs) for maximum
//! compatibility and reuse. Same MMCS, FRI params, Poseidon2 constants.

use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};

use crate::config::{build_stark_config, SahyadriStarkConfig, F};
use crate::sahyadrix_pow::blake3_block::{Blake3BlockAir, build_blake3_block_trace};

#[cfg(test)]
use crate::sahyadrix_pow::blake3_block::blake3_compress_native;

// ═══════════════════════════════════════════════════════════════
// Public inputs packer
// ═══════════════════════════════════════════════════════════════

const TOTAL_COLS: usize = 1685;
const PUBLIC_INPUTS_LEN: usize = 144;

pub fn pack_public_inputs(
    cv: &[u8; 32],
    block: &[u8; 64],
    counter: u64,
    block_len: u32,
    flags: u32,
    output: &[u8; 32],
) -> Vec<F> {
    let mut pi = Vec::with_capacity(PUBLIC_INPUTS_LEN);
    // cv (32 bytes)
    for &b in cv { pi.push(F::new(b as u64)); }
    // block (64 bytes)
    for &b in block { pi.push(F::new(b as u64)); }
    // counter (8 bytes LE)
    for i in 0..8 { pi.push(F::new(((counter >> (i * 8)) & 0xFF) as u64)); }
    // block_len (4 bytes LE)
    for i in 0..4 { pi.push(F::new(((block_len >> (i * 8)) & 0xFF) as u64)); }
    // flags (4 bytes LE)
    for i in 0..4 { pi.push(F::new(((flags >> (i * 8)) & 0xFF) as u64)); }
    // output (32 bytes)
    for &b in output { pi.push(F::new(b as u64)); }
    assert_eq!(pi.len(), PUBLIC_INPUTS_LEN);
    pi
}

// ═══════════════════════════════════════════════════════════════
// Prove + Verify
// ═══════════════════════════════════════════════════════════════

/// Generate a STARK proof for Blake3 compression.
/// Returns the proof struct directly (no serialization — caller decides).
pub fn prove_blake3_block(
    cv: &[u8; 32],
    block: &[u8; 64],
    counter: u64,
    block_len: u32,
    flags: u32,
    output: &[u8; 32],
) -> Proof<SahyadriStarkConfig> {
    let config = build_stark_config();
    let air = Blake3BlockAir;
    let mut trace_flat = build_blake3_block_trace(cv, block, counter, block_len, flags, output);
    // STARK requires power-of-2 rows. Our trace has 58 rows; pad to 64.
    let current_rows = trace_flat.len() / TOTAL_COLS;
    let target_rows = current_rows.next_power_of_two();  // 58 -> 64
    if target_rows > current_rows {
        let padding_rows = target_rows - current_rows;
        // Zero-filled padding rows with is_padding=1 flag (col 1684)
        for _ in 0..padding_rows {
            let mut pad_row = vec![F::new(0u64); TOTAL_COLS];
            pad_row[1684] = F::new(1u64);  // COL_IS_PADDING = 1
            trace_flat.extend_from_slice(&pad_row);
        }
    }
    let trace = RowMajorMatrix::new(trace_flat, TOTAL_COLS);

    let public_inputs = pack_public_inputs(cv, block, counter, block_len, flags, output);

    // prove() returns Result in p3-uni-stark 0.8.0
    prove(&config, &air, trace, &public_inputs).expect("Blake3 block proving failed")
}

/// Verify a STARK proof for Blake3 compression.
pub fn verify_blake3_block(
    proof: &Proof<SahyadriStarkConfig>,
    cv: &[u8; 32],
    block: &[u8; 64],
    counter: u64,
    block_len: u32,
    flags: u32,
    output: &[u8; 32],
) -> bool {
    let config = build_stark_config();
    let air = Blake3BlockAir;
    let public_inputs = pack_public_inputs(cv, block, counter, block_len, flags, output);
    verify(&config, &air, proof, &public_inputs).is_ok()
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_blake3_block() {
        let cv = [0u8; 32];
        let block = [0u8; 64];
        let counter = 0u64;
        let block_len = 64u32;
        let flags = 0u32;
        let expected_out = blake3_compress_native(&cv, &block, counter, block_len, flags);

        let proof = prove_blake3_block(&cv, &block, counter, block_len, flags, &expected_out);
        let ok = verify_blake3_block(&proof, &cv, &block, counter, block_len, flags, &expected_out);
        assert!(ok, "proof should verify");
    }

    #[test]
    fn wrong_output_fails_verify() {
        let cv = [0u8; 32];
        let block = [0u8; 64];
        let expected_out = blake3_compress_native(&cv, &block, 0, 64, 0);

        let proof = prove_blake3_block(&cv, &block, 0, 64, 0, &expected_out);

        let mut wrong_out = expected_out;
        wrong_out[0] ^= 0xFF;
        let ok = verify_blake3_block(&proof, &cv, &block, 0, 64, 0, &wrong_out);
        assert!(!ok, "wrong output should fail");
    }
}
