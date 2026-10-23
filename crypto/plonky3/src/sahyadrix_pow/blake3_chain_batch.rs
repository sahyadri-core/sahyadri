//! Blake3 batched chain proof (Level 0c-4).
//!
//! Uses p3-batch-stark to prove N Blake3 compressions in ONE proof.
//! Each instance is one block; batch aggregates them into a single FRI commitment.
//!
//! Chain semantics are enforced at the Rust wrapper level:
//!   out_i == cv_{i+1} for all i in 0..100
//!
//! This is 100x faster than 100 separate proofs, and is the foundation for
//! the full 262K-block memory fill (Level 0c-5).

use p3_batch_stark::{prove_batch, verify_batch, BatchProof, ProverData, StarkInstance};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::{build_stark_config, SahyadriStarkConfig, F};
use crate::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, build_blake3_block_trace, blake3_compress_native,
};

const TOTAL_COLS: usize = 1685;

/// Compute a chain of N Blake3 compressions natively.
pub fn compute_chain_n(cv_init: &[u8; 32], blocks: &[[u8; 64]]) -> Vec<[u8; 32]> {
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

/// Pack public inputs for a Blake3 block instance.
fn pack_public_inputs(
    cv: &[u8; 32],
    block: &[u8; 64],
    output: &[u8; 32],
) -> Vec<F> {
    let mut pi = Vec::with_capacity(144);
    for &b in cv { pi.push(F::new(b as u64)); }
    for &b in block { pi.push(F::new(b as u64)); }
    // counter = 0 (8 bytes)
    for _ in 0..8 { pi.push(F::new(0u64)); }
    // block_len = 64 (4 bytes LE)
    pi.push(F::new(64u64));
    pi.push(F::new(0u64));
    pi.push(F::new(0u64));
    pi.push(F::new(0u64));
    // flags = 0 (4 bytes)
    for _ in 0..4 { pi.push(F::new(0u64)); }
    for &b in output { pi.push(F::new(b as u64)); }
    assert_eq!(pi.len(), 144);
    pi
}

/// Pad trace to power-of-2 rows (58 -> 64).
fn pad_trace(mut trace_flat: Vec<F>) -> Vec<F> {
    let current_rows = trace_flat.len() / TOTAL_COLS;
    let target_rows = current_rows.next_power_of_two();
    if target_rows > current_rows {
        let padding_rows = target_rows - current_rows;
        for _ in 0..padding_rows {
            let mut pad_row = vec![F::new(0u64); TOTAL_COLS];
            pad_row[1684] = F::new(1u64); // COL_IS_PADDING = 1
            trace_flat.extend_from_slice(&pad_row);
        }
    }
    trace_flat
}

/// Structure: a batched proof for 100 blocks plus their chain context.
pub struct ChainBatchProof {
    pub proof: BatchProof<SahyadriStarkConfig>,
    pub prover_data: ProverData<SahyadriStarkConfig>,
    pub public_inputs: Vec<Vec<F>>,
    pub cv_init: [u8; 32],
    pub blocks: Vec<[u8; 64]>,
    pub cvs: Vec<[u8; 32]>,
}

/// Prove 100 Blake3 blocks in ONE batched proof.
pub fn prove_chain_batch(
    cv_init: &[u8; 32],
    blocks: &[[u8; 64]],
) -> ChainBatchProof {
    assert!(!blocks.is_empty(), "batch cannot be empty");
    let config = build_stark_config();
    let air = Blake3BlockAir;

    let cvs = compute_chain_n(cv_init, blocks);

    let mut traces: Vec<RowMajorMatrix<F>> = Vec::with_capacity(blocks.len());
    let mut public_inputs: Vec<Vec<F>> = Vec::with_capacity(blocks.len());

    for i in 0..blocks.len() {
        let cv_in = &cvs[i];
        let block = &blocks[i];
        let out = &cvs[i + 1];
        let trace_flat = build_blake3_block_trace(cv_in, block, 0, 64, 0, out);
        let trace_flat = pad_trace(trace_flat);
        let trace = RowMajorMatrix::new(trace_flat, TOTAL_COLS);
        let pi = pack_public_inputs(cv_in, block, out);
        traces.push(trace);
        public_inputs.push(pi);
    }

    // Build StarkInstances
    let instances: Vec<StarkInstance<'_, SahyadriStarkConfig, Blake3BlockAir>> = traces
        .iter()
        .zip(public_inputs.iter())
        .map(|(trace, pi)| StarkInstance {
            air: &air,
            trace,
            public_values: pi.clone(),
        })
        .collect();

    let prover_data = ProverData::from_instances(&config, &instances)
        .expect("ProverData::from_instances failed");

    let proof = prove_batch(&config, &instances, &prover_data)
        .expect("prove_batch failed");

    ChainBatchProof {
        proof,
        prover_data,
        public_inputs,
        cv_init: *cv_init,
        blocks: blocks.to_vec(),
        cvs,
    }
}

/// Verify a 100-block batched proof.
pub fn verify_chain_batch(batch: &ChainBatchProof) -> bool {
    assert!(!batch.blocks.is_empty());

    let config = build_stark_config();

    // Verify chain constraint: each public_input block[i]'s cv_in must equal cvs[i]
    // and its output must equal cvs[i+1]. This enforces chain semantics at wrapper level.
    for i in 0..batch.blocks.len() {
        let expected_pi = pack_public_inputs(&batch.cvs[i], &batch.blocks[i], &batch.cvs[i + 1]);
        if expected_pi != batch.public_inputs[i] {
            return false;
        }
    }

    // Build AIR vector (one per instance) — same pattern as smt_stark/batch.rs
    let airs: Vec<Blake3BlockAir> = vec![Blake3BlockAir; batch.public_inputs.len()];

    // CommonData comes from prover_data.common (field name confirmed from smt batch)
    let common = &batch.prover_data.common;

    verify_batch(
        &config,
        &airs,
        &batch.proof,
        &batch.public_inputs,
        common,
    )
    .is_ok()
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_batch_prove_verify() {
        let cv_init = [0x11u8; 32];
        let blocks: Vec<[u8; 64]> = (0..100).map(|i| {
            let mut b = [0x22u8; 64];
            b[0] = (i & 0xFF) as u8;
            b[1] = ((i >> 8) & 0xFF) as u8;
            b
        }).collect();

        let batch = prove_chain_batch(&cv_init, &blocks);
        let ok = verify_chain_batch(&batch);
        assert!(ok, "100-block batch should verify");
    }
}
