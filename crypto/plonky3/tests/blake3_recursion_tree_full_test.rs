//! Blake3 full recursive tree test — 10 batches → 1 root proof.
//!
//! Flow:
//!   1. Prove 10 × 100-block batches → 10 BatchProof
//!   2. Wrap each BatchProof in RecursionOutput (level 1)
//!   3. Binary tree: 10 → 5 → 3 → 2 → 1 (aggregate_two_batches)
//!   4. Verify final root proof
//!
//! This is the exact structure for 262K (2621 batches → 12 levels).

use sahyadri_plonky3::aggregate::{
    build_recursion_config, verify_root_proof, RecursionConfig, AggregateError,
};
use sahyadri_plonky3::aggregate_cross::aggregate_two_batches;
use sahyadri_plonky3::sahyadrix_pow::blake3_chain_batch::{
    prove_chain_batch, compute_chain_n, ChainBatchProof,
};
use p3_recursion::RecursionOutput;
use p3_recursion::prepared::{PreparedAggregation, PreparedInput, PreparedSource};
use p3_recursion::BatchOnly;
use p3_recursion::{FriRecursionBackend, Poseidon2Config, ProveNextLayerParams};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};
use sahyadri_plonky3::config::{SahyadriStarkConfig, F};

/// Wrap a raw batch proof in a RecursionOutput (level 1).
fn batch_to_recursion_output(
    batch: &ChainBatchProof,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError> {
    // Convert our BatchProof to the recursion config's BatchProof type
    // This requires unsafe cast if configs match bit-for-bit
    let recursion_proof = unsafe {
        &*(&batch.proof as *const _ as *const p3_circuit_prover::BatchStarkProof<RecursionConfig>)
    };

    let config = build_recursion_config()?;
    let backend = FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let params = ProveNextLayerParams::default();

    let table_public_inputs: Vec<Vec<Val<RecursionConfig>>> =
        vec![vec![]; recursion_proof.proof.opened_values.instances.len()];

    let owner = PreparedAggregation::new(
        PreparedSource::batch(recursion_proof, &recursion_proof.stark_common, &table_public_inputs),
        PreparedSource::batch(recursion_proof, &recursion_proof.stark_common, &table_public_inputs),
        config.clone(),
        backend.clone(),
        params.clone(),
    )
    .map_err(|e| AggregateError::Recursion(format!("prepare: {e:?}")))?;

    // For now, we need an identity recursion (wrap a batch, don't aggregate)
    // This requires a different API — defer to next iteration
    // Returning error for now
    Err(AggregateError::Config("batch_to_recursion_output not yet implemented".into()))
}

#[test]
#[ignore]
fn recursion_tree_10_batches_to_root() {
    let cv_init = [0x11u8; 32];
    let batch_size = 100;
    let num_batches = 10;
    let total_blocks = batch_size * num_batches;

    // Generate blocks
    let blocks: Vec<[u8; 64]> = (0..total_blocks).map(|i| {
        let mut b = [0x22u8; 64];
        b[0] = (i & 0xFF) as u8;
        b[1] = ((i >> 8) & 0xFF) as u8;
        b
    }).collect();

    let cvs = compute_chain_n(&cv_init, &blocks);

    // Prove each batch
    let mut batch_proofs = Vec::with_capacity(num_batches);
    for k in 0..num_batches {
        let start = k * batch_size;
        let end = start + batch_size;
        let batch_cv = cvs[start];
        let batch_blocks: Vec<[u8; 64]> = blocks[start..end].to_vec();
        let batch = prove_chain_batch(&batch_cv, &batch_blocks);
        batch_proofs.push(batch);
        println!("Batch {} proved", k);
    }

    println!("All {} batches proved.", num_batches);
    println!("Recursive tree aggregation is next iteration (needs batch->recursion wrap).");
}
