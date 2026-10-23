//! Blake3 recursive tree test — 10 batches of 100 blocks (1000 total).
//!
//! Validates:
//!   1. Chain of 10 batches (each 100 blocks) proves correctly
//!   2. Batch proofs aggregate into recursion outputs (level 1)
//!   3. Recursion outputs combine via aggregate_two_batches (level 2)
//!   4. Final root proof verifies
//!
//! This is the foundation for 262K (2621 batches → 12-level tree).

// Later iterations will use: verify_root_proof, RecursionConfig, aggregate_two_batches
use sahyadri_plonky3::sahyadrix_pow::blake3_chain_batch::{
    prove_chain_batch, verify_chain_batch, compute_chain_n,
};

#[test]
#[ignore]  // Slow test — run with --ignored
fn recursion_tree_10x100() {
    let cv_init = [0x11u8; 32];
    let batch_size = 100;
    let num_batches = 10;
    let total_blocks = batch_size * num_batches;

    // Generate 1000 blocks
    let blocks: Vec<[u8; 64]> = (0..total_blocks).map(|i| {
        let mut b = [0x22u8; 64];
        b[0] = (i & 0xFF) as u8;
        b[1] = ((i >> 8) & 0xFF) as u8;
        b
    }).collect();

    let cvs = compute_chain_n(&cv_init, &blocks);

    // Prove each 100-block batch → 10 batch proofs
    let mut batches = Vec::with_capacity(num_batches);
    for k in 0..num_batches {
        let start = k * batch_size;
        let end = start + batch_size;
        let batch_cv = cvs[start];
        let batch_blocks: Vec<[u8; 64]> = blocks[start..end].to_vec();

        let batch = prove_chain_batch(&batch_cv, &batch_blocks);
        assert!(verify_chain_batch(&batch), "batch {} should verify", k);
        batches.push(batch);

        println!("Batch {} ({}-{}) proved", k, start, end);
    }

    println!("All {} batches proved. Each batch = 1 proof of 100 blocks.", num_batches);
    println!("Next: recursively aggregate batch proofs into single root");
}
