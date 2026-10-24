//! Parallel tree aggregation with BOUNDED parallelism at Level 1.
//!
//! Level 1 (aggregate_pair) is memory-heavy: ~2 GB per call.
//! 16 parallel = 32 GB = OOM. Cap at 4.
//! Levels 2+ are lighter, use full thread count.

use rayon::prelude::*;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;
use p3_recursion::recursion::RecursionOutput;

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof, RecursionConfig};
use sahyadri_plonky3::aggregate_cross::aggregate_two_batches;
use sahyadri_plonky3::config::SahyadriStarkConfig;
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};

const NUM_BLOCKS: usize = 32;
const LEVEL1_THREADS: usize = 1;  // Conservative: 2 × 2GB = 4GB

fn main_threads() -> usize {
    rayon::current_num_threads()
}

#[test]
#[ignore]
fn tree_parallel() {
    assert!(NUM_BLOCKS.is_power_of_two());
    println!("\n=== PARALLEL TREE, N={} ===", NUM_BLOCKS);
    println!("main threads: {}, level-1 threads: {}", main_threads(), LEVEL1_THREADS);

    let mut cvs = vec![[0x11u8; 32]; NUM_BLOCKS + 1];
    let mut blocks = vec![[0u8; 64]; NUM_BLOCKS];
    for i in 0..NUM_BLOCKS {
        let mut b = [0x22u8; 64];
        b[0] = (i & 0xFF) as u8;
        b[1] = ((i >> 8) & 0xFF) as u8;
        blocks[i] = b;
        cvs[i + 1] = blake3_compress_native(&cvs[i], &blocks[i], 0, 64, 0);
    }

    // Level 0: leaves (light, full parallel)
    let t = std::time::Instant::now();
    let leaves: Vec<(Proof<SahyadriStarkConfig>, Vec<Goldilocks>)> = (0..NUM_BLOCKS)
        .into_par_iter()
        .map(|i| {
            let p = prove_blake3_block(&cvs[i], &blocks[i], 0, 64, 0, &cvs[i + 1]);
            let pi = pack_public_inputs(&cvs[i], &blocks[i], 0u64, 64u32, 0u32, &cvs[i + 1]);
            (p, pi)
        })
        .collect();
    println!("LEVEL 0 (leaves):       {:>10.2?}  {} proofs", t.elapsed(), leaves.len());

    // Level 1: aggregate_pair (HEAVY) — bounded pool of LEVEL1_THREADS
    let t = std::time::Instant::now();
    let pool1 = rayon::ThreadPoolBuilder::new()
        .num_threads(LEVEL1_THREADS)
        .build()
        .expect("pool1");
    let air = Blake3BlockAir;
    let mut level: Vec<RecursionOutput<RecursionConfig>> = pool1.install(|| {
        leaves
            .par_chunks(2)
            .map(|pair| {
                aggregate_pair(&pair[0].0, &pair[0].1, &pair[1].0, &pair[1].1, &air)
                    .expect("aggregate_pair")
            })
            .collect()
    });
    println!("LEVEL 1 (pair):         {:>10.2?}  {} outputs (threads={})",
             t.elapsed(), level.len(), LEVEL1_THREADS);

    // Levels 2+: light, full parallel
    let mut lvl = 2;
    while level.len() > 1 {
        let t = std::time::Instant::now();
        level = level
            .par_chunks(2)
            .map(|pair| aggregate_two_batches(&pair[0], &pair[1]).expect("aggregate_two_batches"))
            .collect();
        println!("LEVEL {} (batches):      {:>10.2?}  {} outputs", lvl, t.elapsed(), level.len());
        lvl += 1;
    }

    let root = &level[0];
    let t = std::time::Instant::now();
    verify_root_proof(root).expect("root verify");
    let verify_time = t.elapsed();
    let size = bincode::serialize(&root.0).expect("serialize").len();

    println!("\n=== FINAL (N={}) ===", NUM_BLOCKS);
    println!("Root proof:   {} KB", size / 1024);
    println!("Verify:       {:?}  (N-independent)", verify_time);
}
