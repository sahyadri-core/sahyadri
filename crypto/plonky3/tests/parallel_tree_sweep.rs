//! Parallel tree aggregation with Rayon per level.
//!
//! Memory safety: Level 1 (Proof -> RecursionOutput) allocates heavy backend
//! memory per call, so it uses a bounded thread pool. Levels 2+ are lighter
//! and use the default global pool.

use rayon::prelude::*;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof, RecursionConfig};
use sahyadri_plonky3::aggregate_cross::aggregate_two_batches;
use sahyadri_plonky3::config::SahyadriStarkConfig;
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{Blake3BlockAir, blake3_compress_native};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{prove_blake3_block, pack_public_inputs};
use p3_recursion::recursion::RecursionOutput;

fn run_tree(n: usize, level1_threads: usize) {
    assert!(n.is_power_of_two(), "N must be power of two");
    println!("\n=== N={} (level1_threads={}) ===", n, level1_threads);

    let mut cvs = vec![[0x11u8; 32]; n + 1];
    let mut blocks = vec![[0u8; 64]; n];
    for i in 0..n {
        let mut b = [0x22u8; 64];
        b[0] = (i & 0xFF) as u8;
        b[1] = ((i >> 8) & 0xFF) as u8;
        blocks[i] = b;
        cvs[i + 1] = blake3_compress_native(&cvs[i], &blocks[i], 0, 64, 0);
    }

    // Level 0: prove each block in parallel (lightweight, use default pool)
    let t0 = std::time::Instant::now();
    let proofs: Vec<(Proof<SahyadriStarkConfig>, Vec<Goldilocks>)> = (0..n)
        .into_par_iter()
        .map(|i| {
            let proof = prove_blake3_block(&cvs[i], &blocks[i], 0, 64, 0, &cvs[i + 1]);
            let pi = pack_public_inputs(&cvs[i], &blocks[i], 0u64, 64u32, 0u32, &cvs[i + 1]);
            (proof, pi)
        })
        .collect();
    println!("Level 0 ({} proofs, parallel): {:?}", n, t0.elapsed());

    // Level 1: aggregate_pair with bounded pool (memory bound)
    let t1 = std::time::Instant::now();
    let air = Blake3BlockAir;
    let level1_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(level1_threads)
        .build()
        .expect("thread pool");
    let mut level: Vec<RecursionOutput<RecursionConfig>> = level1_pool.install(|| {
        (0..n / 2)
            .into_par_iter()
            .map(|k| {
                let i = 2 * k;
                aggregate_pair(
                    &proofs[i].0, &proofs[i].1,
                    &proofs[i + 1].0, &proofs[i + 1].1,
                    &air,
                )
                .expect("aggregate_pair failed")
            })
            .collect()
    });
    println!("Level 1 ({} pairs, pool={} threads): {:?}", level.len(), level1_threads, t1.elapsed());

    // Drop Level 0 proofs to free memory before continuing
    drop(proofs);

    // Levels 2+: light, use default pool
    let mut lvl = 2;
    while level.len() > 1 {
        let t = std::time::Instant::now();
        let pairs: Vec<(RecursionOutput<RecursionConfig>, RecursionOutput<RecursionConfig>)> = {
            let mut v = Vec::with_capacity(level.len() / 2);
            let mut it = level.into_iter();
            while let (Some(a), Some(b)) = (it.next(), it.next()) {
                v.push((a, b));
            }
            v
        };
        let next: Vec<RecursionOutput<RecursionConfig>> = pairs
            .into_par_iter()
            .map(|(left, right)| {
                aggregate_two_batches(&left, &right).expect("aggregate_two_batches failed")
            })
            .collect();
        println!("Level {} ({} pairs, parallel): {:?}", lvl, next.len(), t.elapsed());
        level = next;
        lvl += 1;
    }

    let root = &level[0];
    let t = std::time::Instant::now();
    verify_root_proof(root).expect("root verify failed");
    println!("Root verify: {:?}", t.elapsed());

    let size = bincode::serialize(&root.0).expect("serialize").len();
    println!("Root proof size: {} KB", size / 1024);
}

#[test]
#[ignore]
fn parallel_tree_sweep() {
    // Start with N=8 + 2 threads to confirm memory safety
    run_tree(32, 2);
}
