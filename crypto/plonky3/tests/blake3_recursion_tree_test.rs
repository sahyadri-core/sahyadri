//! Tree aggregation: 8 single-block Blake3 proofs → 1 root.
//!
//! Level 0: 8 Proof<SahyadriStarkConfig> (one per block)
//! Level 1: 4 aggregate_pair → 4 RecursionOutput
//! Level 2: 2 aggregate_two_batches → 2 RecursionOutput
//! Level 3: 1 aggregate_two_batches → 1 RecursionOutput (root)
//!
//! Run time: ~3-5 min. Scale NUM_BLOCKS to 16, 32, 64.

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

const NUM_BLOCKS: usize = 8;

#[test]
#[ignore]
fn tree_8_blocks() {
    assert!(NUM_BLOCKS.is_power_of_two(), "use power of 2 for clean tree");

    // --- Chain: N blocks, each transitions cv[i] → cv[i+1] ---
    let mut cvs = [[0x11u8; 32]; NUM_BLOCKS + 1];
    let mut blocks = [[0u8; 64]; NUM_BLOCKS];
    for i in 0..NUM_BLOCKS {
        let mut b = [0x22u8; 64];
        b[0] = (i & 0xFF) as u8;
        b[1] = ((i >> 8) & 0xFF) as u8;
        blocks[i] = b;
        cvs[i + 1] = blake3_compress_native(&cvs[i], &blocks[i], 0, 64, 0);
    }

    // --- Level 0: prove each block transition ---
    let t0 = std::time::Instant::now();
    let mut proofs: Vec<Proof<SahyadriStarkConfig>> = Vec::with_capacity(NUM_BLOCKS);
    let mut pis: Vec<Vec<Goldilocks>> = Vec::with_capacity(NUM_BLOCKS);
    for i in 0..NUM_BLOCKS {
        let proof = prove_blake3_block(&cvs[i], &blocks[i], 0, 64, 0, &cvs[i + 1]);
        let pi = pack_public_inputs(&cvs[i], &blocks[i], 0u64, 64u32, 0u32, &cvs[i + 1]);
        proofs.push(proof);
        pis.push(pi);
    }
    println!("LEVEL 0: {} Proof proofs in {:?}", proofs.len(), t0.elapsed());

    // --- Level 1: aggregate_pair (Proof × Proof → RecursionOutput) ---
    let t1 = std::time::Instant::now();
    let air = Blake3BlockAir;
    let mut level1: Vec<RecursionOutput<RecursionConfig>> = Vec::with_capacity(NUM_BLOCKS / 2);
    for i in (0..NUM_BLOCKS).step_by(2) {
        let agg = aggregate_pair(&proofs[i], &pis[i], &proofs[i + 1], &pis[i + 1], &air)
            .expect("aggregate_pair failed");
        level1.push(agg);
    }
    println!("LEVEL 1: {} RecursionOutput in {:?}", level1.len(), t1.elapsed());

    // --- Level 2+: aggregate_two_batches (Output × Output → Output) ---
    let mut level = level1;
    let mut lvl = 2;
    while level.len() > 1 {
        let t = std::time::Instant::now();
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let agg = aggregate_two_batches(&pair[0], &pair[1])
                .expect("aggregate_two_batches failed");
            next.push(agg);
        }
        level = next;
        println!("LEVEL {}: {} RecursionOutput in {:?}", lvl, level.len(), t.elapsed());
        lvl += 1;
    }

    // --- Root ---
    let root = &level[0];
    let t = std::time::Instant::now();
    verify_root_proof(root).expect("root verify failed");
    println!("ROOT VERIFY: {:?}", t.elapsed());

    let size = bincode::serialize(&root.0).expect("serialize root").len();
    println!("\n=== FINAL ===");
    println!("Blocks: {}", NUM_BLOCKS);
    println!("Root proof: {} bytes ({} KB)", size, size / 1024);
    println!("Verify: OK");
}
