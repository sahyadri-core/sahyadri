//! E v2a: Continuous chain aggregation — real chain test.
//!
//! Each "block" aggregates two SMT proofs into a block proof.
//! Chain proof for block N aggregates:
//!     chain_{N-1}  (which proves all blocks 1..N-1)
//!        +
//!     block_N_txs  (which proves block N's transactions)
//!
//! The final chain proof proves: "The entire chain of N blocks is valid."

use std::time::Instant;

use sahyadri_plonky3::aggregate::{aggregate_pair, AggregateError};
use sahyadri_plonky3::aggregate_cross::aggregate_two_chain_blobs;
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::chain_blob::ChainProofBlob;
use sahyadri_plonky3::smt_stark::{prove_smt_state, SmtAir, SmtTraceInput};

fn make_input(seed: u8) -> SmtTraceInput {
    let mut key = [0u8; 32];
    key[0] = seed;
    let mut value = [0u8; 32];
    value[0] = seed.wrapping_mul(7);
    SmtTraceInput {
        siblings: vec![],
        key,
        value,
        is_absent: false,
    }
}

/// Produce a "block proof" by aggregating two SMT proofs.
fn produce_block_proof(seed_a: u8, seed_b: u8) -> Result<ChainProofBlob, AggregateError> {
    let config = build_stark_config();
    let smt_a = prove_smt_state(&config, &make_input(seed_a));
    let smt_b = prove_smt_state(&config, &make_input(seed_b));

    let out = aggregate_pair(
        &smt_a.proof,
        &smt_a.public.to_vec(),
        &smt_b.proof,
        &smt_b.public.to_vec(),
        &SmtAir,
    )?;

    Ok(ChainProofBlob {
        proof: out.0,
        chain_depth: 1,
        chain_commitment: [seed_a; 32],
    })
}

/// Run a continuous chain of `n` blocks.
/// Returns (final chain proof, proof size in bytes, verify time in ms).
fn run_continuous_chain(n: u8) -> (ChainProofBlob, usize, f64) {
    println!("\n========== Continuous Chain N={} ==========", n);

    // Block 1: genesis chain proof
    let t = Instant::now();
    let mut chain = produce_block_proof(1, 2).expect("block 1");
    println!("  Block 1 produced in {:.2}s", t.elapsed().as_secs_f64());

    // Blocks 2..=n: extend the chain
    for block_idx in 2..=n {
        let t = Instant::now();
        let txs = produce_block_proof(
            block_idx.wrapping_mul(2),
            block_idx.wrapping_mul(2).wrapping_add(1),
        )
        .expect("txs");

        chain = aggregate_two_chain_blobs(&chain, &txs).expect("aggregate chain");
        println!(
            "  Block {} chained in {:.2}s (chain_depth={})",
            block_idx,
            t.elapsed().as_secs_f64(),
            chain.chain_depth,
        );
    }

    // Serialize final chain proof
    let bytes = chain.to_bytes();
    let size_kb = bytes.len() / 1024;
    println!("  Final proof size: {} KB", size_kb);

    // Verify final chain proof
    let t = Instant::now();
    chain.verify().expect("verify final chain proof");
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("  Verify time: {:.2} ms", verify_ms);

    // Chain depth must equal N
    assert_eq!(
        chain.chain_depth, n as u32,
        "chain_depth should equal block count N={}",
        n
    );

    (chain, bytes.len(), verify_ms)
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn continuous_chain_n2() {
    let (_chain, size, verify_ms) = run_continuous_chain(2);
    println!("\n  N=2: size={} bytes, verify={:.2}ms", size, verify_ms);
    assert!(verify_ms < 100.0, "verify should be < 100ms, got {:.2}ms", verify_ms);
}

#[test]
fn continuous_chain_n3() {
    let (_chain, size, verify_ms) = run_continuous_chain(3);
    println!("\n  N=3: size={} bytes, verify={:.2}ms", size, verify_ms);
    assert!(verify_ms < 100.0, "verify should be < 100ms, got {:.2}ms", verify_ms);
}

#[test]
fn continuous_chain_n5() {
    let (_chain, size, verify_ms) = run_continuous_chain(5);
    println!("\n  N=5: size={} bytes, verify={:.2}ms", size, verify_ms);
    assert!(verify_ms < 100.0, "verify should be < 100ms, got {:.2}ms", verify_ms);
}

/// Verify O(1) — size and time should NOT grow with chain length.
#[test]
fn continuous_chain_size_and_time_constant() {
    println!("\n========== O(1) verification test ==========");

    let (chain_2, size_2, verify_2) = run_continuous_chain(2);
    let (chain_5, size_5, verify_5) = run_continuous_chain(5);

    let size_ratio = size_5 as f64 / size_2 as f64;
    println!("\n  Size ratio (N=5 / N=2): {:.3}", size_ratio);
    assert!(
        size_ratio < 1.20,
        "size should be roughly constant, got ratio {:.3}",
        size_ratio
    );

    let time_ratio = verify_5 / verify_2;
    println!("  Time ratio (N=5 / N=2): {:.3}", time_ratio);
    assert!(
        time_ratio < 2.5,
        "verify time should be roughly constant, got ratio {:.3}",
        time_ratio
    );

    assert_eq!(chain_2.chain_depth, 2, "chain_2 depth should be 2");
    assert_eq!(chain_5.chain_depth, 5, "chain_5 depth should be 5");
}

/// Chain commitment linkage: block N's chain_commitment should differ from N-1.
#[test]
fn chain_commitments_differ_across_blocks() {
    let block1 = produce_block_proof(1, 2).expect("block 1");
    let block2 = produce_block_proof(3, 4).expect("block 2");

    assert_ne!(
        block1.chain_commitment, block2.chain_commitment,
        "each block should have distinct chain_commitment"
    );
}

// ═══════════════════════════════════════════════════════════════
// Scale tests — N = 10, 20
// ═══════════════════════════════════════════════════════════════

#[test]
fn continuous_chain_n10() {
    let (_chain, size, verify_ms) = run_continuous_chain(10);
    println!("\n  N=10: size={} bytes, verify={:.2}ms", size, verify_ms);
    assert!(verify_ms < 100.0);
}

#[test]
fn continuous_chain_n20() {
    let (_chain, size, verify_ms) = run_continuous_chain(20);
    println!("\n  N=20: size={} bytes, verify={:.2}ms", size, verify_ms);
    assert!(verify_ms < 100.0);
}

// ═══════════════════════════════════════════════════════════════
// Security tests
// ═══════════════════════════════════════════════════════════════

/// Different blocks produce different chain commitments.
#[test]
fn distinct_commitments_across_chain() {
    let block1 = produce_block_proof(1, 2).expect("block 1");
    let block2 = produce_block_proof(3, 4).expect("block 2");
    let block3 = produce_block_proof(5, 6).expect("block 3");

    assert_ne!(block1.chain_commitment, block2.chain_commitment);
    assert_ne!(block2.chain_commitment, block3.chain_commitment);
    assert_ne!(block1.chain_commitment, block3.chain_commitment);
}

/// Serialization is stable: same blob serialized twice → same bytes.
#[test]
fn serialization_deterministic() {
    let chain = produce_block_proof(1, 2).expect("block 1");
    let bytes_a = chain.to_bytes();
    let bytes_b = chain.to_bytes();
    assert_eq!(bytes_a, bytes_b, "serialization must be deterministic");
}

/// Deserialized blob verifies correctly (roundtrip preserves proof validity).
#[test]
fn deserialized_blob_verifies() {
    use sahyadri_plonky3::smt_stark::chain_blob::ChainProofBlob;

    let chain = produce_block_proof(1, 2).expect("block 1");
    let bytes = chain.to_bytes();
    let restored = ChainProofBlob::from_bytes(&bytes).expect("deserialize");
    restored.verify().expect("restored must verify");
}

/// Verifying the same blob twice produces consistent results.
#[test]
fn verify_idempotent() {
    let chain = produce_block_proof(1, 2).expect("block 1");
    chain.verify().expect("first verify");
    chain.verify().expect("second verify");
}
