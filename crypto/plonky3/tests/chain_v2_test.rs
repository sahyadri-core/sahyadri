//! E v2 integration test: chain blob aggregation and verification.
//!
//! Uses aggregate_pair (UniStark path) which works on 485455c.
//! Outputs RecursionOutput whose .0 is a serializable BatchStarkProof.

use std::time::Instant;

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof};
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

#[test]
fn chain_blob_aggregation_roundtrip() {
    println!("\n========== E v2: chain blob aggregation ==========");
    let config = build_stark_config();

    // Step 1: Prove two SMT states via prove_smt_state (UniStark Proof)
    println!("Proving 2 SMT proofs...");
    let t = Instant::now();
    let proof_a = prove_smt_state(&config, &make_input(1));
    let proof_b = prove_smt_state(&config, &make_input(2));
    println!("  Proved in {:.2}s", t.elapsed().as_secs_f64());

    // Step 2: Aggregate via aggregate_pair (UniStark path)
    println!("Aggregating via aggregate_pair...");
    let t = Instant::now();
    let combined = aggregate_pair(
        &proof_a.proof,
        &proof_a.public.to_vec(),
        &proof_b.proof,
        &proof_b.public.to_vec(),
        &SmtAir,
    ).expect("aggregate_pair failed");
    println!("  Aggregated in {:.2}s", t.elapsed().as_secs_f64());

    // Step 3: Verify combined proof
    println!("Verifying combined proof...");
    let t = Instant::now();
    verify_root_proof(&combined).expect("verify_root_proof failed");
    println!("  Verified in {:.2}s", t.elapsed().as_secs_f64());

    // Step 4: Wrap in ChainProofBlob and serialize
    let blob = ChainProofBlob {
        proof: combined.0,
        chain_depth: 2,
        chain_commitment: [0xAAu8; 32],
    };
    let bytes = blob.to_bytes();
    println!("  Chain blob size: {} KB", bytes.len() / 1024);

    // Step 5: Roundtrip
    let restored = ChainProofBlob::from_bytes(&bytes).expect("deserialize failed");
    assert_eq!(restored.chain_depth, 2);
    assert_eq!(restored.chain_commitment, [0xAAu8; 32]);

    // Step 6: Independently verify restored blob
    println!("Verifying restored chain proof...");
    let t = Instant::now();
    restored.verify().expect("chain blob verify failed");
    println!("  Verified in {:.2}s", t.elapsed().as_secs_f64());

    println!("========== SUCCESS ==========\n");
}
