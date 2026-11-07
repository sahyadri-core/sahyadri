//! Serialization gate: can the WIRE format (ChainProofBlob) round-trip via bincode?
//!
//! Note: `RecursionOutput<RecursionConfig>` is an internal prover type
//! (holds `Arc<CircuitProverData>` prepared-circuit cache — not serializable,
//! not meant for wire). The wire format is `ChainProofBlob` which only holds
//! the proof + metadata. This gate verifies the wire format only.

use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;

use sahyadri_plonky3::aggregate::aggregate_pair;
use sahyadri_plonky3::config::SahyadriStarkConfig;
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};
use sahyadri_plonky3::smt_stark::chain_blob::ChainProofBlob;

#[test]
fn can_serialize_chain_proof_blob() {
    println!("\n=== Serialization gate (wire format = ChainProofBlob) ===");

    // Build 2-block chain (minimal)
    let cv0 = [0x11u8; 32];
    let block0 = [0x22u8; 64];
    let block1 = [0x33u8; 64];

    let out0 = blake3_compress_native(&cv0, &block0, 0, 64, 0);
    let out1 = blake3_compress_native(&out0, &block1, 0, 64, 0);

    let p0: Proof<SahyadriStarkConfig> = prove_blake3_block(&cv0, &block0, 0, 64, 0, &out0);
    let p1: Proof<SahyadriStarkConfig> = prove_blake3_block(&out0, &block1, 0, 64, 0, &out1);
    let pi0: Vec<Goldilocks> = pack_public_inputs(&cv0, &block0, 0u64, 64u32, 0u32, &out0);
    let pi1: Vec<Goldilocks> = pack_public_inputs(&out0, &block1, 0u64, 64u32, 0u32, &out1);

    let air = Blake3BlockAir;
    let root = aggregate_pair(&p0, &pi0, &p1, &pi1, &air).expect("aggregate_pair");
    println!("RecursionOutput built (internal prover type)");

    // Extract wire format (BatchStarkProof only — no Arc<CircuitProverData>)
    let blob = ChainProofBlob {
        proof: root.0,
        chain_depth: 1,
        chain_commitment: [0xABu8; 32],
    };

    // Serialize wire format
    let bytes = blob.to_bytes();
    println!("ChainProofBlob serialize: OK, {} bytes ({} KB)", bytes.len(), bytes.len() / 1024);

    // Deserialize
    let blob2 = ChainProofBlob::from_bytes(&bytes).expect("deserialize ChainProofBlob");
    println!("ChainProofBlob deserialize: OK");

    // Verify metadata preserved
    assert_eq!(blob.chain_depth, blob2.chain_depth, "chain_depth mismatch");
    assert_eq!(blob.chain_commitment, blob2.chain_commitment, "commitment mismatch");
    println!("Metadata preserved: depth={}, commitment={:?}",
        blob2.chain_depth, &blob2.chain_commitment[..4]);

    // Verify deserialized proof
    match blob2.verify() {
        Ok(()) => println!("Deserialized ChainProofBlob verifies: OK"),
        Err(e) => panic!("DESERIALIZED VERIFY FAILED: {e:?}"),
    }

    println!("\n=== GATE PASSED: ChainProofBlob (wire format) round-trips + verifies ===");
    println!("Streaming tree viable: serialize per-node ChainProofBlob, verify at end.");
}
