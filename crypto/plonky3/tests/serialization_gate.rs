//! Serialization gate: can RecursionOutput round-trip via bincode?
//! If yes, Option C (streaming tree) is straightforward.
//! If no, we need to redesign the tree to avoid holding RecursionOutputs.

use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;
use p3_recursion::recursion::RecursionOutput;

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof, RecursionConfig};
use sahyadri_plonky3::config::SahyadriStarkConfig;
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};

#[test]
fn can_serialize_recursion_output() {
    println!("\n=== Serialization gate ===");

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
    let root: RecursionOutput<RecursionConfig> =
        aggregate_pair(&p0, &pi0, &p1, &pi1, &air).expect("aggregate_pair");

    println!("RecursionOutput built");

    // Serialize
    let bytes = match bincode::serialize(&root) {
        Ok(b) => {
            println!("Serialize: OK, {} bytes ({} KB)", b.len(), b.len() / 1024);
            b
        }
        Err(e) => {
            panic!("SERIALIZE FAILED: {:?}", e);
        }
    };

    // Deserialize
    let deser: RecursionOutput<RecursionConfig> = match bincode::deserialize(&bytes) {
        Ok(d) => {
            println!("Deserialize: OK");
            d
        }
        Err(e) => {
            panic!("DESERIALIZE FAILED: {:?}", e);
        }
    };

    // Verify deserialized
    match verify_root_proof(&deser) {
        Ok(()) => println!("Deserialized verifies: OK -> Option C viable"),
        Err(e) => {
            panic!("DESERIALIZED VERIFY FAILED: {:?}", e);
        }
    }

    println!("\n=== GATE PASSED: Option C (streaming) is viable ===");
}
