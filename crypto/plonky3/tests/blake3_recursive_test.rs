use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof};
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};

#[test]
fn recursive_2_blocks() {
    let cv0 = [0x11u8; 32];
    let block0 = [0x22u8; 64];
    let block1 = [0x33u8; 64];

    let out0 = blake3_compress_native(&cv0, &block0, 0, 64, 0);
    let out1 = blake3_compress_native(&out0, &block1, 0, 64, 0);

    let proof0 = prove_blake3_block(&cv0, &block0, 0, 64, 0, &out0);
    let proof1 = prove_blake3_block(&out0, &block1, 0, 64, 0, &out1);

    let pi0 = pack_public_inputs(&cv0, &block0, 0u64, 64u32, 0u32, &out0);
    let pi1 = pack_public_inputs(&out0, &block1, 0u64, 64u32, 0u32, &out1);

    let air = Blake3BlockAir;
    let root = aggregate_pair(&proof0, &pi0, &proof1, &pi1, &air)
        .expect("aggregate_pair should work");

    verify_root_proof(&root).expect("root proof should verify");

    println!("Root recursive proof verified: 2 blocks aggregated");
}
