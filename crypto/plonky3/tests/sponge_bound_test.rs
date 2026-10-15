// Sponge-bound STARK tests, comparing with native sahyadri-smt hashing.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::sponge_bound::{
    branch_chunks, leaf_chunks, prove_sponge_hash, verify_sponge_hash,
};
use sahyadri_plonky3::smt_stark::trace::limbs_to_h256;

type F = Goldilocks;

#[test]
fn leaf_sponge_matches_native() {
    let key = [0x11u8; 32];
    let value = [0x22u8; 32];
    let config = build_stark_config();

    let chunks = leaf_chunks(&key, &value);
    let proof = prove_sponge_hash(&config, chunks);
    verify_sponge_hash(&config, &proof).expect("verify failed");

    let native_h = sahyadri_smt::hash_leaf(&key, &value);
    let proof_bytes = limbs_to_h256(&proof.output);
    assert_eq!(proof_bytes, native_h, "sponge output != native hash_leaf");
}

#[test]
fn branch_sponge_matches_native() {
    let left = [0xAAu8; 32];
    let right = [0xBBu8; 32];
    let config = build_stark_config();

    let chunks = branch_chunks(&left, &right);
    let proof = prove_sponge_hash(&config, chunks);
    verify_sponge_hash(&config, &proof).expect("verify failed");

    let native_h = sahyadri_smt::hash_branch(&left, &right);
    let proof_bytes = limbs_to_h256(&proof.output);
    assert_eq!(proof_bytes, native_h, "sponge output != native hash_branch");
}

#[test]
fn tamper_chunk_fails() {
    let key = [0x33u8; 32];
    let value = [0x44u8; 32];
    let config = build_stark_config();

    let chunks = leaf_chunks(&key, &value);
    let mut proof = prove_sponge_hash(&config, chunks);
    proof.chunks[0][0] = proof.chunks[0][0] + F::ONE;

    assert!(verify_sponge_hash(&config, &proof).is_err());
}

#[test]
fn tamper_output_fails() {
    let key = [0x55u8; 32];
    let value = [0x66u8; 32];
    let config = build_stark_config();

    let chunks = leaf_chunks(&key, &value);
    let mut proof = prove_sponge_hash(&config, chunks);
    proof.output[0] = proof.output[0] + F::ONE;

    assert!(verify_sponge_hash(&config, &proof).is_err());
}
