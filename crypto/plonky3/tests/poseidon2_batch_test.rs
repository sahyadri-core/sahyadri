// Round-trip tests for Poseidon2 batch STARK.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::poseidon2_batch::{
    prove_poseidon2_batch, verify_poseidon2_batch,
};

type F = Goldilocks;

fn make_input(seed: u64) -> [F; 8] {
    let mut out = [F::ZERO; 8];
    for i in 0..8 {
        out[i] = F::from_u64(seed + i as u64);
    }
    out
}

#[test]
fn single_permutation_roundtrip() {
    let config = build_stark_config();
    let inputs = vec![make_input(1)];
    let proof = prove_poseidon2_batch(&config, inputs);
    assert_eq!(proof.num_permutations, 2);
    verify_poseidon2_batch(&config, &proof).expect("verify failed");
}

#[test]
fn two_permutations_roundtrip() {
    let config = build_stark_config();
    let inputs = vec![make_input(1), make_input(10)];
    let proof = prove_poseidon2_batch(&config, inputs);
    assert_eq!(proof.num_permutations, 2);
    verify_poseidon2_batch(&config, &proof).expect("verify failed");
}

#[test]
fn eight_permutations_roundtrip() {
    let config = build_stark_config();
    let inputs: Vec<[F; 8]> = (0..8).map(|i| make_input(i * 10)).collect();
    let proof = prove_poseidon2_batch(&config, inputs);
    assert_eq!(proof.num_permutations, 8);
    verify_poseidon2_batch(&config, &proof).expect("verify failed");
}

#[test]
fn sixty_four_permutations_roundtrip() {
    let config = build_stark_config();
    let inputs: Vec<[F; 8]> = (0..64).map(|i| make_input(i)).collect();
    let proof = prove_poseidon2_batch(&config, inputs);
    assert_eq!(proof.num_permutations, 64);
    verify_poseidon2_batch(&config, &proof).expect("verify failed");
}

#[test]
fn padding_three_to_four() {
    let config = build_stark_config();
    let inputs: Vec<[F; 8]> = (0..3).map(|i| make_input(i)).collect();
    let proof = prove_poseidon2_batch(&config, inputs);
    assert_eq!(proof.num_permutations, 4);
    verify_poseidon2_batch(&config, &proof).expect("verify failed");
}
