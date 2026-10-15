// Tests for the single-permutation bound Poseidon2 STARK.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Poseidon2Goldilocks, Goldilocks};
use p3_symmetric::Permutation;
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::poseidon2_bound::{
    prove_single_bound, verify_single_bound,
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
fn single_bound_roundtrip() {
    let config = build_stark_config();
    let input = make_input(100);
    let proof = prove_single_bound(&config, input);
    verify_single_bound(&config, &proof).expect("verify failed");
}

#[test]
fn native_output_matches_proof() {
    let input = make_input(200);
    let config = build_stark_config();
    let proof = prove_single_bound(&config, input);

    // Independently compute the expected output.
    let perm: Poseidon2Goldilocks<8> = {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
    };
    let mut state = input;
    perm.permute_mut(&mut state);

    assert_eq!(proof.output, state);
}

#[test]
fn tamper_input_fails() {
    let config = build_stark_config();
    let input = make_input(300);
    let mut proof = prove_single_bound(&config, input);

    proof.input[0] = proof.input[0] + F::ONE;

    assert!(verify_single_bound(&config, &proof).is_err());
}

#[test]
fn tamper_output_fails() {
    let config = build_stark_config();
    let input = make_input(400);
    let mut proof = prove_single_bound(&config, input);

    proof.output[0] = proof.output[0] + F::ONE;

    assert!(verify_single_bound(&config, &proof).is_err());
}

#[test]
fn different_inputs_different_proofs() {
    let config = build_stark_config();
    let p1 = prove_single_bound(&config, make_input(500));
    let p2 = prove_single_bound(&config, make_input(600));

    assert_ne!(p1.input, p2.input);
    assert_ne!(p1.output, p2.output);

    // Both should still verify.
    verify_single_bound(&config, &p1).expect("p1 verify failed");
    verify_single_bound(&config, &p2).expect("p2 verify failed");
}

#[test]
fn zero_input_roundtrip() {
    let config = build_stark_config();
    let input = [F::ZERO; 8];
    let proof = prove_single_bound(&config, input);
    verify_single_bound(&config, &proof).expect("zero input verify failed");
}
