// Round-trip tests for SMT STARK.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use sahyadri_smt::{hash_branch, hash_leaf, Terminal};

use sahyadri_plonky3::config::{build_stark_config, SahyadriStarkConfig};
use sahyadri_plonky3::smt_stark::{
    generate_smt_trace, h256_to_limbs, prove_smt_state, verify_smt_state,
    SmtTraceInput, HASH_LIMBS, NUM_ROWS, NUM_TRACE_COLS,
};

type F = Goldilocks;

#[test]
fn trace_has_correct_shape() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [1u8; 32],
        value: [2u8; 32],
        is_absent: false,
    };
    let trace = generate_smt_trace(&input);
    assert_eq!(trace.height(), NUM_ROWS);
    assert_eq!(trace.width(), NUM_TRACE_COLS);
}

#[test]
fn absent_trace_shape() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [1u8; 32],
        value: [0u8; 32],
        is_absent: true,
    };
    let trace = generate_smt_trace(&input);
    assert_eq!(trace.height(), NUM_ROWS);
    assert_eq!(trace.width(), NUM_TRACE_COLS);
}

#[test]
fn h256_limbs_roundtrip() {
    let mut h = [0u8; 32];
    for i in 0..32 {
        h[i] = i as u8;
    }
    let limbs = h256_to_limbs(&h);
    for k in 0..HASH_LIMBS {
        assert!(limbs[k] != F::ZERO, "limb {} unexpectedly zero", k);
    }
}

#[test]
fn prove_verify_roundtrip_single_leaf() {
    let key = [7u8; 32];
    let value = [42u8; 32];
    let input = SmtTraceInput {
        siblings: vec![],
        key,
        value,
        is_absent: false,
    };

    let config: SahyadriStarkConfig = build_stark_config();
    let proof = prove_smt_state(&config, &input);

    assert!(!proof.public.is_absent);
    assert_eq!(
        proof.public.root,
        h256_to_limbs(&hash_leaf(&key, &value))
    );

    verify_smt_state(&config, &proof).expect("verify failed");
}

#[test]
fn prove_verify_roundtrip_with_sibling() {
    let key_a = [0x00u8; 32];
    let key_b = [0x80u8; 32];
    let value_a = [0xAAu8; 32];
    let value_b = [0xBBu8; 32];

    let h_a = hash_leaf(&key_a, &value_a);
    let h_b = hash_leaf(&key_b, &value_b);

    let input_a = SmtTraceInput {
        siblings: vec![h_b],
        key: key_a,
        value: value_a,
        is_absent: false,
    };
    let input_b = SmtTraceInput {
        siblings: vec![h_a],
        key: key_b,
        value: value_b,
        is_absent: false,
    };

    let config = build_stark_config();
    let proof_a = prove_smt_state(&config, &input_a);
    verify_smt_state(&config, &proof_a).expect("verify a failed");

    let proof_b = prove_smt_state(&config, &input_b);
    verify_smt_state(&config, &proof_b).expect("verify b failed");

    assert_eq!(proof_a.public.root, proof_b.public.root);
    assert_eq!(
        proof_a.public.root,
        h256_to_limbs(&hash_branch(&h_a, &h_b))
    );
}

#[test]
fn verify_rejects_mismatched_root() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [3u8; 32],
        value: [4u8; 32],
        is_absent: false,
    };
    let config = build_stark_config();
    let mut proof = prove_smt_state(&config, &input);
    proof.public.root[0] = proof.public.root[0] + F::ONE;

    assert!(verify_smt_state(&config, &proof).is_err());
}

#[test]
fn smt_absent_inclusion_differs() {
    let key = [9u8; 32];
    let value = [0x11u8; 32];

    let present = SmtTraceInput {
        siblings: vec![],
        key,
        value,
        is_absent: false,
    };
    let absent = SmtTraceInput {
        siblings: vec![],
        key,
        value: [0u8; 32],
        is_absent: true,
    };

    let config = build_stark_config();
    let p_present = prove_smt_state(&config, &present);
    let p_absent = prove_smt_state(&config, &absent);

    assert!(!p_present.public.is_absent);
    assert!(p_absent.public.is_absent);
    assert_ne!(p_present.public.root, p_absent.public.root);
}

// -- Tamper tests --------------------------------------------------------

#[test]
fn tamper_key_fails() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [5u8; 32],
        value: [6u8; 32],
        is_absent: false,
    };
    let config = build_stark_config();
    let mut proof = prove_smt_state(&config, &input);
    proof.public.key[0] = proof.public.key[0] + F::ONE;

    assert!(verify_smt_state(&config, &proof).is_err());
}

#[test]
fn tamper_value_fails() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [7u8; 32],
        value: [8u8; 32],
        is_absent: false,
    };
    let config = build_stark_config();
    let mut proof = prove_smt_state(&config, &input);
    proof.public.value[0] = proof.public.value[0] + F::ONE;

    assert!(verify_smt_state(&config, &proof).is_err());
}

#[test]
fn tamper_absent_flag_fails() {
    let input = SmtTraceInput {
        siblings: vec![],
        key: [9u8; 32],
        value: [10u8; 32],
        is_absent: false,
    };
    let config = build_stark_config();
    let mut proof = prove_smt_state(&config, &input);
    proof.public.is_absent = true;

    assert!(verify_smt_state(&config, &proof).is_err());
}

#[test]
fn tamper_swapped_public_inputs_fails() {
    let input_a = SmtTraceInput {
        siblings: vec![],
        key: [11u8; 32],
        value: [12u8; 32],
        is_absent: false,
    };
    let input_b = SmtTraceInput {
        siblings: vec![],
        key: [13u8; 32],
        value: [14u8; 32],
        is_absent: false,
    };

    let config = build_stark_config();
    let proof_a = prove_smt_state(&config, &input_a);
    let mut proof_b = prove_smt_state(&config, &input_b);
    proof_b.public = proof_a.public.clone();

    assert!(verify_smt_state(&config, &proof_b).is_err());
}

#[test]
fn same_leaf_different_direction_same_root() {
    let key_left = [0x00u8; 32];
    let key_right = [0x80u8; 32];
    let value = [0x55u8; 32];

    let h_left = hash_leaf(&key_left, &value);
    let h_right = hash_leaf(&key_right, &value);

    let input = SmtTraceInput {
        siblings: vec![h_right],
        key: key_left,
        value,
        is_absent: false,
    };

    let config = build_stark_config();
    let proof = prove_smt_state(&config, &input);
    let expected_root = h256_to_limbs(&hash_branch(&h_left, &h_right));
    assert_eq!(proof.public.root, expected_root);
    verify_smt_state(&config, &proof).expect("verify should pass");
}

#[allow(dead_code)]
fn _sanity_terminal_is_used() {
    let _ = Terminal::Empty;
}

// -- Tamper tests --------------------------------------------------------

