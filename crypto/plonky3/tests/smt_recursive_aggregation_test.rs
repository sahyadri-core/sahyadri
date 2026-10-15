// Aggregate two SMT state proofs into one recursive proof.

use sahyadri_smt::{hash_branch, hash_leaf};

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof};
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::{
    prove_smt_state, SmtAir, SmtTraceInput,
};

#[test]
fn aggregate_two_smt_proofs() {
    let config = build_stark_config();

    // Two unrelated SMT claims.
    let input1 = SmtTraceInput {
        siblings: vec![],
        key: [0x11u8; 32],
        value: [0xAAu8; 32],
        is_absent: false,
    };
    let input2 = SmtTraceInput {
        siblings: vec![],
        key: [0x22u8; 32],
        value: [0xBBu8; 32],
        is_absent: false,
    };

    let proof1 = prove_smt_state(&config, &input1);
    let proof2 = prove_smt_state(&config, &input2);

    let pv1 = proof1.public.to_vec();
    let pv2 = proof2.public.to_vec();

    // Aggregate into one recursive proof.
    let aggregated = aggregate_pair(
        &proof1.proof,
        &pv1,
        &proof2.proof,
        &pv2,
        &SmtAir,
    )
    .expect("aggregate_pair failed");

    // Verify the recursive proof.
    verify_root_proof(&aggregated).expect("verify_root_proof failed");
}

#[test]
fn aggregate_two_smt_proofs_with_siblings() {
    let config = build_stark_config();

    let key_a = [0x00u8; 32];
    let key_b = [0x80u8; 32];
    let value_a = [0xAAu8; 32];
    let value_b = [0xBBu8; 32];

    let h_a = hash_leaf(&key_a, &value_a);
    let h_b = hash_leaf(&key_b, &value_b);
    let _ = hash_branch(&h_a, &h_b);

    let input1 = SmtTraceInput {
        siblings: vec![h_b],
        key: key_a,
        value: value_a,
        is_absent: false,
    };
    let input2 = SmtTraceInput {
        siblings: vec![h_a],
        key: key_b,
        value: value_b,
        is_absent: false,
    };

    let proof1 = prove_smt_state(&config, &input1);
    let proof2 = prove_smt_state(&config, &input2);

    let pv1 = proof1.public.to_vec();
    let pv2 = proof2.public.to_vec();

    let aggregated = aggregate_pair(
        &proof1.proof,
        &pv1,
        &proof2.proof,
        &pv2,
        &SmtAir,
    )
    .expect("aggregate_pair failed");

    verify_root_proof(&aggregated).expect("verify_root_proof failed");
}
