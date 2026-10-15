// Cross-aggregate SMT and Poseidon2 proofs into one recursive proof.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::aggregate::verify_root_proof;
use sahyadri_plonky3::aggregate_cross::aggregate_cross;
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::poseidon2_bound::{prove_single_bound, Poseidon2BoundAir};
use sahyadri_plonky3::smt_stark::{prove_smt_state, SmtAir, SmtTraceInput};

type F = Goldilocks;

fn make_p2_input(seed: u64) -> [F; 8] {
    let mut out = [F::ZERO; 8];
    for i in 0..8 {
        out[i] = F::from_u64(seed + i as u64);
    }
    out
}

#[test]
fn cross_aggregate_smt_and_poseidon2() {
    let config = build_stark_config();

    // Two SMT proofs.
    let smt_input_1 = SmtTraceInput {
        siblings: vec![],
        key: [0x11u8; 32],
        value: [0xAAu8; 32],
        is_absent: false,
    };
    let smt_input_2 = SmtTraceInput {
        siblings: vec![],
        key: [0x22u8; 32],
        value: [0xBBu8; 32],
        is_absent: false,
    };
    let smt_proof_1 = prove_smt_state(&config, &smt_input_1);
    let smt_proof_2 = prove_smt_state(&config, &smt_input_2);

    let smt_pv_1 = smt_proof_1.public.to_vec();
    let smt_pv_2 = smt_proof_2.public.to_vec();

    // Two Poseidon2 bound proofs.
    let p2_proof_1 = prove_single_bound(&config, make_p2_input(100));
    let p2_proof_2 = prove_single_bound(&config, make_p2_input(200));

    let mut p2_pv_1 = Vec::with_capacity(16);
    p2_pv_1.extend_from_slice(&p2_proof_1.input);
    p2_pv_1.extend_from_slice(&p2_proof_1.output);

    let mut p2_pv_2 = Vec::with_capacity(16);
    p2_pv_2.extend_from_slice(&p2_proof_2.input);
    p2_pv_2.extend_from_slice(&p2_proof_2.output);

    // Cross-aggregate.
    let final_proof = aggregate_cross(
        vec![smt_proof_1.proof, smt_proof_2.proof],
        vec![smt_pv_1, smt_pv_2],
        &SmtAir,
        vec![p2_proof_1.proof, p2_proof_2.proof],
        vec![p2_pv_1, p2_pv_2],
        &Poseidon2BoundAir::new(),
        4,
    )
    .expect("aggregate_cross failed");

    verify_root_proof(&final_proof).expect("verify_root_proof failed");
}
