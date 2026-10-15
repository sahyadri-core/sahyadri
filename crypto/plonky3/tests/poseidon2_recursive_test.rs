// Aggregate two Poseidon2 bound proofs into one recursive proof.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::aggregate::{aggregate_pair, verify_root_proof};
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::poseidon2_bound::{
    prove_single_bound, verify_single_bound, Poseidon2BoundAir,
};
use sahyadri_plonky3::smt_stark::sponge_bound::{
    branch_chunks, leaf_chunks, prove_sponge_hash, SpongeHashProof,
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
fn aggregate_two_poseidon2_bound_proofs() {
    let config = build_stark_config();

    let input1 = make_input(100);
    let input2 = make_input(200);

    let proof1 = prove_single_bound(&config, input1);
    let proof2 = prove_single_bound(&config, input2);

    // Public inputs: input (8) || output (8) = 16 elements
    let mut pv1 = Vec::with_capacity(16);
    pv1.extend_from_slice(&proof1.input);
    pv1.extend_from_slice(&proof1.output);

    let mut pv2 = Vec::with_capacity(16);
    pv2.extend_from_slice(&proof2.input);
    pv2.extend_from_slice(&proof2.output);

    let air = Poseidon2BoundAir::new();

    let aggregated = aggregate_pair(
        &proof1.proof,
        &pv1,
        &proof2.proof,
        &pv2,
        &air,
    )
    .expect("aggregate_pair failed");

    verify_root_proof(&aggregated).expect("verify_root_proof failed");
}

#[test]
fn prove_verify_sponge_hash() {
    // Sanity: sponge proof works standalone.
    let config = build_stark_config();
    let key = [0x11u8; 32];
    let value = [0x22u8; 32];
    let chunks = leaf_chunks(&key, &value);
    let proof = prove_sponge_hash(&config, chunks);

    // Verify sub-proofs.
    for perm_proof in &proof.perm_proofs {
        verify_single_bound(&config, perm_proof).expect("perm verify failed");
    }

    // Check output matches native.
    let native = sahyadri_smt::hash_leaf(&key, &value);
    let proof_bytes = sahyadri_plonky3::smt_stark::trace::limbs_to_h256(&proof.output);
    assert_eq!(proof_bytes, native);
}

// Note: aggregating sponge proofs requires the sponge proof's top-level
// proof to be a UniStark — currently our SpongeHashProof holds three
// sub-proofs. Aggregating them is Phase D3 (cross-aggregate) work.
// For now, we test Poseidon2 bound aggregation only.

fn _silence() {
    let _: fn(&SpongeHashProof) = |_| {};
    let _ = branch_chunks;
}
