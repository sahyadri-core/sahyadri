// Verifier-level binding: SMT hash column fold == sponge output fold.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::air::ALPHA_U64;
use sahyadri_plonky3::smt_stark::{
    prove_smt_state, verify_smt_state, SmtTraceInput,
};
use sahyadri_plonky3::smt_stark::sponge_bound::{
    branch_chunks, leaf_chunks, prove_sponge_hash, verify_sponge_hash,
};

type F = Goldilocks;

#[test]
fn smt_sponge_fold_binding() {
    let config = build_stark_config();

    // SMT with depth 1: one leaf row + one branch row.
    let key = [0x00u8; 32];   // first bit = 0
    let value = [0xAAu8; 32];
    let sibling_hash = [0x80u8; 32];  // first bit = 1

    let smt_input = SmtTraceInput {
        siblings: vec![sibling_hash],
        key,
        value,
        is_absent: false,
    };
    let smt_proof = prove_smt_state(&config, &smt_input);
    verify_smt_state(&config, &smt_proof).expect("SMT verify failed");

    // Sponge proof for the leaf hash.
    let leaf_chunks_val = leaf_chunks(&key, &value);
    let leaf_proof = prove_sponge_hash(&config, leaf_chunks_val);
    verify_sponge_hash(&config, &leaf_proof).expect("leaf sponge verify failed");

    // Sponge proof for the branch hash.
    // key bit 0 = 0, so branch is hash_branch(leaf_hash, sibling_hash).
    let leaf_hash = sahyadri_smt::hash_leaf(&key, &value);
    let branch_chunks_val = branch_chunks(&leaf_hash, &sibling_hash);
    let branch_proof = prove_sponge_hash(&config, branch_chunks_val);
    verify_sponge_hash(&config, &branch_proof).expect("branch sponge verify failed");

    // Compute fold of sponge outputs using the same alpha.
    let alpha = F::from_u64(ALPHA_U64);
    let outputs = [leaf_proof.output, branch_proof.output];
    let mut computed_fold = [F::ZERO; 4];
    for (i, out) in outputs.iter().enumerate() {
        for k in 0..4 {
            computed_fold[k] = if i == 0 {
                out[k]
            } else {
                computed_fold[k] * alpha + out[k]
            };
        }
    }

    // Cross-binding: SMT fold must equal sponge fold.
    assert_eq!(
        smt_proof.public.hash_fold, computed_fold,
        "SMT fold does not match sponge fold — binding failed",
    );
}

#[test]
fn smt_sponge_fold_binding_tamper_fails() {
    let config = build_stark_config();

    let key = [0x00u8; 32];
    let value = [0xAAu8; 32];
    let sibling_hash = [0x80u8; 32];

    let smt_input = SmtTraceInput {
        siblings: vec![sibling_hash],
        key,
        value,
        is_absent: false,
    };
    let smt_proof = prove_smt_state(&config, &smt_input);

    // Sponge proofs for a DIFFERENT value — should NOT match SMT fold.
    let wrong_value = [0xBBu8; 32];
    let wrong_leaf_chunks = leaf_chunks(&key, &wrong_value);
    let wrong_leaf_proof = prove_sponge_hash(&config, wrong_leaf_chunks);

    let leaf_hash = sahyadri_smt::hash_leaf(&key, &wrong_value);
    let wrong_branch_chunks = branch_chunks(&leaf_hash, &sibling_hash);
    let wrong_branch_proof = prove_sponge_hash(&config, wrong_branch_chunks);

    let alpha = F::from_u64(ALPHA_U64);
    let outputs = [wrong_leaf_proof.output, wrong_branch_proof.output];
    let mut computed_fold = [F::ZERO; 4];
    for (i, out) in outputs.iter().enumerate() {
        for k in 0..4 {
            computed_fold[k] = if i == 0 {
                out[k]
            } else {
                computed_fold[k] * alpha + out[k]
            };
        }
    }

    // Should NOT match.
    assert_ne!(
        smt_proof.public.hash_fold, computed_fold,
        "tampered fold should not match — but it did!",
    );
}
