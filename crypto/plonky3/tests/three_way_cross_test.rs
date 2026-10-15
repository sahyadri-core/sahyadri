use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;
use sahyadri_dilithium::{generate_keypair, sign_message};

use sahyadri_plonky3::aggregate::verify_root_proof;
use sahyadri_plonky3::aggregate_cross::aggregate_cross_three;
use sahyadri_plonky3::batch::DilithiumBatch;
use sahyadri_plonky3::config::{build_stark_config, DilithiumStarkConfig};
use sahyadri_plonky3::dilithium_stark::composed_stark::DilithiumSigProof;
use sahyadri_plonky3::dilithium_stark::matrix_vec_stark::MatrixVecAir;
use sahyadri_plonky3::generate_stark_proof;
use sahyadri_plonky3::smt_stark::poseidon2_bound::{prove_single_bound, Poseidon2BoundAir};
use sahyadri_plonky3::smt_stark::{prove_smt_state, SmtAir, SmtTraceInput};

type F = Goldilocks;

fn make_mv_proofs(n: usize) -> Vec<Proof<DilithiumStarkConfig>> {
    let keypair = generate_keypair().expect("keypair");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();
    let mut batch = DilithiumBatch::new();
    for i in 0..n {
        let msg = format!("3way-{}", i);
        let sig = sign_message(&msg, &keypair).expect("sign");
        batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap();
    }
    let batch_proof = generate_stark_proof(&mut batch).expect("prove");
    let sig_proofs: Vec<DilithiumSigProof> =
        bincode::deserialize(&batch_proof.proof_bytes).unwrap();
    sig_proofs.into_iter().map(|sp| bincode::deserialize(&sp.mv_proof).unwrap()).collect()
}

fn make_p2_input(seed: u64) -> [F; 8] {
    let mut out = [F::ZERO; 8];
    for i in 0..8 { out[i] = F::from_u64(seed + i as u64); }
    out
}

#[test]
fn three_way_cross_aggregate() {
    println!("\n========== 3-way cross-aggregate ==========");
    let config = build_stark_config();

    // Dilithium side
    println!("Dilithium proofs...");
    let t = std::time::Instant::now();
    let mv_proofs = make_mv_proofs(2);
    println!("  Done in {:.2}s", t.elapsed().as_secs_f64());

    // SMT side
    let smt_p1 = prove_smt_state(&config, &SmtTraceInput {
        siblings: vec![], key: [0x11u8; 32], value: [0xAAu8; 32], is_absent: false,
    });
    let smt_p2 = prove_smt_state(&config, &SmtTraceInput {
        siblings: vec![], key: [0x22u8; 32], value: [0xBBu8; 32], is_absent: false,
    });
    let smt_pv1 = smt_p1.public.to_vec();
    let smt_pv2 = smt_p2.public.to_vec();

    // Poseidon2 side
    let p2_p1 = prove_single_bound(&config, make_p2_input(100));
    let p2_p2 = prove_single_bound(&config, make_p2_input(200));
    let mut p2_pv1 = Vec::with_capacity(16);
    p2_pv1.extend_from_slice(&p2_p1.input);
    p2_pv1.extend_from_slice(&p2_p1.output);
    let mut p2_pv2 = Vec::with_capacity(16);
    p2_pv2.extend_from_slice(&p2_p2.input);
    p2_pv2.extend_from_slice(&p2_p2.output);

    // Cross-aggregate
    println!("3-way cross-aggregating...");
    let t = std::time::Instant::now();
    let final_proof = aggregate_cross_three(
        mv_proofs, vec![vec![]; 2], &MatrixVecAir,
        vec![smt_p1.proof, smt_p2.proof], vec![smt_pv1, smt_pv2], &SmtAir,
        vec![p2_p1.proof, p2_p2.proof], vec![p2_pv1, p2_pv2], &Poseidon2BoundAir::new(),
        4,
    ).expect("aggregate_cross_three failed");
    println!("  Done in {:.2}s", t.elapsed().as_secs_f64());

    println!("Verifying...");
    let t = std::time::Instant::now();
    verify_root_proof(&final_proof).expect("verify failed");
    println!("  Verify in {:.2}s", t.elapsed().as_secs_f64());

    let size = bincode::serialize(&final_proof.0).unwrap().len();
    println!("\n  Final proof size: {} bytes", size);
    println!("========== SUCCESS ==========\n");
}
