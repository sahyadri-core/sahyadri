// Cross-aggregate Dilithium (MatrixVecAir) and SMT proofs.

use p3_uni_stark::Proof;
use sahyadri_dilithium::{generate_keypair, sign_message};

use sahyadri_plonky3::aggregate::verify_root_proof;
use sahyadri_plonky3::aggregate_cross::aggregate_cross;
use sahyadri_plonky3::batch::DilithiumBatch;
use sahyadri_plonky3::config::{build_stark_config, DilithiumStarkConfig};
use sahyadri_plonky3::dilithium_stark::composed_stark::DilithiumSigProof;
use sahyadri_plonky3::dilithium_stark::matrix_vec_stark::MatrixVecAir;
use sahyadri_plonky3::generate_stark_proof;
use sahyadri_plonky3::smt_stark::{prove_smt_state, SmtAir, SmtTraceInput};

// Build N MatrixVecAir proofs from N real Dilithium signatures.
fn make_mv_proofs(n: usize) -> Vec<Proof<DilithiumStarkConfig>> {
    let keypair = generate_keypair().expect("keypair");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    let mut batch = DilithiumBatch::new();
    for i in 0..n {
        let msg = format!("cross-test-{}", i);
        let sig = sign_message(&msg, &keypair).expect("sign");
        batch
            .add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes)
            .unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }

    let batch_proof = generate_stark_proof(&mut batch).expect("prove");
    let sig_proofs: Vec<DilithiumSigProof> =
        bincode::deserialize(&batch_proof.proof_bytes).expect("deserialize");
    assert_eq!(sig_proofs.len(), n, "expected {n} sig proofs");

    sig_proofs
        .into_iter()
        .map(|sp| bincode::deserialize(&sp.mv_proof).expect("deser mv_proof"))
        .collect()
}

#[test]
fn cross_aggregate_dilithium_and_smt() {
    println!("\n========== cross-aggregate Dilithium + SMT ==========");
    let config = build_stark_config();

    // ── Dilithium side: 2 real MV proofs ─────────────────────
    println!("Generating 2 Dilithium signatures and proving...");
    let t0 = std::time::Instant::now();
    let mv_proofs = make_mv_proofs(2);
    println!("  Done in {:.2}s", t0.elapsed().as_secs_f64());

    // ── SMT side: 2 simple proofs ────────────────────────────
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

    // ── Cross-aggregate ──────────────────────────────────────
    println!("Cross-aggregating...");
    let t1 = std::time::Instant::now();
    let final_proof = aggregate_cross(
        mv_proofs,
        vec![vec![]; 2],           // MatrixVecAir has no public inputs
        &MatrixVecAir,
        vec![smt_proof_1.proof, smt_proof_2.proof],
        vec![smt_pv_1, smt_pv_2],
        &SmtAir,
        4,
    )
    .expect("aggregate_cross failed");
    println!("  Aggregation done in {:.2}s", t1.elapsed().as_secs_f64());

    // ── Verify ───────────────────────────────────────────────
    println!("Verifying root...");
    let t2 = std::time::Instant::now();
    verify_root_proof(&final_proof).expect("verify_root_proof failed");
    println!("  Verify done in {:.2}s", t2.elapsed().as_secs_f64());

    let size = bincode::serialize(&final_proof.0).expect("ser").len();
    println!("\n  Final proof size: {} bytes", size);
    println!("========== SUCCESS ==========\n");
}
