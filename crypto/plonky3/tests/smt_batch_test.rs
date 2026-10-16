// Batch SMT proofs into one proof.

use std::time::Instant;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::batch::{prove_smt_batch, verify_smt_batch};
use sahyadri_plonky3::smt_stark::SmtTraceInput;

fn make_input(seed: u8) -> SmtTraceInput {
    let mut key = [0u8; 32];
    key[0] = seed;
    let mut value = [0u8; 32];
    value[0] = seed.wrapping_mul(7);
    SmtTraceInput {
        siblings: vec![],
        key,
        value,
        is_absent: false,
    }
}

fn run_batch(n: usize) {
    println!("\n========== Batch N={} ==========", n);
    let config = build_stark_config();

    let inputs: Vec<SmtTraceInput> = (0..n).map(|i| make_input((i & 0xff) as u8)).collect();

    let t0 = Instant::now();
    let batch = prove_smt_batch(&config, &inputs);
    let prove_time = t0.elapsed().as_secs_f64();
    println!("  Prove: {:.2}s", prove_time);

    let t1 = Instant::now();
    verify_smt_batch(&config, &batch).expect("verify failed");
    let verify_time = t1.elapsed().as_secs_f64();
    println!("  Verify: {:.2}s", verify_time);

    let size = bincode::serialize(&batch.proof).expect("ser").len();
    println!("  Proof size: {} KB", size / 1024);
}

#[test]
fn batch_n4() {
    run_batch(4);
}

#[test]
fn batch_n16() {
    run_batch(16);
}

#[test]
fn batch_n64() {
    run_batch(64);
}

#[test]
fn batch_n256() {
    run_batch(256);
}
