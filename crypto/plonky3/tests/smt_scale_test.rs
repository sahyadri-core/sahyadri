// Scale test for SMT recursive aggregation.
// Measures time and proof size as N (number of SMT proofs) grows.

use std::time::Instant;

use sahyadri_plonky3::aggregate::{aggregate_batch, verify_root_proof};
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::{prove_smt_state, SmtAir, SmtTraceInput};

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

fn run_scale(n: usize, threads: usize) {
    println!("\n========== Scale N={} ==========", n);
    let config = build_stark_config();

    // 1. Generate N SMT proofs.
    let t0 = Instant::now();
    let mut proofs = Vec::with_capacity(n);
    let mut publics = Vec::with_capacity(n);
    for i in 0..n {
        let input = make_input((i & 0xff) as u8);
        let p = prove_smt_state(&config, &input);
        publics.push(p.public.to_vec());
        proofs.push(p.proof);
    }
    let gen_time = t0.elapsed().as_secs_f64();
    println!("  Generate {} proofs: {:.2}s ({:.1}ms each)",
             n, gen_time, gen_time * 1000.0 / n as f64);

    // 2. Aggregate into 1 proof.
    let t1 = Instant::now();
    let root = aggregate_batch(proofs, publics, &SmtAir, threads)
        .expect("aggregate_batch failed");
    let agg_time = t1.elapsed().as_secs_f64();
    println!("  Aggregate: {:.2}s", agg_time);

    // 3. Verify.
    let t2 = Instant::now();
    verify_root_proof(&root).expect("verify failed");
    let verify_time = t2.elapsed().as_secs_f64();
    println!("  Verify root: {:.2}s", verify_time);

    // 4. Proof size.
    let size = bincode::serialize(&root.0).expect("ser").len();
    println!("  Root proof size: {} bytes ({:.1} KB)", size, size as f64 / 1024.0);

    let total = gen_time + agg_time + verify_time;
    println!("  Total: {:.2}s", total);
}

#[test]
fn scale_n4() {
    run_scale(4, 4);
}

#[test]
fn scale_n8() {
    run_scale(8, 8);
}

#[test]
fn scale_n16() {
    run_scale(16, 16);
}
