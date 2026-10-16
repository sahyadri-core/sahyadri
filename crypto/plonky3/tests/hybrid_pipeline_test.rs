use std::time::Instant;
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::batch::{prove_smt_batch, verify_smt_batch};
use sahyadri_plonky3::smt_stark::SmtTraceInput;

fn make_input(seed: u32) -> SmtTraceInput {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&seed.to_le_bytes());
    let mut value = [0u8; 32];
    value[0..4].copy_from_slice(&seed.wrapping_mul(7).to_le_bytes());
    SmtTraceInput { siblings: vec![], key, value, is_absent: false }
}

#[test]
fn hybrid_1024_smt_proofs() {
    println!("\n========== Hybrid: 1024 SMT proofs ==========");
    let config = build_stark_config();
    let batch_size = 256;
    let num_batches = 4;
    let total = batch_size * num_batches;
    println!("Total inputs: {}", total);

    let all_inputs: Vec<SmtTraceInput> = (0..total as u32).map(make_input).collect();

    let t1 = Instant::now();
    for i in 0..num_batches {
        let chunk = &all_inputs[i * batch_size..(i + 1) * batch_size];
        let batch = prove_smt_batch(&config, chunk);
        verify_smt_batch(&config, &batch).expect("batch verify failed");
    }
    println!("  {} batches of {}: {:.2}s", num_batches, batch_size, t1.elapsed().as_secs_f64());
    println!("========== DONE ==========\n");
}
