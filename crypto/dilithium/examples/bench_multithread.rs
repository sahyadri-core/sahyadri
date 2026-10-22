//! Multi-threaded verification benchmark — real parallel with thread pool.

use std::time::Instant;

use rayon::prelude::*;
use sahyadri_dilithium::{generate_keypair, pubkey_from_hex, pubkey_to_hex, sign_message};

fn main() {
    let keypair = generate_keypair().expect("keypair");
    let pk_hex = pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = pubkey_from_hex(&pk_hex).expect("pk");

    // Pre-generate 100 signatures for varied inputs
    let msgs: Vec<String> = (0..100).map(|i| format!("bench-msg-{}", i)).collect();
    let sigs: Vec<Vec<u8>> = msgs
        .iter()
        .map(|m| sign_message(m, &keypair).expect("sign").as_bytes().to_vec())
        .collect();

    // Build thread pool like consensus code
    let threads = num_cpus::get().saturating_sub(1).max(1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("bench-verify-{}", i))
        .build()
        .expect("pool");

    println!("Thread pool: {} threads", threads);

    // Warmup
    let _ = pool.install(|| {
        (0..1000).into_par_iter().map(|i| {
            sahyadri_dilithium::verify_signature_bytes(
                &msgs[i % 100], &sigs[i % 100], &pk_bytes,
            )
        }).collect::<Vec<bool>>()
    });

    // Benchmark: 100,000 verifications
    let n = 100_000u32;
    let t0 = Instant::now();
    let results: Vec<bool> = pool.install(|| {
        (0..n).into_par_iter().map(|i| {
            sahyadri_dilithium::verify_signature_bytes(
                &msgs[(i as usize) % 100],
                &sigs[(i as usize) % 100],
                &pk_bytes,
            )
        }).collect()
    });
    let elapsed = t0.elapsed();

    let valid = results.iter().filter(|&&r| r).count();

    println!("\n=== Sahyadri Dilithium3 multi-threaded verify ===");
    println!("Iterations:      {}", n);
    println!("Valid:           {}/{}", valid, n);
    println!("Threads:         {}", threads);
    println!("Total time:      {:?}", elapsed);
    println!("Per verify:      {:.4} ms", elapsed.as_secs_f64() * 1000.0 / n as f64);
    println!("Throughput:      {:.0} verify/sec (real, {}-thread)", n as f64 / elapsed.as_secs_f64(), threads);
}
