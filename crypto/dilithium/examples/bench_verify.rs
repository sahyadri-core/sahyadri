//! AVX2 verification benchmark — single-threaded, measures raw NTT speedup.

use std::time::Instant;

use sahyadri_dilithium::{generate_keypair, pubkey_from_hex, pubkey_to_hex, sign_message};

fn main() {
    // Setup: one keypair, one message, one signature
    let keypair = generate_keypair().expect("keypair");
    let pk_hex = pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = pubkey_from_hex(&pk_hex).expect("pk");

    let msg = "sahyadri-bench-msg";
    let sig = sign_message(msg, &keypair).expect("sign");
    let sig_bytes = sig.as_bytes();

    // Correct API: verify_signature_bytes(message: &str, sig_bytes: &[u8], pk: &[u8]) -> bool
    let verify = |sig: &[u8], msg: &str, pk: &[u8]| -> bool {
        sahyadri_dilithium::verify_signature_bytes(msg, sig, pk)
    };

    // Warmup
    for _ in 0..100 {
        let _ = verify(sig_bytes, msg, &pk_bytes);
    }

    // Single-thread benchmark
    let n = 10_000u32;
    let t0 = Instant::now();
    let mut ok = 0u32;
    for _ in 0..n {
        if verify(sig_bytes, msg, &pk_bytes) {
            ok += 1;
        }
    }
    let elapsed = t0.elapsed();

    println!("\n=== Sahyadri Dilithium3 verify benchmark ===");
    println!("Iterations:      {}", n);
    println!("Valid:           {}/{}", ok, n);
    println!("Total time:      {:?}", elapsed);
    println!("Per verify:      {:.4} ms", elapsed.as_secs_f64() * 1000.0 / n as f64);
    println!("Throughput:      {:.0} verify/sec (1 thread)", n as f64 / elapsed.as_secs_f64());

    // Extrapolate with available threads
    let threads = std::thread::available_parallelism()
        .map(|n| n.get() - 1)
        .unwrap_or(1)
        .max(1);
    let single_thread_sec = elapsed.as_secs_f64() / n as f64;
    let multi_thread_sec = single_thread_sec / threads as f64;

    println!("\n=== Extrapolation ===");
    println!("Available threads:   {}", threads);
    println!("Per verify (1T):     {:.4} ms", single_thread_sec * 1000.0);
    println!("Per verify ({}T par): {:.4} ms", threads, multi_thread_sec * 1000.0);
    println!("Throughput ({}T):     {:.0} verify/sec", threads, 1.0 / multi_thread_sec);
}
