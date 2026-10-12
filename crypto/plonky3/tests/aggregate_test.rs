//! Runtime tests for p3-recursion aggregation.
//!
//! Covers:
//!   * 2-to-1 pair aggregation (`aggregate_pair`)
//!   * N-to-1 binary-tree aggregation (`aggregate_batch`)
//!   * input validation (empty / odd / mismatch)
//!   * mining-safe local Rayon pool

use p3_uni_stark::Proof;
use sahyadri_dilithium::{generate_keypair, sign_message};
use sahyadri_plonky3::aggregate::{aggregate_batch, aggregate_pair, verify_root_proof, AggregateError};
use sahyadri_plonky3::batch::DilithiumBatch;
use sahyadri_plonky3::config::DilithiumStarkConfig;
use sahyadri_plonky3::dilithium_stark::composed_stark::DilithiumSigProof;
use sahyadri_plonky3::dilithium_stark::matrix_vec_stark::MatrixVecAir;
use sahyadri_plonky3::generate_stark_proof;

// ── Test helpers ────────────────────────────────────────────

/// Build a batch STARK proof over `n` distinct messages under one keypair,
/// extract the per-signature `Proof<DilithiumStarkConfig>`s.
fn make_proofs(n: usize) -> Vec<Proof<DilithiumStarkConfig>> {
    let keypair = generate_keypair().expect("keypair");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    let mut batch = DilithiumBatch::new();
    for i in 0..n {
        let msg = format!("agg-batch-{}", i);
        let sig = sign_message(&msg, &keypair).expect("sign");
        batch
            .add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes)
            .unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }

    let batch_proof = generate_stark_proof(&mut batch).expect("prove");
    let sig_proofs: Vec<DilithiumSigProof> =
        bincode::deserialize(&batch_proof.proof_bytes).expect("deserialize sig_proofs");
    assert_eq!(sig_proofs.len(), n, "expected {n} sig proofs");

    sig_proofs
        .into_iter()
        .map(|sp| bincode::deserialize(&sp.mv_proof).expect("deser mv_proof"))
        .collect()
}

// ── Existing 2-to-1 test ────────────────────────────────────

#[test]
fn test_aggregate_pair_runtime() {
    println!("\n========== aggregate_pair runtime test ==========");
    let mv_proofs = make_proofs(2);

    println!("Calling aggregate_pair...");
    let t0 = std::time::Instant::now();
    let result = aggregate_pair(
        &mv_proofs[0], &[],
        &mv_proofs[1], &[],
        &MatrixVecAir,
    );
    let elapsed = t0.elapsed();

    match result {
        Ok(root) => {
            let root_bytes = bincode::serialize(&root.0).expect("serialize root");
            println!("  SUCCESS");
            println!("  Root proof size: {} bytes", root_bytes.len());
            println!("  Time: {:.2}s", elapsed.as_secs_f64());
        }
        Err(e) => {
            println!("  FAILED: {:?}", e);
            println!("  Time: {:.2}s", elapsed.as_secs_f64());
            panic!("aggregation failed");
        }
    }
}

// ── N-to-1 tree tests ───────────────────────────────────────

#[test]
fn test_aggregate_batch_4() {
    println!("\n========== aggregate_batch N=4 (2 layers) ==========");
    let mv_proofs = make_proofs(4);
    let publics: Vec<Vec<_>> = vec![Vec::new(); 4];

    let t0 = std::time::Instant::now();
    let root = aggregate_batch(mv_proofs, publics, &MatrixVecAir, 6)
        .expect("aggregate_batch N=4");
    let elapsed = t0.elapsed();

    let root_bytes = bincode::serialize(&root.0).expect("serialize root");
    println!("  Root proof size: {} bytes", root_bytes.len());
    println!("  Time: {:.2}s", elapsed.as_secs_f64());

    // Root size should be near the pair-case size (~626 KB), independent of N.
    assert!(root_bytes.len() > 100_000, "root proof suspiciously small");
}

// ── Input validation ────────────────────────────────────────

#[test]
fn test_empty_rejected() {
    let result = aggregate_batch::<MatrixVecAir>(vec![], vec![], &MatrixVecAir, 2);
    assert!(matches!(result, Err(AggregateError::Empty)));
}

#[test]
fn test_odd_count_rejected() {
    let mv_proofs = make_proofs(3);
    let publics: Vec<Vec<_>> = vec![Vec::new(); 3];
    let result = aggregate_batch(mv_proofs, publics, &MatrixVecAir, 2);
    match result {
        Err(AggregateError::Config(msg)) => {
            assert!(msg.contains("even"), "unexpected error msg: {msg}");
        }
        other => panic!("expected Config error, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn test_length_mismatch_rejected() {
    let mv_proofs = make_proofs(4);
    let publics: Vec<Vec<_>> = vec![Vec::new(); 3]; // wrong length
    let result = aggregate_batch(mv_proofs, publics, &MatrixVecAir, 2);
    match result {
        Err(AggregateError::Config(msg)) => {
            assert!(msg.contains("mismatch"), "unexpected error msg: {msg}");
        }
        other => panic!("expected Config error, got {:?}", other.map(|_| ())),
    }
}

// ── Mining-safe pool ────────────────────────────────────────

#[test]
fn test_mining_safe_pool_creates_and_aggregates() {
    println!("\n========== mining-safe pool (threads=2) ==========");
    let mv_proofs = make_proofs(2);
    let publics: Vec<Vec<_>> = vec![Vec::new(); 2];

    // Global Rayon pool size — must be unchanged after we build our local pool.
    // (Rayon doesn't expose "global pool threads" portably, so we assert we
    //  don't panic and the aggregation completes.)
    let t0 = std::time::Instant::now();
    let root = aggregate_batch(mv_proofs, publics, &MatrixVecAir, 2)
        .expect("aggregate_batch with local pool");
    let elapsed = t0.elapsed();
    println!("  Time (2 threads): {:.2}s", elapsed.as_secs_f64());

    let root_bytes = bincode::serialize(&root.0).expect("serialize root");
    assert!(root_bytes.len() > 100_000);

    // Global pool remains usable — sanity check.
    use rayon::prelude::*;
    let sum: u64 = (0..1000u64).into_par_iter().sum();
    assert_eq!(sum, 499_500);
}

#[test]
fn test_aggregate_batch_8() {
    println!("\n========== aggregate_batch N=8 (3 layers) ==========");
    let mv_proofs = make_proofs(8);
    let publics: Vec<Vec<_>> = vec![Vec::new(); 8];

    let t0 = std::time::Instant::now();
    let root = aggregate_batch(mv_proofs, publics, &MatrixVecAir, 16)
        .expect("aggregate_batch N=8");
    let elapsed = t0.elapsed();

    let root_bytes = bincode::serialize(&root.0).expect("serialize root");
    println!("  Root proof size: {} bytes", root_bytes.len());
    println!("  Time: {:.2}s", elapsed.as_secs_f64());

    // ── Verify root proof ───────────────────────────────
    println!("  Verifying root proof...");
    let t_verify = std::time::Instant::now();
    verify_root_proof(&root).expect("root proof must verify");
    println!("Verified in {:.3}s", t_verify.elapsed().as_secs_f64());

    assert!(root_bytes.len() > 100_000);
}

// ── Tamper rejection (proof integrity binding) ──────────────

#[test]
fn test_root_proof_rejects_tampered_proof() {
    println!("\n========== Tampered proof rejection test ==========");

    // ── Positive control: honest pair verifies. ─────────
    {
        let honest = make_proofs(2);
        let root = aggregate_batch(honest, vec![vec![]; 2], &MatrixVecAir, 16)
            .expect("aggregate honest");
        verify_root_proof(&root).expect("honest root must verify");
        println!("  Honest pair: verified");
    }

    // ── Negative: tamper a byte in one proof, expect rejection. ──
    let mut tampered = make_proofs(2);

    // Serialize → flip byte → deserialize. If the codec rejects, we're done.
    let mut bytes = bincode::serialize(&tampered[1]).expect("serialize");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;

    let tampered_proof: Proof<DilithiumStarkConfig> = match bincode::deserialize(&bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("  Tampered proof: rejected at deserialize: {e}");
            return;
        }
    };
    tampered[1] = tampered_proof;

    let result = aggregate_batch(tampered, vec![vec![]; 2], &MatrixVecAir, 16);
    match result {
        Ok(root) => {
            assert!(
                verify_root_proof(&root).is_err(),
                "TAMPERED PROOF VERIFIED — proof integrity binding is BROKEN!"
            );
            println!("  Tampered proof: rejected at verify");
        }
        Err(e) => {
            println!("  Tampered proof: rejected at prove: {e:?}");
        }
    }
}

// ── Mining hashrate benchmark ───────────────────────────────

/// Simulated mining: CPU-bound hash loop on `n` threads.
/// Returns total hashes done.
fn run_mining(threads: usize, duration_ms: u64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let c = counter.clone();
            let s = stop.clone();
            std::thread::spawn(move || {
                let mut local: u64 = t as u64;
                let mut batch_count: u64 = 0;
                loop {
                    // Simple hash-like work (proves CPU usage)
                    for _ in 0..10_000 {
                        local = local.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        local ^= local >> 33;
                        local = local.wrapping_mul(0xff51afd7ed558ccd);
                    }
                    batch_count += 10_000;
                    c.fetch_add(10_000, Ordering::Relaxed);
                    if s.load(Ordering::Relaxed) {
                        break;
                    }
                }
                let _ = batch_count;
            })
        })
        .collect();

    std::thread::sleep(std::time::Duration::from_millis(duration_ms));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    let _ = Instant::now();
    counter.load(Ordering::Relaxed)
}

#[test]
fn test_mining_hashrate_under_aggregation() {
    println!("\n========== Mining hashrate benchmark ==========");
    let total_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("  Available threads: {}", total_threads);

    // ── Baseline: mining alone (12 threads, 3s) ─────────────
    let mining_threads = 12.min(total_threads);
    let baseline = run_mining(mining_threads, 3_000);
    let baseline_rate = baseline as f64 / 3.0;
    println!("  Baseline ({} threads, alone): {:.0} ops/s", mining_threads, baseline_rate);

    // ── Case 1: aggregation threads=2 ───────────────────────
    let mv = make_proofs(2);
    let publics = vec![vec![]; 2];
    let mining_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mining_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handles: Vec<_> = (0..mining_threads)
        .map(|t| {
            let c = mining_counter.clone();
            let s = mining_stop.clone();
            std::thread::spawn(move || {
                let mut local: u64 = t as u64;
                loop {
                    for _ in 0..10_000 {
                        local = local.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        local ^= local >> 33;
                        local = local.wrapping_mul(0xff51afd7ed558ccd);
                    }
                    c.fetch_add(10_000, std::sync::atomic::Ordering::Relaxed);
                    if s.load(std::sync::atomic::Ordering::Relaxed) { break; }
                }
            })
        })
        .collect();

    let t0 = std::time::Instant::now();
    let _root = aggregate_batch(mv, publics, &MatrixVecAir, 2).expect("agg threads=2");
    let agg_time = t0.elapsed().as_secs_f64();

    mining_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in handles { h.join().unwrap(); }
    let mining_ops = mining_counter.load(std::sync::atomic::Ordering::Relaxed);
    let mining_rate = mining_ops as f64 / agg_time;
    println!("  Agg threads=2:  agg={:.2}s, mining={:.0} ops/s ({:.1}% of baseline)",
        agg_time, mining_rate, 100.0 * mining_rate / baseline_rate);

    // ── Case 2: aggregation threads=16 ──────────────────────
    let mv = make_proofs(2);
    let publics = vec![vec![]; 2];
    let mining_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mining_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handles: Vec<_> = (0..mining_threads)
        .map(|t| {
            let c = mining_counter.clone();
            let s = mining_stop.clone();
            std::thread::spawn(move || {
                let mut local: u64 = t as u64;
                loop {
                    for _ in 0..10_000 {
                        local = local.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        local ^= local >> 33;
                        local = local.wrapping_mul(0xff51afd7ed558ccd);
                    }
                    c.fetch_add(10_000, std::sync::atomic::Ordering::Relaxed);
                    if s.load(std::sync::atomic::Ordering::Relaxed) { break; }
                }
            })
        })
        .collect();

    let t0 = std::time::Instant::now();
    let _root = aggregate_batch(mv, publics, &MatrixVecAir, 16).expect("agg threads=16");
    let agg_time = t0.elapsed().as_secs_f64();

    mining_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in handles { h.join().unwrap(); }
    let mining_ops = mining_counter.load(std::sync::atomic::Ordering::Relaxed);
    let mining_rate = mining_ops as f64 / agg_time;
    println!("  Agg threads=16: agg={:.2}s, mining={:.0} ops/s ({:.1}% of baseline)",
        agg_time, mining_rate, 100.0 * mining_rate / baseline_rate);

    println!("\n  Benchmark complete");
}
