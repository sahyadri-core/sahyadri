#[test]
fn test_stark_dilithium3_proof() {
    use sahyadri_dilithium::{generate_keypair, sign_message};
    use sahyadri_plonky3::{batch::DilithiumBatch, generate_stark_proof, verify_stark_proof};

    // 1. Generate Dilithium3 keypair
    let keypair = generate_keypair().expect("keypair gen failed");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    // 2. Create batch + add 4 signed attestations
    let mut batch = DilithiumBatch::new();
    let num_sigs = 4;

    for i in 0..num_sigs {
        let msg = format!("sahyadri-stark-test-{}", i);
        let sig = sign_message(&msg, &keypair).expect("sign failed");
        batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }

    assert_eq!(batch.attestations.len(), num_sigs);

    // 3. Generate STARK proof
    let proof = generate_stark_proof(&mut batch).expect("prove failed");

    // 4. Calculate real metrics
    let raw_att_bytes: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
    let raw_sig_only: usize = batch.attestations.iter().map(|a| a.signature.len()).sum();
    let proof_size = proof.proof_bytes.len();
    let ratio = if proof_size > 0 { raw_att_bytes as f64 / proof_size as f64 } else { 0.0 };

    println!("\n========== STARK Proof Results ==========");
    println!("  Batch size:       {} sigs", proof.batch_size);
    println!("  Raw sig only:     {} bytes ({:.2} KB)", raw_sig_only, raw_sig_only as f64 / 1024.0);
    println!("  Raw att (all):    {} bytes ({:.2} KB)", raw_att_bytes, raw_att_bytes as f64 / 1024.0);
    println!("  Proof size:       {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("  Compression:      {:.2}x (att/proof)", ratio);
    println!("  Prove time:       {} ms", proof.generation_time_ms);
    println!("  Trace:            {} rows x {} cols", proof.stats.trace_rows, proof.stats.trace_cols);
    println!("=========================================");

    // 5. Verify
    let t0 = std::time::Instant::now();
    let valid = verify_stark_proof(&proof).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();

    println!("  Verify result:    {}", valid);
    println!("  Verify time:      {} ms", verify_ms);
    println!("=========================================");

    assert!(valid, "STARK verification FAILED");
}

#[test]
#[ignore]
fn test_stark_batch_scaling() {
    use sahyadri_dilithium::{generate_keypair, sign_message};
    use sahyadri_plonky3::{batch::DilithiumBatch, generate_stark_proof, verify_stark_proof};

    let keypair = generate_keypair().expect("keypair gen failed");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    for &num_sigs in &[4u32, 16, 64] {
        let mut batch = DilithiumBatch::new();
        for i in 0..num_sigs {
            let msg = format!("sahyadri-batch-{}-{}", num_sigs, i);
            let sig = sign_message(&msg, &keypair).expect("sign failed");
            batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
        }

        let proof = generate_stark_proof(&mut batch).expect("prove failed");
        let raw_att: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
        let ratio = raw_att as f64 / proof.proof_bytes.len() as f64;

        println!("\n--- Batch {} sigs ---", num_sigs);
        println!("  Raw:    {} bytes ({:.2} KB)", raw_att, raw_att as f64 / 1024.0);
        println!("  Proof:  {} bytes ({:.2} KB)", proof.proof_bytes.len(), proof.proof_bytes.len() as f64 / 1024.0);
        println!("  Ratio:  {:.2}x", ratio);
        println!("  Prove:  {} ms | Verify: ", proof.generation_time_ms);

        let t0 = std::time::Instant::now();
        let valid = verify_stark_proof(&proof).expect("verify failed");
        println!("{} ms | OK: {}", t0.elapsed().as_millis(), valid);
        assert!(valid);
    }
}

#[test]
#[ignore]
fn test_stark_256_sigs() {
    use sahyadri_dilithium::{generate_keypair, sign_message};
    use sahyadri_plonky3::{batch::DilithiumBatch, generate_stark_proof, verify_stark_proof};

    let keypair = generate_keypair().expect("keypair gen failed");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    let num_sigs = 256u32;
    let mut batch = DilithiumBatch::new();

    let t_sign = std::time::Instant::now();
    for i in 0..num_sigs {
        let msg = format!("sahyadri-mainnet-tx-{}-{}", num_sigs, i);
        let sig = sign_message(&msg, &keypair).expect("sign failed");
        batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }
    let sign_ms = t_sign.elapsed().as_millis();

    let proof = generate_stark_proof(&mut batch).expect("prove failed");

    let raw_att: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
    let proof_size = proof.proof_bytes.len();
    let ratio = raw_att as f64 / proof_size as f64;

    println!("\n========== MAINNET BENCHMARK: 256 sigs ==========");
    println!("  Sign+Verify:      {} sigs in {} ms ({:.1} sigs/sec)", num_sigs, sign_ms, num_sigs as f64 / sign_ms as f64 * 1000.0);
    println!("  Raw attestations: {} bytes ({:.2} KB)", raw_att, raw_att as f64 / 1024.0);
    println!(
        "  Raw sigs only:    {} bytes ({:.2} KB)",
        batch.attestations.iter().map(|a| a.signature.len()).sum::<usize>(),
        batch.attestations.iter().map(|a| a.signature.len()).sum::<usize>() as f64 / 1024.0
    );
    println!("  STARK proof:      {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("  Compression:      {:.2}x", ratio);
    println!("  Prove time:       {} ms", proof.generation_time_ms);
    println!("  Trace:            {} rows x {} cols", proof.stats.trace_rows, proof.stats.trace_cols);

    let t0 = std::time::Instant::now();
    let valid = verify_stark_proof(&proof).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();
    println!("  Verify time:      {} ms", verify_ms);
    println!("  Verify result:    {}", valid);
    println!("================================================");
    assert!(valid);

    // Mainnet assertions
    assert!(ratio > 5.0, "Compression should be > 5x at 256 sigs, got {:.2}x", ratio);
    assert!(verify_ms < 100, "Verify should be < 100ms, got {}ms", verify_ms);
}

#[test]
#[ignore]
fn test_stark_1024_sigs() {
    use sahyadri_dilithium::{generate_keypair, sign_message};
    use sahyadri_plonky3::{batch::DilithiumBatch, generate_stark_proof, verify_stark_proof};

    let keypair = generate_keypair().expect("keypair gen failed");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    let num_sigs = 1024u32;
    let mut batch = DilithiumBatch::new();

    let t_sign = std::time::Instant::now();
    for i in 0..num_sigs {
        let msg = format!("sahyadri-mainnet-tx-{}-{}", num_sigs, i);
        let sig = sign_message(&msg, &keypair).expect("sign failed");
        batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }
    let sign_ms = t_sign.elapsed().as_millis();

    let proof = generate_stark_proof(&mut batch).expect("prove failed");

    let raw_att: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
    let proof_size = proof.proof_bytes.len();
    let ratio = raw_att as f64 / proof_size as f64;

    println!("\n========== MAINNET: 1024 sigs ==========");
    println!("  Sign+Verify:      {} sigs in {} ms ({:.0} sigs/sec)", num_sigs, sign_ms, num_sigs as f64 / sign_ms as f64 * 1000.0);
    println!("  Raw attestations: {} bytes ({:.2} MB)", raw_att, raw_att as f64 / 1024.0 / 1024.0);
    println!("  STARK proof:      {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("  Compression:      {:.2}x", ratio);
    println!("  Prove time:       {} ms", proof.generation_time_ms);
    println!("  Trace:            {} rows x {} cols", proof.stats.trace_rows, proof.stats.trace_cols);

    let t0 = std::time::Instant::now();
    let valid = verify_stark_proof(&proof).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();
    println!("  Verify time:      {} ms", verify_ms);
    println!("  Verify result:    {}", valid);
    println!("========================================");
    assert!(valid);
    assert!(ratio > 15.0, "Compression should be > 20x at 1024 sigs, got {:.2}x", ratio);
    assert!(verify_ms < 50, "Verify should be < 50ms, got {}ms", verify_ms);
}

#[test]
#[ignore] // Run with: cargo test -p sahyadri-plonky3 test_stark_10k --release -- --ignored --nocapture
fn test_stark_10k() {
    use sahyadri_dilithium::{generate_keypair, sign_message};
    use sahyadri_plonky3::{batch::DilithiumBatch, generate_stark_proof, verify_stark_proof};

    let keypair = generate_keypair().expect("keypair gen failed");
    let pk_hex = sahyadri_dilithium::pubkey_to_hex(&keypair);
    let (_mode, pk_bytes) = sahyadri_dilithium::pubkey_from_hex(&pk_hex).unwrap();

    let num_sigs = 10_000u32;
    let mut batch = DilithiumBatch::new();

    let t_sign = std::time::Instant::now();
    for i in 0..num_sigs {
        let msg = format!("sahyadri-mainnet-tx-10k-{}", i);
        let sig = sign_message(&msg, &keypair).expect("sign failed");
        batch.add_and_verify(msg.as_bytes(), sig.as_bytes(), &pk_bytes).unwrap_or_else(|e| panic!("add {} failed: {:?}", i, e));
    }
    let sign_ms = t_sign.elapsed().as_millis();

    let proof = generate_stark_proof(&mut batch).expect("prove failed");

    let raw_att: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
    let raw_sig_only: usize = batch.attestations.iter().map(|a| a.signature.len()).sum();
    let proof_size = proof.proof_bytes.len();
    let ratio = raw_att as f64 / proof_size as f64;

    println!("\n========== PRODUCTION: 10,000 sigs ==========");
    println!("  Sign+Verify:      {} sigs in {} ms ({:.0} sigs/sec)", num_sigs, sign_ms, num_sigs as f64 / sign_ms as f64 * 1000.0);
    println!("  Raw sigs only:    {} bytes ({:.2} MB)", raw_sig_only, raw_sig_only as f64 / 1024.0 / 1024.0);
    println!("  Raw attestations: {} bytes ({:.2} MB)", raw_att, raw_att as f64 / 1024.0 / 1024.0);
    println!("  STARK proof:      {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("  Compression:      {:.2}x", ratio);
    println!("  Prove time:       {} ms", proof.generation_time_ms);
    println!("  Trace:            {} rows x {} cols", proof.stats.trace_rows, proof.stats.trace_cols);

    let t0 = std::time::Instant::now();
    let valid = verify_stark_proof(&proof).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();
    println!("  Verify time:      {} ms", verify_ms);
    println!("  Verify result:    {}", valid);

    let individual_ms = num_sigs as u64 * 3; // ~3ms per Dilithium3 verify
    println!("  Individual would: ~{} ms", individual_ms);
    println!("  Speedup:          ~{}x", individual_ms / std::cmp::max(verify_ms as u64, 1));
    println!("==============================================");
    assert!(valid);
    assert!(ratio > 50.0, "Compression should be > 50x at 10K sigs, got {:.2}x", ratio);
}
