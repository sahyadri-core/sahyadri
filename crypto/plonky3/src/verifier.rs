//! # STARK Verifier — TRUE ZK Dilithium3 Verification
use std::time::Instant;
use log::info;
use crate::batch::{BatchProof, ZKPError};
use crate::dilithium_stark::composed_stark::{verify_signature, DilithiumSigProof};

pub fn verify_stark_proof(proof: &BatchProof) -> Result<bool, ZKPError> {
    let start = Instant::now();
    if proof.version != crate::PROOF_FORMAT_VERSION {
        return Err(ZKPError::InvalidProofVersion(proof.version));
    }
    if proof.proof_bytes.is_empty() {
        return Err(ZKPError::ProofVerificationFailed("Empty proof bytes".into()));
    }
    let sig_proofs: Vec<DilithiumSigProof> = bincode::deserialize(&proof.proof_bytes)
        .map_err(|e: Box<bincode::ErrorKind>| ZKPError::ProofDeserializationFailed(e.to_string()))?;
    if sig_proofs.len() != proof.batch_size as usize {
        return Err(ZKPError::ProofVerificationFailed(
            format!("Proof count {} != batch size {}", sig_proofs.len(), proof.batch_size)));
    }
    for (i, sp) in sig_proofs.iter().enumerate() {
        verify_signature(sp).map_err(|e| ZKPError::ProofVerificationFailed(format!("sig {}: {:?}", i, e)))?;
        // valid is now STARK-proved via FiatShamirAir (c_tilde == c2)
    }
    let ms = start.elapsed().as_millis();
    info!("[STARK-VERIFIER] VALID — {} sigs (TRUE-ZK composed), {} bytes, {}ms", proof.batch_size, proof.proof_bytes.len(), ms);
    Ok(true)
}

pub fn is_valid_proof(proof: &BatchProof) -> bool { verify_stark_proof(proof).unwrap_or(false) }

pub fn estimate_batch(batch_size: usize) -> crate::batch::ProverStats {
    let raw = batch_size * 3309;
    let proof_est = match batch_size { 0..=1=>200_000, 2..=5=>500_000, _=>batch_size*150_000 };
    crate::batch::ProverStats { batch_size, raw_signature_bytes: raw, compressed_proof_bytes: proof_est,
        compression_ratio: if proof_est>0{raw/proof_est}else{0}, prove_time_ms: 0,
        verify_time_ms: batch_size as u64, trace_rows: 0, trace_cols: 0 }
}
