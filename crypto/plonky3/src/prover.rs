//! # STARK Prover — TRUE ZK Dilithium3 Verification
use crate::batch::{BatchProof, DilithiumBatch, ProverStats, ZKPError};
use crate::dilithium_stark::composed_stark::prove_signature;
use crate::dilithium_stark::witness::verify_with_witness;
use log::info;
use std::time::Instant;

pub fn generate_stark_proof(batch: &mut DilithiumBatch) -> Result<BatchProof, ZKPError> {
    if batch.is_empty() {
        return Err(ZKPError::EmptyBatch);
    }
    let start = Instant::now();
    let batch_size = batch.len();
    info!("[STARK-PROVER] TRUE-ZK: composed sub-STARK proofs for {} sigs", batch_size);
    let mut sig_proofs = Vec::with_capacity(batch_size);
    for (i, att) in batch.attestations.iter().enumerate() {
        info!("[STARK-PROVER] Proving sig {}/{}...", i + 1, batch_size);
        let w = verify_with_witness(&att.signature, &att.public_key, &att.message)
            .map_err(|e| ZKPError::ProofGenerationFailed(format!("witness {} failed: {}", i, e)))?;
        if !w.valid {
            return Err(ZKPError::VerificationFailed { index: i });
        }
        let sp = prove_signature(&w).map_err(|e| ZKPError::ProofGenerationFailed(format!("prove sig {} failed: {}", i, e)))?;
        sig_proofs.push(sp);
    }
    let commitment_root = batch.commitment_root();
    let proof_bytes = bincode::serialize(&sig_proofs).map_err(|e| ZKPError::ProofSerializationFailed(e.to_string()))?;
    let prove_ms = start.elapsed().as_millis() as u64;
    let raw_bytes: usize = batch.attestations.iter().map(|a| a.message.len() + a.signature.len() + a.public_key.len()).sum();
    let proof_len = proof_bytes.len();
    let ratio = raw_bytes.checked_div(proof_len).unwrap_or(0);
    info!("[STARK-PROVER] Done: {} sigs -> {} bytes ({}x) in {}ms", batch_size, proof_len, ratio, prove_ms);
    Ok(BatchProof {
        proof_bytes,
        commitment_root,
        batch_size: batch_size as u32,
        version: crate::PROOF_FORMAT_VERSION,
        generation_time_ms: prove_ms,
        stats: ProverStats {
            batch_size,
            raw_signature_bytes: raw_bytes,
            compressed_proof_bytes: proof_len,
            compression_ratio: ratio,
            prove_time_ms: prove_ms,
            verify_time_ms: 0,
            trace_rows: 0,
            trace_cols: 0,
        },
    })
}

pub fn prove_batch(messages: &[Vec<u8>], signatures: &[Vec<u8>], public_keys: &[Vec<u8>]) -> Result<BatchProof, ZKPError> {
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return Err(ZKPError::ProofGenerationFailed("messages/signatures/pubkeys length mismatch".into()));
    }
    let mut batch = DilithiumBatch::new();
    for i in 0..messages.len() {
        batch.add_and_verify(&messages[i], &signatures[i], &public_keys[i]).map_err(|e| {
            log::error!("[STARK-PROVER] sig {} failed: {}", i, e);
            e
        })?;
    }
    info!("[STARK-PROVER] {} sigs added, generating TRUE-ZK proof...", batch.len());
    generate_stark_proof(&mut batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_proof_empty_batch_fails() {
        assert!(generate_stark_proof(&mut DilithiumBatch::new()).is_err());
    }
}
