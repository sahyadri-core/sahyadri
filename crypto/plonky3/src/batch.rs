//! # Batch Management
//!
//! Collects (message, signature, pubkey) tuples, verifies each with dilithium-rs,
//! computes Merkle commitment root, prepares data for STARK proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::MAX_BATCH_SIZE;

#[derive(Error, Debug)]
pub enum ZKPError {
    #[error("Batch is empty")]
    EmptyBatch,
    #[error("Batch size {0} exceeds max {MAX_BATCH_SIZE}")]
    BatchTooLarge(usize),
    #[error("Signature size mismatch: got {0}, expected {1}")]
    SignatureSizeMismatch(usize, usize),
    #[error("Public key size mismatch: got {0}, expected {1}")]
    PubkeySizeMismatch(usize, usize),
    #[error("Dilithium verify failed at index {index}")]
    VerificationFailed { index: usize },
    #[error("STARK proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("STARK proof verification failed: {0}")]
    ProofVerificationFailed(String),
    #[error("Proof serialization failed: {0}")]
    ProofSerializationFailed(String),
    #[error("Proof deserialization failed: {0}")]
    ProofDeserializationFailed(String),
    #[error("Invalid proof version: {0}")]
    InvalidProofVersion(u8),
}

/// One Dilithium3 verification statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumAttestation {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub index: u32,
    #[serde(skip)]
    pub attestation_hash: [u8; 32],
}

/// Batch of verified Dilithium attestations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumBatch {
    pub attestations: Vec<DilithiumAttestation>,
    pub commitment_root: Option<[u8; 32]>,
    pub created_at: u64,
}

/// The compressed STARK proof replacing 33 MB of raw signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProof {
    pub proof_bytes: Vec<u8>,
    pub commitment_root: [u8; 32],
    pub batch_size: u32,
    pub version: u8,
    pub generation_time_ms: u64,
    pub stats: ProverStats,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProverStats {
    pub batch_size: usize,
    pub raw_signature_bytes: usize,
    pub compressed_proof_bytes: usize,
    pub compression_ratio: usize,
    pub prove_time_ms: u64,
    pub verify_time_ms: u64,
    pub trace_rows: usize,
    pub trace_cols: usize,
}

/// Domain-separated SHA-256 of one attestation.
pub fn hash_attestation(att: &DilithiumAttestation) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sahyadri-attestation-v2");
    h.update(&att.index.to_le_bytes());
    h.update(&(att.message.len() as u64).to_le_bytes());
    h.update(&att.message);
    h.update(&(att.signature.len() as u64).to_le_bytes());
    h.update(&att.signature);
    h.update(&(att.public_key.len() as u64).to_le_bytes());
    h.update(&att.public_key);
    let hash = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Binary Merkle root from 32-byte leaves (SHA-256, odd = duplicate last).
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut cur: Vec<[u8; 32]> = leaves.to_vec();
    while cur.len() > 1 {
        let mut nxt = Vec::with_capacity((cur.len() + 1) / 2);
        for chunk in cur.chunks(2) {
            let mut h = Sha256::new();
            h.update(&chunk[0]);
            h.update(if chunk.len() > 1 { &chunk[1] } else { &chunk[0] });
            let hash = h.finalize();
            let mut r = [0u8; 32];
            r.copy_from_slice(&hash);
            nxt.push(r);
        }
        cur = nxt;
    }
    cur[0]
}

impl DilithiumBatch {
    pub fn new() -> Self {
        Self {
            attestations: Vec::with_capacity(256),
            commitment_root: None,
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        }
    }

    /// Add pre-verified attestation.
    pub fn add(&mut self, mut att: DilithiumAttestation) -> Result<(), ZKPError> {
        if self.attestations.len() >= MAX_BATCH_SIZE {
            return Err(ZKPError::BatchTooLarge(self.attestations.len()));
        }
        att.index = self.attestations.len() as u32;
        att.attestation_hash = hash_attestation(&att);
        self.attestations.push(att);
        Ok(())
    }

    /// Add attestation + auto-verify with dilithium.
    pub fn add_and_verify(&mut self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), ZKPError> {
        const EXPECTED_SIG: usize = 3309;
        const EXPECTED_PK: usize = 1952;

        if signature.len() != EXPECTED_SIG {
            return Err(ZKPError::SignatureSizeMismatch(signature.len(), EXPECTED_SIG));
        }
        if public_key.len() != EXPECTED_PK {
            return Err(ZKPError::PubkeySizeMismatch(public_key.len(), EXPECTED_PK));
        }

        let idx = self.attestations.len();
        crate::dilithium_stark::zk_verify::verify_dilithium_native(signature, public_key, message).map_err(|e| {
            log::warn!("[ZKP] Dilithium verify failed at {}: {}", idx, e);
            ZKPError::VerificationFailed { index: idx }
        })?;

        let mut att = DilithiumAttestation {
            message: message.to_vec(),
            signature: signature.to_vec(),
            public_key: public_key.to_vec(),
            index: idx as u32,
            attestation_hash: [0u8; 32],
        };
        att.attestation_hash = hash_attestation(&att);
        self.attestations.push(att);
        Ok(())
    }

    pub fn compute_commitment(&mut self) -> [u8; 32] {
        if self.attestations.is_empty() {
            return [0u8; 32];
        }
        let leaves: Vec<[u8; 32]> = self.attestations.iter().map(|a| a.attestation_hash).collect();
        let root = compute_merkle_root(&leaves);
        self.commitment_root = Some(root);
        root
    }

    pub fn commitment_root(&mut self) -> [u8; 32] {
        self.commitment_root.unwrap_or_else(|| self.compute_commitment())
    }

    pub fn attestation_hashes(&self) -> Vec<[u8; 32]> {
        self.attestations.iter().map(|a| a.attestation_hash).collect()
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

impl Default for DilithiumBatch {
    fn default() -> Self {
        Self::new()
    }
}
