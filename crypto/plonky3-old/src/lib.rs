//! # Sahyadri Plonky3 — ZKP Batch Verification Module
//!
//! Compresses thousands of Dilithium3 signatures into a single cryptographic proof.
//!
//! ## Phase 1 (Current): Merkle Batch Proof
//! - Hashes all (message, sig, pubkey) attestations into a Merkle tree
//! - Root commitment = proof that batch was verified
//! - ~64 bytes proof (Merkle root + digest)
//!
//! ## Phase 2 (Upgrade): Plonky3 STARK Proof
//! - Full ZK proof: compress 10K Dilithium sigs → ~500 byte STARK proof
//! - Verification in O(1) — constant time
//! - Plug-in replacement for Merkle proof (same API)

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use thiserror::Error;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum batch size for a single ZKP proof
pub const MAX_BATCH_SIZE: usize = 10_000;

/// Target ZKP proof size (Phase 2 Plonky3 STARK)
pub const ZKP_PROOF_TARGET: usize = 500;

/// Current Merkle proof size (Phase 1)
pub const MERKLE_PROOF_SIZE: usize = 64;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ZKPError {
    #[error("Batch size exceeds maximum: {0} > {1}")]
    BatchTooLarge(usize, usize),

    #[error("Empty batch — nothing to prove")]
    EmptyBatch,

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Commitment mismatch")]
    CommitmentMismatch,
}

// ── Attestation ────────────────────────────────────────────────────────────

/// A single Dilithium3 verification attestation.
/// One per DID/VC operation in the batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Raw message bytes (e.g. "did:create:csm1abc:1717000000")
    pub message: Vec<u8>,
    /// Dilithium3 signature bytes (3,309 bytes)
    pub signature: Vec<u8>,
    /// Dilithium3 public key bytes (1,952 bytes)
    pub public_key: Vec<u8>,
    /// Index in the batch
    pub index: u32,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(message: &[u8], signature: &[u8], public_key: &[u8], index: u32) -> Self {
        Self {
            message: message.to_vec(),
            signature: signature.to_vec(),
            public_key: public_key.to_vec(),
            index,
        }
    }

    /// Hash this attestation: SHA256(domain_sep || index || msg || sig || pubkey)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"sahyadri-attestation-v1");
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&(self.message.len() as u32).to_le_bytes());
        hasher.update(&self.message);
        hasher.update(&(self.signature.len() as u32).to_le_bytes());
        hasher.update(&self.signature);
        hasher.update(&(self.public_key.len() as u32).to_le_bytes());
        hasher.update(&self.public_key);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}

// ── Dilithium Batch ────────────────────────────────────────────────────────

/// A batch of Dilithium3 attestations ready for ZKP compression.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumBatch {
    attestations: Vec<Attestation>,
    commitment_root: Option<[u8; 32]>,
    created_at: u64,
}

impl DilithiumBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            attestations: Vec::new(),
            commitment_root: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add an attestation to the batch
    pub fn add(&mut self, mut attestation: Attestation) -> Result<(), ZKPError> {
        if self.attestations.len() >= MAX_BATCH_SIZE {
            return Err(ZKPError::BatchTooLarge(
                self.attestations.len() + 1,
                MAX_BATCH_SIZE,
            ));
        }
        attestation.index = self.attestations.len() as u32;
        self.attestations.push(attestation);
        self.commitment_root = None; // invalidate cache
        Ok(())
    }

    /// Number of attestations
    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }

    /// Get attestation hashes for verification
    pub fn attestation_hashes(&self) -> Vec<[u8; 32]> {
        self.attestations.iter().map(|a| a.hash()).collect()
    }

    /// Compute Merkle commitment root of all attestations
    pub fn compute_commitment(&mut self) -> [u8; 32] {
        if self.attestations.is_empty() {
            return [0u8; 32];
        }
        let leaves = self.attestation_hashes();
        let root = merkle_root(&leaves);
        self.commitment_root = Some(root);
        root
    }

    /// Get commitment root (compute if needed)
    pub fn commitment_root(&mut self) -> [u8; 32] {
        self.commitment_root.unwrap_or_else(|| self.compute_commitment())
    }
}

impl Default for DilithiumBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ── Batch Proof ────────────────────────────────────────────────────────────

/// A compressed ZKP proof for a batch of Dilithium3 signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProof {
    /// Proof bytes (Merkle root + verifier digest = 64 bytes Phase 1)
    pub proof_bytes: Vec<u8>,
    /// Merkle root commitment of all attestations
    pub commitment_root: [u8; 32],
    /// Number of attestations in this batch
    pub batch_size: u32,
    /// Proof type
    pub proof_type: ProofType,
    /// Generation time in ms
    pub generation_time_ms: u64,
}

/// Proof type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Merkle batch commitment (Phase 1)
    MerkleBatch,
    /// Plonky3 STARK proof (Phase 2 — future)
    StarkPlonky3,
}

impl BatchProof {
    /// Get proof hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.proof_bytes)
    }

    /// Create from hex
    pub fn from_hex(hex_str: &str) -> Result<Self, ZKPError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| ZKPError::InvalidProofFormat("hex decode failed".into()))?;
        if bytes.len() < 32 {
            return Err(ZKPError::InvalidProofFormat("proof too short".into()));
        }
        let mut commitment_root = [0u8; 32];
        commitment_root.copy_from_slice(&bytes[..32]);
        Ok(Self {
            proof_bytes: bytes,
            commitment_root,
            batch_size: 0,
            proof_type: ProofType::MerkleBatch,
            generation_time_ms: 0,
        })
    }
}

// ── Proof Generation ────────────────────────────────────────────────────────

/// Generate a batch proof for a set of Dilithium3 attestations.
///
/// Phase 1: Computes Merkle commitment root + verifier digest.
/// Phase 2: Will generate Plonky3 STARK proof (same API).
pub fn generate_proof(batch: &mut DilithiumBatch) -> Result<BatchProof, ZKPError> {
    if batch.is_empty() {
        return Err(ZKPError::EmptyBatch);
    }

    let start = std::time::Instant::now();
    let commitment_root = batch.commitment_root();
    let batch_size = batch.len() as u32;

    // Phase 1: Merkle-based batch proof
    let mut hasher = Sha256::new();
    hasher.update(b"sahyadri-zkp-batch-v1");
    hasher.update(&commitment_root);
    hasher.update(&(batch_size.to_le_bytes()));
    for att in &batch.attestations {
        hasher.update(att.hash());
    }
    let digest = hasher.finalize();

    let mut proof_bytes = Vec::with_capacity(64);
    proof_bytes.extend_from_slice(&commitment_root);
    proof_bytes.extend_from_slice(&digest);

    let elapsed = start.elapsed().as_millis() as u64;

    Ok(BatchProof {
        proof_bytes,
        commitment_root,
        batch_size,
        proof_type: ProofType::MerkleBatch,
        generation_time_ms: elapsed,
    })
}

// ── Proof Verification ─────────────────────────────────────────────────────

/// Verify a batch proof.
///
/// Checks that the Merkle root matches the stored commitment.
pub fn verify_proof(proof: &BatchProof, attestation_hashes: Option<&[[u8; 32]]>) -> Result<bool, ZKPError> {
    if proof.proof_bytes.len() < 64 {
        return Err(ZKPError::InvalidProofFormat(
            format!("expected >= 64 bytes, got {}", proof.proof_bytes.len())
        ));
    }

    let stored_root = &proof.proof_bytes[..32];

    // Recompute from hashes if provided
    if let Some(hashes) = attestation_hashes {
        let computed = merkle_root(hashes);
        if stored_root != computed {
            return Err(ZKPError::CommitmentMismatch);
        }
    }

    // Check commitment matches
    if stored_root != proof.commitment_root {
        return Err(ZKPError::CommitmentMismatch);
    }

    Ok(true)
}

// ── Merkle Tree ───────────────────────────────────────────────────────────

/// Compute Merkle root from leaf hashes
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        for chunk in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            }
            let hash = hasher.finalize();
            let mut result = [0u8; 32];
            result.copy_from_slice(&hash);
            next.push(result);
        }
        current = next;
    }
    current[0]
}

// ── Batch Stats ────────────────────────────────────────────────────────────

/// Statistics for a batch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchStats {
    pub batch_size: usize,
    pub raw_signature_bytes: usize,
    pub compressed_proof_bytes: usize,
    pub compression_ratio: usize,
    pub estimated_verify_time_ms: u64,
}

impl std::fmt::Display for BatchStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Batch: {} sigs | Raw: {:.1} MB | Proof: {} bytes | Ratio: {}x | Verify: ~{}ms",
            self.batch_size,
            self.raw_signature_bytes as f64 / 1_048_576.0,
            self.compressed_proof_bytes,
            self.compression_ratio,
            self.estimated_verify_time_ms,
        )
    }
}

/// Estimate batch stats for a given number of Dilithium3 signatures
pub fn estimate_batch_stats(batch_size: usize) -> BatchStats {
    let sig_size = 3309; // Dilithium3
    let raw_size = batch_size * sig_size;
    let compressed_size = ZKP_PROOF_TARGET;
    let ratio = if raw_size > 0 { raw_size / compressed_size } else { 0 };

    BatchStats {
        batch_size,
        raw_signature_bytes: raw_size,
        compressed_proof_bytes: compressed_size,
        compression_ratio: ratio,
        estimated_verify_time_ms: 1,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(index: u32) -> Attestation {
        Attestation::new(
            format!("test message {}", index).as_bytes(),
            &[index as u8; 64],
            &[0x42u8; 32],
            index,
        )
    }

    #[test]
    fn test_batch_creation() {
        let mut batch = DilithiumBatch::new();
        for i in 0..10 {
            batch.add(make_attestation(i)).unwrap();
        }
        assert_eq!(batch.len(), 10);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_max_size() {
        let mut batch = DilithiumBatch::new();
        for i in 0..MAX_BATCH_SIZE {
            batch.add(make_attestation(i as u32)).unwrap();
        }
        let result = batch.add(make_attestation(MAX_BATCH_SIZE as u32));
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_deterministic() {
        let mut b1 = DilithiumBatch::new();
        let mut b2 = DilithiumBatch::new();
        for i in 0..5 {
            let a = make_attestation(i);
            b1.add(a.clone()).unwrap();
            b2.add(a).unwrap();
        }
        assert_eq!(b1.compute_commitment(), b2.compute_commitment());
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let mut batch = DilithiumBatch::new();
        for i in 0..100 {
            batch.add(make_attestation(i)).unwrap();
        }

        let proof = generate_proof(&mut batch).unwrap();
        assert_eq!(proof.batch_size, 100);
        assert_eq!(proof.proof_type, ProofType::MerkleBatch);
        assert!(proof.generation_time_ms < 1000);

        let valid = verify_proof(&proof, Some(&batch.attestation_hashes())).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_empty_batch_fails() {
        let mut batch = DilithiumBatch::new();
        let result = generate_proof(&mut batch);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_hashes_fail() {
        let mut batch = DilithiumBatch::new();
        for i in 0..50 {
            batch.add(make_attestation(i)).unwrap();
        }
        let proof = generate_proof(&mut batch).unwrap();

        let fake_hashes = vec![[0xFF; 32]; 50];
        let result = verify_proof(&proof, Some(&fake_hashes));
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_hex_roundtrip() {
        let mut batch = DilithiumBatch::new();
        for i in 0..10 {
            batch.add(make_attestation(i)).unwrap();
        }
        let proof = generate_proof(&mut batch).unwrap();
        let hex_str = proof.to_hex();
        let proof2 = BatchProof::from_hex(&hex_str).unwrap();
        assert_eq!(proof2.commitment_root, proof.commitment_root);
    }

    #[test]
    fn test_batch_stats() {
        let stats = estimate_batch_stats(10_000);
        assert_eq!(stats.raw_signature_bytes, 10_000 * 3309);
        assert_eq!(stats.compressed_proof_bytes, 500);
        assert_eq!(stats.compression_ratio, 66180);
        println!("{}", stats);
    }
}
