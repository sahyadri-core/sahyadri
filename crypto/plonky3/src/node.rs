//! # Sahyadri Node Integration
//!
//! Plugs STARK proof into block production and validation.
//!
//! ## Block Producer Flow:
//! 1. Collect transactions with Dilithium3 signatures
//! 2. Call `produce_block_with_proof()` → verifies all sigs + generates STARK proof
//! 3. Store `ZkpBlockData` in block header (proof + commitment_root + batch_size)
//!
//! ## Block Validator Flow:
//! 1. Extract `ZkpBlockData` from block header
//! 2. Call `validate_block_proof()` → STARK verify in ~1ms
//! 3. If valid → skip all individual sig verifications (save ~30s for 10K sigs)
//! 4. If invalid/rejected → fall back to individual verification

use crate::batch::{BatchProof, ProverStats, ZKPError};

/// ZKP data stored in the block header.
///
/// Wire format (serialized with bincode):
/// ```text
/// [version: 1B][batch_size: 4B LE][commitment_root: 32B][proof_bytes: ~30KB]
/// Total: ~30 KB per block (replaces 33 MB of raw signatures)
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkpBlockData {
    /// Proof format version (must be 1).
    pub version: u8,
    /// Number of signatures in this batch.
    pub batch_size: u32,
    /// Merkle root of all attestation hashes.
    /// Verifier must have access to the actual attestation data
    /// (stored off-chain or in block body) to reconstruct this.
    pub commitment_root: [u8; 32],
    /// Serialized STARK proof bytes.
    pub proof_bytes: Vec<u8>,
}

impl ZkpBlockData {
    /// Serialize for block header storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization failed")
    }

    /// Deserialize from block header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKPError> {
        bincode::deserialize(bytes).map_err(|e| ZKPError::ProofDeserializationFailed(e.to_string()))
    }

    /// Size in bytes when serialized.
    pub fn serialized_size(&self) -> usize {
        1 + 4 + 32 + self.proof_bytes.len()
    }
}

impl From<BatchProof> for ZkpBlockData {
    fn from(proof: BatchProof) -> Self {
        Self {
            version: proof.version,
            batch_size: proof.batch_size,
            commitment_root: proof.commitment_root,
            proof_bytes: proof.proof_bytes,
        }
    }
}

impl From<ZkpBlockData> for BatchProof {
    fn from(data: ZkpBlockData) -> Self {
        Self {
            proof_bytes: data.proof_bytes,
            commitment_root: data.commitment_root,
            batch_size: data.batch_size,
            version: data.version,
            generation_time_ms: 0,
            stats: ProverStats::default(),
        }
    }
}

/// Result of block validation with ZKP.
#[derive(Clone, Debug)]
pub struct ZkpValidationResult {
    /// Is the STARK proof valid?
    pub is_valid: bool,
    /// How many signatures are covered by this proof.
    pub batch_size: u32,
    /// Time taken to verify the STARK proof.
    pub verify_time_ms: u64,
    /// Time saved compared to individual verification.
    /// Estimated as: batch_size * 3ms (approximate Dilithium3 verify time).
    pub estimated_time_saved_ms: u64,
}

/// Block Producer: verify sigs + generate STARK proof in one call.
///
/// # Usage
/// ```ignore
/// let zkp_data = produce_block_with_proof(&messages, &sigs, &pubkeys)?;
/// // Store zkp_data.to_bytes() in block header
/// // Store raw attestation data in block body (or IPFS)
/// ```
pub fn produce_block_with_proof(
    messages: &[Vec<u8>],
    signatures: &[Vec<u8>],
    public_keys: &[Vec<u8>],
) -> Result<ZkpBlockData, ZKPError> {
    let proof = crate::prover::prove_batch(messages, signatures, public_keys)?;
    log::info!(
        "[ZKP-NODE] Block proof generated: {} sigs → {} bytes in {}ms",
        proof.batch_size,
        proof.proof_bytes.len(),
        proof.generation_time_ms,
    );
    Ok(ZkpBlockData::from(proof))
}

/// Block Validator: verify STARK proof from block header.
///
/// # Usage
/// ```ignore
/// let zkp_data = ZkpBlockData::from_bytes(&block_header.zkp_bytes)?;
/// let result = validate_block_proof(&zkp_data)?;
/// if result.is_valid {
///     // Skip individual sig verification — proof covers it
/// } else {
///     // Fall back to individual verification
/// }
/// ```
pub fn validate_block_proof(zkp_data: &ZkpBlockData) -> Result<ZkpValidationResult, ZKPError> {
    let batch_proof: BatchProof = zkp_data.clone().into();

    let t0 = std::time::Instant::now();
    let valid = crate::verifier::verify_stark_proof(&batch_proof)?;
    let verify_ms = t0.elapsed().as_millis() as u64;

    // Estimated time for individual Dilithium3 verification: ~3ms per sig
    let estimated_time_saved_ms = zkp_data.batch_size as u64 * 3;

    Ok(ZkpValidationResult { is_valid: valid, batch_size: zkp_data.batch_size, verify_time_ms: verify_ms, estimated_time_saved_ms })
}

/// Estimate block header overhead for ZKP data.
///
/// Returns estimated bytes added to block header.
pub fn estimate_header_overhead(batch_size: usize) -> usize {
    // Fixed: 1 (version) + 4 (batch_size) + 32 (commitment_root) = 37
    // Variable: proof size scales logarithmically with batch
    let estimated_proof_size = match batch_size {
        0..=16 => 30_000,
        17..=128 => 50_000,
        129..=1024 => 80_000,
        1025..=10000 => 120_000,
        _ => 150_000,
    };
    37 + estimated_proof_size
}
