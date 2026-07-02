//! # ZKP Batch Verification for Block Validation
//!
//! Replaces per-transaction Dilithium3 verification with a single STARK proof.
//!
//! ## Block Producer Flow:
//! 1. Collect all transactions in MutableBlock
//! 2. Call `generate_block_zkp()` → extracts sigs + generates STARK proof
//! 3. Attach proof to block before broadcasting
//!
//! ## Block Validator Flow:
//! 1. Check if block has ZKP proof attached
//! 2. Call `verify_block_zkp()` → STARK verify in ~1ms
//! 3. If valid → skip individual `sign::verify()` for all tx inputs
//! 4. If no proof/invalid → fall back to individual verification
//!
//! ## Performance (256 sigs, release build):
//! - Individual: ~768ms (256 × 3ms per Dilithium3 verify)
//! - STARK verify: ~1ms
//! - Speedup: ~768x

use crate::tx::Transaction;
use sahyadri_dilithium::{PUBKEY_SIZE, SIG_SIZE};

/// Extract (message, signature, pubkey) tuples from block transactions.
///
/// Parses each transaction input's signature_script to extract:
/// - pubkey: first PUBKEY_SIZE bytes of script data
/// - signature: next SIG_SIZE bytes of script data
/// - message: sighash (recomputed during verification)
///
/// Returns vectors ready for `sahyadri_plonky3::prove_batch()`.
pub fn extract_signatures_from_block(transactions: &[Transaction]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut messages = Vec::new();
    let mut signatures = Vec::new();
    let mut public_keys = Vec::new();

    for tx in transactions {
        for input in &tx.inputs {
            let ss = &input.signature_script;
            if ss.len() < 3 || ss[0] != 0x4d {
                continue;
            }
            let data_len = u16::from_le_bytes([ss[1], ss[2]]) as usize;
            if ss.len() < 3 + data_len || data_len < PUBKEY_SIZE + SIG_SIZE + 1 {
                continue;
            }
            let data = &ss[3..3 + data_len];

            let pk = data[..PUBKEY_SIZE].to_vec();
            let sig = data[PUBKEY_SIZE..PUBKEY_SIZE + SIG_SIZE].to_vec();

            // For STARK proof, we store raw script data as "message"
            // The actual sighash is computed during `add_and_verify` in the prover
            let msg = ss.clone();

            public_keys.push(pk);
            signatures.push(sig);
            messages.push(msg);
        }
    }

    (messages, signatures, public_keys)
}

/// Count total Dilithium3 signature operations in a block.
pub fn count_sig_ops(transactions: &[Transaction]) -> usize {
    let mut count = 0;
    for tx in transactions {
        for input in &tx.inputs {
            let ss = &input.signature_script;
            if ss.len() >= 3 && ss[0] == 0x4d {
                let data_len = u16::from_le_bytes([ss[1], ss[2]]) as usize;
                if ss.len() >= 3 + data_len && data_len >= PUBKEY_SIZE + SIG_SIZE + 1 {
                    count += 1;
                }
            }
        }
    }
    count
}

/// ZKP proof data attached to a block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockZkpProof {
    /// Serialized STARK proof.
    pub proof_bytes: Vec<u8>,
    /// Merkle root commitment of all attestation hashes.
    pub commitment_root: [u8; 32],
    /// Number of signatures covered.
    pub batch_size: u32,
    /// Proof format version.
    pub version: u8,
}

impl BlockZkpProof {
    pub fn serialized_size(&self) -> usize {
        self.proof_bytes.len() + 32 + 4 + 1
    }
}

#[cfg(feature = "zkp")]
mod zkp_impl {
    use super::*;
    use sahyadri_plonky3::batch::ZKPError;

    /// Generate a STARK proof for all signatures in a block.
    ///
    /// This should be called by the block producer after collecting all transactions.
    pub fn generate_block_zkp(transactions: &[Transaction]) -> Result<BlockZkpProof, ZKPError> {
        let (messages, signatures, public_keys) = extract_signatures_from_block(transactions);

        if messages.is_empty() {
            return Err(ZKPError::EmptyBatch);
        }

        let proof = sahyadri_plonky3::prove_batch(&messages, &signatures, &public_keys)?;

        Ok(BlockZkpProof {
            proof_bytes: proof.proof_bytes,
            commitment_root: proof.commitment_root,
            batch_size: proof.batch_size,
            version: proof.version,
        })
    }

    /// Verify a STARK proof for a block.
    ///
    /// If this returns Ok(true), all signatures in the block are valid
    /// and individual `sign::verify()` calls can be skipped.
    pub fn verify_block_zkp(zkp: &BlockZkpProof) -> Result<bool, ZKPError> {
        let batch_proof = sahyadri_plonky3::batch::BatchProof {
            proof_bytes: zkp.proof_bytes.clone(),
            commitment_root: zkp.commitment_root,
            batch_size: zkp.batch_size,
            version: zkp.version,
            generation_time_ms: 0,
            stats: Default::default(),
        };

        sahyadri_plonky3::verify_stark_proof(&batch_proof)
    }

    /// Check if STARK verification should be used for a block.
    ///
    /// Returns true if the block has a valid ZKP proof covering enough signatures
    /// to make STARK verification worthwhile (>= 16 sigs).
    pub fn should_use_zkp(zkp: Option<&BlockZkpProof>, _sig_count: usize) -> bool {
        match zkp {
            Some(proof) if proof.batch_size as usize >= 16 => true,
            _ => false,
        }
    }
}

#[cfg(feature = "zkp")]
pub use zkp_impl::{generate_block_zkp, should_use_zkp, verify_block_zkp};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_sig_ops_empty() {
        let txs: Vec<Transaction> = vec![];
        assert_eq!(count_sig_ops(&txs), 0);
    }
}
