//! Serializable chain proof blob.
//!
//! `BatchStarkProof` from `p3_circuit_prover` already implements
//! Serialize/Deserialize in 485455c — no fork needed.
//!
//! `RecursionOutput.0` = BatchStarkProof (serializable)
//! `RecursionOutput.1` = Arc<CircuitProverData> (proving-only, not serializable)

pub use p3_circuit_prover::BatchStarkProof;

use p3_recursion::builtin_config::GoldilocksD2Poseidon2BinaryConfig;
use serde::{Deserialize, Serialize};

pub type RecursionConfig = GoldilocksD2Poseidon2BinaryConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainProofBlob {
    pub proof: BatchStarkProof<RecursionConfig>,
    pub chain_depth: u32,
    pub chain_commitment: [u8; 32],
}

impl ChainProofBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("chain blob serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("chain blob deser: {e}"))
    }

    pub fn verify(&self) -> Result<(), String> {
        crate::aggregate::verify_batch_stark_proof(&self.proof)
            .map_err(|e| format!("verify: {e}"))
    }
}
