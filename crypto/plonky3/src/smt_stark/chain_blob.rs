// Serializable chain proof blob.
//
// Wraps the serializable parts of RecursionOutput:
//   - BatchStarkProof (serializable in emberian fork rev 72ffc56)
//   - CommonData
// CircuitProverData is NOT included (needed only for proving, not verifying).

use p3_batch_stark::{BatchProof, CommonData};
use serde::{Deserialize, Serialize};

use crate::aggregate::RecursionConfig;

/// Serializable chain proof: everything to verify, nothing to prove.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainProofBlob {
    pub proof: BatchProof<RecursionConfig>,
    pub common_data: CommonData<RecursionConfig>,
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
}
