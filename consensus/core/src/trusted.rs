use crate::{BlockHashMap, BlueWorkType, KType, block::Block, header::Header};
use sahyadri_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents semi-trusted externally provided SahyadriConsensus data (by a network peer)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSahyadriConsensusData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    pub selected_parent: Hash,
    pub mergeset_blues: Vec<Hash>,
    pub mergeset_reds: Vec<Hash>,
    pub blues_anticone_sizes: BlockHashMap<KType>,
}

/// Represents an externally provided block with associated SahyadriConsensus data which
/// is only partially validated by the consensus layer. Note there is no actual trust
/// but rather these blocks are indirectly validated through the PoW mined over them
#[derive(Clone)]
pub struct TrustedBlock {
    pub block: Block,
    pub sahyadri_consensus: ExternalSahyadriConsensusData,
}

impl TrustedBlock {
    pub fn new(block: Block, sahyadri_consensus: ExternalSahyadriConsensusData) -> Self {
        Self { block, sahyadri_consensus }
    }
}

/// Represents an externally provided header with associated SahyadriConsensus data which
/// is only partially validated by the consensus layer. Note there is no actual trust
/// but rather these headers are indirectly validated through the PoW mined over them
pub struct TrustedHeader {
    pub header: Arc<Header>,
    pub sahyadri_consensus: ExternalSahyadriConsensusData,
}

impl TrustedHeader {
    pub fn new(header: Arc<Header>, sahyadri_consensus: ExternalSahyadriConsensusData) -> Self {
        Self { header, sahyadri_consensus }
    }
}

/// Represents externally provided SahyadriConsensus data associated with a block Hash
pub struct TrustedSahyadriConsensusData {
    pub hash: Hash,
    pub sahyadri_consensus: ExternalSahyadriConsensusData,
}

impl TrustedSahyadriConsensusData {
    pub fn new(hash: Hash, sahyadri_consensus: ExternalSahyadriConsensusData) -> Self {
        Self { hash, sahyadri_consensus }
    }
}
