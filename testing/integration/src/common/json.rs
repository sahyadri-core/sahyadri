use sahyadri_consensus_core::block::Block;
use sahyadri_consensus_core::trusted::TrustedBlock;
use serde::{Deserialize, Serialize};

pub use sahyadri_consensus_core::trusted::ExternalSahyadriConsensusData as JtfSahyadriConsensusData;
pub use sahyadri_rpc_core::{RpcBlock as JtfBlock, RpcHeader as JtfHeader};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JtfTrustedBlock {
    pub block: JtfBlock,
    pub sahyadri_consensus: JtfSahyadriConsensusData,
}

pub fn json_line_to_trusted_block(line: String) -> TrustedBlock {
    let jtf_trusted_block: JtfTrustedBlock = serde_json::from_str(&line).unwrap();
    let block: Block = jtf_trusted_block.block.try_into().unwrap();
    TrustedBlock::new(block, jtf_trusted_block.sahyadri_consensus)
}

pub fn json_line_to_block(line: String) -> Block {
    let jtf_block: JtfBlock = serde_json::from_str(&line).unwrap();
    jtf_block.try_into().unwrap()
}
