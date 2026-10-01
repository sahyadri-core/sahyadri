use sahyadri_consensus_core::model::proof::AccountProof;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountProof {
    pub block_hash: String,
    pub account_root: String,
    pub key: String,
    pub proof: RpcAccountProofPayload,
    pub state: Option<RpcAccountProofState>,
    pub state_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountProofPayload {
    pub siblings: Vec<String>,
    pub terminal: RpcAccountProofTerminal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RpcAccountProofTerminal {
    Empty,
    Leaf { key: String, value: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountProofState {
    pub balance: u64,
    pub recent_flashes: Vec<RpcAccountProofFlashEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountProofFlashEntry {
    pub flash_id: String,
    pub expiry_daa_score: u64,
}

impl From<AccountProof> for RpcAccountProof {
    fn from(p: AccountProof) -> Self {
        let hex = |b: &[u8]| faster_hex::hex_string(b);
        Self {
            block_hash: p.block_hash.to_string(),
            account_root: p.account_root.to_string(),
            key: hex(&p.key),
            proof: RpcAccountProofPayload {
                siblings: p.proof.siblings.iter().map(|s| hex(s)).collect(),
                terminal: match p.proof.terminal {
                    sahyadri_consensus_core::model::proof::AccountProofTerminal::Empty => {
                        RpcAccountProofTerminal::Empty
                    }
                    sahyadri_consensus_core::model::proof::AccountProofTerminal::Leaf { key, value } => {
                        RpcAccountProofTerminal::Leaf { key: hex(&key), value: hex(&value) }
                    }
                },
            },
            state: p.state.map(|s| RpcAccountProofState {
                balance: s.balance,
                recent_flashes: s.recent_flashes.into_iter().map(|f| RpcAccountProofFlashEntry {
                    flash_id: f.flash_id.to_string(),
                    expiry_daa_score: f.expiry_daa_score,
                }).collect(),
            }),
            state_hash: hex(&p.state_hash),
        }
    }
}
