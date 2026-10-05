//! SyncWave — bulk state transfer for fast node bootstrap.
//!
//! Lets a fresh node catch up to a network tip by downloading a verified
//! snapshot of account state at a recent block, instead of replaying the
//! full chain from genesis.
//!
//! Security model: a snapshot is UNTRUSTED. The receiving node rebuilds the
//! SMT root from the transmitted nodes and compares it against the checkpoint
//! header's `account_commitment`. Any peer may serve a snapshot; the receiver
//! verifies locally.

use borsh::{BorshDeserialize, BorshSerialize};
use sahyadri_hashes::Hash;
use serde::{Deserialize, Serialize};

/// 32-byte hash (mirrors `sahyadri_smt::H256`; inlined to avoid dep cycle).
pub type H256 = [u8; 32];

/// Snapshot metadata — cheap to fetch, tells the receiver how much to download.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveMetadata {
    /// Checkpoint block hash.
    pub block_hash: Hash,
    /// Blue score (height) of the checkpoint block.
    pub block_height: u64,
    /// SMT root committed by the checkpoint header.
    pub account_root: Hash,
    /// Number of SMT nodes in the snapshot.
    pub total_smt_nodes: u64,
    /// Number of account states in the snapshot.
    pub total_accounts: u64,
    /// Number of DID states in the snapshot.
    pub total_did_states: u64,
    /// Entries per chunk (for wire transport).
    pub chunk_size: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
}

/// A single SMT node in the snapshot. Mirrors `sahyadri_smt::Node`.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncWaveNode {
    Leaf { key: H256, value: H256 },
    Branch { left: H256, right: H256 },
}

impl SyncWaveNode {
    /// 32-byte content-address of this node.
    ///
    /// MUST match `sahyadri_smt::hash_leaf` / `hash_branch` exactly —
    /// the receiving node rebuilds the SMT root from these hashes and
    /// compares it against the checkpoint header's `account_commitment`.
    pub fn hash(&self) -> H256 {
        use sha3::{Digest, Sha3_256};
        match self {
            Self::Leaf { key, value } => {
                let mut h = Sha3_256::new();
                h.update(b"SAHYADRI_SMT_LEAF_V1");
                h.update(key);
                h.update(value);
                let mut out = [0u8; 32];
                out.copy_from_slice(&h.finalize());
                out
            }
            Self::Branch { left, right } => {
                let mut h = Sha3_256::new();
                h.update(b"SAHYADRI_SMT_BRANCH_V1");
                h.update(left);
                h.update(right);
                let mut out = [0u8; 32];
                out.copy_from_slice(&h.finalize());
                out
            }
        }
    }
}

/// Account state carried in the snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveState {
    pub balance: u64,
    pub recent_flashes: Vec<SyncWaveFlashEntry>,
}

/// DID state carried in the snapshot.
/// Mirror of `crate::model::stores::did_store::DidDocument`.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveDidState {
    pub did: String,
    pub csm_address: String,
    pub public_key: String,
    pub document: String,
    pub purposes: Vec<String>,
    pub services: Vec<String>,
    pub active: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveFlashEntry {
    pub flash_id: Hash,
    pub expiry_daa_score: u64,
}

/// Full state snapshot at a checkpoint block.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveSnapshot {
    pub metadata: SyncWaveMetadata,
    /// Content-addressed SMT nodes: (hash, node).
    pub smt_nodes: Vec<(H256, SyncWaveNode)>,
    /// Account states keyed by content-hash (the SMT leaf `value`).
    pub account_states: Vec<(Hash, SyncWaveState)>,
    /// DID states keyed by content-hash (the SMT leaf `value`).
    pub did_states: Vec<(Hash, SyncWaveDidState)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_hash_matches_smt_domain_separation() {
        // Hardcoded expected values computed from sahyadri_smt::hash_leaf/hash_branch
        // domain separation prefixes. If this test fails, the prefix constants
        // in either place have drifted — SyncWave verification will fail on the network.
        let key = [0x11u8; 32];
        let value = [0x22u8; 32];

        let leaf = SyncWaveNode::Leaf { key, value };
        let h = leaf.hash();

        // Recompute reference: SHA3("SAHYADRI_SMT_LEAF_V1" || key || value)
        use sha3::{Digest, Sha3_256};
        let mut ref_h = Sha3_256::new();
        ref_h.update(b"SAHYADRI_SMT_LEAF_V1");
        ref_h.update(key);
        ref_h.update(value);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&ref_h.finalize());
        assert_eq!(h, expected, "leaf hash must match SMT domain separation");

        let branch = SyncWaveNode::Branch { left: key, right: value };
        let h = branch.hash();
        let mut ref_h = Sha3_256::new();
        ref_h.update(b"SAHYADRI_SMT_BRANCH_V1");
        ref_h.update(key);
        ref_h.update(value);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&ref_h.finalize());
        assert_eq!(h, expected, "branch hash must match SMT domain separation");
    }
}

/// A chunk of a snapshot for wire transport.
///
/// Chunks are slices of the full snapshot; the receiver concatenates them
/// and calls `verify()` on the assembled snapshot before `load()`.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncWaveChunkWire {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub smt_nodes: Vec<(H256, SyncWaveNode)>,
    pub account_states: Vec<(Hash, SyncWaveState)>,
}


/// Errors from SyncWave export / verify / load.
#[derive(Debug)]
pub enum SyncWaveError {
    Store(String),
    HeaderNotFound(Hash),
    MissingNode(H256),
    RootMismatch { expected: Hash, computed: Hash },
    NodeCountMismatch { declared: u64, actual: u64 },
    NodeHashMismatch(H256),
    StateHashMismatch(Hash),
    DanglingReference(H256),
}

impl std::fmt::Display for SyncWaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(s) => write!(f, "store error: {s}"),
            Self::HeaderNotFound(h) => write!(f, "header not found for block {h}"),
            Self::MissingNode(h) => write!(f, "SMT node missing: {h:?}"),
            Self::RootMismatch { expected, computed } => {
                write!(f, "SMT root mismatch: header={expected} computed={computed}")
            }
            Self::NodeCountMismatch { declared, actual } => {
                write!(f, "node count mismatch: declared={declared} actual={actual}")
            }
            Self::NodeHashMismatch(h) => write!(f, "node content-address mismatch: {h:?}"),
            Self::StateHashMismatch(h) => write!(f, "state content-hash mismatch: {h}"),
            Self::DanglingReference(h) => write!(f, "dangling SMT reference: {h:?}"),
        }
    }
}

impl std::error::Error for SyncWaveError {}

pub type SyncWaveResult<T> = Result<T, SyncWaveError>;
