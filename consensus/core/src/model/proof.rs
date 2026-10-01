//! Account-state proof types.
//!
//! A proof is a compact witness that `key → value` (or its absence) is
//! present in the SMT whose root is committed in a block header's
//! `account_commitment`. Verifiers recompute the root from the proof and
//! compare it against the trusted header — no trust in the serving node.

use sahyadri_hashes::Hash;
use serde::{Deserialize, Serialize};

/// 32-byte hash. Mirrors `sahyadri_smt::H256`; inlined here to avoid a
/// dependency cycle (consensus-core cannot depend on sahyadri-smt).
pub type H256 = [u8; 32];

/// SMT proof payload. Mirrors `sahyadri_smt::Proof` but is fully serde-friendly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountProofPayload {
    /// Sibling hashes, root-down. Empty when the terminal is the root itself.
    pub siblings: Vec<H256>,
    /// Terminal node reached by the key path.
    pub terminal: AccountProofTerminal,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AccountProofTerminal {
    /// Empty subtree — proof of absence.
    Empty,
    /// Leaf at the end of the key path.
    Leaf { key: H256, value: H256 },
}

/// Complete account proof as returned by `get_account_proof`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountProof {
    /// Block whose header's `account_commitment` this proof is against.
    pub block_hash: Hash,
    /// The committed root at `block_hash` (== header.account_commitment).
    pub account_root: Hash,
    /// The SMT key that was queried (hash of the script public key).
    pub key: H256,
    /// The proof payload.
    pub proof: AccountProofPayload,
    /// Present state (None iff the account is absent).
    pub state: Option<AccountProofState>,
    /// Content-hash of `state` — the SMT leaf value (zero if absent).
    pub state_hash: H256,
}

/// Serializable account state (mirrors `AccountState`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountProofState {
    pub balance: u64,
    pub recent_flashes: Vec<AccountProofFlashEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountProofFlashEntry {
    pub flash_id: Hash,
    pub expiry_daa_score: u64,
}
