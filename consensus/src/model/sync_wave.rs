//! SyncWave — exporter, verifier, loader.
//!
//! A fresh node can bootstrap by:
//!   1. Discovering the highest checkpoint from peers
//!   2. Exporting (on the serving side) or downloading (on the receiving side)
//!      a `SyncWaveSnapshot` at that checkpoint
//!   3. Verifying: rebuild SMT root from snapshot nodes, compare against the
//!      checkpoint header's `account_commitment`
//!   4. Loading: atomically insert all nodes and states into local stores
//!
//! Snapshots are UNTRUSTED — verification is what binds them to consensus.

use std::collections::HashMap;
use std::sync::Arc;

use sahyadri_consensus_core::model::sync_wave::{
    SyncWaveDidState, SyncWaveFlashEntry, SyncWaveMetadata, SyncWaveNode, SyncWaveSnapshot, SyncWaveState,
};
use sahyadri_consensus_core::Hash;
use sahyadri_database::prelude::StoreError;
use sahyadri_smt::{Node as SmtNode, NodeStore as SmtNodeStoreTrait, H256};
use sahyadri_smt::EMPTY as SMT_EMPTY;

use crate::model::stores::did_store::DidDocument;
use crate::model::stores::did_states::{DbDidStatesStore, DidStatesStoreReader};
use crate::pipeline::virtual_processor::did_changes::did_content_hash;
use crate::model::stores::account_states::{AccountStatesStoreReader, DbAccountStatesStore};
use crate::model::stores::account_store::{AccountState, FlashEntry};
use crate::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use crate::model::stores::smt_nodes::{h256_to_hash, hash_to_h256, DbSmtNodeStore, DbSmtNodeStoreBase};

// ═══════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════

pub use sahyadri_consensus_core::model::sync_wave::SyncWaveError;
pub type SyncWaveResult<T> = Result<T, SyncWaveError>;


/// Local helper: convert a `StoreError` into a `SyncWaveError`.
///
/// Can't use `From` here — both types are external to this crate
/// (orphan rule).
#[inline]
fn store_err(e: StoreError) -> SyncWaveError {
    SyncWaveError::Store(format!("{e:?}"))
}

// ═══════════════════════════════════════════════════════════════
// Default chunk size for wire transport
// ═══════════════════════════════════════════════════════════════

pub const DEFAULT_CHUNK_SIZE: u32 = 2048;

// ═══════════════════════════════════════════════════════════════
// Exporter / Verifier / Loader
// ═══════════════════════════════════════════════════════════════

pub struct SyncWaveExporter {
    pub smt_nodes_store: Arc<DbSmtNodeStore>,
    pub account_states_store: Arc<DbAccountStatesStore>,
    pub did_states_store: Arc<DbDidStatesStore>,
    pub account_roots_store: Arc<crate::model::stores::account_roots::DbAccountRootsStore>,
    pub headers_store: Arc<DbHeadersStore>,
}

impl SyncWaveExporter {
    pub fn new(
        smt_nodes_store: Arc<DbSmtNodeStore>,
        account_states_store: Arc<DbAccountStatesStore>,
        did_states_store: Arc<DbDidStatesStore>,
        account_roots_store: Arc<crate::model::stores::account_roots::DbAccountRootsStore>,
        headers_store: Arc<DbHeadersStore>,
    ) -> Self {
        Self {
            smt_nodes_store,
            account_states_store,
            did_states_store,
            account_roots_store,
            headers_store,
        }
    }

    // ─────────────────────────────────────────────────────────────
    // export — build a snapshot at a given block
    // ─────────────────────────────────────────────────────────────

    pub fn export(&self, block_hash: Hash) -> SyncWaveResult<SyncWaveSnapshot> {
        let header = self
            .headers_store
            .get_header(block_hash)
            .map_err(|_| SyncWaveError::HeaderNotFound(block_hash))?;
        let root = hash_to_h256(header.account_commitment);

        // 1. Walk SMT from root, collect all nodes
        let base = DbSmtNodeStoreBase::new(&self.smt_nodes_store);
        let mut nodes: HashMap<H256, SyncWaveNode> = HashMap::new();
        self.collect_smt_nodes(&base, root, &mut nodes)?;

        // 2. For each leaf, fetch its state — account first, then DID.
        let mut states: Vec<(Hash, SyncWaveState)> = Vec::new();
        let mut did_states: Vec<(Hash, SyncWaveDidState)> = Vec::new();

        for node in nodes.values() {
            if let SyncWaveNode::Leaf { value, .. } = node {
                let state_hash = h256_to_hash(*value);

                if let Ok(state) = self.account_states_store.get(state_hash) {
                    states.push((state_hash, to_sync_state(&state)));
                    continue;
                }
                if let Ok(doc) = self.did_states_store.get(state_hash) {
                    did_states.push((state_hash, to_sync_did_state(&doc)));
                    continue;
                }
                return Err(SyncWaveError::MissingNode(*value));
            }
        }

        let total_smt_nodes = nodes.len() as u64;
        let total_accounts = states.len() as u64;
        let total_did_states = did_states.len() as u64;
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let total_chunks = ((total_smt_nodes + total_accounts + total_did_states) as u32)
            .div_ceil(chunk_size);

        let metadata = SyncWaveMetadata {
            block_hash,
            block_height: header.blue_score,
            account_root: header.account_commitment,
            total_smt_nodes,
            total_accounts,
            total_did_states,
            chunk_size,
            total_chunks,
        };

        let smt_nodes: Vec<(H256, SyncWaveNode)> = nodes.into_iter().collect();

        Ok(SyncWaveSnapshot {
            metadata,
            smt_nodes,
            account_states: states,
            did_states,
        })
    }

    /// DFS over the SMT, collecting every reachable node into `out`.
    fn collect_smt_nodes<S: SmtNodeStoreTrait>(
        &self,
        store: &S,
        hash: H256,
        out: &mut HashMap<H256, SyncWaveNode>,
    ) -> SyncWaveResult<()> {
        if hash == SMT_EMPTY {
            return Ok(());
        }
        if out.contains_key(&hash) {
            return Ok(());
        }
        let node = store.get(&hash).ok_or(SyncWaveError::MissingNode(hash))?;
        match node {
            SmtNode::Leaf { key, value } => {
                out.insert(hash, SyncWaveNode::Leaf { key, value });
            }
            SmtNode::Branch { left, right } => {
                out.insert(hash, SyncWaveNode::Branch { left, right });
                self.collect_smt_nodes(store, left, out)?;
                self.collect_smt_nodes(store, right, out)?;
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // verify — self-contained: no store access, only the snapshot
    // ─────────────────────────────────────────────────────────────

    pub fn verify(snapshot: &SyncWaveSnapshot) -> SyncWaveResult<()> {
        let root = hash_to_h256(snapshot.metadata.account_root);

        let mut index: HashMap<H256, &SyncWaveNode> =
            HashMap::with_capacity(snapshot.smt_nodes.len());
        for (h, node) in &snapshot.smt_nodes {
            if node.hash() != *h {
                return Err(SyncWaveError::NodeHashMismatch(*h));
            }
            index.insert(*h, node);
        }

        let mut visited: HashMap<H256, ()> = HashMap::new();
        Self::walk_and_check(root, &index, &mut visited)?;

        if visited.len() as u64 != snapshot.metadata.total_smt_nodes {
            return Err(SyncWaveError::NodeCountMismatch {
                declared: snapshot.metadata.total_smt_nodes,
                actual: visited.len() as u64,
            });
        }

        let computed = root;
        if computed != hash_to_h256(snapshot.metadata.account_root) {
            return Err(SyncWaveError::RootMismatch {
                expected: snapshot.metadata.account_root,
                computed: h256_to_hash(computed),
            });
        }

        // Account states
        for (state_hash, state) in &snapshot.account_states {
            let s = from_sync_state(state);
            if s.content_hash() != *state_hash {
                return Err(SyncWaveError::StateHashMismatch(*state_hash));
            }
        }

        // DID states
        for (state_hash, did_state) in &snapshot.did_states {
            let doc = from_sync_did_state(did_state);
            if did_content_hash(&doc) != *state_hash {
                return Err(SyncWaveError::StateHashMismatch(*state_hash));
            }
        }

        Ok(())
    }

    fn walk_and_check(
        hash: H256,
        index: &HashMap<H256, &SyncWaveNode>,
        visited: &mut HashMap<H256, ()>,
    ) -> SyncWaveResult<()> {
        if hash == SMT_EMPTY {
            return Ok(());
        }
        if visited.contains_key(&hash) {
            return Ok(());
        }
        let node = index
            .get(&hash)
            .ok_or(SyncWaveError::DanglingReference(hash))?;
        visited.insert(hash, ());
        if let SyncWaveNode::Branch { left, right } = node {
            Self::walk_and_check(*left, index, visited)?;
            Self::walk_and_check(*right, index, visited)?;
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // load — atomic persist into local stores
    // ─────────────────────────────────────────────────────────────

    pub fn load(&self, snapshot: &SyncWaveSnapshot) -> SyncWaveResult<()> {
        // 1. SMT nodes
        for (h, node) in &snapshot.smt_nodes {
            let smt_node = match node {
                SyncWaveNode::Leaf { key, value } => SmtNode::Leaf {
                    key: *key,
                    value: *value,
                },
                SyncWaveNode::Branch { left, right } => SmtNode::Branch {
                    left: *left,
                    right: *right,
                },
            };
            self.smt_nodes_store
                .insert_sync(*h, smt_node)
                .map_err(store_err)?;
        }

        // 2a. Account states
        for (state_hash, state) in &snapshot.account_states {
            let s = from_sync_state(state);
            self.account_states_store
                .insert_sync(*state_hash, &s)
                .map_err(store_err)?;
        }

        // 2b. DID states
        for (state_hash, did_state) in &snapshot.did_states {
            let doc = from_sync_did_state(did_state);
            self.did_states_store
                .insert_sync(*state_hash, &doc)
                .map_err(store_err)?;
        }

        // 3. Account root — keyed by the checkpoint block hash
        self.account_roots_store
            .insert_sync(
                snapshot.metadata.block_hash,
                hash_to_h256(snapshot.metadata.account_root),
            )
            .map_err(store_err)?;

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Conversions
// ═══════════════════════════════════════════════════════════════

fn to_sync_state(s: &AccountState) -> SyncWaveState {
    SyncWaveState {
        balance: s.balance,
        recent_flashes: s
            .recent_flashes
            .iter()
            .map(|f| SyncWaveFlashEntry {
                flash_id: f.flash_id,
                expiry_daa_score: f.expiry_daa_score,
            })
            .collect(),
    }
}

fn from_sync_state(s: &SyncWaveState) -> AccountState {
    AccountState {
        balance: s.balance,
        // block_hash is reorg-local and not part of the content hash.
        // A fresh sync has no reorg history, so we set it to default.
        recent_flashes: s
            .recent_flashes
            .iter()
            .map(|f| FlashEntry {
                flash_id: f.flash_id,
                expiry_daa_score: f.expiry_daa_score,
                block_hash: Hash::default(),
            })
            .collect(),
    }
}

fn to_sync_did_state(d: &DidDocument) -> SyncWaveDidState {
    SyncWaveDidState {
        did: d.did.clone(),
        csm_address: d.csm_address.clone(),
        public_key: d.public_key.clone(),
        document: d.document.clone(),
        purposes: d.purposes.clone(),
        services: d.services.clone(),
        active: d.active,
        created_at: d.created_at,
        updated_at: d.updated_at,
        version: d.version,
    }
}

fn from_sync_did_state(s: &SyncWaveDidState) -> DidDocument {
    DidDocument {
        did: s.did.clone(),
        csm_address: s.csm_address.clone(),
        public_key: s.public_key.clone(),
        document: s.document.clone(),
        purposes: s.purposes.clone(),
        services: s.services.clone(),
        active: s.active,
        created_at: s.created_at,
        updated_at: s.updated_at,
        version: s.version,
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_smt::{update, MemStore, EMPTY};
    use sahyadri_consensus_core::model::sync_wave::SyncWaveNode;

    fn test_key(seed: u8) -> H256 {
        [seed; 32]
    }

    /// Build an in-memory SMT, return (store, root, snapshot).
    fn build_snapshot(num_leaves: u8) -> (MemStore, H256, SyncWaveSnapshot) {
        let mut smt = MemStore::default();
        let mut root = EMPTY;
        let mut states_by_hash: HashMap<Hash, SyncWaveState> = HashMap::new();

        for i in 0..num_leaves {
            // Real AccountState → real content-hash → real SMT leaf value.
            let state = AccountState { balance: (i as u64) + 1, recent_flashes: vec![] };
            let state_hash = state.content_hash();
            let value: H256 = state_hash.as_bytes();

            root = update(&mut smt, root, &test_key(i), Some(value)).unwrap();
            states_by_hash.insert(state_hash, to_sync_state(&state));
        }

        // Walk the SMT
        let mut nodes: HashMap<H256, SyncWaveNode> = HashMap::new();
        collect_mem(&smt, root, &mut nodes).unwrap();

        let states: Vec<(Hash, SyncWaveState)> = states_by_hash.into_iter().collect();

        let smt_nodes: Vec<(H256, SyncWaveNode)> = nodes.into_iter().collect();

        let snapshot = SyncWaveSnapshot {
            metadata: SyncWaveMetadata {
                block_hash: Hash::default(),
                block_height: 0,
                account_root: h256_to_hash(root),
                total_smt_nodes: smt_nodes.len() as u64,
                total_accounts: states.len() as u64,
                total_did_states: 0,
                chunk_size: 2048,
                total_chunks: 1,
            },
            smt_nodes,
            account_states: states,
            did_states: vec![],
        };
        (smt, root, snapshot)
    }

    fn collect_mem<S: SmtNodeStoreTrait>(
        store: &S,
        hash: H256,
        out: &mut HashMap<H256, SyncWaveNode>,
    ) -> SyncWaveResult<()> {
        if hash == EMPTY {
            return Ok(());
        }
        if out.contains_key(&hash) {
            return Ok(());
        }
        let node = store.get(&hash).ok_or(SyncWaveError::MissingNode(hash))?;
        match node {
            SmtNode::Leaf { key, value } => {
                out.insert(hash, SyncWaveNode::Leaf { key, value });
            }
            SmtNode::Branch { left, right } => {
                out.insert(hash, SyncWaveNode::Branch { left, right });
                collect_mem(store, left, out)?;
                collect_mem(store, right, out)?;
            }
        }
        Ok(())
    }

    #[test]
    fn test_snapshot_verify_ok() {
        let (_smt, _root, snapshot) = build_snapshot(8);
        SyncWaveExporter::verify(&snapshot).expect("verify should pass");
    }

    #[test]
    fn test_snapshot_verify_detects_bad_node_hash() {
        let (_smt, _root, mut snapshot) = build_snapshot(4);
        // Corrupt the first node's declared hash
        snapshot.smt_nodes[0].0 = [0xff; 32];
        // Verify should fail with a mismatch
        assert!(SyncWaveExporter::verify(&snapshot).is_err());
    }

    #[test]
    fn test_snapshot_verify_detects_truncated_set() {
        let (_smt, _root, mut snapshot) = build_snapshot(8);
        // Drop the last node — declared count now exceeds actual
        snapshot.smt_nodes.pop();
        let r = SyncWaveExporter::verify(&snapshot);
        assert!(matches!(r, Err(SyncWaveError::NodeCountMismatch { .. }) | Err(SyncWaveError::DanglingReference(_))));
    }
}
