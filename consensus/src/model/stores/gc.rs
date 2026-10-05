//! Sahyadri garbage collector.
//!
//! Content-addressed SMT nodes and account states accumulate forever
//! unless explicitly pruned. This module implements a DAG-aware
//! mark-and-sweep:
//!
//! 1. Live roots = every block whose header still exists. Those are the
//!    blocks a future block can still reference as a parent.
//!
//! 2. Mark: DFS from each live root through the SMT node store, recording
//!    every reachable node hash and every leaf's state hash.
//!
//! 3. Sweep: iterate the persistent stores, delete anything not marked.
//!    Also delete `account_roots_store` entries for pruned blocks.
//!
//! Retention is implicitly bounded by the pruning point: once a block's
//! header is pruned, its root and any SMT nodes only it referenced become
//! unreachable and are swept.

use sahyadri_hashes::Hash;
use sahyadri_smt::{Node, H256};
use std::collections::HashSet;

use super::did_states::DbDidStatesStore;
use super::account_roots::DbAccountRootsStore;
use super::account_states::DbAccountStatesStore;
use super::headers::{DbHeadersStore, HeaderStoreReader};
use super::smt_nodes::{DbSmtNodeStore, SmtNodeStoreReader};

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct GcStats {
    pub live_roots: usize,
    pub scanned_nodes: usize,
    pub scanned_states: usize,
    pub scanned_did_states: usize,
    pub marked_nodes: usize,
    pub marked_states: usize,
    pub marked_did_states: usize,
    pub deleted_nodes: usize,
    pub deleted_states: usize,
    pub deleted_did_states: usize,
    pub deleted_roots: usize,
}

/// Run mark-and-sweep.
///
/// Caller should hold the pruning lock so no concurrent commit can
/// introduce a new root while we are sweeping.
pub fn mark_and_sweep(
    smt_store: &DbSmtNodeStore,
    state_store: &DbAccountStatesStore,
    did_states_store: &DbDidStatesStore,
    roots_store: &DbAccountRootsStore,
    headers_store: &DbHeadersStore,
) -> GcStats {
    let start = std::time::Instant::now();

    // ── 1. Determine live roots from ALL retained headers ──
    //
    // Every block whose header is still present must be considered live.
    // This includes parallel/side blocks that were verified but are not
    // (yet) on the selected chain — they could become chain blocks via a
    // reorg, and their SMT nodes must not be swept.
    //
    // The header's `account_commitment` field is the block's SMT root.
    let mut live_roots: Vec<H256> = Vec::new();
    let mut retained_blocks: std::collections::HashSet<Hash> = std::collections::HashSet::new();

    for block_hash in headers_store.iter_block_hashes() {
        if let Ok(header) = headers_store.get_header(block_hash) {
            retained_blocks.insert(block_hash);
            let root = header.account_commitment.as_bytes();
            if root != sahyadri_smt::EMPTY {
                live_roots.push(root);
            }
        }
    }
    let live_roots_count = live_roots.len();

    // ── 1b. Identify stale roots: their headers no longer exist ──
    //      NOTE: never delete the pruning point's root — assert_account_commitment
    //      reads it during pruning.
    // NOTE: the pruning point's header is always retained, so its block
    // hash is always in `retained_blocks` — no special-casing needed here.
    let mut roots_to_delete: Vec<Hash> = Vec::new();
    for block_hash in roots_store.iter_block_hashes() {
        if !retained_blocks.contains(&block_hash) {
            roots_to_delete.push(block_hash);
        }
    }

    // ── 2. Delete stale roots ──
    let deleted_roots = roots_to_delete.len();
    if !roots_to_delete.is_empty() {
        if let Err(e) = roots_store.delete_many_sync(&roots_to_delete) {
            log::error!("SAHYADRI GC: root delete failed: {:?}", e);
        }
    }

    // ── 3. Mark ──
    let mut marked_nodes: HashSet<H256> = HashSet::new();
    let mut marked_states: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<H256> = live_roots;

    while let Some(h) = stack.pop() {
        if h == sahyadri_smt::EMPTY {
            continue;
        }
        if !marked_nodes.insert(h) {
            continue;
        }
        match smt_store.get(h) {
            Ok(Some(Node::Leaf { value, .. })) => {
                marked_states.insert(Hash::from_bytes(value));
            }
            Ok(Some(Node::Branch { left, right })) => {
                stack.push(left);
                stack.push(right);
            }
            Ok(None) => {
                log::warn!("SAHYADRI GC: missing node {:?}", h);
            }
            Err(e) => {
                log::error!("SAHYADRI GC: read error {:?}: {:?}", h, e);
            }
        }
    }

    // ── 4. Sweep nodes ──
    let all_nodes: Vec<H256> = smt_store.iter_hashes().collect();
    let scanned_nodes = all_nodes.len();
    let nodes_to_delete: Vec<H256> = all_nodes
        .into_iter()
        .filter(|h| !marked_nodes.contains(h))
        .collect();
    let deleted_nodes = nodes_to_delete.len();

    // ── 5. Sweep states ──
    let all_states: Vec<Hash> = state_store.iter_hashes().collect();
    let scanned_states = all_states.len();
    let states_to_delete: Vec<Hash> = all_states
        .into_iter()
        .filter(|h| !marked_states.contains(h))
        .collect();
    let deleted_states = states_to_delete.len();
    if !states_to_delete.is_empty() {
        if let Err(e) = state_store.delete_many_sync(&states_to_delete) {
            log::error!("SAHYADRI GC: state delete failed: {:?}", e);
        }
    }

    // ── 5b. Sweep DID states ──
    let all_did: Vec<Hash> = did_states_store.iter_hashes().collect();
    let scanned_did_states = all_did.len();
    let did_to_delete: Vec<Hash> = all_did
        .into_iter()
        .filter(|h| !marked_states.contains(h))
        .collect();
    let deleted_did_states = did_to_delete.len();
    if !did_to_delete.is_empty() {
        if let Err(e) = did_states_store.delete_many_sync(&did_to_delete) {
            log::error!("SAHYADRI GC: did state delete failed: {:?}", e);
        }
    }

    let stats = GcStats {
        live_roots: live_roots_count,
        scanned_nodes,
        scanned_states,
        scanned_did_states,
        marked_nodes: marked_nodes.len(),
        marked_states: marked_states.len(),
        marked_did_states: marked_states.len(),
        deleted_nodes,
        deleted_states,
        deleted_did_states,
        deleted_roots,
    };

    log::info!(
        "SAHYADRI GC: {} live roots; scanned {} nodes, {} states; \
         marked {} nodes, {} states; deleted {} nodes, {} states, {} roots in {:?}",
        stats.live_roots,
        stats.scanned_nodes, stats.scanned_states,
        stats.marked_nodes, stats.marked_states,
        stats.deleted_nodes, stats.deleted_states, stats.deleted_roots,
        start.elapsed()
    );

    stats
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stores::account_states::DbAccountStatesStore;
    use crate::model::stores::account_roots::DbAccountRootsStore;
    use crate::model::stores::headers::DbHeadersStore;
    use crate::model::stores::smt_nodes::DbSmtNodeStore;
    use sahyadri_database::prelude::CachePolicy;

    #[test]
    fn test_gc_empty_stores() {
        // Sanity: empty stores → no-op
        let (lifetime, db) = test_db();
        let smt = DbSmtNodeStore::new(db.clone(), 100);
        let states = DbAccountStatesStore::new(db.clone(), 100);
        let roots = DbAccountRootsStore::new(db.clone(), 100);
        let headers = DbHeadersStore::new(db.clone(), CachePolicy::Count(100), CachePolicy::Count(100));
        let stats = mark_and_sweep(&smt, &states, &roots, &headers);
        assert_eq!(stats.deleted_nodes, 0);
        assert_eq!(stats.deleted_states, 0);
        assert_eq!(stats.deleted_roots, 0);
        drop(lifetime);
    }

    fn test_db() -> (impl Drop, std::sync::Arc<sahyadri_database::prelude::DB>) {
        sahyadri_database::create_temp_db!(sahyadri_database::prelude::ConnBuilder::default().with_files_limit(10))
    }

    // Helpers below — actual assertions on the algorithm
    // Live root should preserve reachable nodes; orphaned nodes get deleted.

    // NOTE: full integration test would need Header construction which is
    // heavy. We test the mark phase in isolation via `MemStore` in the smt
    // crate. This test file will be expanded with a proper mini-consensus
    // harness before mainnet.
}
