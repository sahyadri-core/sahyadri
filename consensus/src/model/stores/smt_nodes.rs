//! Persistent store of Sparse Merkle Tree nodes, keyed by node hash
//! (content-addressed). Same-hash nodes are deduplicated automatically.

use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreError, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use sahyadri_smt::{Node, H256};
use std::sync::Arc;

#[inline]
pub fn h256_to_hash(h: H256) -> Hash {
    Hash::from_bytes(h)
}

#[inline]
pub fn hash_to_h256(h: Hash) -> H256 {
    h.as_bytes()
}

pub trait SmtNodeStoreReader {
    fn get(&self, hash: H256) -> StoreResult<Option<Node>>;
}

pub trait SmtNodeStore: SmtNodeStoreReader {
    fn insert_batch(&self, batch: &mut WriteBatch, hash: H256, node: Node) -> StoreResult<()>;
    fn insert_batch_many(
        &self,
        batch: &mut WriteBatch,
        nodes: impl IntoIterator<Item = (H256, Node)>,
    ) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbSmtNodeStore {
    access: CachedDbAccess<Hash, Vec<u8>>,
}

impl DbSmtNodeStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::SmtNodes.into(),
            ),
        }
    }
}

impl SmtNodeStoreReader for DbSmtNodeStore {
    fn get(&self, hash: H256) -> StoreResult<Option<Node>> {
        match self.access.read(h256_to_hash(hash)) {
            Ok(bytes) => Ok(Node::decode(&bytes)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl SmtNodeStore for DbSmtNodeStore {
    fn insert_batch(&self, batch: &mut WriteBatch, hash: H256, node: Node) -> StoreResult<()> {
        self.access.write(
            BatchDbWriter::new(batch),
            h256_to_hash(hash),
            node.encode().to_vec(),
        )
    }

    fn insert_batch_many(
        &self,
        batch: &mut WriteBatch,
        nodes: impl IntoIterator<Item = (H256, Node)>,
    ) -> StoreResult<()> {
        for (hash, node) in nodes {
            self.insert_batch(batch, hash, node)?;
        }
        Ok(())
    }
}


// ═══════════════════════════════════════════════════════════════
// Read-only adapter for the SMT crate's NodeStore trait
// ═══════════════════════════════════════════════════════════════

/// Read-only view over `DbSmtNodeStore` that implements the SMT crate's
/// `NodeStore` trait, for use as the base of an `OverlayStore`.
///
/// `put()` is `unreachable!()` — the overlay holds all mutations in
/// memory until they are flushed via `insert_batch_many`.
pub struct DbSmtNodeStoreBase<'a> {
    inner: &'a DbSmtNodeStore,
}

impl<'a> DbSmtNodeStoreBase<'a> {
    pub fn new(inner: &'a DbSmtNodeStore) -> Self {
        Self { inner }
    }
}

impl<'a> sahyadri_smt::NodeStore for DbSmtNodeStoreBase<'a> {
    fn get(&self, hash: &H256) -> Option<Node> {
        self.inner.get(*hash).ok().flatten()
    }

    fn put(&mut self, _node: Node) -> H256 {
        unreachable!("DbSmtNodeStoreBase is read-only; writes go through OverlayStore")
    }
}
