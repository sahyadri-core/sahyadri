//! Persistent store of Sparse Merkle Tree nodes, keyed by node hash
//! (content-addressed). Same-hash nodes are deduplicated automatically.

use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreError, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use sahyadri_smt::{Node, H256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
    db: Arc<sahyadri_database::prelude::DB>,
    access: CachedDbAccess<Hash, Vec<u8>>,
    mem_pool: Arc<RwLock<HashMap<H256, Node>>>,
}

impl DbSmtNodeStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::SmtNodes.into(),
            ),
            mem_pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    /// Insert a node into the in-memory pool. Visible to all overlays
    /// immediately, regardless of DB flush state.
    pub fn mem_put(&self, hash: H256, node: Node) {
        self.mem_pool.write().unwrap().insert(hash, node);
    }

    /// Look up a node in the in-memory pool first.
    pub fn mem_get(&self, hash: &H256) -> Option<Node> {
        self.mem_pool.read().unwrap().get(hash).cloned()
    }

    /// Truncate the in-memory pool. Called periodically by the virtual
    /// processor to bound memory usage.
    pub fn mem_clear(&self) {
        let mut pool = self.mem_pool.write().unwrap();
        pool.clear();
        pool.shrink_to_fit();
    }

    /// Number of entries currently held in the in-memory pool.
    pub fn mem_len(&self) -> usize {
        self.mem_pool.read().unwrap().len()
    }

    /// SAHYADRI: synchronously persist a node to DB.
    ///
    /// Used by the build and verify paths to write SMT nodes immediately,
    /// before the block is committed. Without this, a disqualified block's
    /// SMT nodes would live only in the mem_pool and would be lost if the
    /// pool is cleared — orphaning every descendant block that references
    /// the same root.
    pub fn insert_sync(&self, hash: H256, node: Node) -> StoreResult<()> {
        // mem_pool me daalo (in-memory visibility)
        self.mem_put(hash, node.clone());

        // Direct DB write — bypass batch
        use sahyadri_database::prelude::DirectDbWriter;
        self.access.write(
            DirectDbWriter::new(&self.db),
            h256_to_hash(hash),
            node.encode().to_vec(),
        )
    }

    /// SAHYADRI: synchronously persist many nodes.
    pub fn insert_sync_many(
        &self,
        nodes: impl IntoIterator<Item = (H256, Node)>,
    ) -> StoreResult<()> {
        for (h, n) in nodes {
            self.insert_sync(h, n)?;
        }
        Ok(())
    }

}

impl SmtNodeStoreReader for DbSmtNodeStore {
    fn get(&self, hash: H256) -> StoreResult<Option<Node>> {
        // Check mem_pool first
        if let Some(n) = self.mem_get(&hash) {
            return Ok(Some(n));
        }
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
/// Reads hit the in-memory pool first (recent blocks not yet flushed),
/// then fall through to the persistent store.
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
        // SAHYADRI: mem_pool first — recent nodes may not be flushed to DB yet.
        if let Some(n) = self.inner.mem_get(hash) {
            return Some(n);
        }
        self.inner.get(*hash).ok().flatten()
    }

    fn put(&mut self, _node: Node) -> H256 {
        unreachable!("DbSmtNodeStoreBase is read-only; writes go through OverlayStore")
    }
}
