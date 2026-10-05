//! Content-addressed store of canonical DidDocument snapshots.
//!
//! Parallel to `account_states.rs`. Keyed by `did_content_hash(doc)`.
//! Reorg unwind goes through the SMT root pointer (in `account_roots`),
//! not through this store. This store never deletes on reorg.
use sahyadri_database::prelude::StoreError;
use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use std::sync::Arc;

use super::did_store::DidDocument;

pub trait DidStatesStoreReader {
    fn get(&self, state_hash: Hash) -> StoreResult<DidDocument>;
}

pub trait DidStatesStore: DidStatesStoreReader {
    fn insert_batch(&self, batch: &mut WriteBatch, state_hash: Hash, state: &DidDocument) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbDidStatesStore {
    db: Arc<sahyadri_database::prelude::DB>,
    access: CachedDbAccess<Hash, DidDocument>,
}

impl DbDidStatesStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::DidStates.into(),
            ),
        }
    }

    /// SAHYADRI: synchronously persist a DID snapshot to DB.
    ///
    /// Content-addressed (keyed by `state_hash`), so this is idempotent.
    pub fn insert_sync(&self, state_hash: Hash, state: &DidDocument) -> StoreResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        self.access.write(
            BatchDbWriter::new(&mut batch),
            state_hash,
            state.clone(),
        )?;
        self.db.write(batch)?;
        Ok(())
    }

    /// SAHYADRI GC: iterate all state hashes.
    pub fn iter_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
        self.access.iterator().filter_map(|res| {
            res.ok().and_then(|(k, _v)| {
                if k.len() == 32 {
                    Some(Hash::from_slice(&k))
                } else {
                    None
                }
            })
        })
    }

    /// SAHYADRI GC: batch-delete states by hash.
    pub fn delete_many_sync(&self, hashes: &[Hash]) -> StoreResult<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let mut batch = rocksdb::WriteBatch::default();
        for h in hashes {
            self.access.delete(BatchDbWriter::new(&mut batch), *h)?;
        }
        self.db.write(batch)?;
        Ok(())
    }
}

impl DidStatesStoreReader for DbDidStatesStore {
    fn get(&self, state_hash: Hash) -> StoreResult<DidDocument> {
        self.access.read(state_hash)
    }
}

impl DidStatesStore for DbDidStatesStore {
    fn insert_batch(&self, batch: &mut WriteBatch, state_hash: Hash, state: &DidDocument) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), state_hash, state.clone())
    }
}

// Adapter: impl did_changes::DidStatesReader for DbDidStatesStore
impl crate::pipeline::virtual_processor::did_changes::DidStatesReader for DbDidStatesStore {
    fn get_did_state(&self, hash: Hash) -> Result<Option<DidDocument>, StoreError> {
        match self.get(hash) {
            Ok(doc) => Ok(Some(doc)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
