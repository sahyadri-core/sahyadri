//! Content-addressed store of canonical AccountState snapshots.
//!
//! Keyed by `content_hash()` (which excludes `block_hash`). Two blocks
//! that see the same balance + same flash set produce the same key, so
//! state is naturally deduplicated.
//!
//! Reorg unwind goes through the SMT root pointer (in `account_roots`),
//! not through this store. This store never deletes on reorg.

use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use std::sync::Arc;

use super::account_store::AccountState;

pub trait AccountStatesStoreReader {
    fn get(&self, state_hash: Hash) -> StoreResult<AccountState>;
}

pub trait AccountStatesStore: AccountStatesStoreReader {
    fn insert_batch(&self, batch: &mut WriteBatch, state_hash: Hash, state: &AccountState) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbAccountStatesStore {
    db: Arc<sahyadri_database::prelude::DB>,
    access: CachedDbAccess<Hash, AccountState>,
}

impl DbAccountStatesStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::AccountStates.into(),
            ),
        }
    }

    /// SAHYADRI: synchronously persist a state snapshot to DB.
    ///
    /// Content-addressed (keyed by `state_hash`), so this is idempotent —
    /// writing the same state twice is a no-op effect. Called from verify
    /// and build paths so that descendants can read the state without
    /// waiting for the commit-time batch flush.
    pub fn insert_sync(&self, state_hash: Hash, state: &AccountState) -> StoreResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        self.access.write(
            BatchDbWriter::new(&mut batch),
            state_hash,
            state.clone(),
        )?;
        self.db.write(batch)?;
        Ok(())
    }
}

impl AccountStatesStoreReader for DbAccountStatesStore {
    fn get(&self, state_hash: Hash) -> StoreResult<AccountState> {
        self.access.read(state_hash)
    }
}

impl AccountStatesStore for DbAccountStatesStore {
    fn insert_batch(&self, batch: &mut WriteBatch, state_hash: Hash, state: &AccountState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), state_hash, state.clone())
    }
}
