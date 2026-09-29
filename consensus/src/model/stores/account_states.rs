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
    access: CachedDbAccess<Hash, AccountState>,
}

impl DbAccountStatesStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::AccountStates.into(),
            ),
        }
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
