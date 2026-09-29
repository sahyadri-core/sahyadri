//! Per-block account commitment root. Analogous to `utxo_multisets.rs`,
//! but keyed by block hash and storing the SMT root that block commits to.

use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use sahyadri_smt::H256;
use std::sync::Arc;

pub trait AccountRootsStoreReader {
    fn get(&self, block_hash: Hash) -> StoreResult<H256>;
}

pub trait AccountRootsStore: AccountRootsStoreReader {
    fn insert_batch(&self, batch: &mut WriteBatch, block_hash: Hash, root: H256) -> StoreResult<()>;
    fn delete_batch(&self, batch: &mut WriteBatch, block_hash: Hash) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbAccountRootsStore {
    access: CachedDbAccess<Hash, Vec<u8>>,
}

impl DbAccountRootsStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::AccountRoots.into(),
            ),
        }
    }
}

impl AccountRootsStoreReader for DbAccountRootsStore {
    fn get(&self, block_hash: Hash) -> StoreResult<H256> {
        let bytes = self.access.read(block_hash)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("account_roots invariant: stored value is always 32 bytes");
        Ok(arr)
    }
}

impl AccountRootsStore for DbAccountRootsStore {
    fn insert_batch(&self, batch: &mut WriteBatch, block_hash: Hash, root: H256) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block_hash, root.to_vec())
    }

    fn delete_batch(&self, batch: &mut WriteBatch, block_hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block_hash)
    }
}
