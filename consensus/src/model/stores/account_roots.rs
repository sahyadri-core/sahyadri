//! Per-block account commitment root. Analogous to `registry_unit_multisets.rs`,
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
    db: Arc<sahyadri_database::prelude::DB>,
    access: CachedDbAccess<Hash, Vec<u8>>,
}

impl DbAccountRootsStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::AccountRoots.into(),
            ),
        }
    }

    /// SAHYADRI GC: iterate all block hashes that have a stored root.
    pub fn iter_block_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
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

    /// SAHYADRI GC: batch-delete roots for blocks that were pruned.
    pub fn delete_many_sync(&self, block_hashes: &[Hash]) -> StoreResult<()> {
        if block_hashes.is_empty() {
            return Ok(());
        }
        let mut batch = rocksdb::WriteBatch::default();
        for h in block_hashes {
            self.access.delete(BatchDbWriter::new(&mut batch), *h)?;
        }
        self.db.write(batch)?;
        Ok(())
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
