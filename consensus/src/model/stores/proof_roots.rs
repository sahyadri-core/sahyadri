//! Per-block recursively-aggregated root STARK proofs, keyed by block hash.
//!
//! Analogous to `account_roots.rs`: stores an opaque byte blob (the serialized
//! `RecursionOutput` root proof) alongside lightweight metadata. Root proofs
//! are auxiliary — they do not affect consensus rules — and are served to
//! light clients via RPC.

use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DirectDbWriter, StoreResult};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRootEntry {
    pub proof: Vec<u8>,
    pub blue_score: u64,
    pub aggregated_count: u32,
    #[serde(default)]
    pub chain_commitment: [u8; 32],
    #[serde(default)]
    pub chain_depth: u32,
    #[serde(default)]
    pub chain_proof: Vec<u8>,
    #[serde(default)]
    pub nearest_checkpoint: Option<Hash>,
    #[serde(default)]
    pub proof_pending: bool,
}/// Metadata + serialized proof stored per block.

pub trait ProofRootsStoreReader {
    fn get(&self, block_hash: Hash) -> StoreResult<Option<ProofRootEntry>>;
    fn has(&self, block_hash: Hash) -> StoreResult<bool>;
}

pub trait ProofRootsStore: ProofRootsStoreReader {
    fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        block_hash: Hash,
        entry: &ProofRootEntry,
    ) -> StoreResult<()>;
    fn delete_batch(&self, batch: &mut WriteBatch, block_hash: Hash) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbProofRootsStore {
    db: Arc<sahyadri_database::prelude::DB>,
    access: CachedDbAccess<Hash, Vec<u8>>,
}

impl DbProofRootsStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                CachePolicy::Count(cache_size as usize),
                DatabaseStorePrefixes::ProofRoots.into(),
            ),
        }
    }

    /// SAHYADRI GC: iterate all block hashes with a stored proof.
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

    /// Synchronously persist a single proof root, bypassing a batch.
    pub fn insert_sync(&self, block_hash: Hash, entry: &ProofRootEntry) -> StoreResult<()> {
        let bytes = bincode::serialize(entry)
            .expect("proof_roots: bincode serialize infallible");
        self.access.write(DirectDbWriter::new(&self.db), block_hash, bytes)
    }

    /// SAHYADRI GC: batch-delete proofs for pruned blocks.
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

impl ProofRootsStoreReader for DbProofRootsStore {
    fn get(&self, block_hash: Hash) -> StoreResult<Option<ProofRootEntry>> {
        match self.access.read(block_hash) {
            Ok(bytes) => {
                let entry = bincode::deserialize(&bytes)
                    .expect("proof_roots: bincode deserialize corrupt");
                Ok(Some(entry))
            }
            Err(sahyadri_database::prelude::StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn has(&self, block_hash: Hash) -> StoreResult<bool> {
        Ok(self.access.read(block_hash).is_ok())
    }
}

impl ProofRootsStore for DbProofRootsStore {
    fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        block_hash: Hash,
        entry: &ProofRootEntry,
    ) -> StoreResult<()> {
        let bytes = bincode::serialize(entry)
            .expect("proof_roots: bincode serialize infallible");
        self.access.write(BatchDbWriter::new(batch), block_hash, bytes)
    }

    fn delete_batch(&self, batch: &mut WriteBatch, block_hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_database::create_temp_db;
    use sahyadri_database::prelude::ConnBuilder;
    use sahyadri_hashes::Hash;

    /// Full DB roundtrip: insert, read, has, overwrite, batch, delete.
    /// Uses a real temp RocksDB — auto-deleted on lifetime drop.
    #[test]
    fn test_proof_roots_store_real_db() {
        // Temp DB — auto-cleanup on `_lifetime` drop
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbProofRootsStore::new(db.clone(), 1024);

        let block_hash = Hash::from_bytes([7u8; 32]);
        let entry = ProofRootEntry {
            proof: vec![1, 2, 3, 4, 5],
            blue_score: 12345,
            aggregated_count: 8,
            chain_commitment: [0u8; 32],
            chain_depth: 0,
            chain_proof: Vec::new(),
            proof_pending: false,
            nearest_checkpoint: None,
        };

        // ── 1. Insert ───────────────────────────────────────
        store.insert_sync(block_hash, &entry).expect("insert");

        // ── 2. Read back ────────────────────────────────────
        let read = store.get(block_hash).expect("get").expect("some");
        assert_eq!(read.proof, vec![1, 2, 3, 4, 5]);
        assert_eq!(read.blue_score, 12345);
        assert_eq!(read.aggregated_count, 8);

        // ── 3. has() ────────────────────────────────────────
        assert!(store.has(block_hash).expect("has"));

        // ── 4. Non-existent key returns None ────────────────
        let other = Hash::from_bytes([8u8; 32]);
        assert!(store.get(other).expect("get").is_none());
        assert!(!store.has(other).expect("has"));

        // ── 5. Overwrite ────────────────────────────────────
        let updated = ProofRootEntry {
            proof: vec![9, 9, 9],
            blue_score: 99999,
            aggregated_count: 16,
            chain_commitment: [1u8; 32],
            chain_depth: 5,
            chain_proof: Vec::new(),
            proof_pending: false,
            nearest_checkpoint: None,
        };
        store.insert_sync(block_hash, &updated).expect("re-insert");
        let read2 = store.get(block_hash).expect("get").expect("some");
        assert_eq!(read2.proof, vec![9, 9, 9]);
        assert_eq!(read2.blue_score, 99999);
        assert_eq!(read2.aggregated_count, 16);

        // ── 6. Batch insert path ────────────────────────────
        let mut batch = rocksdb::WriteBatch::default();
        let batch_hash = Hash::from_bytes([10u8; 32]);
        store.insert_batch(&mut batch, batch_hash, &entry).expect("batch insert");
        db.write(batch).expect("db write");
        assert!(store.has(batch_hash).expect("has batch"));

        // ── 7. Delete batch path ────────────────────────────
        let mut del_batch = rocksdb::WriteBatch::default();
        store.delete_batch(&mut del_batch, batch_hash).expect("delete");
        db.write(del_batch).expect("db write delete");
        assert!(!store.has(batch_hash).expect("has after delete"));

        println!("proof_roots_store real DB roundtrip OK");
        // `_lifetime` drop = temp DB auto-deleted
    }
}
