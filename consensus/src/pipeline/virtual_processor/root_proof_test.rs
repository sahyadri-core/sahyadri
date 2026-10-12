//! E2E test for `generate_root_proof_for_block`.
//!
//! Verifies the background worker function is callable and handles
//! empty/insufficient-input blocks without crashing.

#[cfg(test)]
mod tests {
    use sahyadri_database::{create_temp_db, prelude::{CachePolicy, ConnBuilder}};
    use sahyadri_hashes::Hash;
    use sahyadri_consensus_core::tx::Transaction;
    use std::sync::Arc;

    use crate::model::stores::{
        block_transactions::DbBlockTransactionsStore,
        headers::DbHeadersStore,
        proof_roots::{DbProofRootsStore, ProofRootsStoreReader},
    };

    /// Empty block → no-op, no proof stored.
    #[test]
    fn test_empty_block_noop() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let db = Arc::new(db);

        let proof_roots = DbProofRootsStore::new(db.clone(), 100);
        let txs_store = DbBlockTransactionsStore::new(
            db.clone(),
            CachePolicy::Count(100),
            CachePolicy::Count(100),
        );
        let headers_store = DbHeadersStore::new(
            db.clone(),
            CachePolicy::Count(100),
            CachePolicy::Count(100),
        );

        let block_hash = Hash::from_bytes([7u8; 32]);

        // No txs inserted → get() returns Err (not found)
        let result = crate::pipeline::virtual_processor::processor::generate_root_proof_for_block(
            block_hash, &proof_roots, &txs_store, &headers_store,
        );

        // Empty/not-found → Ok (early return)
        assert!(result.is_ok(), "empty block must be Ok: {result:?}");

        // Nothing stored
        assert!(proof_roots.get(block_hash).unwrap().is_none());

        println!("Empty block: no-op, nothing stored");
    }

    /// Block with txs but insufficient for aggregation (< 2 valid) → no-op.
    #[test]
    fn test_insufficient_txs_noop() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let db = Arc::new(db);

        let proof_roots = DbProofRootsStore::new(db.clone(), 100);
        let txs_store = DbBlockTransactionsStore::new(
            db.clone(),
            CachePolicy::Count(100),
            CachePolicy::Count(100),
        );
        let headers_store = DbHeadersStore::new(
            db.clone(),
            CachePolicy::Count(100),
            CachePolicy::Count(100),
        );

        let block_hash = Hash::from_bytes([8u8; 32]);

        // Insert 1 dummy tx (no valid Dilithium sig) — not enough for aggregation
        let dummy_tx = Transaction::new(
            0, vec![], vec![], 0,
            sahyadri_consensus_core::subnets::SubnetworkId::from_bytes([0u8; 20]),
            0, vec![],
        );
        txs_store.insert(block_hash, Arc::new(vec![dummy_tx])).unwrap();

        let result = crate::pipeline::virtual_processor::processor::generate_root_proof_for_block(
            block_hash, &proof_roots, &txs_store, &headers_store,
        );

        // <2 valid sigs → early return Ok
        assert!(result.is_ok(), "insufficient txs must be Ok: {result:?}");
        assert!(proof_roots.get(block_hash).unwrap().is_none());

        println!("Insufficient txs: no-op, nothing stored");
    }
}
