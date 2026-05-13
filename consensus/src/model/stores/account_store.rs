use sahyadri_consensus_core::tx::ScriptPublicKey;
// Changed cache::CachePolicy to prelude::CachePolicy
use sahyadri_database::prelude::{CachedDbAccess, StoreError, StoreResult, CachePolicy, BatchDbWriter};
use sahyadri_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents the state of an account in the Sahyadri network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}

impl AccountState {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Self { balance, nonce }
    }
}

// RocksDB needs to know how much memory this struct takes for caching
impl MemSizeEstimator for AccountState {
    fn estimate_mem_bytes(&self) -> usize {
        16 // 8 bytes for u64 balance + 8 bytes for u64 nonce
    }
}

/// A wrapper to make ScriptPublicKey compatible with RocksDB keys
#[derive(Clone, Eq, Hash, PartialEq)] // <-- ADDED Eq, Hash, PartialEq HERE
pub struct AccountKey(Vec<u8>);

impl AccountKey {
    pub fn new(spk: &ScriptPublicKey) -> Self {
        // Use getter methods .version() and .script() instead of direct property access
        let mut bytes = spk.version().to_le_bytes().to_vec();
        bytes.extend(spk.script().iter());
        Self(bytes)
    }
}

// Required trait for RocksDB keys
impl AsRef<[u8]> for AccountKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Required trait for RocksDB error logging
impl std::fmt::Display for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AccountKey({} bytes)", self.0.len())
    }
}

/// Trait defining the interface for the Account Store.
pub trait AccountStoreReader {
    fn get(&self, script_public_key: &ScriptPublicKey) -> StoreResult<AccountState>;
    fn get_balance(&self, script_public_key: &ScriptPublicKey) -> StoreResult<u64>;
    fn get_nonce(&self, script_public_key: &ScriptPublicKey) -> StoreResult<u64>;
}

pub trait AccountStore: AccountStoreReader {
    fn set_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, state: AccountState) -> StoreResult<()>;
    fn update_balance_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, balance_change: i64) -> StoreResult<()>;
    fn increment_nonce_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey) -> StoreResult<()>;
}

const STORE_PREFIX: &[u8] = b"accounts-store";

#[derive(Clone)]
pub struct DbAccountStore {
    access: CachedDbAccess<AccountKey, AccountState>,
}

impl DbAccountStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            access: CachedDbAccess::new(db, CachePolicy::Count(cache_size as usize), STORE_PREFIX.to_vec()),
        }
    }
}

impl AccountStoreReader for DbAccountStore {
    fn get(&self, script_public_key: &ScriptPublicKey) -> StoreResult<AccountState> {
        match self.access.read(AccountKey::new(script_public_key)) {
            Ok(state) => Ok(state),
            Err(StoreError::KeyNotFound(_)) => Ok(AccountState::default()),
            Err(e) => Err(e),
        }
    }

    fn get_balance(&self, script_public_key: &ScriptPublicKey) -> StoreResult<u64> {
        self.get(script_public_key).map(|state| state.balance)
    }

    fn get_nonce(&self, script_public_key: &ScriptPublicKey) -> StoreResult<u64> {
        self.get(script_public_key).map(|state| state.nonce)
    }
}

impl AccountStore for DbAccountStore {
    fn set_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, state: AccountState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), AccountKey::new(script_public_key), state)
    }

fn update_balance_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, balance_change: i64) -> StoreResult<()> {
        
        println!("SAHYADRI REWARD: Adding {} to account {:?}", balance_change, script_public_key);

        let mut state = self.get(script_public_key).unwrap_or(AccountState { balance: 0, nonce: 0 });
        
        if balance_change >= 0 {
            state.balance = state.balance.saturating_add(balance_change as u64);
        } else {
            let decrement = balance_change.unsigned_abs();
            state.balance = state.balance.saturating_sub(decrement);
        }

        self.set_batch(batch, script_public_key, state)
    }

    fn increment_nonce_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey) -> StoreResult<()> {
        let mut state = self.get(script_public_key).unwrap_or(AccountState { balance: 0, nonce: 0 });
        state.nonce = state.nonce.saturating_add(1);
        self.set_batch(batch, script_public_key, state)
    }
}
