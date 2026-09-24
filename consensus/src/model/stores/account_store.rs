use sahyadri_consensus_core::tx::ScriptPublicKey;
// Changed cache::CachePolicy to prelude::CachePolicy
use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, StoreError, StoreResult};
use sahyadri_utils::mem_size::MemSizeEstimator;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A single flash-tx entry in an account's recent history.
/// Block_hash tracking enables per-block reorg unwind.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FlashEntry {
    pub flash_id: sahyadri_hashes::Hash,
    pub expiry_daa_score: u64,
    pub block_hash: sahyadri_hashes::Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountState {
    pub balance: u64,
    pub recent_flashes: Vec<FlashEntry>,
}

impl AccountState {
    pub fn new(balance: u64) -> Self {
        Self {
            balance,
            recent_flashes: Vec::new(),
        }
    }
}

// RocksDB needs to know how much memory this struct takes for caching
impl MemSizeEstimator for AccountState {
    fn estimate_mem_bytes(&self) -> usize {
        // 16 bytes base + 40 bytes per recent_flash entry
        16 + self.recent_flashes.len() * 40
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
    fn get_last_tx_id(&self, script_public_key: &ScriptPublicKey) -> StoreResult<[u8; 32]>;
}

pub trait AccountStore: AccountStoreReader {
    fn set_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, state: AccountState) -> StoreResult<()>;
    fn update_balance_batch(
        &self,
        batch: &mut WriteBatch,
        script_public_key: &ScriptPublicKey,
        balance_change: i64,
    ) -> StoreResult<()>;
    fn set_last_tx_id_batch(
        &self,
        batch: &mut WriteBatch,
        script_public_key: &ScriptPublicKey,
        tx_id: [u8; 32],
    ) -> StoreResult<()>;
}

const STORE_PREFIX: &[u8] = b"accounts-store";

#[derive(Clone)]
pub struct DbAccountStore {
    access: CachedDbAccess<AccountKey, AccountState>,
}

impl DbAccountStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self { access: CachedDbAccess::new(db, CachePolicy::Count(cache_size as usize), STORE_PREFIX.to_vec()) }
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

    fn get_last_tx_id(&self, _script_public_key: &ScriptPublicKey) -> StoreResult<[u8; 32]> {
        Ok([0u8; 32])
    }
}

impl AccountStore for DbAccountStore {
    fn set_batch(&self, batch: &mut WriteBatch, script_public_key: &ScriptPublicKey, state: AccountState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), AccountKey::new(script_public_key), state)
    }

    fn update_balance_batch(
        &self,
        batch: &mut WriteBatch,
        script_public_key: &ScriptPublicKey,
        balance_change: i64,
    ) -> StoreResult<()> {
        let mut state = self.get(script_public_key).unwrap_or_default();

        if balance_change >= 0 {
            state.balance = state.balance.saturating_add(balance_change as u64);
        } else {
            let decrement = balance_change.unsigned_abs();
            state.balance = state.balance.saturating_sub(decrement);
        }

        self.set_batch(batch, script_public_key, state)
    }

    fn set_last_tx_id_batch(
        &self,
        _batch: &mut WriteBatch,
        _script_public_key: &ScriptPublicKey,
        _tx_id: [u8; 32],
    ) -> StoreResult<()> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// FLASH TRANSACTION HELPERS (SFT)
// ═══════════════════════════════════════════════════════════════

/// Prune window — must be > FLASH_EXPIRY_BLOCKS to avoid edge-case replay
pub const FLASH_EXPIRY_BLOCKS: u64 = 100;
pub const FLASH_PRUNE_BUFFER: u64 = 50;
pub const FLASH_PRUNE_WINDOW: u64 = FLASH_EXPIRY_BLOCKS + FLASH_PRUNE_BUFFER; // 150

impl AccountState {
    /// Check if this flash_id is a replay (already applied within window)
    pub fn is_flash_replay(&self, flash_id: &sahyadri_hashes::Hash) -> bool {
        self.recent_flashes.iter().any(|e| &e.flash_id == flash_id)
    }

    /// Record a flash entry with block_hash (for per-block reorg tracking)
    pub fn record_flash(
        &mut self,
        flash_id: sahyadri_hashes::Hash,
        expiry_daa_score: u64,
        block_hash: sahyadri_hashes::Hash,
    ) {
        self.recent_flashes.push(FlashEntry { flash_id, expiry_daa_score, block_hash });
    }

    /// Prune expired flash entries — call after each block commit
    pub fn prune_recent_flashes(&mut self, current_daa_score: u64) {
        let cutoff = current_daa_score.saturating_sub(FLASH_PRUNE_BUFFER);
        self.recent_flashes.retain(|e| e.expiry_daa_score > cutoff);
    }

    /// Reorg: remove all flash entries that came from the given block_hash.
    /// Returns true if any entry was removed.
    ///
    /// Note: this is the safe unwind — we only remove entries that this
    /// specific block added. Parallel flash-txs from other blocks are
    /// untouched, so they remain valid and replay-protected.
    pub fn reorg_block_flashes(&mut self, block_hash: &sahyadri_hashes::Hash) -> bool {
        let before = self.recent_flashes.len();
        self.recent_flashes.retain(|e| &e.block_hash != block_hash);
        self.recent_flashes.len() < before
    }
}
