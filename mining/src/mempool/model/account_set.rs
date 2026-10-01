//! Account-model mempool state tracker (replaces legacy `MempoolRegistryUnitSet`).
//!
//! In the account model there are no outpoints. The only two invariants the
//! mempool must enforce are:
//!   1. Flash-tx replay: same `flash_id` must not enter mempool twice.
//!   2. Aggregate over-spend: sum of (amount+fee) per sender must not exceed
//!      the sender's on-chain balance.
//!
//! RBF is expressed as: same sender, same flash_id → treated as double-spend,
//! and the higher-feerate version replaces the older one.

use std::collections::HashMap;

use crate::mempool::{
    errors::{RuleError, RuleResult},
    model::tx::DoubleSpend,
};
use sahyadri_consensus_core::tx::{FlashTransaction, MutableTransaction, TransactionId, RegistryRef};
use sahyadri_hashes::Hash;

pub(crate) struct MempoolAccountSet {
    /// flash_id → mempool tx id (replay + RBF owner lookup)
    flash_owners: HashMap<Hash, TransactionId>,
    /// sender pubkey (ML-DSA-65) → total pending debit
    pending_debits: HashMap<Vec<u8>, u64>,
    /// tx_id → (sender pubkey, debit) — O(1) reversal on removal
    tx_debits: HashMap<TransactionId, (Vec<u8>, u64)>,
}

impl MempoolAccountSet {
    pub(crate) fn new() -> Self {
        Self {
            flash_owners: HashMap::new(),
            pending_debits: HashMap::new(),
            tx_debits: HashMap::new(),
        }
    }

    fn extract_flash_debit(tx: &MutableTransaction) -> Option<(Vec<u8>, u64, Hash)> {
        let flash = FlashTransaction::from_transaction(&tx.tx)?;
        let debit = flash.amount.checked_add(flash.fee)?;
        Some((flash.pubkey.clone(), debit, flash.flash_id()))
    }

    /// Register a newly-added mempool tx.
    /// Rejects mempool-level replay of the same flash_id.
    pub(crate) fn add_transaction(&mut self, transaction: &MutableTransaction) -> RuleResult<()> {
        let tx_id = transaction.id();

        if let Some((pubkey, debit, flash_id)) = Self::extract_flash_debit(transaction) {
            if let Some(existing) = self.flash_owners.get(&flash_id) {
                // Replay — same flash_id already pending in mempool
                return Err(RuleError::RejectDuplicate(*existing));
            }

            self.flash_owners.insert(flash_id, tx_id);
            let entry = self.pending_debits.entry(pubkey.clone()).or_insert(0);
            *entry = entry.saturating_add(debit);
            self.tx_debits.insert(tx_id, (pubkey, debit));
        }

        Ok(())
    }

    pub(crate) fn remove_transaction(&mut self, transaction: &MutableTransaction) {
        let tx_id = transaction.id();
        if let Some((pubkey, debit)) = self.tx_debits.remove(&tx_id) {
            if let Some(entry) = self.pending_debits.get_mut(&pubkey) {
                *entry = entry.saturating_sub(debit);
                if *entry == 0 {
                    self.pending_debits.remove(&pubkey);
                }
            }
            self.flash_owners.retain(|_, owner| *owner != tx_id);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn pending_debit_for(&self, pubkey: &[u8]) -> u64 {
        self.pending_debits.get(pubkey).copied().unwrap_or(0)
    }

    /// Account-model double-spend: flash_id collision with an existing mempool tx.
    pub(crate) fn check_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        if let Some((_, _, flash_id)) = Self::extract_flash_debit(transaction) {
            if let Some(owner) = self.flash_owners.get(&flash_id) {
                return Err(RuleError::RejectDuplicate(*owner));
            }
        }
        Ok(())
    }

    /// Legacy outpoint lookup — in account model there are no outpoints.
    /// Always returns `None`. Kept for API compatibility with
    /// `handle_new_block_transactions.rs`.
    pub(crate) fn get_outpoint_owner_id(&self, _outpoint: &RegistryRef) -> Option<&TransactionId> {
        None
    }

    /// Return all pending mempool txs that conflict with `transaction`
    /// (same flash_id). Used by `replace_by_fee.rs` for RBF feerate comparison.
    pub(crate) fn get_double_spend_transaction_ids(&self, transaction: &MutableTransaction) -> Vec<DoubleSpend> {
        if let Some((_, _, flash_id)) = Self::extract_flash_debit(transaction) {
            if let Some(owner) = self.flash_owners.get(&flash_id) {
                // Synthesize a pseudo-outpoint from flash_id so existing
                // DoubleSpend plumbing in replace_by_fee.rs keeps working.
                let outpoint = RegistryRef::new(flash_id, 0);
                return vec![DoubleSpend::new(outpoint, *owner)];
            }
        }
        vec![]
    }
}
