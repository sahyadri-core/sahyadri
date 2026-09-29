//! Account state transition function.
//!
//! This module contains the pure function that computes the account
//! commitment for a block, given the parent's commitment and the block's
//! effects. Both the verify path and the block template path call this
//! function with identical inputs, guaranteeing byte-identical roots.
//!
//! The function:
//!   1. Starts from `parent_root`
//!   2. Applies flash tx effects (debit sender, credit recipient, record flash_id)
//!   3. Applies coinbase rewards (credit miner(s))
//!   4. Prunes expired flash entries on all touched accounts
//!   5. Updates the SMT overlay and returns the new root + list of changes
//!
//! The caller is responsible for persisting the overlay's pending nodes
//! and the new root. This function does not touch any persistent store.

use sahyadri_consensus_core::tx::{FlashTransaction, ScriptPublicKey};
use sahyadri_database::prelude::StoreError;
use sahyadri_hashes::Hash;
use sahyadri_smt::{self, NodeStore, H256};

use crate::model::stores::account_states::AccountStatesStoreReader;
use crate::model::stores::account_store::{AccountState, FlashEntry};
use crate::pipeline::virtual_processor::flash_tx::{flash_pubkey_to_spk, hash20_to_p2pkh_spk};

#[derive(Debug)]
pub enum AccountError {
    Smt(sahyadri_smt::SmtError),
    Store(StoreError),
}

impl From<sahyadri_smt::SmtError> for AccountError {
    fn from(e: sahyadri_smt::SmtError) -> Self {
        AccountError::Smt(e)
    }
}

impl From<StoreError> for AccountError {
    fn from(e: StoreError) -> Self {
        AccountError::Store(e)
    }
}

/// Deterministic SMT key for an account.
///
/// `sha3("SAHYADRI_SMT_KEY_V1" || version_le(2) || script_bytes)`
pub fn account_key_hash(spk: &ScriptPublicKey) -> H256 {
    let mut bytes = spk.version().to_le_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    sahyadri_smt::hash_key(&bytes)
}

/// Read the current account state via SMT → state_hash → state_store.
fn read_account_state(
    smt_overlay: &impl NodeStore,
    state_store: &dyn AccountStatesStoreReader,
    root: H256,
    spk: &ScriptPublicKey,
) -> Result<AccountState, AccountError> {
    let key = account_key_hash(spk);
    match sahyadri_smt::get(smt_overlay, root, &key)? {
        None => Ok(AccountState::default()),
        Some(state_hash_bytes) => {
            let state_hash = Hash::from_bytes(state_hash_bytes);
            match state_store.get(state_hash) {
                Ok(state) => Ok(state),
                Err(StoreError::KeyNotFound(_)) => Ok(AccountState::default()),
                Err(e) => Err(AccountError::Store(e)),
            }
        }
    }
}

/// Compute the new SMT root and the set of account changes for a block.
///
/// Inputs:
/// - `parent_root`: SMT root of the block's selected parent (genesis = `sahyadri_smt::EMPTY`)
/// - `smt_overlay`: an `OverlayStore` on top of the persistent SMT node store
/// - `state_store`: content-addressed state snapshots (read-only)
/// - `flash_txs`: FlashTransactions accepted by this block, in canonical order
/// - `rewards`: coinbase rewards: `(miner_spk, subsidy + fee_sum)` per merged block
/// - `daa_score`: current DAA score (for flash pruning)
///
/// Returns:
/// - `new_root`: SMT root after all changes
/// - `changes`: `(SPK, new_state)` for each account modified. Order is
///   unspecified (HashMap iteration); the SMT root is order-independent.
///
/// The changes carry `block_hash = Hash::default()`. Callers that persist
/// to the live `account_store` should overwrite this field with the actual
/// block hash for reorg tracking.
pub fn compute_block_account_changes(
    parent_root: H256,
    smt_overlay: &mut impl NodeStore,
    state_store: &dyn AccountStatesStoreReader,
    flash_txs: &[FlashTransaction],
    rewards: &[(ScriptPublicKey, u64)],
    daa_score: u64,
) -> Result<(H256, Vec<(ScriptPublicKey, AccountState)>), AccountError> {
    use std::collections::HashMap;

    let mut touched: HashMap<ScriptPublicKey, AccountState> = HashMap::new();

    // ── 1. Apply flash txs ─────────────────────────────────────
    for tx in flash_txs {
        let sender_spk = flash_pubkey_to_spk(&tx.pubkey);
        let recipient_spk = hash20_to_p2pkh_spk(&tx.recipient);

        if !touched.contains_key(&sender_spk) {
            let s = read_account_state(smt_overlay, state_store, parent_root, &sender_spk)?;
            touched.insert(sender_spk.clone(), s);
        }
        if !touched.contains_key(&recipient_spk) {
            let s = read_account_state(smt_overlay, state_store, parent_root, &recipient_spk)?;
            touched.insert(recipient_spk.clone(), s);
        }

        let total_debit = tx.amount.saturating_add(tx.fee);
        {
            let sender = touched.get_mut(&sender_spk).unwrap();
            sender.balance = sender.balance.saturating_sub(total_debit);
            sender.recent_flashes.push(FlashEntry {
                flash_id: tx.flash_id(),
                expiry_daa_score: tx.expiry_daa_score,
                block_hash: Hash::default(),
            });
        }
        {
            let recipient = touched.get_mut(&recipient_spk).unwrap();
            recipient.balance = recipient.balance.saturating_add(tx.amount);
        }
    }

    // ── 2. Apply coinbase rewards ──────────────────────────────
    for (miner_spk, amount) in rewards {
        if !touched.contains_key(miner_spk) {
            let s = read_account_state(smt_overlay, state_store, parent_root, miner_spk)?;
            touched.insert(miner_spk.clone(), s);
        }
        let miner = touched.get_mut(miner_spk).unwrap();
        miner.balance = miner.balance.saturating_add(*amount);
    }

    // ── 3. Prune expired flashes on all touched accounts ───────
    for state in touched.values_mut() {
        state.prune_recent_flashes(daa_score);
    }

    // ── 4. Update SMT and produce the new root ─────────────────
    let mut root = parent_root;
    for (spk, state) in touched.iter() {
        let key = account_key_hash(spk);
        let leaf = if state.is_empty() {
            None // absent account
        } else {
            Some(state.content_hash().as_bytes())
        };
        root = sahyadri_smt::update(smt_overlay, root, &key, leaf)?;
    }

    Ok((root, touched.into_iter().collect()))
}
