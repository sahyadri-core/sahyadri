//! Sahyadri Flash Transaction (SFT) — apply / reorg / SPK helpers.
//!
//! These functions are the runtime side of the nonce-less transaction
//! layer. They are called from `processor.rs` when a block commits or
//! reorgs. Splitting them out keeps `processor.rs` focused on the
//! commit/reorg orchestration and lets the flash-tx logic be tested
//! independently.

use crate::model::stores::account_store::{AccountStore, AccountStoreReader, DbAccountStore};
use rocksdb::WriteBatch;
use sahyadri_consensus_core::tx::{FlashTransaction, ScriptPublicKey};
use sahyadri_database::prelude::StoreError;
use sahyadri_hashes::Hash;

/// Convert a 20-byte address hash into a P2PKH script (`0x14 <20> 0xac`).
pub fn hash20_to_p2pkh_spk(hash20: &[u8]) -> ScriptPublicKey {
    assert!(hash20.len() >= 20, "recipient hash must be >= 20 bytes");
    let mut script = Vec::with_capacity(22);
    script.push(0x14);
    script.extend_from_slice(&hash20[..20]);
    script.push(0xac);
    ScriptPublicKey::from_vec(0, script)
}

/// Convert a sender pubkey (1952 bytes) into a P2PKH script.
/// Matches the wallet SDK's `pubkeyToAddress` derivation: `sha3(pubkey)[..20]`.
pub fn flash_pubkey_to_spk(pubkey: &[u8]) -> ScriptPublicKey {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(pubkey);
    let hash = h.finalize();
    let hash20 = &hash[..20];
    let mut script = Vec::with_capacity(22);
    script.push(0x14);
    script.extend_from_slice(hash20);
    script.push(0xac);
    ScriptPublicKey::from_vec(0, script)
}

/// Apply a `FlashTransaction` from a specific block.
///
/// - Debits sender by `amount + fee`
/// - Credits recipient by `amount`
/// - Records `flash_id` with the source `block_hash` for reorg tracking
pub fn apply_flash_tx(
    account_store: &DbAccountStore,
    batch: &mut WriteBatch,
    tx: &FlashTransaction,
    block_hash: Hash,
) -> Result<(), StoreError> {
    let sender_spk = flash_pubkey_to_spk(&tx.pubkey);
    let recipient_spk = hash20_to_p2pkh_spk(&tx.recipient);

    // 1. Debit sender
    let mut sender = account_store.get(&sender_spk)?;
    let total_debit = tx.amount.saturating_add(tx.fee);
    sender.balance = sender.balance.saturating_sub(total_debit);
    sender.record_flash(tx.flash_id(), tx.expiry_daa_score, block_hash);
    account_store.set_batch(batch, &sender_spk, sender)?;

    // 2. Credit recipient
    let mut recipient = account_store.get(&recipient_spk)?;
    recipient.balance = recipient.balance.saturating_add(tx.amount);
    account_store.set_batch(batch, &recipient_spk, recipient)?;

    Ok(())
}

/// Reorg a block's `FlashTransaction`s.
///
/// Only unwinds entries whose `block_hash` matches the disconnected block.
/// This is safe under GhostDAG: parallel flash-txs from *other* blocks stay
/// intact and remain replay-protected.
pub fn reorg_flash_block(
    account_store: &DbAccountStore,
    batch: &mut WriteBatch,
    block_hash: Hash,
    txs: &[FlashTransaction],
) -> Result<(), StoreError> {
    for tx in txs {
        let sender_spk = flash_pubkey_to_spk(&tx.pubkey);
        let recipient_spk = hash20_to_p2pkh_spk(&tx.recipient);

        let mut sender = account_store.get(&sender_spk)?;
        if !sender.reorg_block_flashes(&block_hash) {
            // This block did not add the entry — nothing to unwind.
            continue;
        }
        let total_credit = tx.amount.saturating_add(tx.fee);
        sender.balance = sender.balance.saturating_add(total_credit);
        account_store.set_batch(batch, &sender_spk, sender)?;

        let mut recipient = account_store.get(&recipient_spk)?;
        recipient.balance = recipient.balance.saturating_sub(tx.amount);
        account_store.set_batch(batch, &recipient_spk, recipient)?;
    }

    Ok(())
}

/// Prune expired flash entries from the given set of accounts.
/// Cheap — only touches accounts that actually have flash history.
pub fn prune_flashes_for_accounts(
    account_store: &DbAccountStore,
    batch: &mut WriteBatch,
    accounts: &[ScriptPublicKey],
    current_daa_score: u64,
) -> Result<(), StoreError> {
    for spk in accounts {
        let mut acc = account_store.get(spk)?;
        if acc.recent_flashes.is_empty() {
            continue;
        }
        let before = acc.recent_flashes.len();
        acc.prune_recent_flashes(current_daa_score);
        if acc.recent_flashes.len() != before {
            account_store.set_batch(batch, spk, acc)?;
        }
    }
    Ok(())
}
