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


use sahyadri_consensus_core::model::proof::{
    AccountProof, AccountProofFlashEntry, AccountProofPayload, AccountProofState,
    AccountProofTerminal,
};

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

// ═══════════════════════════════════════════════════════════════
// Block effects extraction — existing commit logic ko pure karo
// ═══════════════════════════════════════════════════════════════

use crate::processes::coinbase::CoinbaseManager;
use sahyadri_consensus_core::tx::Transaction;

/// Treasury pubkey hex ko SPK me convert karo.
/// Existing `commit_virtual_state` jaisa — `ScriptPublicKey::from_vec(0, raw_pubkey)`.
fn treasury_spk_from_hex(hex: &str) -> Option<ScriptPublicKey> {
    if hex.is_empty() {
        return None;
    }
    // Dilithium pubkey size = 1952 bytes
    let mut bytes = vec![0u8; 1952];
    if faster_hex::hex_decode(hex.as_bytes(), &mut bytes).is_ok() {
        Some(ScriptPublicKey::from_vec(0, bytes))
    } else {
        None
    }
}

/// Block ke txs se account-model effects nikalo.
///
/// **Ye function pure hai** — kuch mutate nahi karta.
///
/// Returns:
/// - `flash_txs`: block ke flash txs, canonical order me
/// - `rewards`: `[(spk, amount)]` — miner + treasury credit
///
/// DID txs aur legacy account txs **ignore** hote hain — ye SMT state ka
/// part nahi hain (DID alag store me, legacy dead hai).
pub fn extract_block_effects(
    txs: &[Transaction],
    coinbase_manager: &CoinbaseManager,
    treasury_hex: &str,
) -> (Vec<FlashTransaction>, Vec<(ScriptPublicKey, u64)>) {
    let mut flash_txs = Vec::new();
    let mut rewards = Vec::new();

    if txs.is_empty() {
        return (flash_txs, rewards);
    }

    // ── Coinbase reward split (txs[0]) ──
    if let Ok(cb) = coinbase_manager.deserialize_coinbase_payload(&txs[0].payload) {
        let total = cb.subsidy;
        if total > 0 {
            let dev_fee = if treasury_hex.is_empty() {
                0
            } else {
                total / 50
            };
            let miner_reward = total - dev_fee;

            rewards.push((cb.miner_data.script_public_key.clone(), miner_reward));

            if dev_fee > 0 {
                if let Some(spk) = treasury_spk_from_hex(treasury_hex) {
                    rewards.push((spk, dev_fee));
                }
            }
        }
    }

    // ── Flash txs (skip coinbase) ──
    for tx in txs.iter().skip(1) {
        if let Some(flash) = FlashTransaction::from_transaction(tx) {
            flash_txs.push(flash);
        }
        // DID (DCRT/DUPD/DDEC) — skip, SMT ke bahar
        // Legacy account tx — skip, dead hai
    }

    (flash_txs, rewards)
}

// ═══════════════════════════════════════════════════════════════
// ACCOUNT PROOF GENERATION (light-client support)
// ═══════════════════════════════════════════════════════════════

/// Generate a proof of account membership / absence against `root`.
pub fn prove_account<S: NodeStore>(
    smt_store: &S,
    account_states_store: &dyn AccountStatesStoreReader,
    root: H256,
    spk: &ScriptPublicKey,
) -> Result<AccountProof, AccountError> {
    let key = account_key_hash(spk);

    // 1. SMT proof
    let smt_proof = sahyadri_smt::prove(smt_store, root, &key)
        .map_err(AccountError::Smt)?;

    // 2. Translate into serde-friendly shape
    let siblings = smt_proof.siblings.clone();
    let terminal = match smt_proof.terminal {
        sahyadri_smt::Terminal::Empty => AccountProofTerminal::Empty,
        sahyadri_smt::Terminal::Leaf { key, value } => {
            AccountProofTerminal::Leaf { key, value }
        }
    };

    // 3. Resolve account state via leaf value.
    //
    // Two exclusion cases exist:
    //   (a) Empty terminal — path ends in an empty subtree.
    //   (b) Divergent leaf — path ends at a leaf whose key differs from
    //       the queried key. In that case the queried account is absent
    //       and we MUST NOT return the divergent account's state.
    let (state, state_hash) = match &terminal {
        AccountProofTerminal::Empty => (None, [0u8; 32]),
        AccountProofTerminal::Leaf { key: leaf_key, value } => {
            if *leaf_key != key {
                // Divergent leaf — queried account is absent.
                (None, [0u8; 32])
            } else {
                // Inclusion — fetch the AccountState keyed by its content hash.
                match account_states_store.get(Hash::from_bytes(*value)) {
                    Ok(s) => (
                        Some(AccountProofState {
                            balance: s.balance,
                            recent_flashes: s
                                .recent_flashes
                                .iter()
                                .map(|f| AccountProofFlashEntry {
                                    flash_id: f.flash_id,
                                    expiry_daa_score: f.expiry_daa_score,
                                })
                                .collect(),
                        }),
                        *value,
                    ),
                    Err(_) => (None, *value),
                }
            }
        }
    };

    Ok(AccountProof {
        block_hash: Default::default(),   // caller sets
        account_root: Hash::from_bytes(root),
        key,
        proof: AccountProofPayload { siblings, terminal },
        state,
        state_hash,
    })
}


#[cfg(test)]
mod proof_generation_tests {
    use super::*;
    use sahyadri_smt::{MemStore, EMPTY as SMT_EMPTY};
    use std::collections::HashMap;

    /// In-memory mock of `AccountStatesStoreReader` for tests.
    struct MockStatesStore(HashMap<Hash, AccountState>);

    impl AccountStatesStoreReader for MockStatesStore {
        fn get(&self, state_hash: Hash) -> Result<AccountState, StoreError> {
            self.0
                .get(&state_hash)
                .cloned()
                .ok_or_else(|| StoreError::DataInconsistency(format!("state not found: {state_hash}")))
        }
    }

    fn test_spk(seed: u8) -> ScriptPublicKey {
        ScriptPublicKey::from_vec(0, vec![seed; 20])
    }

    fn test_state(balance: u64) -> AccountState {
        AccountState { balance, recent_flashes: vec![] }
    }

    /// Insert an account into a fresh SMT, return (store, root, state_hash, state_store).
    fn setup_one_account(
        spk: &ScriptPublicKey,
        balance: u64,
    ) -> (MemStore, H256, Hash, MockStatesStore) {
        let mut smt = MemStore::default();
        let key = account_key_hash(spk);
        let state = test_state(balance);
        let state_hash = state.content_hash();
        let value: [u8; 32] = state_hash.as_bytes().try_into().unwrap();
        let root = sahyadri_smt::update(&mut smt, SMT_EMPTY, &key, Some(value)).unwrap();

        let mut states = HashMap::new();
        states.insert(state_hash, state);
        (smt, root, state_hash, MockStatesStore(states))
    }

    fn to_smt_proof(p: &AccountProofPayload) -> sahyadri_smt::Proof {
        sahyadri_smt::Proof {
            siblings: p.siblings.clone(),
            terminal: match &p.terminal {
                AccountProofTerminal::Empty => sahyadri_smt::Terminal::Empty,
                AccountProofTerminal::Leaf { key, value } => {
                    sahyadri_smt::Terminal::Leaf { key: *key, value: *value }
                }
            },
        }
    }

    #[test]
    fn test_prove_account_inclusion() {
        let spk = test_spk(1);
        let (smt, root, state_hash, states) = setup_one_account(&spk, 1_000);

        let proof = prove_account(&smt, &states, root, &spk).expect("proof generation failed");

        // Leaf terminal expected
        assert!(matches!(proof.proof.terminal, AccountProofTerminal::Leaf { .. }));
        assert_eq!(proof.account_root, Hash::from_bytes(root));
        assert_eq!(proof.key, account_key_hash(&spk));
        let expected_value: [u8; 32] = state_hash.as_bytes().try_into().unwrap();
        assert_eq!(proof.state_hash, expected_value);

        // Resolved state
        let s = proof.state.as_ref().expect("state should be Some");
        assert_eq!(s.balance, 1_000);
        assert!(s.recent_flashes.is_empty());

        // Cryptographic verification
        let value: [u8; 32] = state_hash.as_bytes().try_into().unwrap();
        let smt_proof = to_smt_proof(&proof.proof);
        assert!(
            sahyadri_smt::verify_inclusion(&root, &proof.key, &value, &smt_proof),
            "inclusion proof must verify against root"
        );
    }

    #[test]
    fn test_prove_account_exclusion() {
        // Tree has account #1, we query #2
        let existing = test_spk(1);
        let (smt, root, _, states) = setup_one_account(&existing, 500);

        let absent = test_spk(2);
        let proof = prove_account(&smt, &states, root, &absent).expect("proof generation failed");

        // Absence shape: either an empty terminal OR a divergent leaf
        // (a leaf whose key differs from the queried key).
        match &proof.proof.terminal {
            AccountProofTerminal::Empty => {}
            AccountProofTerminal::Leaf { key, .. } => {
                assert_ne!(*key, proof.key, "divergent leaf must not carry the queried key");
            }
        }

        // Either way, the queried account is absent.
        assert!(proof.state.is_none(), "exclusion proof must not yield a state");
        assert_eq!(proof.state_hash, [0u8; 32]);

        // Cryptographic verification (handles both exclusion cases).
        let smt_proof = to_smt_proof(&proof.proof);
        assert!(
            sahyadri_smt::verify_exclusion(&root, &proof.key, &smt_proof),
            "exclusion proof must verify against root"
        );
    }

    #[test]
    fn test_prove_account_against_empty_tree() {
        let smt = MemStore::default();
        let root = SMT_EMPTY;
        let states = MockStatesStore(HashMap::new());

        let spk = test_spk(3);
        let proof = prove_account(&smt, &states, root, &spk).expect("proof generation failed");

        assert!(matches!(proof.proof.terminal, AccountProofTerminal::Empty));
        assert!(proof.state.is_none());

        let smt_proof = to_smt_proof(&proof.proof);
        assert!(sahyadri_smt::verify_exclusion(&root, &proof.key, &smt_proof));
    }
}
