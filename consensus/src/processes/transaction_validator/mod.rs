pub mod errors;
pub mod tx_validation_in_account_context;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;

use crate::model::stores::account_store::DbAccountStore;
use std::sync::Arc; // <--- IMPORT BANK

use sahyadri_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use sahyadri_consensus_core::{KType};

#[derive(Clone)]
pub struct TransactionValidator {
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    max_signature_script_len: usize,
    max_script_public_key_len: usize,
    coinbase_payload_script_public_key_max_len: u8,
    /// Coinbase maturity window in blocks. Configured but not yet enforced
    /// in the account model — enforcing it requires tracking unmaturred rewards
    /// per account (pending_rewards field on AccountState).
    coinbase_maturity: u64,
    _sahyadri_consensus_k: KType,
    sig_cache: Cache<SigCacheKey, bool>,

    pub account_store: Arc<DbAccountStore>,
}

impl TransactionValidator {
    pub fn new(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        sahyadri_consensus_k: KType,
        counters: Arc<TxScriptCacheCounters>,
        account_store: Arc<DbAccountStore>, // <--- REQUIRED IT IN THE CONSTRUCTOR
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            _sahyadri_consensus_k: sahyadri_consensus_k,
            sig_cache: Cache::with_counters(10_000, counters),
            account_store, // <--- SAVED IT
        }
    }

    pub fn new_for_tests(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        sahyadri_consensus_k: KType,
        counters: Arc<TxScriptCacheCounters>,
        account_store: Arc<DbAccountStore>, // <--- REQUIRED IT HERE TOO
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            _sahyadri_consensus_k: sahyadri_consensus_k,
            sig_cache: Cache::with_counters(10_000, counters),
            account_store, // <--- SAVED IT
        }
    }
}

impl TransactionValidator {
    /// Returns the configured coinbase maturity window in blocks.
    /// Maturity enforcement is not yet implemented in the account model.
    /// Full remediation requires tracking unmaturred rewards per account.
    pub fn coinbase_maturity(&self) -> u64 {
        self.coinbase_maturity
    }
}
