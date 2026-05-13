pub mod errors;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
pub mod tx_validation_in_account_context; // <--- RENAMED FROM UTXO!

use std::sync::Arc;
use crate::model::stores::account_store::DbAccountStore; // <--- IMPORT BANK

use sahyadri_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use sahyadri_consensus_core::{KType, mass::MassCalculator};

#[derive(Clone)]
pub struct TransactionValidator {
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    max_signature_script_len: usize,
    max_script_public_key_len: usize,
    coinbase_payload_script_public_key_max_len: u8,
    _coinbase_maturity: u64,
    _sahyadri_consensus_k: KType,
    sig_cache: Cache<SigCacheKey, bool>,

    pub(crate) mass_calculator: MassCalculator,
    pub account_store: Arc<DbAccountStore>, // <--- GAVE THE BANK KEY TO BOUNCER
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
        mass_calculator: MassCalculator,
        account_store: Arc<DbAccountStore>, // <--- REQUIRED IT IN THE CONSTRUCTOR
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            _coinbase_maturity: coinbase_maturity,
            _sahyadri_consensus_k: sahyadri_consensus_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator,
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
            _coinbase_maturity: coinbase_maturity,
            _sahyadri_consensus_k: sahyadri_consensus_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator: MassCalculator::new(0, 0, 0, 0),
            account_store, // <--- SAVED IT
        }
    }
}
