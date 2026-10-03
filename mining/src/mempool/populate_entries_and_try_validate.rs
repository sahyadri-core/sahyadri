use crate::mempool::{Mempool, errors::RuleResult, model::pool::Pool};
use sahyadri_consensus_core::{
    api::{
        ConsensusApi,
        args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    },
    constants::UNACCEPTED_DAA_SCORE,
    tx::{MutableTransaction, RegistryUnit},
};
use sahyadri_mining_errors::mempool::RuleError;

impl Mempool {
    pub(crate) fn populate_mempool_entries(&self, transaction: &mut MutableTransaction) {
        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            if let Some(parent) = self.transaction_pool.get(&input.previous_outpoint.transaction_id) {
                let output = &parent.mtx.tx.outputs[input.previous_outpoint.index as usize];
                transaction.entries[i] =
                    Some(RegistryUnit::new(output.value, output.script_public_key.clone(), UNACCEPTED_DAA_SCORE, false));
            }
        }
    }
}

pub(crate) fn validate_mempool_transaction(
    consensus: &dyn ConsensusApi,
    transaction: &mut MutableTransaction,
    args: &TransactionValidationArgs,
) -> RuleResult<()> {
    Ok(consensus.validate_mempool_transaction(transaction, args)?)
}

pub(crate) fn validate_mempool_transactions_in_parallel(
    consensus: &dyn ConsensusApi,
    transactions: &mut [MutableTransaction],
    args: &TransactionValidationBatchArgs,
) -> Vec<RuleResult<()>> {
    consensus.validate_mempool_transactions_in_parallel(transactions, args).into_iter().map(|x| x.map_err(RuleError::from)).collect()
}

pub(crate) fn populate_mempool_transactions_in_parallel(
    consensus: &dyn ConsensusApi,
    transactions: &mut [MutableTransaction],
) -> Vec<RuleResult<()>> {
    consensus.populate_mempool_transactions_in_parallel(transactions).into_iter().map(|x| x.map_err(RuleError::from)).collect()
}


/// Populate fee + mass fields for account-model FlashTx.
///
/// Flash transactions bypass legacy input validation, so `calculated_fee` and
/// `calculated_non_contextual_masses` are normally `None`. We populate
/// them here so downstream mempool code (frontier, orphan checks,
/// standard checks) works without special-casing every call site.
pub(crate) fn populate_flash_tx_fields(transaction: &mut MutableTransaction) {
    let payload = &transaction.tx.payload;
    if payload.len() < 8 || &payload[..8] != b"FLASH_V1" {
        return;
    }

    // Flash payload layout (after magic):
    //   [2] version | [4] pk_len | [pk_len] pk | [4] rc_len | [rc_len] rc
    //   [8] amount | [8] fee | [8] expiry | [16] salt | [4] sig_len | [sig]
    let mut off = 8 + 2;
    if payload.len() < off + 4 { return; }
    let pk_len = u32::from_le_bytes(payload[off..off+4].try_into().unwrap()) as usize;
    off += 4 + pk_len;
    if payload.len() < off + 4 { return; }
    let rc_len = u32::from_le_bytes(payload[off..off+4].try_into().unwrap()) as usize;
    off += 4 + rc_len;
    if payload.len() < off + 16 { return; }
    off += 8; // skip amount
    let fee = u64::from_le_bytes(payload[off..off+8].try_into().unwrap());

    transaction.calculated_fee = Some(fee);
    let approx_mass = 1000u64 + payload.len() as u64;
    transaction.calculated_non_contextual_masses = Some(sahyadri_consensus_core::mass::NonContextualMasses {
        compute_mass: approx_mass,
        transient_mass: approx_mass,
    });
}
