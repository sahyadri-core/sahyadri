use sahyadri_consensus_core::tx::{VerifiableTransaction, ScriptPublicKey};
use crate::model::stores::account_store::AccountStoreReader;
use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TxValidationFlags {
    Full,
    SkipScriptChecks,
    SkipMassCheck,
}

impl TransactionValidator {
    pub fn validate_populated_transaction_and_get_fee(
        &self,
        tx: &impl VerifiableTransaction,
        _pov_daa_score: u64,
        flags: TxValidationFlags,
        _mass_and_feerate_threshold: Option<(u64, f64)>,
    ) -> TxResult<u64> {
        
        if tx.is_coinbase() {
            return Ok(0);
        }

        let (sender_spk, tx_nonce) = self.extract_sender_and_nonce(tx)?;
        let account_state = self.account_store.get(&sender_spk).map_err(|_| TxRuleError::Unknown)?;

        if tx_nonce != account_state.nonce + 1 {
            return Err(TxRuleError::InvalidNonce(account_state.nonce + 1, tx_nonce));
        }

        let total_out: u64 = tx.outputs().iter().map(|out| out.value).sum();
        let gas = tx.tx().gas;
        let total_required = total_out.checked_add(gas).ok_or(TxRuleError::InputAmountOverflow)?;

        if account_state.balance < total_required {
            return Err(TxRuleError::SpendTooHigh(total_out, account_state.balance));
        }

        if flags == TxValidationFlags::Full {
            self.check_scripts(tx)?;
        }

        Ok(gas)
    }

    fn extract_sender_and_nonce(&self, tx: &impl VerifiableTransaction) -> TxResult<(ScriptPublicKey, u64)> {
        let payload = &tx.tx().payload;
        if payload.len() < 8 {
            return Err(TxRuleError::InvalidPayload);
        }
        let nonce_bytes_start = payload.len() - 8;
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&payload[nonce_bytes_start..]);
        let nonce = u64::from_le_bytes(nonce_bytes);
        let sender_script = payload[..nonce_bytes_start].to_vec();
        let sender_spk = ScriptPublicKey::new(0, sender_script.into());
        Ok((sender_spk, nonce))
    }

    pub fn check_scripts(&self, tx: &impl VerifiableTransaction) -> TxResult<()> {
        let reused_values = sahyadri_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
        for (i, (input, entry)) in tx.populated_inputs().enumerate() {
            sahyadri_txscript::TxScriptEngine::from_transaction_input(tx, input, i, entry, &reused_values, &self.sig_cache)
                .execute()
                .map_err(|_| TxRuleError::Unknown)?;
        }
        Ok(())
    }
}
