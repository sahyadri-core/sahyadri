use crate::constants::{MAX_KANA, TX_VERSION};
use sahyadri_consensus_core::tx::Transaction;
use std::collections::HashSet;

use sahyadri_dilithium::{DilithiumSignature, DilithiumKeyPair, PUBKEY_SIZE, SIG_SIZE, SAHYADRI_MODE};
use sha2::{Sha256, Digest};
use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};

impl TransactionValidator {
    /// Performs a variety of transaction validation checks which are independent of any
    /// context -- header or utxo. **Note** that any check performed here should be moved to
    /// header contextual validation if it becomes HF activation dependent. This is bcs we rely
    /// on checks here to be truly independent and avoid calling it multiple times wherever possible
    /// (e.g., BBT relies on mempool in isolation checks even though virtual daa score might have changed)   
    pub fn validate_tx_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        // SAHYADRI ACCOUNT MODEL: Verify signature for account transactions
        // Payload: [sender_pubkey:PUBKEY_SIZE][nonce:8][signature:SIG_SIZE]
        if tx.inputs.is_empty() && !tx.payload.is_empty() && !tx.is_coinbase() {
            check_transaction_output_value_ranges(tx)?;
            verify_account_tx_signature(tx)?;
            return Ok(());
        }

        self.check_transaction_inputs_in_isolation(tx)?;
        self.check_transaction_outputs_in_isolation(tx)?;
        self.check_coinbase_in_isolation(tx)?;

        check_transaction_output_value_ranges(tx)?;
        check_duplicate_transaction_inputs(tx)?;
        check_gas(tx)?;
        check_transaction_subnetwork(tx)?;
        check_transaction_version(tx)
    }

    fn check_transaction_inputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_count(tx)?;
        self.check_transaction_signature_scripts(tx)
    }

    fn check_transaction_outputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_outputs_count(tx)?;
        self.check_transaction_script_public_keys(tx)
    }

    fn check_coinbase_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        if !tx.is_coinbase() {
            return Ok(());
        }
        if !tx.inputs.is_empty() {
            return Err(TxRuleError::CoinbaseHasInputs(tx.inputs.len()));
        }

        if tx.mass() > 0 {
            return Err(TxRuleError::CoinbaseNonZeroMassCommitment);
        }

        let outputs_limit = 100;
        if tx.outputs.len() as u64 > outputs_limit {
            return Err(TxRuleError::CoinbaseTooManyOutputs(tx.outputs.len(), outputs_limit));
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            if output.script_public_key.script().len() > self.coinbase_payload_script_public_key_max_len as usize {
                return Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(i));
            }
        }
        Ok(())
    }

    fn check_transaction_outputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if tx.is_coinbase() {
            // We already check coinbase outputs count vs. SahyadriConsensus K + 2
            return Ok(());
        }
        if tx.outputs.len() > self.max_tx_outputs {
            return Err(TxRuleError::TooManyOutputs(tx.outputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    fn check_transaction_inputs_count(&self, tx: &Transaction) -> TxResult<()> {
        // SAHYADRI ACCOUNT MODEL: Allow account transactions (empty inputs + payload has sender)
        if !tx.is_coinbase() && tx.inputs.is_empty() && tx.payload.is_empty() {
            return Err(TxRuleError::NoTxInputs);
        }

        if tx.inputs.len() > self.max_tx_inputs {
            return Err(TxRuleError::TooManyInputs(tx.inputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_signature_scripts(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > self.max_signature_script_len) {
            return Err(TxRuleError::TooBigSignatureScript(i, self.max_signature_script_len));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_script_public_keys(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.outputs.iter().position(|out| out.script_public_key.script().len() > self.max_script_public_key_len) {
            return Err(TxRuleError::TooBigScriptPublicKey(i, self.max_script_public_key_len));
        }

        Ok(())
    }
}

fn check_duplicate_transaction_inputs(tx: &Transaction) -> TxResult<()> {
    let mut existing = HashSet::new();
    for input in &tx.inputs {
        if !existing.insert(input.previous_outpoint) {
            return Err(TxRuleError::TxDuplicateInputs);
        }
    }
    Ok(())
}

fn check_gas(tx: &Transaction) -> TxResult<()> {
    // This should be revised if subnetworks are activated (along with other validations that weren't copied from sahyadrid)
    if tx.gas > 0 {
        return Err(TxRuleError::TxHasGas);
    }
    Ok(())
}

fn check_transaction_version(tx: &Transaction) -> TxResult<()> {
    if tx.version != TX_VERSION {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }
    Ok(())
}

fn check_transaction_output_value_ranges(tx: &Transaction) -> TxResult<()> {
    let mut total: u64 = 0;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(TxRuleError::TxOutZero(i));
        }

        if output.value > MAX_KANA {
            return Err(TxRuleError::TxOutTooHigh(i));
        }

        if let Some(new_total) = total.checked_add(output.value) {
            total = new_total
        } else {
            return Err(TxRuleError::OutputsValueOverflow);
        }

        if total > MAX_KANA {
            return Err(TxRuleError::TotalTxOutTooHigh);
        }
    }

    Ok(())
}

fn check_transaction_subnetwork(tx: &Transaction) -> TxResult<()> {
    if tx.is_coinbase() || tx.subnetwork_id.is_native() {
        Ok(())
    } else {
        Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id.clone()))
    }
}

const ACCOUNT_TX_MIN_PAYLOAD: usize = PUBKEY_SIZE + 8 + SIG_SIZE;

fn verify_account_tx_signature(tx: &Transaction) -> TxResult<()> {
    if tx.payload.len() < ACCOUNT_TX_MIN_PAYLOAD {
        return Err(TxRuleError::Message(format!(
            "Account tx payload too small: {} bytes, minimum {}", tx.payload.len(), ACCOUNT_TX_MIN_PAYLOAD
        )));
    }
    let sig_start = tx.payload.len() - SIG_SIZE;
    let nonce_start = sig_start - 8;
    let sender_pubkey = &tx.payload[..nonce_start];
    let sig_bytes = &tx.payload[sig_start..];
    if sender_pubkey.len() != PUBKEY_SIZE {
        return Err(TxRuleError::Message(format!(
            "Account tx sender pubkey invalid: {} bytes, expected {}", sender_pubkey.len(), PUBKEY_SIZE
        )));
    }
    let signable_payload = &tx.payload[..sig_start];
    let sighash = compute_account_tx_sighash(tx, signable_payload);
    let sig = DilithiumSignature::from_slice(sig_bytes);
    let valid = DilithiumKeyPair::verify(sender_pubkey, &sig, &sighash, b"", SAHYADRI_MODE);
    if !valid {
        return Err(TxRuleError::Message("Account tx Dilithium3 signature verification FAILED".to_string()));
    }
    Ok(())
}

fn compute_account_tx_sighash(tx: &Transaction, signable_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SAHYADRI_ACCOUNT_TX_V1");
    hasher.update(&tx.version.to_le_bytes());
    for output in &tx.outputs {
        hasher.update(&output.value.to_le_bytes());
        hasher.update(&output.script_public_key.version.to_le_bytes());
        let script = output.script_public_key.script();
        hasher.update(&(script.len() as u64).to_le_bytes());
        hasher.update(script);
    }
    hasher.update(&tx.lock_time.to_le_bytes());
    hasher.update(tx.subnetwork_id.as_bytes());
    hasher.update(&tx.gas.to_le_bytes());
    hasher.update(&(signable_payload.len() as u64).to_le_bytes());
    hasher.update(signable_payload);
    hasher.finalize().into()
}
