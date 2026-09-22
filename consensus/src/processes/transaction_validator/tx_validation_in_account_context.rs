use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};
use crate::model::stores::account_store::AccountStoreReader;
use sahyadri_consensus_core::tx::{ScriptPublicKey, VerifiableTransaction};
use sahyadri_dilithium::{DilithiumKeyPair, DilithiumSignature, PUBKEY_SIZE, SAHYADRI_MODE, SIG_SIZE};
use sahyadri_consensus_core::tx::FlashTransaction;

/// Convert sender pubkey (1952 bytes) to P2PKH script.
/// Matches SDK's pubkeyToAddress: sha3(pubkey)[..20] with 0x14/0xac wrapper.
fn pubkey_to_p2pkh_spk(pubkey: &[u8]) -> ScriptPublicKey {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let hash20 = &hash[..20];

    let mut script = Vec::with_capacity(22);
    script.push(0x14);
    script.extend_from_slice(hash20);
    script.push(0xac);

    ScriptPublicKey::new(0, script.into())
}

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

        // ──── FLASH TX BYPASS ────
        {
            let payload = &tx.tx().payload;
            if payload.len() >= 8 && &payload[..8] == b"FLASH_V1" {
                return Ok(0);
            }
        }

        // ──── DID TX BYPASS ────
        // DID operations (create/update/deactivate) use 0-value outputs and
        // do not go through account-tx nonce validation. Signature verification
        // happens in the processor (DCRT/DUPD/DDEC handlers).
        {
            let payload = &tx.tx().payload;
            if payload.len() >= 4 {
                let p = &payload[..4];
                if p == b"DCRT" || p == b"DUPD" || p == b"DDEC" {
                    return Ok(0);
                }
            }
        }

        let (sender_spk, tx_nonce) = self.extract_sender_and_nonce(tx)?;
        let account_state = self.account_store.get(&sender_spk).map_err(|_| TxRuleError::Unknown)?;

        if tx_nonce != account_state.nonce + 1 {
            return Err(TxRuleError::InvalidNonce(account_state.nonce + 1, tx_nonce));
        }

        let total_out: u64 = tx.outputs().iter().map(|out| out.value).sum();
        let gas = tx.tx().gas;

        // --- SAHYADRI MINIMUM FEE ENFORCEMENT ---
        // Mass-based fee is enforced at mempool level (check_transaction_standard.rs)
        const MIN_FEE_KANA: u64 = 1000; // 0.00001 CSM
        if gas < MIN_FEE_KANA {
            return Err(TxRuleError::ZeroFee);
        }
        // -------------------------------------------

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
        // Payload layout: [sender_pubkey:PUBKEY_SIZE][nonce:8][signature:SIG_SIZE]
        if payload.len() < PUBKEY_SIZE + 8 + SIG_SIZE {
            return Err(TxRuleError::InvalidPayload);
        }
        let sig_start = payload.len() - SIG_SIZE;
        let nonce_start = sig_start - 8;
        let sender_pubkey = &payload[..nonce_start];
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&payload[nonce_start..sig_start]);
        let nonce = u64::from_le_bytes(nonce_bytes);
        // Convert pubkey to P2PKH script — same as account store uses
        let sender_spk = pubkey_to_p2pkh_spk(sender_pubkey);
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

    // ═══════════════════════════════════════════════════════════════
    // SAHYADRI FLASH TRANSACTION (SFT) VALIDATION
    // Order-independent, nonce-less. Cheap checks first.
    // ═══════════════════════════════════════════════════════════════

    /// Validate a FlashTransaction. Check order (cheap → expensive):
    ///   1. Expiry (u64 compare — fail fast)
    ///   2. Fee minimum
    ///   3. Replay (bounded `recent_flashes` lookup)
    ///   4. Signature (ML-DSA-65 — CPU heavy)
    ///   5. Balance (state read + compare)
    pub fn validate_flash_transaction(
        &self,
        tx: &FlashTransaction,
        current_daa_score: u64,
    ) -> TxResult<()> {
        // ── 1. Expiry (cheapest) ──
        if current_daa_score > tx.expiry_daa_score {
            return Err(TxRuleError::Message(format!(
                "FlashTx expired: current_daa={} > expiry={}",
                current_daa_score, tx.expiry_daa_score
            )));
        }

        // ── 2. Fee minimum ──
        const FLASH_MIN_FEE_KANA: u64 = 1000; // 0.00001 CSM
        if tx.fee < FLASH_MIN_FEE_KANA {
            return Err(TxRuleError::ZeroFee);
        }

        // ── 3. Load sender account ──
        let sender_spk = pubkey_to_p2pkh_spk(&tx.pubkey);
        let account_state = self
            .account_store
            .get(&sender_spk)
            .map_err(|_| TxRuleError::Unknown)?;

        // ── 4. Replay check (bounded window) ──
        let flash_id = tx.flash_id();
        if account_state.is_flash_replay(&flash_id) {
            return Err(TxRuleError::Message(format!(
                "FlashTx replay detected: {:?}",
                flash_id
            )));
        }

        // ── 5. Signature verification (expensive, last before balance) ──
        let sig = DilithiumSignature::from_slice(&tx.signature);
        let sighash = tx.sighash();
        let is_valid = DilithiumKeyPair::verify(&tx.pubkey, &sig, &sighash, b"", SAHYADRI_MODE);
        if !is_valid {
            return Err(TxRuleError::Message(
                "FlashTx ML-DSA-65 signature verification FAILED".into(),
            ));
        }

        // ── 6. Balance check ──
        let total_required = tx
            .amount
            .checked_add(tx.fee)
            .ok_or(TxRuleError::InputAmountOverflow)?;
        if account_state.balance < total_required {
            return Err(TxRuleError::SpendTooHigh(tx.amount, account_state.balance));
        }

        Ok(())
    }
    /// Validate a batch of FlashTransactions from a single block.
    ///
    /// Handles double-spend via cumulative sender debits:
    ///   ─ Same block, same sender, multiple FlashTxs = aggregate check
    ///   ─ If aggregate > balance → whole batch rejected (all-or-nothing)
    ///
    /// Check order:
    ///   1. Aggregate sender debits → cumulative balance check
    ///   2. Duplicate flash_id within batch
    ///   3. Per-tx: validate_flash_transaction (expiry, replay, sig)
    pub fn validate_flash_batch(
        &self,
        txs: &[sahyadri_consensus_core::tx::FlashTransaction],
        current_daa_score: u64,
    ) -> TxResult<()> {
        use std::collections::{HashMap, HashSet};

        if txs.is_empty() {
            return Ok(());
        }

        // ── 1. Aggregate sender debits ──
        let mut sender_debits: HashMap<ScriptPublicKey, u64> = HashMap::new();
        for tx in txs {
            let spk = pubkey_to_p2pkh_spk(&tx.pubkey);
            let entry = sender_debits.entry(spk).or_insert(0);
            *entry = entry
                .checked_add(tx.amount)
                .and_then(|v| v.checked_add(tx.fee))
                .ok_or(TxRuleError::InputAmountOverflow)?;
        }

        // ── 2. Cumulative balance check (all-or-nothing) ──
        for (spk, total_debit) in sender_debits.iter() {
            let account = self.account_store.get(spk).map_err(|_| TxRuleError::Unknown)?;
            if account.balance < *total_debit {
                return Err(TxRuleError::SpendTooHigh(*total_debit, account.balance));
            }
        }

        // ── 3. Duplicate flash_id within same batch ──
        let mut seen = HashSet::new();
        for tx in txs {
            let id = tx.flash_id();
            if !seen.insert(id) {
                return Err(TxRuleError::Message(format!(
                    "Duplicate flash_id in batch: {:?}",
                    id
                )));
            }
        }

        // ── 4. Per-tx validation ──
        for tx in txs {
            self.validate_flash_transaction(tx, current_daa_score)?;
        }

        Ok(())
    }
}

