//!
//! Utilities for signing transactions.
//!

use crate::transaction::Transaction;
use sahyadri_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::PopulatedTransaction,
};
use sahyadri_dilithium::{generate_keypair_from_seed, sign_bytes, DilithiumKeyPair};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

/// A wrapper enum that represents the transaction signed state. A transaction
/// contained by this enum can be either fully signed or partially signed.
pub enum Signed<'a> {
    Fully(&'a Transaction),
    Partially(&'a Transaction),
}

impl<'a> Signed<'a> {
    /// Returns the transaction regardless of whether it is fully or partially signed
    pub fn unwrap(self) -> &'a Transaction {
        match self {
            Signed::Fully(tx) => tx,
            Signed::Partially(tx) => tx,
        }
    }
}

/// Sign a transaction using Dilithium3
#[allow(clippy::result_large_err)]
pub fn sign_with_multiple_v3<'a>(tx: &'a Transaction, seeds: &[[u8; 32]]) -> crate::result::Result<Signed<'a>> {
    let mut map: BTreeMap<Vec<u8>, DilithiumKeyPair> = BTreeMap::new();
    for seed in seeds {
        let keypair = generate_keypair_from_seed(seed);
        let pk_bytes = keypair.public_key();
        let pk_hash = Sha256::digest(pk_bytes);
        let script_pub_key_script: Vec<u8> = std::iter::once(0x14u8).chain(pk_hash[0..20].iter().copied()).chain(std::iter::once(0xac)).collect();
        map.insert(script_pub_key_script, keypair);
    }

    let reused_values = SigHashReusedValuesUnsync::new();
    let mut additional_signatures_required = false;
    {
        let input_len = tx.inner().inputs.len();
        let (cctx, utxos) = tx.tx_and_utxos()?;
        let populated_transaction = PopulatedTransaction::new(&cctx, utxos);
        for i in 0..input_len {
            let script_pub_key = match tx.inner().inputs[i].script_public_key() {
                Some(script) => script,
                None => {
                    return Err(crate::imports::Error::Custom(
                        "expected to be called only following full UTXO population".to_string(),
                    ));
                }
            };
            let script = script_pub_key.script();
            if let Some(keypair) = map.get(script) {
                let sig_hash = calc_signature_hash(&populated_transaction, i, SIG_HASH_ALL, &reused_values);
                let sig = sign_bytes(sig_hash.as_bytes().as_slice(), keypair).expect("Dilithium signing failed");
                let pk_bytes = keypair.public_key();
                let mut sig_script = Vec::new();
                let payload_len = (pk_bytes.len() + sig.as_bytes().len() + 1) as u16;
                sig_script.push(0x4d); // OP_PUSHDATA2
                sig_script.extend_from_slice(&payload_len.to_le_bytes());
                sig_script.extend_from_slice(pk_bytes);
                sig_script.extend_from_slice(&sig.as_bytes());
                sig_script.push(SIG_HASH_ALL.to_u8());
                tx.set_signature_script(i, sig_script)?;
            } else {
                additional_signatures_required = true;
            }
        }
    }
    if additional_signatures_required { Ok(Signed::Partially(tx)) } else { Ok(Signed::Fully(tx)) }
}
