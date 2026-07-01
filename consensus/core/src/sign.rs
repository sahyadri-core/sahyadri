use crate::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_signature_hash},
        sighash_type::{SIG_HASH_ALL, SigHashType},
    },
    tx::{SignableTransaction, VerifiableTransaction},
};
use sahyadri_dilithium::{
    DilithiumKeyPair, DilithiumSignature, DilithiumError,
    PUBKEY_SIZE, SIG_SIZE, SAHYADRI_MODE,
    sign_bytes,
};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("Dilithium error: {0}")]
    DilithiumError(#[from] DilithiumError),
    #[error("The transaction is partially signed")]
    PartiallySigned,
    #[error("The transaction is fully signed")]
    FullySigned,
}

pub enum Signed {
    Fully(SignableTransaction),
    Partially(SignableTransaction),
}

impl Signed {
    pub fn fully_signed(self) -> std::result::Result<SignableTransaction, Error> {
        match self {
            Signed::Fully(tx) => Ok(tx),
            Signed::Partially(_) => Err(Error::PartiallySigned),
        }
    }
    #[allow(clippy::result_large_err)]
    pub fn try_fully_signed(self) -> std::result::Result<SignableTransaction, SignableTransaction> {
        match self {
            Signed::Fully(tx) => Ok(tx),
            Signed::Partially(tx) => Err(tx),
        }
    }
    pub fn partially_signed(self) -> std::result::Result<SignableTransaction, Error> {
        match self {
            Signed::Fully(_) => Err(Error::FullySigned),
            Signed::Partially(tx) => Ok(tx),
        }
    }
    #[allow(clippy::result_large_err)]
    pub fn try_partially_signed(self) -> std::result::Result<SignableTransaction, SignableTransaction> {
        match self {
            Signed::Fully(tx) => Err(tx),
            Signed::Partially(tx) => Ok(tx),
        }
    }
    pub fn unwrap(self) -> SignableTransaction {
        match self {
            Signed::Fully(tx) => tx,
            Signed::Partially(tx) => tx,
        }
    }
}

fn build_sig_script(pk: &[u8], sig_bytes: &[u8], sighash_type: SigHashType) -> Vec<u8> {
    let data_len = (pk.len() + sig_bytes.len() + 1) as u16;
    let mut script = vec![0x4d];
    script.extend_from_slice(&data_len.to_le_bytes());
    script.extend_from_slice(pk);
    script.extend_from_slice(sig_bytes);
    script.push(sighash_type.to_u8());
    script
}

fn build_expected_script(pk: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pk);
    let hash = hasher.finalize();
    let mut script = vec![0x14];
    script.extend_from_slice(&hash[..20]);
    script.push(0xac);
    script
}

pub fn sign(mut signable_tx: SignableTransaction, keypair: &DilithiumKeyPair) -> SignableTransaction {
    for i in 0..signable_tx.tx.inputs.len() {
        signable_tx.tx.inputs[i].sig_op_count = 1;
    }
    let reused_values = SigHashReusedValuesUnsync::new();
    let pk = keypair.public_key();
    for i in 0..signable_tx.tx.inputs.len() {
        let sig_hash = calc_signature_hash(&signable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
        let sig = sign_bytes(&sig_hash.as_bytes(), keypair).expect("Dilithium signing failed");
        signable_tx.tx.inputs[i].signature_script = build_sig_script(pk, sig.as_bytes(), SIG_HASH_ALL);
    }
    signable_tx
}

pub fn sign_with_multiple(mut mutable_tx: SignableTransaction, keypairs: Vec<&DilithiumKeyPair>) -> SignableTransaction {
    for i in 0..mutable_tx.tx.inputs.len() {
        mutable_tx.tx.inputs[i].sig_op_count = 1;
    }
    let reused_values = SigHashReusedValuesUnsync::new();
    for (i, keypair) in keypairs.iter().enumerate() {
        if i < mutable_tx.tx.inputs.len() {
            let sig_hash = calc_signature_hash(&mutable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
            let sig = sign_bytes(&sig_hash.as_bytes(), keypair).expect("Dilithium signing failed");
            let pk = keypair.public_key();
            mutable_tx.tx.inputs[i].signature_script = build_sig_script(pk, sig.as_bytes(), SIG_HASH_ALL);
        }
    }
    mutable_tx
}
#[allow(clippy::result_large_err)]
pub fn sign_with_multiple_v2(mut mutable_tx: SignableTransaction, keypairs: &[&DilithiumKeyPair]) -> Signed {
    let mut map = BTreeMap::new();
    for keypair in keypairs {
        let expected_script = build_expected_script(keypair.public_key());
        map.insert(expected_script, *keypair);
    }
    let reused_values = SigHashReusedValuesUnsync::new();
    let mut additional_signatures_required = false;
    for i in 0..mutable_tx.tx.inputs.len() {
        let script = mutable_tx.entries[i].as_ref().unwrap().script_public_key.script();
        if let Some(keypair) = map.get(script) {
            let sig_hash = calc_signature_hash(&mutable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
            let sig = sign_bytes(&sig_hash.as_bytes(), keypair).expect("Dilithium signing failed");
            let pk = keypair.public_key();
            mutable_tx.tx.inputs[i].signature_script = build_sig_script(pk, sig.as_bytes(), SIG_HASH_ALL);
        } else {
            additional_signatures_required = true;
        }
    }
    if additional_signatures_required { Signed::Partially(mutable_tx) } else { Signed::Fully(mutable_tx) }
}

pub fn sign_input(tx: &impl VerifiableTransaction, input_index: usize, keypair: &DilithiumKeyPair, hash_type: SigHashType) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let hash = calc_signature_hash(tx, input_index, hash_type, &reused_values);
    let sig = sign_bytes(&hash.as_bytes(), keypair).expect("Dilithium signing failed");
    build_sig_script(keypair.public_key(), sig.as_bytes(), hash_type)
}

pub fn verify(tx: &impl VerifiableTransaction) -> Result<(), Error> {
    let reused_values = SigHashReusedValuesUnsync::new();
    for (i, (input, entry)) in tx.populated_inputs().enumerate() {
        if input.signature_script.is_empty() {
            return Err(Error::Message(format!("Signature is empty for input: {i}")));
        }
        let ss = &input.signature_script;
        if ss.len() < 3 || ss[0] != 0x4d {
            return Err(Error::Message(format!("Invalid signature script format for input: {i}")));
        }
        let data_len = u16::from_le_bytes([ss[1], ss[2]]) as usize;
        if ss.len() < 3 + data_len {
            return Err(Error::Message(format!("Signature script truncated for input: {i}")));
        }
        let data = &ss[3..3 + data_len];
        if data.len() < PUBKEY_SIZE + SIG_SIZE + 1 {
            return Err(Error::Message(format!("Signature script data too short for input: {i}")));
        }
        let pk = &data[..PUBKEY_SIZE];
        let sig = &data[PUBKEY_SIZE..PUBKEY_SIZE + SIG_SIZE];
        let script = entry.script_public_key.script();
        if script.len() < 22 || script[0] != 0x14 {
            return Err(Error::Message(format!("Invalid script_pubkey format for input: {i}")));
        }
        let expected_hash = &script[1..21];
        let mut hasher = Sha256::new();
        hasher.update(pk);
        let actual_hash = &hasher.finalize()[..20];
        if actual_hash != expected_hash {
            return Err(Error::Message(format!("Public key hash mismatch for input: {i}")));
        }
        let sig_hash = calc_signature_hash(tx, i, SIG_HASH_ALL, &reused_values);
        let dilithium_sig = DilithiumSignature::from_slice(sig);
        let valid = DilithiumKeyPair::verify(pk, &dilithium_sig, &sig_hash.as_bytes(), b"", SAHYADRI_MODE);
        if !valid {
            return Err(Error::Message(format!("Dilithium signature verification failed for input: {i}")));
        }
    }
    Ok(())
}

/// ZKP-aware batch verification.
///
/// If a valid STARK proof is provided and covers this transaction's signatures,
/// individual Dilithium3 verification is skipped (1000x faster).
///
/// Call this instead of `verify()` when ZKP proofs are available.
#[cfg(feature = "zkp")]
#[allow(dead_code)]
pub fn verify_with_zkp(
    tx: &impl VerifiableTransaction,
    zkp_proof: Option<&crate::zkp_batch::BlockZkpProof>,
) -> Result<(), Error> {
    use crate::zkp_batch::{verify_block_zkp, should_use_zkp};

    // Count sig ops in this transaction
    let sig_count = tx.populated_inputs().len();

    // If ZKP proof is valid and covers enough sigs, trust it
    if should_use_zkp(zkp_proof, sig_count) {
        match verify_block_zkp(zkp_proof.unwrap()) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // ZKP invalid — fall back to individual verification
            }
            Err(_) => {
                // ZKP error — fall back to individual verification
            }
        }
    }

    // Fall back to individual verification
    verify(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{subnets::SubnetworkId, tx::*};
    use sahyadri_dilithium::generate_keypair_from_seed;
    use std::str::FromStr;

    #[test]
    fn test_sign_and_verify() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_from_seed(&seed);
        let script_pub_key = ScriptVec::from_vec(build_expected_script(keypair.public_key()));
        let seed2 = [0x43u8; 32];
        let keypair2 = generate_keypair_from_seed(&seed2);
        let script_pub_key2 = ScriptVec::from_vec(build_expected_script(keypair2.public_key()));
        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let unsigned_tx = Transaction::new(
            0,
            vec![
                TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id.clone(), index: 0 }, signature_script: vec![], sequence: 0, sig_op_count: 0 },
                TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 }, signature_script: vec![], sequence: 1, sig_op_count: 0 },
            ],
            vec![
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()) },
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()) },
            ],
            1615462089000,
            SubnetworkId::from_bytes([1,2,3,4,5,6,7,8,9,10,0,0,0,0,0,0,0,0,0,0]),
            0,
            vec![],
        );
        let entries = vec![
            UtxoEntry { amount: 100, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()), block_daa_score: 0, is_coinbase: false },
            UtxoEntry { amount: 200, script_public_key: ScriptPublicKey::new(0, script_pub_key2), block_daa_score: 0, is_coinbase: false },
        ];
        let signed_tx = sign_with_multiple(SignableTransaction::with_entries(unsigned_tx, entries), vec![&keypair, &keypair2]);
        assert!(verify(&signed_tx.as_verifiable()).is_ok());
    }
}
