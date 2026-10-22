//! WASM SMT + Chain proof verification.
//!
//! Runs entirely in the browser — no RPC trust required.
//! Uses `sahyadri-plonky3` for STARK verification.

use wasm_bindgen::prelude::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::{
    verify_smt_state,
    prove::SmtStateProof,
};

// ═══════════════════════════════════════════════════════════════
// SMT proof verification (existing)
// ═══════════════════════════════════════════════════════════════

/// Verify an SMT inclusion proof against a trusted state root.
/// Returns the account value (first limb) on success.
#[wasm_bindgen]
pub fn verify_smt_proof(
    state_root_hex: &str,
    account_key_hex: &str,
    proof_bytes: &[u8],
) -> Result<String, JsValue> {
    let root_bytes = hex::decode(state_root_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid root hex: {e}")))?;
    if root_bytes.len() != 32 {
        return Err(JsValue::from_str("root must be 32 bytes"));
    }
    let root_limbs = bytes_to_limbs(&root_bytes);

    let key_bytes = hex::decode(account_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    let key_limbs = bytes_to_limbs(&key_bytes);

    let proof: SmtStateProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid proof bytes: {e}")))?;

    if proof.public.root != root_limbs {
        return Err(JsValue::from_str("proof root does not match trusted header"));
    }
    if proof.public.key != key_limbs {
        return Err(JsValue::from_str("proof key does not match requested account"));
    }

    let config = build_stark_config();
    verify_smt_state(&config, &proof)
        .map_err(|e| JsValue::from_str(&format!("verification failed: {e}")))?;

    Ok(format!("{}", proof.public.value[0].as_canonical_u64()))
}

/// Boolean-only SMT check — returns true if valid.
#[wasm_bindgen]
pub fn is_smt_proof_valid(
    state_root_hex: &str,
    account_key_hex: &str,
    proof_bytes: &[u8],
) -> bool {
    verify_smt_proof(state_root_hex, account_key_hex, proof_bytes).is_ok()
}

// ═══════════════════════════════════════════════════════════════
// Chain proof verification (E v2)
// ═══════════════════════════════════════════════════════════════

/// Verify a serialized ChainProofBlob.
/// Returns the chain depth (number of blocks proven) on success.
/// Trustless: cryptographic proof is the authority, not the RPC.
#[wasm_bindgen]
pub fn verify_chain_proof(proof_bytes: &[u8]) -> Result<u32, JsValue> {
    use sahyadri_plonky3::smt_stark::chain_blob::ChainProofBlob;

    let blob = ChainProofBlob::from_bytes(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid chain proof blob: {e}")))?;

    blob.verify()
        .map_err(|e| JsValue::from_str(&format!("chain proof verify failed: {e}")))?;

    Ok(blob.chain_depth)
}

/// Boolean-only chain proof check.
#[wasm_bindgen]
pub fn is_chain_proof_valid(proof_bytes: &[u8]) -> bool {
    verify_chain_proof(proof_bytes).is_ok()
}

/// Inspect a chain proof without verifying.
/// Returns { chain_depth: number, chain_commitment_hex: string }.
#[wasm_bindgen]
pub fn inspect_chain_proof(proof_bytes: &[u8]) -> Result<JsValue, JsValue> {
    use sahyadri_plonky3::smt_stark::chain_blob::ChainProofBlob;

    let blob = ChainProofBlob::from_bytes(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid chain proof blob: {e}")))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("chain_depth"),
        &JsValue::from_f64(blob.chain_depth as f64),
    )
    .map_err(|e| JsValue::from_str(&format!("set depth: {e:?}")))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("chain_commitment_hex"),
        &JsValue::from_str(&hex::encode(blob.chain_commitment)),
    )
    .map_err(|e| JsValue::from_str(&format!("set commitment: {e:?}")))?;

    Ok(result.into())
}

// ── helpers ────────────────────────────────────────────────────

fn bytes_to_limbs(bytes: &[u8]) -> [Goldilocks; 4] {
    let mut out = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}
