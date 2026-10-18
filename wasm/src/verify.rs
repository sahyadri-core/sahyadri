// WASM verify module — trustless SMT proof verification in the browser.
//
// Usage from JS:
//   import init, { verify_smt_proof } from 'sahyadri-wasm';
//   await init();
//   const balance = verify_smt_proof(state_root_hex, account_key_hex, proof_bytes);
//
// The proof is a bincode-serialized SmtStateProof from the RPC.

use wasm_bindgen::prelude::*;
use sahyadri_plonky3::config::build_stark_config;
use sahyadri_plonky3::smt_stark::{
    verify_smt_state, SmtPublicInputs, SmtStateProof,
};
use sahyadri_plonky3::smt_stark::prove::SmtStateProof as SmtProof;
use p3_uni_stark::Proof;
use sahyadri_plonky3::config::SahyadriStarkConfig;

/// Verify an SMT inclusion proof against a trusted state root.
///
/// Returns the account balance as a string (or "0" for absent).
/// Throws on verification failure.
#[wasm_bindgen]
pub fn verify_smt_proof(
    state_root_hex: &str,
    account_key_hex: &str,
    proof_bytes: &[u8],
) -> Result<String, JsValue> {
    // Parse public inputs from hex strings.
    let root_bytes = hex::decode(state_root_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid root hex: {}", e)))?;
    if root_bytes.len() != 32 {
        return Err(JsValue::from_str("root must be 32 bytes"));
    }
    let root_limbs = bytes_to_limbs(&root_bytes);

    let key_bytes = hex::decode(account_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid key hex: {}", e)))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    let key_limbs = bytes_to_limbs(&key_bytes);

    // Deserialize the proof.
    let proof: SmtProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid proof bytes: {}", e)))?;

    // Verify the root and key match what the caller claims.
    if proof.public.root != root_limbs {
        return Err(JsValue::from_str("proof root does not match trusted header"));
    }
    if proof.public.key != key_limbs {
        return Err(JsValue::from_str("proof key does not match requested account"));
    }

    // Cryptographically verify the STARK proof.
    let config = build_stark_config();
    verify_smt_state(&config, &proof)
        .map_err(|e| JsValue::from_str(&format!("verification failed: {}", e)))?;

    // Return the balance as a decimal string.
    Ok(limbs_to_decimal_string(&proof.public.value))
}

/// Fast helper: just check that a proof is valid, no data extraction.
#[wasm_bindgen]
pub fn is_smt_proof_valid(
    state_root_hex: &str,
    account_key_hex: &str,
    proof_bytes: &[u8],
) -> bool {
    verify_smt_proof(state_root_hex, account_key_hex, proof_bytes).is_ok()
}

// ── Helpers ──────────────────────────────────────────────────────

fn bytes_to_limbs(bytes: &[u8]) -> [p3_goldilocks::Goldilocks; 4] {
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    let mut out = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}

fn limbs_to_decimal_string(limbs: &[p3_goldilocks::Goldilocks; 4]) -> String {
    use p3_field::PrimeField64;
    // Simple: take first limb as u64 decimal.
    // For real balance (256-bit), we would need big-integer conversion.
    // For now, this is enough for the demo.
    format!("{}", limbs[0].as_canonical_u64())
}
