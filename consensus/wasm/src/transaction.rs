//! Account Transaction WASM bindings - Sighash only

use wasm_bindgen::prelude::*;
use sahyadri_consensus_client::Transaction;

/// Compute the sighash for an account transaction
#[wasm_bindgen(js_name = "computeAccountTxSighash")]
pub fn compute_account_tx_sighash(tx: &Transaction, js_payload: JsValue) -> String {
    tx.compute_account_tx_sighash(js_payload)
}
