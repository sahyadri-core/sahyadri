use crate::imports::NetworkParams;
use crate::result::Result;
use crate::wasm::api::message::INetworkParams;
use js_sys::BigInt;
use sahyadri_consensus_core::network::{NetworkIdT, NetworkType, NetworkTypeT};
use wasm_bindgen::prelude::*;
use workflow_wasm::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "bigint | number | HexString")]
    #[derive(Clone, Debug)]
    pub type IKanaToSahyadri;
}

/// Convert a Sahyadri string to Kana represented by bigint.
/// This function provides correct precision handling and
/// can be used to parse user input.
/// @category Wallet SDK
#[wasm_bindgen(js_name = "sahyadriToKana")]
pub fn sahyadri_to_kana(sahyadri: String) -> Option<BigInt> {
    crate::utils::try_sahyadri_str_to_kana(sahyadri).ok().flatten().map(Into::into)
}

///
/// Convert Kana to a string representation of the amount in Sahyadri.
///
/// @category Wallet SDK
///
#[wasm_bindgen(js_name = "kanaToSahyadriString")]
pub fn kana_to_sahyadri_string(kana: IKanaToSahyadri) -> Result<String> {
    let kana = kana.try_as_u64()?;
    Ok(crate::utils::kana_to_sahyadri_string(kana))
}

///
/// Format a Kana amount to a string representation of the amount in Sahyadri with a suffix
/// based on the network type (e.g. `KAS` for mainnet, `TKAS` for testnet,
/// `SKAS` for simnet, `DKAS` for devnet).
///
/// @category Wallet SDK
///
#[wasm_bindgen(js_name = "kanaToSahyadriStringWithSuffix")]
pub fn kana_to_sahyadri_string_with_suffix(kana: IKanaToSahyadri, network: &NetworkTypeT) -> Result<String> {
    let kana = kana.try_as_u64()?;
    let network_type = NetworkType::try_from(network)?;
    Ok(crate::utils::kana_to_sahyadri_string_with_suffix(kana, &network_type))
}

#[wasm_bindgen(js_name = "getNetworkParams")]
#[allow(non_snake_case)]
pub fn get_network_params(networkId: NetworkIdT) -> Result<INetworkParams> {
    let params = NetworkParams::from(*networkId.try_into_cast()?);
    params.try_into()
}

#[wasm_bindgen(js_name = "getTransactionMaturityProgress")]
#[allow(non_snake_case)]
pub fn get_transaction_maturity_progress(
    blockDaaScore: BigInt,
    currentDaaScore: BigInt,
    networkId: NetworkIdT,
    isCoinbase: bool,
) -> Result<String> {
    let network_id = *networkId.try_into_cast()?;
    let params = NetworkParams::from(network_id);
    let block_daa_score = blockDaaScore.try_as_u64()?;
    let current_daa_score = currentDaaScore.try_as_u64()?;
    let maturity =
        if isCoinbase { params.coinbase_transaction_maturity_period_daa() } else { params.user_transaction_maturity_period_daa() };

    if current_daa_score < block_daa_score + maturity {
        let progress = (current_daa_score - block_daa_score) as f64 / maturity as f64;
        Ok(format!("{}", (progress * 100.) as usize))
    } else {
        Ok("".to_string())
    }
}
