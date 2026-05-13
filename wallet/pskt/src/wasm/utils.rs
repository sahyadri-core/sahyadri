use sahyadri_consensus_core::constants::*;
use sahyadri_consensus_core::network::NetworkType;
use separator::{Separatable, separated_float, separated_int, separated_uint_with_output};

#[inline]
pub fn kana_to_sahyadri(kana: u64) -> f64 {
    kana as f64 / KANA_PER_SAHYADRI as f64
}

#[inline]
pub fn sahyadri_to_kana(sahyadri: f64) -> u64 {
    (sahyadri * KANA_PER_SAHYADRI as f64) as u64
}

#[inline]
pub fn kana_to_sahyadri_string(kana: u64) -> String {
    kana_to_sahyadri(kana).separated_string()
}

#[inline]
pub fn kana_to_sahyadri_string_with_trailing_zeroes(kana: u64) -> String {
    separated_float!(format!("{:.8}", kana_to_sahyadri(kana)))
}

pub fn sahyadri_suffix(network_type: &NetworkType) -> &'static str {
    match network_type {
        NetworkType::Mainnet => "CSM",
        NetworkType::Testnet => "TKAS",
        NetworkType::Simnet => "SKAS",
        NetworkType::Devnet => "DKAS",
    }
}

#[inline]
pub fn kana_to_sahyadri_string_with_suffix(kana: u64, network_type: &NetworkType) -> String {
    let kas = kana_to_sahyadri_string(kana);
    let suffix = sahyadri_suffix(network_type);
    format!("{kas} {suffix}")
}
