//!
//! REGISTRY_UNIT record representation used by wallet transactions.
//!

use crate::imports::*;
use sahyadri_addresses::Address;
use serde::{Deserialize, Serialize};

pub use sahyadri_consensus_core::tx::TransactionId;

/// [`RegistryUnitRecord`] represents an incoming transaction REGISTRY_UNIT entry
/// stored within [`TransactionRecord`].
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RegistryUnitRecord {
    pub address: Option<Address>,
    pub index: TransactionIndexType,
    pub amount: u64,
    #[serde(rename = "scriptPubKey")]
    pub script_public_key: ScriptPublicKey,
    #[serde(rename = "isCoinbase")]
    pub is_coinbase: bool,
}

impl From<&RegistryUnitRef> for RegistryUnitRecord {
    fn from(registry_unit: &RegistryUnitRef) -> Self {
        let RegistryUnitRef { registry_unit } = registry_unit;
        RegistryUnitRecord {
            index: registry_unit.outpoint.get_index(),
            address: registry_unit.address.clone(),
            amount: registry_unit.amount,
            script_public_key: registry_unit.script_public_key.clone(),
            is_coinbase: registry_unit.is_coinbase,
        }
    }
}
