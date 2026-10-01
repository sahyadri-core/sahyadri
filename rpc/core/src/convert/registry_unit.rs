//! Conversion functions for REGISTRY_UNIT related types.

use crate::RpcRegistryUnit;
use crate::RpcRegistryByAddressesEntry;
use sahyadri_addresses::Prefix;
use sahyadri_index_core::indexed_registry::RegistryUnitSetByScriptPublicKey;
use sahyadri_txscript::extract_script_pub_key_address;

// ----------------------------------------------------------------------------
// index to rpc_core
// ----------------------------------------------------------------------------

pub fn registry_set_into_rpc(item: &RegistryUnitSetByScriptPublicKey, prefix: Option<Prefix>) -> Vec<RpcRegistryByAddressesEntry> {
    item.iter()
        .flat_map(|(script_public_key, registry_unit_collection)| {
            let address = prefix.and_then(|x| extract_script_pub_key_address(script_public_key, x).ok());
            registry_unit_collection
                .iter()
                .map(|(outpoint, entry)| RpcRegistryByAddressesEntry {
                    address: address.clone(),
                    outpoint: (*outpoint).into(),
                    registry_unit_entry: RpcRegistryUnit::new(entry.amount, script_public_key.clone(), entry.block_daa_score, entry.is_coinbase),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}
