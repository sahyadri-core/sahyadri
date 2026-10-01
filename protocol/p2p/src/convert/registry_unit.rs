use crate::pb as protowire;
use sahyadri_consensus_core::tx::{RegistryRef, RegistryUnit};

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<&RegistryUnit> for protowire::RegistryUnit {
    fn from(entry: &RegistryUnit) -> Self {
        Self {
            amount: entry.amount,
            script_public_key: Some((&entry.script_public_key).into()),
            block_daa_score: entry.block_daa_score,
            is_coinbase: entry.is_coinbase,
        }
    }
}

impl From<(&RegistryRef, &RegistryUnit)> for protowire::OutpointAndRegistryUnitPair {
    fn from((outpoint, entry): (&RegistryRef, &RegistryUnit)) -> Self {
        Self { outpoint: Some(outpoint.into()), registry_unit_entry: Some(entry.into()) }
    }
}
