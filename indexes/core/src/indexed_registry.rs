use sahyadri_consensus_core::tx::{ScriptPublicKey, RegistryRef, RegistryUnit};
use sahyadri_utils::mem_size::MemSizeEstimator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// TODO: explore potential optimization via custom RegistryRef hasher for below,
// One possible implementation: u64 of transaction id xor'd with 4 bytes of transaction index.
pub type CompactRegistryUnitCollection = HashMap<RegistryRef, CompactRegistryUnit>;

/// A collection of registry_units indexed via; [`ScriptPublicKey`] => [`RegistryRef`] => [`CompactRegistryUnit`].
pub type RegistryUnitSetByScriptPublicKey = HashMap<ScriptPublicKey, CompactRegistryUnitCollection>;

/// A map of balance by script public key
pub type BalanceByScriptPublicKey = HashMap<ScriptPublicKey, u64>;

// Note: memory optimization compared to go-lang sahyadrid:
// Unlike `consensus_core::tx::RegistryUnit` the registry_unitindex utilizes a compacted registry_unit form, where `script_public_key` field is removed.
// This registry_unit structure can be utilized in the registry_unitindex, since registry_units are implicitly key'd via its script public key (and outpoint) at all times.
/// A compacted form of [`RegistryUnit`] without reference to [`ScriptPublicKey`] or [`RegistryRef`]
#[derive(Clone, Copy, Deserialize, Serialize, Debug)]
pub struct CompactRegistryUnit {
    pub amount: u64,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

impl CompactRegistryUnit {
    /// Creates a new [`CompactRegistryUnit`]
    pub fn new(amount: u64, block_daa_score: u64, is_coinbase: bool) -> Self {
        Self { amount, block_daa_score, is_coinbase }
    }
}

impl MemSizeEstimator for CompactRegistryUnit {}

impl From<RegistryUnit> for CompactRegistryUnit {
    fn from(registry_unit_entry: RegistryUnit) -> Self {
        Self { amount: registry_unit_entry.amount, block_daa_score: registry_unit_entry.block_daa_score, is_coinbase: registry_unit_entry.is_coinbase }
    }
}

/// A struct holding registry_unit changes to the registry_unitindex via `added` and `removed` [`RegistryUnitSetByScriptPublicKey`]'s
#[derive(Debug, Clone)]
pub struct RegistryChanges {
    pub added: RegistryUnitSetByScriptPublicKey,
    pub removed: RegistryUnitSetByScriptPublicKey,
}

impl RegistryChanges {
    /// Create a new [`RegistryChanges`] struct via supplied `added` and `removed` [`RegistryUnitSetByScriptPublicKey`]'s
    pub fn new(added: RegistryUnitSetByScriptPublicKey, removed: RegistryUnitSetByScriptPublicKey) -> Self {
        Self { added, removed }
    }
}
