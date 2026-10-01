//!
//! Implementation of [`RegistryUnitContextBinding`] which allows binding of
//! [`RegistryUnitContext`] to [`Account`] or custom developer-defined ids.
//!

use crate::imports::*;
use crate::registry_unit::RegistryUnitContextId;

#[derive(Clone)]
pub enum RegistryUnitContextBinding {
    Internal(RegistryUnitContextId),
    AccountId(AccountId),
    Id(RegistryUnitContextId),
}

impl Default for RegistryUnitContextBinding {
    fn default() -> Self {
        RegistryUnitContextBinding::Internal(RegistryUnitContextId::default())
    }
}

impl RegistryUnitContextBinding {
    pub fn id(&self) -> RegistryUnitContextId {
        match self {
            RegistryUnitContextBinding::Internal(id) => *id,
            RegistryUnitContextBinding::AccountId(id) => (*id).into(),
            RegistryUnitContextBinding::Id(id) => *id,
        }
    }
}
