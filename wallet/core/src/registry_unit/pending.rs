//!
//! Implements the [`PendingRegistryUnitRef`] type used
//! by the [`RegistryUnitProcessor`] to monitor REGISTRY_UNIT maturity progress.
//!

use crate::imports::*;
use crate::registry_unit::{Maturity, RegistryUnitContext, RegistryUnitId, RegistryUnitRef, RegistryUnitRefExtension};

pub struct PendingRegistryUnitRefInner {
    pub entry: RegistryUnitRef,
    pub registry_unit_context: RegistryUnitContext,
}

#[derive(Clone)]
pub struct PendingRegistryUnitRef {
    pub inner: Arc<PendingRegistryUnitRefInner>,
}

impl PendingRegistryUnitRef {
    pub fn new(entry: RegistryUnitRef, registry_unit_context: RegistryUnitContext) -> Self {
        Self { inner: Arc::new(PendingRegistryUnitRefInner { entry, registry_unit_context }) }
    }

    #[inline(always)]
    pub fn inner(&self) -> &PendingRegistryUnitRefInner {
        &self.inner
    }

    #[inline(always)]
    pub fn entry(&self) -> &RegistryUnitRef {
        &self.inner().entry
    }

    #[inline(always)]
    pub fn registry_unit_context(&self) -> &RegistryUnitContext {
        &self.inner().registry_unit_context
    }

    #[inline(always)]
    pub fn id(&self) -> RegistryUnitId {
        self.inner().entry.id()
    }

    #[inline(always)]
    pub fn transaction_id(&self) -> TransactionId {
        self.inner().entry.transaction_id()
    }

    #[inline(always)]
    pub fn maturity(&self, params: &NetworkParams, current_daa_score: u64) -> Maturity {
        self.inner().entry.maturity(params, current_daa_score)
    }
}

impl From<(&Arc<dyn Account>, RegistryUnitRef)> for PendingRegistryUnitRef {
    fn from((account, entry): (&Arc<dyn Account>, RegistryUnitRef)) -> Self {
        Self::new(entry, (*account.registry_unit_context()).clone())
    }
}

impl From<PendingRegistryUnitRef> for RegistryUnitRef {
    fn from(pending: PendingRegistryUnitRef) -> Self {
        pending.inner().entry.clone()
    }
}
