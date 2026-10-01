//!
//! Implements an async stream of REGISTRY_UNITs.
//!

use super::{RegistryUnitContext, RegistryUnitRef};
use crate::imports::*;

pub struct RegistryUnitStream {
    registry_unit_context: RegistryUnitContext,
    cursor: usize,
}

impl RegistryUnitStream {
    pub fn new(registry_unit_context: &RegistryUnitContext) -> Self {
        Self { registry_unit_context: registry_unit_context.clone(), cursor: 0 }
    }
}

impl Stream for RegistryUnitStream {
    type Item = RegistryUnitRef;
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let entry = self.registry_unit_context.context().mature.get(self.cursor).cloned();
        self.cursor += 1;
        Poll::Ready(entry)
    }
}
