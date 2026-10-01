//!
//! Associative iterator over the REGISTRY_UNIT set.
//!

use crate::registry_unit::{RegistryUnitContext, RegistryUnitRef};

#[derive(Debug)]
pub struct RegistryUnitIterator {
    entries: Vec<RegistryUnitRef>,
    cursor: usize,
}

impl RegistryUnitIterator {
    pub fn new(registry_unit_context: &RegistryUnitContext) -> Self {
        Self { entries: registry_unit_context.context().mature.clone(), cursor: 0 }
    }
}

impl Iterator for RegistryUnitIterator {
    type Item = RegistryUnitRef;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(self.cursor).cloned();
        self.cursor += 1;
        entry
    }
}
