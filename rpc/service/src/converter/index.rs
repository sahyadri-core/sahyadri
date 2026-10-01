use async_trait::async_trait;
use sahyadri_consensus_core::config::Config;
use sahyadri_index_core::indexed_registry::RegistryUnitSetByScriptPublicKey;
use sahyadri_index_core::notification::{self as index_notify, Notification as IndexNotification};
use sahyadri_notify::converter::Converter;
use sahyadri_rpc_core::{
    Notification, RpcRegistryByAddressesEntry, RegistryChangedNotification, registry_set_into_rpc,
};
use std::sync::Arc;

/// Conversion of consensus_core to rpc_core structures.
///
/// NOTE: In the account model there is no REGISTRY_UNIT index, so the index-backed
/// notification path is inert. The type is kept so that any caller holding
/// an `IndexConverter` still compiles. `get_registry_unit_changed_notification`
/// simply forwards the incoming REGISTRY_UNIT set into the RPC shape (empty if the
/// index is disabled at the node config level).
#[derive(Debug)]
pub struct IndexConverter {
    config: Arc<Config>,
}

impl IndexConverter {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub fn get_registry_by_addresses_entries(
        &self,
        item: &RegistryUnitSetByScriptPublicKey,
    ) -> Vec<RpcRegistryByAddressesEntry> {
        registry_set_into_rpc(item, Some(self.config.prefix()))
    }

    /// Build the RPC-side REGISTRY_UNIT-changed notification. The index layer
    /// (`sahyadri_index_core`) may still feed us REGISTRY_UNIT sets from an
    /// optional side-index; we just translate them to RPC shape.
    pub fn get_registry_unit_changed_notification(
        &self,
        msg: sahyadri_index_core::notification::RegistryChangedNotification,
    ) -> RegistryChangedNotification {
        let added = self.get_registry_by_addresses_entries(&msg.added);
        let removed = self.get_registry_by_addresses_entries(&msg.removed);
        RegistryChangedNotification { added: Arc::new(added), removed: Arc::new(removed) }
    }
}

#[async_trait]
impl Converter for IndexConverter {
    type Incoming = IndexNotification;
    type Outgoing = Notification;

    async fn convert(&self, incoming: IndexNotification) -> Notification {
        match incoming {
            index_notify::Notification::RegistryChanged(msg) => {
                Notification::RegistryChanged(self.get_registry_unit_changed_notification(msg))
            }
            _ => (&incoming).into(),
        }
    }
}
