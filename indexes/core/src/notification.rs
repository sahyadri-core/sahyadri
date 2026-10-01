use crate::indexed_registry::{RegistryChanges, RegistryUnitSetByScriptPublicKey};
use derive_more::Display;
use sahyadri_notify::{
    events::EventType,
    full_featured,
    notification::Notification as NotificationTrait,
    subscription::{
        Subscription,
        context::SubscriptionContext,
        single::{OverallSubscription, RegistryChangedSubscription, VirtualChainChangedSubscription},
    },
};
use std::{collections::HashMap, sync::Arc};

full_featured! {
#[derive(Clone, Debug, Display)]
pub enum Notification {
    #[display(fmt = "RegistryChanged notification")]
    RegistryChanged(RegistryChangedNotification),

    #[display(fmt = "PruningPointRegistryUnitSetOverride notification")]
    PruningPointRegistryUnitSetOverride(PruningPointRegistryUnitSetOverrideNotification),
}
}

impl NotificationTrait for Notification {
    fn apply_overall_subscription(&self, subscription: &OverallSubscription, _context: &SubscriptionContext) -> Option<Self> {
        match subscription.active() {
            true => Some(self.clone()),
            false => None,
        }
    }

    fn apply_virtual_chain_changed_subscription(
        &self,
        _subscription: &VirtualChainChangedSubscription,
        _context: &SubscriptionContext,
    ) -> Option<Self> {
        Some(self.clone())
    }

    fn apply_registry_changed_subscription(
        &self,
        subscription: &RegistryChangedSubscription,
        context: &SubscriptionContext,
    ) -> Option<Self> {
        match subscription.active() {
            true => {
                let Self::RegistryChanged(notification) = self else { return None };
                notification.apply_registry_changed_subscription(subscription, context).map(Self::RegistryChanged)
            }
            false => None,
        }
    }

    fn event_type(&self) -> EventType {
        self.into()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PruningPointRegistryUnitSetOverrideNotification {}

#[derive(Debug, Clone)]
pub struct RegistryChangedNotification {
    pub added: Arc<RegistryUnitSetByScriptPublicKey>,
    pub removed: Arc<RegistryUnitSetByScriptPublicKey>,
}

impl From<RegistryChanges> for RegistryChangedNotification {
    fn from(item: RegistryChanges) -> Self {
        Self { added: Arc::new(item.added), removed: Arc::new(item.removed) }
    }
}

impl RegistryChangedNotification {
    pub fn from_registry_changed(registry_changed: RegistryChanges) -> Self {
        Self { added: Arc::new(registry_changed.added), removed: Arc::new(registry_changed.removed) }
    }

    pub(crate) fn apply_registry_changed_subscription(
        &self,
        subscription: &RegistryChangedSubscription,
        context: &SubscriptionContext,
    ) -> Option<Self> {
        if subscription.to_all() {
            Some(self.clone())
        } else {
            let added = Self::filter_registry_unit_set(&self.added, subscription, context);
            let removed = Self::filter_registry_unit_set(&self.removed, subscription, context);
            if added.is_empty() && removed.is_empty() {
                None
            } else {
                Some(Self { added: Arc::new(added), removed: Arc::new(removed) })
            }
        }
    }

    fn filter_registry_unit_set(
        registry_unit_set: &RegistryUnitSetByScriptPublicKey,
        subscription: &RegistryChangedSubscription,
        context: &SubscriptionContext,
    ) -> RegistryUnitSetByScriptPublicKey {
        // As an optimization, we iterate over the smaller set (O(n)) among the two below
        // and check existence over the larger set (O(1))
        let mut result = HashMap::default();
        let subscription_data = subscription.data();
        if registry_unit_set.len() < subscription_data.len() {
            {
                registry_unit_set.iter().for_each(|(script_public_key, collection)| {
                    if subscription_data.contains(script_public_key, context) {
                        result.insert(script_public_key.clone(), collection.clone());
                    }
                });
            }
        } else {
            let tracker_data = context.address_tracker.data();
            subscription_data.iter().for_each(|index| {
                if let Some(script_public_key) = tracker_data.get_index(*index)
                    && let Some(collection) = registry_unit_set.get(script_public_key)
                {
                    result.insert(script_public_key.clone(), collection.clone());
                }
            });
        }
        result
    }
}
