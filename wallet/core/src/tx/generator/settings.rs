//!
//! Transaction [`GeneratorSettings`] used when
//! constructing and instance of the [`Generator`](crate::tx::Generator).
//!

use crate::events::Events;
use crate::imports::*;
use crate::result::Result;
use crate::tx::{Fees, PaymentDestination};
use crate::registry_unit::{RegistryUnitContext, RegistryUnitRef, RegistryUnitIterator};
use sahyadri_addresses::Address;
use workflow_core::channel::Multiplexer;

pub struct GeneratorSettings {
    // Network type
    pub network_id: NetworkId,
    // Event multiplexer
    pub multiplexer: Option<Multiplexer<Box<Events>>>,
    // RegistryUnit iterator
    pub registry_unit_iterator: Box<dyn Iterator<Item = RegistryUnitRef> + Send + Sync + 'static>,
    // RegistryUnit Context
    pub source_registry_unit_context: Option<RegistryUnitContext>,
    // Priority registry_unit entries that are consumed before others
    pub priority_registry_unit_entries: Option<Vec<RegistryUnitRef>>,
    // typically a number of keys required to sign the transaction
    pub sig_op_count: u8,
    // number of minimum signatures required to sign the transaction
    pub minimum_signatures: u16,
    // change address
    pub change_address: Address,
    // fee rate
    pub fee_rate: Option<f64>,
    // applies only to the final transaction
    pub final_transaction_priority_fee: Fees,
    // final transaction outputs
    pub final_transaction_destination: PaymentDestination,
    // payload
    pub final_transaction_payload: Option<Vec<u8>>,
    // transaction is a transfer between accounts
    pub destination_registry_unit_context: Option<RegistryUnitContext>,
}

// impl std::fmt::Debug for GeneratorSettings {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("GeneratorSettings")
//             .field("network_id", &self.network_id)
//             // .field("multiplexer", &self.multiplexer)
//             .field("registry_unit_iterator", &"Box<dyn Iterator<Item = RegistryUnitRef> + Send + Sync + 'static>")
//             // .field("source_registry_unit_context", &self.source_registry_unit_context)
//             .field("sig_op_count", &self.sig_op_count)
//             .field("minimum_signatures", &self.minimum_signatures)
//             .field("change_address", &self.change_address)
//             .field("final_transaction_priority_fee", &self.final_transaction_priority_fee)
//             .field("final_transaction_destination", &self.final_transaction_destination)
//             .field("final_transaction_payload", &self.final_transaction_payload)
//             // .field("destination_registry_unit_context", &self.destination_registry_unit_context)
//             .finish()
//     }
// }

impl GeneratorSettings {
    pub fn try_new_with_account(
        account: Arc<dyn Account>,
        final_transaction_destination: PaymentDestination,
        fee_rate: Option<f64>,
        final_priority_fee: Fees,
        final_transaction_payload: Option<Vec<u8>>,
    ) -> Result<Self> {
        let network_id = account.registry_unit_context().processor().network_id()?;
        let change_address = account.change_address()?;
        let multiplexer = account.wallet().multiplexer().clone();
        let sig_op_count = account.sig_op_count();
        let minimum_signatures = account.minimum_signatures();

        let registry_unit_iterator = RegistryUnitIterator::new(account.registry_unit_context());

        let settings = GeneratorSettings {
            network_id,
            multiplexer: Some(multiplexer),
            sig_op_count,
            minimum_signatures,
            change_address,
            registry_unit_iterator: Box::new(registry_unit_iterator),
            source_registry_unit_context: Some(account.registry_unit_context().clone()),
            priority_registry_unit_entries: None,

            fee_rate,
            final_transaction_priority_fee: final_priority_fee,
            final_transaction_destination,
            final_transaction_payload,
            destination_registry_unit_context: None,
        };

        Ok(settings)
    }

    pub fn try_new_with_context(
        registry_unit_context: RegistryUnitContext,
        priority_registry_unit_entries: Option<Vec<RegistryUnitRef>>,
        change_address: Address,
        sig_op_count: u8,
        minimum_signatures: u16,
        final_transaction_destination: PaymentDestination,
        fee_rate: Option<f64>,
        final_priority_fee: Fees,
        final_transaction_payload: Option<Vec<u8>>,
        multiplexer: Option<Multiplexer<Box<Events>>>,
    ) -> Result<Self> {
        let network_id = registry_unit_context.processor().network_id()?;
        let registry_unit_iterator = RegistryUnitIterator::new(&registry_unit_context);

        let settings = GeneratorSettings {
            network_id,
            multiplexer,
            sig_op_count,
            minimum_signatures,
            change_address,
            registry_unit_iterator: Box::new(registry_unit_iterator),
            source_registry_unit_context: Some(registry_unit_context),
            priority_registry_unit_entries,

            fee_rate,
            final_transaction_priority_fee: final_priority_fee,
            final_transaction_destination,
            final_transaction_payload,
            destination_registry_unit_context: None,
        };

        Ok(settings)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_iterator(
        network_id: NetworkId,
        registry_unit_iterator: Box<dyn Iterator<Item = RegistryUnitRef> + Send + Sync + 'static>,
        priority_registry_unit_entries: Option<Vec<RegistryUnitRef>>,
        change_address: Address,
        sig_op_count: u8,
        minimum_signatures: u16,
        final_transaction_destination: PaymentDestination,
        fee_rate: Option<f64>,
        final_priority_fee: Fees,
        final_transaction_payload: Option<Vec<u8>>,
        multiplexer: Option<Multiplexer<Box<Events>>>,
    ) -> Result<Self> {
        let settings = GeneratorSettings {
            network_id,
            multiplexer,
            sig_op_count,
            minimum_signatures,
            change_address,
            registry_unit_iterator: Box::new(registry_unit_iterator),
            source_registry_unit_context: None,
            priority_registry_unit_entries,

            fee_rate,
            final_transaction_priority_fee: final_priority_fee,
            final_transaction_destination,
            final_transaction_payload,
            destination_registry_unit_context: None,
        };

        Ok(settings)
    }

    pub fn registry_unit_context_transfer(mut self, destination_registry_unit_context: &RegistryUnitContext) -> Self {
        self.destination_registry_unit_context = Some(destination_registry_unit_context.clone());
        self
    }
}
