//!
//! Address scanner implementation, responsible for
//! aggregating REGISTRY_UNITs from multiple addresses and
//! building corresponding balances.
//!

use crate::derivation::AddressManager;
use crate::imports::*;
use crate::registry_unit::balance::AtomicBalance;
use crate::registry_unit::{RegistryUnitContext, RegistryUnitRef, RegistryUnitRefExtension};
use std::cmp::max;

pub const DEFAULT_WINDOW_SIZE: usize = 8;

#[derive(Default, Clone, Copy)]
pub enum ScanExtent {
    /// Scan until an empty range is found
    #[default]
    EmptyWindow,
    /// Scan until a specific depth (a particular derivation index)
    Depth(u32),
}

enum Provider {
    AddressManager(Arc<AddressManager>),
    AddressSet(HashSet<Address>),
}

pub struct Scan {
    provider: Provider,
    window_size: Option<usize>,
    extent: Option<ScanExtent>,
    balance: Arc<AtomicBalance>,
    current_daa_score: u64,
}

impl Scan {
    pub fn new_with_address_manager(
        address_manager: Arc<AddressManager>,
        balance: &Arc<AtomicBalance>,
        current_daa_score: u64,
        window_size: Option<usize>,
        extent: Option<ScanExtent>,
    ) -> Scan {
        Scan { provider: Provider::AddressManager(address_manager), window_size, extent, balance: balance.clone(), current_daa_score }
    }
    pub fn new_with_address_set(addresses: HashSet<Address>, balance: &Arc<AtomicBalance>, current_daa_score: u64) -> Scan {
        Scan {
            provider: Provider::AddressSet(addresses),
            window_size: None,
            extent: None,
            balance: balance.clone(),
            current_daa_score,
        }
    }

    pub async fn scan(&self, registry_unit_context: &RegistryUnitContext) -> Result<()> {
        // block notifications while scanning...
        let _lock = registry_unit_context.processor().notification_lock().await;

        match &self.provider {
            Provider::AddressManager(address_manager) => self.scan_with_address_manager(address_manager, registry_unit_context).await,
            Provider::AddressSet(addresses) => self.scan_with_address_set(addresses, registry_unit_context).await,
        }
    }

    pub async fn scan_with_address_manager(&self, address_manager: &Arc<AddressManager>, registry_unit_context: &RegistryUnitContext) -> Result<()> {
        let params = registry_unit_context.processor().network_params()?;

        let window_size = self.window_size.unwrap_or(DEFAULT_WINDOW_SIZE) as u32;
        let extent = self.extent.expect("address manager requires an extent");

        let mut cursor: u32 = 0;
        let mut last_address_index = address_manager.index();

        'scan: loop {
            // scan first up to address index, then in window chunks
            let first = cursor;
            let last = if cursor == 0 { max(last_address_index + 1, window_size) } else { cursor + window_size };
            cursor = last;

            // generate address derivations
            let addresses = address_manager.get_range(first..last)?;
            // register address in the registry_unit context; NOTE:  during the scan,
            // before `get_registry_by_addresses()` is complete we may receive
            // new transactions  as such registry_unit context should be aware of the
            // addresses used before we start interacting with them.
            registry_unit_context.register_addresses(&addresses).await?;

            let ts = Instant::now();
            let resp = registry_unit_context.processor().rpc_api().get_registry_by_addresses(addresses).await?;
            let elapsed_sec = ts.elapsed().as_secs_f32();
            if elapsed_sec > 1.0 {
                log_warn!("get_registry_units_by_address() fetched {} entries in: {} msec", resp.len(), elapsed_sec);
            }
            yield_executor().await;

            if !resp.is_empty() {
                let refs: Vec<RegistryUnitRef> = resp.into_iter().map(RegistryUnitRef::from).collect();
                for registry_unit_ref in refs.iter() {
                    if let Some(address) = registry_unit_ref.registry_unit.address.as_ref() {
                        if let Some(registry_unit_address_index) = address_manager.inner().address_to_index_map.get(address) {
                            if last_address_index < *registry_unit_address_index {
                                last_address_index = *registry_unit_address_index;
                            }
                        } else {
                            panic!("Account::scan_address_manager() has received an unknown address: `{address}`");
                        }
                    }
                }

                let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
                    let entry_balance = r.balance(params, self.current_daa_score);
                    balance.mature += entry_balance.mature;
                    balance.pending += entry_balance.pending;
                    balance.mature_registry_unit_count += entry_balance.mature_registry_unit_count;
                    balance.pending_registry_unit_count += entry_balance.pending_registry_unit_count;
                    balance.stasis_registry_unit_count += entry_balance.stasis_registry_unit_count;
                    balance
                });

                registry_unit_context.extend_from_scan(refs, self.current_daa_score).await?;

                self.balance.add(balance);
            } else {
                match &extent {
                    ScanExtent::EmptyWindow => {
                        if cursor > last_address_index + window_size {
                            break 'scan;
                        }
                    }
                    ScanExtent::Depth(depth) => {
                        if &cursor > depth {
                            break 'scan;
                        }
                    }
                }
            }
            yield_executor().await;
        }

        // update address manager with the last used index
        address_manager.set_index(last_address_index)?;

        Ok(())
    }

    pub async fn scan_with_address_set(&self, address_set: &HashSet<Address>, registry_unit_context: &RegistryUnitContext) -> Result<()> {
        let params = registry_unit_context.processor().network_params()?;
        let address_vec = address_set.iter().cloned().collect::<Vec<_>>();

        registry_unit_context.register_addresses(&address_vec).await?;
        let resp = registry_unit_context.processor().rpc_api().get_registry_by_addresses(address_vec).await?;
        let refs: Vec<RegistryUnitRef> = resp.into_iter().map(RegistryUnitRef::from).collect();

        let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
            let entry_balance = r.balance(params, self.current_daa_score);
            balance.mature += entry_balance.mature;
            balance.pending += entry_balance.pending;
            balance.mature_registry_unit_count += entry_balance.mature_registry_unit_count;
            balance.pending_registry_unit_count += entry_balance.pending_registry_unit_count;
            balance.stasis_registry_unit_count += entry_balance.stasis_registry_unit_count;
            balance
        });
        yield_executor().await;

        registry_unit_context.extend_from_scan(refs, self.current_daa_score).await?;

        if !balance.is_empty() {
            self.balance.add(balance);
        }

        Ok(())
    }
}
