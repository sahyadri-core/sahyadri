//!
//! Implementation of the [`RegistryUnitContext`] which is a runtime
//! primitive responsible for monitoring multiple addresses,
//! generation of address-related events and balance tracking.
//!

use crate::encryption::sha256_hash;
use crate::events::Events;
use crate::imports::*;
use crate::result::Result;
use crate::storage::TransactionRecord;
use crate::tx::PendingTransaction;
use crate::registry_unit::{
    Maturity, NetworkParams, OutgoingTransaction, PendingRegistryUnitRef, RegistryUnitContextBinding, RegistryUnitId, RegistryUnitRef,
    RegistryUnitRefExtension, RegistryUnitProcessor,
};
use sahyadri_consensus_client::RegistryUnit;
use sahyadri_hashes::Hash;
use sorted_insert::SortedInsertBinaryByKey;

static REGISTRY_UNIT_CONTEXT_ID_SEQUENCER: AtomicU64 = AtomicU64::new(0);
fn next_registry_unit_context_id() -> Hash {
    let id = REGISTRY_UNIT_CONTEXT_ID_SEQUENCER.fetch_add(1, Ordering::SeqCst);
    Hash::from_slice(sha256_hash(id.to_le_bytes().as_slice()).as_ref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RegistryUnitContextId(pub(crate) Hash);

impl Default for RegistryUnitContextId {
    fn default() -> Self {
        RegistryUnitContextId(next_registry_unit_context_id())
    }
}

impl From<AccountId> for RegistryUnitContextId {
    fn from(id: AccountId) -> Self {
        RegistryUnitContextId(id.0)
    }
}

impl From<&AccountId> for RegistryUnitContextId {
    fn from(id: &AccountId) -> Self {
        RegistryUnitContextId(id.0)
    }
}

impl From<RegistryUnitContextId> for AccountId {
    fn from(id: RegistryUnitContextId) -> Self {
        AccountId(id.0)
    }
}

impl RegistryUnitContextId {
    pub fn new(id: Hash) -> Self {
        RegistryUnitContextId(id)
    }

    pub fn short(&self) -> String {
        let hex = self.to_hex();
        format!("[{}]", &hex[0..4])
    }
}

impl ToHex for RegistryUnitContextId {
    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl std::fmt::Display for RegistryUnitContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub enum RegistryUnitVariant {
    Mature(RegistryUnitRef),
    Pending(RegistryUnitRef),
    Stasis(RegistryUnitRef),
}

pub struct Context {
    /// Mature (Confirmed) REGISTRY_UNITs
    pub(crate) mature: Vec<RegistryUnitRef>,
    /// REGISTRY_UNITs that are pending confirmation
    pub(crate) pending: AHashMap<RegistryUnitId, RegistryUnitRef>,
    /// REGISTRY_UNITs that are in stasis (freshly minted coinbase transactions only)
    pub(crate) stasis: AHashMap<RegistryUnitId, RegistryUnitRef>,
    /// All REGISTRY_UNITs in possession of this context instance
    pub(crate) map: AHashMap<RegistryUnitId, RegistryUnitRef>,
    /// Outgoing transactions that have not yet been confirmed.
    /// Confirmation occurs when the transaction REGISTRY_UNITs are
    /// removed from the context by the REGISTRY_UNIT change notification.
    pub(crate) outgoing: AHashMap<TransactionId, OutgoingTransaction>,
    /// Total balance of all REGISTRY_UNITs in this context (mature, pending)
    balance: Option<Balance>,
    /// Addresses monitored by this REGISTRY_UNIT context
    addresses: Arc<DashSet<Arc<Address>>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            mature: vec![],
            pending: AHashMap::default(),
            stasis: AHashMap::default(),
            map: AHashMap::default(),
            outgoing: AHashMap::default(),
            balance: None,
            addresses: Arc::new(DashSet::new()),
        }
    }
}

impl Context {
    fn new_with_mature(mature: Vec<RegistryUnitRef>) -> Self {
        Self { mature, ..Default::default() }
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.mature.clear();
        self.stasis.clear();
        self.pending.clear();
        self.outgoing.clear();
        self.addresses.clear();
        self.balance = None;
    }
}

struct Inner {
    id: RegistryUnitContextId,
    binding: RegistryUnitContextBinding,
    context: Mutex<Context>,
    processor: RegistryUnitProcessor,
}

impl Inner {
    pub fn new(processor: &RegistryUnitProcessor, binding: RegistryUnitContextBinding) -> Self {
        Self { id: binding.id(), binding, context: Mutex::new(Context::default()), processor: processor.clone() }
    }

    pub fn new_with_mature_entries(processor: &RegistryUnitProcessor, binding: RegistryUnitContextBinding, mature: Vec<RegistryUnitRef>) -> Self {
        let context = Context::new_with_mature(mature);
        Self { id: binding.id(), binding, context: Mutex::new(context), processor: processor.clone() }
    }
}

///
///  RegistryUnitContext is a data structure responsible for monitoring multiple addresses
/// for transactions.  It scans the address set for existing RegistryUnit records, then
/// monitors for transaction-related events in order to maintain a consistent view
/// on that RegistryUnit set throughout its connection lifetime.
///
/// RegistryUnitContext typically represents a single wallet account, but can monitor any set
/// of addresses. When receiving transaction events, RegistryUnitContext detects types of these
/// events and emits corresponding notifications on the RegistryUnitProcessor event multiplexer.
///
/// In addition to standard monitoring, RegistryUnitContext works in conjunction with the
/// TransactionGenerator to track outgoing transactions in an effort to segregate
/// different types of RegistryUnit updates (regular incoming vs. change).
///
#[derive(Clone)]
pub struct RegistryUnitContext {
    inner: Arc<Inner>,
}

impl RegistryUnitContext {
    pub fn new(processor: &RegistryUnitProcessor, binding: RegistryUnitContextBinding) -> Self {
        Self { inner: Arc::new(Inner::new(processor, binding)) }
    }

    pub fn new_with_mature_entries(
        processor: &RegistryUnitProcessor,
        binding: RegistryUnitContextBinding,
        mature_entries: Vec<RegistryUnitRef>,
    ) -> Self {
        Self { inner: Arc::new(Inner::new_with_mature_entries(processor, binding, mature_entries)) }
    }

    pub fn context(&self) -> MutexGuard<'_, Context> {
        self.inner.context.lock().unwrap()
    }

    pub fn processor(&self) -> &RegistryUnitProcessor {
        &self.inner.processor
    }

    pub fn binding(&self) -> RegistryUnitContextBinding {
        self.inner.binding.clone()
    }

    pub fn id(&self) -> RegistryUnitContextId {
        self.inner.id
    }

    pub fn id_as_ref(&self) -> &RegistryUnitContextId {
        &self.inner.id
    }

    pub fn mature_registry_unit_size(&self) -> usize {
        self.context().mature.len()
    }

    pub fn pending_registry_unit_size(&self) -> usize {
        self.context().pending.len()
    }

    pub fn balance(&self) -> Option<Balance> {
        self.context().balance.clone()
    }

    pub fn addresses(&self) -> Arc<DashSet<Arc<Address>>> {
        self.context().addresses.clone()
    }

    pub async fn clear(&self) -> Result<()> {
        let local = self.addresses();
        let addresses = local.iter().map(|v| v.clone()).collect::<Vec<_>>();
        if !addresses.is_empty() {
            self.processor().unregister_addresses(addresses).await?;
            local.clear();
        }

        self.context().clear();

        Ok(())
    }

    pub async fn update_balance(&self) -> Result<Balance> {
        let balance = {
            let previous_balance = self.balance();
            let mut balance = self.calculate_balance().await;
            balance.delta(&previous_balance);
            let mut context = self.context();
            context.balance.replace(balance.clone());
            balance
        };
        self.processor().notify(Events::Balance { balance: Some(balance.clone()), id: self.id() }).await?;

        Ok(balance)
    }

    /// Process pending transaction. Remove mature REGISTRY_UNIT entries and add them to the consumed set.
    /// Produces a notification on the even multiplexer.
    pub(crate) async fn register_outgoing_transaction(&self, pending_tx: &PendingTransaction) -> Result<()> {
        {
            let current_daa_score =
                self.processor().current_daa_score().ok_or(Error::MissingDaaScore("register_outgoing_transaction()"))?;

            let mut context = self.context();
            let pending_registry_unit_entries = pending_tx.registry_unit_entries();
            context.mature.retain(|entry| !pending_registry_unit_entries.contains_key(&entry.id()));

            let outgoing_transaction = OutgoingTransaction::new(current_daa_score, self.clone(), pending_tx.clone());
            self.processor().register_outgoing_transaction(outgoing_transaction.clone());
            context.outgoing.insert(outgoing_transaction.id(), outgoing_transaction);
        }

        Ok(())
    }

    pub(crate) async fn notify_outgoing_transaction(&self, pending_tx: &PendingTransaction) -> Result<()> {
        let outgoing_tx = match self.inner.processor.outgoing().get(&pending_tx.id()) {
            Some(tx) => tx,
            None => return Ok(()),
        };

        if pending_tx.is_batch() {
            let record = TransactionRecord::new_batch(self, &outgoing_tx, None)?;
            self.processor().notify(Events::Pending { record }).await?;
        } else {
            let record = TransactionRecord::new_outgoing(self, &outgoing_tx, None)?;
            self.processor().notify(Events::Pending { record }).await?;
        }
        self.update_balance().await?;
        Ok(())
    }

    /// Cancel outgoing transaction in case of a submission error. Removes [`OutgoingTransaction`] from the
    /// [`RegistryUnitProcessor`] and returns RegistryUnitEntries from the outgoing transaction back to the mature pool.
    pub(crate) async fn cancel_outgoing_transaction(&self, pending_tx: &PendingTransaction) -> Result<()> {
        self.processor().cancel_outgoing_transaction(pending_tx.id());

        let mut context = self.context();

        let outgoing_transaction = context.outgoing.remove(&pending_tx.id()).expect("outgoing transaction");
        outgoing_transaction.registry_unit_entries().iter().for_each(|(_, entry)| {
            context.mature.push(entry.clone());
        });

        Ok(())
    }

    /// Insert `registry_unit_entry` into the `RegistryUnitSet`.
    /// NOTE: The insert will be ignored if already present in the inner map.
    pub async fn insert(&self, registry_unit_entry: RegistryUnitRef, current_daa_score: u64, force_maturity: bool) -> Result<()> {
        let mut context = self.context();
        if let std::collections::hash_map::Entry::Vacant(e) = context.map.entry(registry_unit_entry.id().clone()) {
            e.insert(registry_unit_entry.clone());
            if force_maturity {
                context.mature.sorted_insert_binary_asc_by_key(registry_unit_entry.clone(), |entry| entry.amount_as_ref());
            } else {
                let params = NetworkParams::from(self.processor().network_id()?);
                match registry_unit_entry.maturity(params, current_daa_score) {
                    Maturity::Stasis => {
                        context.stasis.insert(registry_unit_entry.id().clone(), registry_unit_entry.clone());
                        self.processor()
                            .stasis()
                            .insert(registry_unit_entry.id().clone(), PendingRegistryUnitRef::new(registry_unit_entry, self.clone()));
                    }
                    Maturity::Pending => {
                        context.pending.insert(registry_unit_entry.id().clone(), registry_unit_entry.clone());
                        self.processor()
                            .pending()
                            .insert(registry_unit_entry.id().clone(), PendingRegistryUnitRef::new(registry_unit_entry, self.clone()));
                    }
                    Maturity::Confirmed => {
                        context.mature.sorted_insert_binary_asc_by_key(registry_unit_entry.clone(), |entry| entry.amount_as_ref());
                    }
                }
            }
            Ok(())
        } else {
            // log_warn!("Warning: Ignoring duplicate REGISTRY_UNIT entry");
            Ok(())
        }
    }

    pub async fn update(&self, registry_unit_entry: RegistryUnitRef, _current_daa_score: u64, _force_maturity: bool) -> Result<bool> {
        let mut context = self.context();
        if context.map.get(&registry_unit_entry.id()).is_some() {
            // if old_entry.block_daa_score() > registry_unit_entry.block_daa_score() {
            //     return Ok(false);
            // }
            let id = registry_unit_entry.id();
            let entry = PendingRegistryUnitRef::new(registry_unit_entry.clone(), self.clone());

            context.stasis.entry(id.clone()).and_modify(|e| *e = registry_unit_entry.clone());
            self.processor().stasis().entry(id.clone()).and_modify(|e| *e = entry.clone());

            context.pending.entry(id.clone()).and_modify(|e| *e = registry_unit_entry.clone());
            self.processor().pending().entry(id.clone()).and_modify(|e| *e = entry.clone());

            if let Some(entry) = context.mature.iter_mut().find(|entry| entry.id() == id) {
                *entry = registry_unit_entry.clone();
            }

            context.map.entry(id.clone()).and_modify(|e| *e = registry_unit_entry);

            return Ok(true);
        }

        Ok(false)
    }

    pub async fn remove(&self, registry_units: Vec<RegistryUnitRef>) -> Result<Vec<RegistryUnitVariant>> {
        let mut context = self.context();
        let mut removed = vec![];
        let mut remove_mature_ids = vec![];

        for registry_unit in registry_units.into_iter() {
            let id = registry_unit.id();
            // remove from local map
            if context.map.remove(&id).is_some() {
                if let Some(pending) = context.pending.remove(&id) {
                    removed.push(RegistryUnitVariant::Pending(pending));
                    if self.processor().pending().remove(&id).is_none() {
                        log_error!("Error: unable to remove registry_unit entry from global pending (with context)");
                    }
                } else if let Some(stasis) = context.stasis.remove(&id) {
                    removed.push(RegistryUnitVariant::Stasis(stasis));
                    if self.processor().stasis().remove(&id).is_none() {
                        log_error!("Error: unable to remove registry_unit entry from global pending (with context)");
                    }
                } else {
                    remove_mature_ids.push(id);
                }
            } else if context.outgoing.get(&registry_unit.transaction_id()).is_none() {
                // log_warm!("Warning: REGISTRY_UNIT not found in RegistryUnitContext map!");
            }
        }

        context.mature.retain(|entry| {
            if remove_mature_ids.contains(&entry.id()) {
                removed.push(RegistryUnitVariant::Mature(entry.clone()));
                false
            } else {
                true
            }
        });

        Ok(removed)
    }

    /// This function handles `Pending` to `Mature` transformation.
    pub async fn promote(&self, registry_units: Vec<RegistryUnitRef>) -> Result<()> {
        let transactions = HashMap::group_from(registry_units.iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit.clone())));

        for (txid, registry_units) in transactions.into_iter() {
            for registry_unit_entry in registry_units.iter() {
                let mut context = self.context();
                if context.pending.remove(registry_unit_entry.id_as_ref()).is_some() {
                    context.mature.sorted_insert_binary_asc_by_key(registry_unit_entry.clone(), |entry| entry.amount_as_ref());
                } else {
                    log_error!("Error: non-pending registry_unit promotion!");
                }
            }

            // sanity check
            if self.context().outgoing.get(&txid).is_some() {
                unreachable!("Error: promotion of the outgoing transaction!");
            }

            let record = TransactionRecord::new_incoming(self, txid, &registry_units);
            self.processor().notify(Events::Maturity { record }).await?;
        }

        Ok(())
    }

    /// This function handles `Stasis` to `Pending` transformation.
    pub async fn revive(&self, registry_units: Vec<RegistryUnitRef>) -> Result<()> {
        let transactions = HashMap::group_from(registry_units.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));

        for (txid, registry_units) in transactions.into_iter() {
            for registry_unit_entry in registry_units.iter() {
                let mut context = self.context();
                if context.stasis.remove(registry_unit_entry.id_as_ref()).is_some() {
                    context.pending.insert(registry_unit_entry.id(), registry_unit_entry.clone());
                } else {
                    log_error!("Error: non-stasis registry_unit revival!");
                    panic!("Error: non-stasis registry_unit revival!");
                }
            }

            let record = TransactionRecord::new_incoming(self, txid, &registry_units);
            self.processor().notify(Events::Pending { record }).await?;
        }

        Ok(())
    }

    pub fn remove_outgoing_transaction(&self, txid: &TransactionId) -> Option<OutgoingTransaction> {
        let mut context = self.context();
        context.outgoing.remove(txid)
    }

    pub async fn extend_from_scan(&self, registry_unit_entries: Vec<RegistryUnitRef>, current_daa_score: u64) -> Result<()> {
        let (pending, mature) = {
            let mut context = self.context();

            let mut pending = vec![];
            let mut mature = Vec::with_capacity(registry_unit_entries.len());

            let params = NetworkParams::from(self.processor().network_id()?);

            for registry_unit_entry in registry_unit_entries.into_iter() {
                if let std::collections::hash_map::Entry::Vacant(e) = context.map.entry(registry_unit_entry.id()) {
                    e.insert(registry_unit_entry.clone());
                    match registry_unit_entry.maturity(params, current_daa_score) {
                        Maturity::Stasis => {
                            context.stasis.insert(registry_unit_entry.id().clone(), registry_unit_entry.clone());
                            self.processor()
                                .stasis()
                                .insert(registry_unit_entry.id().clone(), PendingRegistryUnitRef::new(registry_unit_entry, self.clone()));
                        }
                        Maturity::Pending => {
                            pending.push(registry_unit_entry.clone());
                            context.pending.insert(registry_unit_entry.id().clone(), registry_unit_entry.clone());
                            self.processor()
                                .pending()
                                .insert(registry_unit_entry.id().clone(), PendingRegistryUnitRef::new(registry_unit_entry, self.clone()));
                        }
                        Maturity::Confirmed => {
                            mature.push(registry_unit_entry.clone());
                        }
                    }
                } else {
                    log_warn!("ignoring duplicate registry_unit entry");
                }
            }

            context.mature.extend(mature.iter().cloned());
            context.mature.sort_by_key(|entry| entry.amount());

            (pending, mature)
        };

        // cascade discovery to the processor
        // for unixtime resolution

        let pending = HashMap::group_from(pending.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        for (id, registry_units) in pending.into_iter() {
            let record = TransactionRecord::new_external(self, id, &registry_units);
            self.processor().handle_discovery(record).await?;
        }

        let mature = HashMap::group_from(mature.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        for (id, registry_units) in mature.into_iter() {
            let record = TransactionRecord::new_external(self, id, &registry_units);
            self.processor().handle_discovery(record).await?;
        }

        Ok(())
    }

    pub async fn calculate_balance(&self) -> Balance {
        let context = self.context();
        let mature: u64 = context.mature.iter().map(|e| e.as_ref().amount).sum();
        let pending: u64 = context.pending.values().map(|e| e.as_ref().amount).sum();

        // this will aggregate only transactions containing
        // the final payments (not compound transactions)
        // and outgoing transactions that have not yet
        // been accepted
        let mut outgoing_without_batch_tx = 0;
        let mut outgoing: u64 = 0;
        let mut consumed: u64 = 0;

        let transactions = context.outgoing.values().filter(|tx| !tx.is_accepted());
        for tx in transactions {
            if let Some(payment_value) = tx.payment_value() {
                consumed += tx.aggregate_input_value();
                if tx.is_batch() {
                    outgoing += tx.fees() + tx.aggregate_output_value();
                } else {
                    // final tx
                    outgoing += tx.fees() + payment_value;
                    outgoing_without_batch_tx += payment_value;
                }
            } else {
                // compound tx has no payment value
                outgoing += tx.fees() + tx.aggregate_output_value();
                consumed += tx.aggregate_input_value();
            }
        }

        // TODO - remove this check once we are confident that
        // this condition does not occur. This is a temporary
        // log for a fixed bug, but we want to keep the check
        // just in case.
        if consumed < outgoing {
            log_error!(
                "Error: outgoing transaction value exceeds available balance, mature: {mature}, consumed: {consumed}, outgoing: {outgoing}"
            );
        }

        let mature = (mature + consumed).saturating_sub(outgoing);
        Balance::new(mature, pending, outgoing_without_batch_tx, context.mature.len(), context.pending.len(), context.stasis.len())
    }

    pub(crate) async fn update_registry_units(&self, registry_units: Vec<RegistryUnitRef>, current_daa_score: u64) -> Result<()> {
        if registry_units.is_empty() {
            return Ok(());
        }

        let registry_units = HashMap::group_from(registry_units.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        for (txid, registry_units) in registry_units.into_iter() {
            // get outgoing transaction from the processor in case the transaction
            // originates from a different [`Account`] represented by a different [`RegistryUnitContext`].
            let outgoing_transaction = self.processor().outgoing().get(&txid);
            let force_maturity_if_outgoing = outgoing_transaction.is_some();
            let is_batch = outgoing_transaction.as_ref().map_or_else(|| false, |tx| tx.is_batch());
            if !is_batch {
                for registry_unit in registry_units.iter() {
                    if let Err(err) = self.update(registry_unit.clone(), current_daa_score, force_maturity_if_outgoing).await {
                        // TODO - remove `Result<>` from insert at a later date once
                        // we are confident that the insert will never result in an error.
                        log_error!("{}", err);
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_registry_unit_added(&self, registry_units: Vec<RegistryUnitRef>, current_daa_score: u64) -> Result<()> {
        // add REGISTRY_UNITs to account set

        let params = NetworkParams::from(self.processor().network_id()?);

        let mut accepted_outgoing_transactions = AHashSet::new();

        let added = HashMap::group_from(registry_units.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        for (txid, registry_units) in added.into_iter() {
            // get outgoing transaction from the processor in case the transaction
            // originates from a different [`Account`] represented by a different [`RegistryUnitContext`].
            let outgoing_transaction = self.processor().outgoing().get(&txid);

            let force_maturity_if_outgoing = outgoing_transaction.is_some();
            let is_coinbase_stasis =
                registry_units.first().map(|registry_unit| matches!(registry_unit.maturity(params, current_daa_score), Maturity::Stasis)).unwrap_or_default();
            let is_batch = outgoing_transaction.as_ref().map_or_else(|| false, |tx| tx.is_batch());
            if !is_batch {
                for registry_unit in registry_units.iter() {
                    if let Err(err) = self.insert(registry_unit.clone(), current_daa_score, force_maturity_if_outgoing).await {
                        // TODO - remove `Result<>` from insert at a later date once
                        // we are confident that the insert will never result in an error.
                        log_error!("{}", err);
                    }
                }
            }

            if let Some(outgoing_transaction) = outgoing_transaction {
                accepted_outgoing_transactions.insert((*outgoing_transaction).clone());
                if outgoing_transaction.is_batch() {
                    let record = TransactionRecord::new_batch(self, &outgoing_transaction, Some(current_daa_score))?;
                    self.processor().notify(Events::Maturity { record }).await?;
                } else if outgoing_transaction.originating_context() == self {
                    let record = TransactionRecord::new_change(self, &outgoing_transaction, Some(current_daa_score), &registry_units)?;
                    self.processor().notify(Events::Maturity { record }).await?;
                } else {
                    let record =
                        TransactionRecord::new_transfer_incoming(self, &outgoing_transaction, Some(current_daa_score), &registry_units)?;
                    self.processor().notify(Events::Maturity { record }).await?;
                }
            } else if !is_coinbase_stasis {
                // do not notify if coinbase transaction is in stasis
                let record = TransactionRecord::new_incoming(self, txid, &registry_units);
                self.processor().notify(Events::Pending { record }).await?;
            }
        }

        for outgoing_transaction in accepted_outgoing_transactions.into_iter() {
            outgoing_transaction.tag_as_accepted_at_daa_score(current_daa_score);
        }

        Ok(())
    }

    pub(crate) async fn handle_registry_unit_removed(&self, registry_units: Vec<RegistryUnitRef>, current_daa_score: u64) -> Result<()> {
        // remove REGISTRY_UNITs from account set

        let outgoing_transactions = self.processor().outgoing();

        #[allow(clippy::mutable_key_type)]
        let mut accepted_outgoing_transactions = HashSet::<OutgoingTransaction>::new();
        for registry_unit in &registry_units {
            for outgoing_transaction in outgoing_transactions.iter() {
                if outgoing_transaction.registry_unit_entries().contains_key(&registry_unit.id()) {
                    accepted_outgoing_transactions.insert((*outgoing_transaction).clone());
                }
            }
        }

        for accepted_outgoing_transaction in accepted_outgoing_transactions.into_iter() {
            if accepted_outgoing_transaction.is_batch() {
                let record = TransactionRecord::new_batch(self, &accepted_outgoing_transaction, Some(current_daa_score))?;
                self.processor().notify(Events::Maturity { record }).await?;
            } else if accepted_outgoing_transaction.destination_context().is_some() {
                let record =
                    TransactionRecord::new_transfer_outgoing(self, &accepted_outgoing_transaction, Some(current_daa_score), &registry_units)?;
                self.processor().notify(Events::Maturity { record }).await?;
            } else {
                let record = TransactionRecord::new_outgoing(self, &accepted_outgoing_transaction, Some(current_daa_score))?;
                self.processor().notify(Events::Maturity { record }).await?;
            }
        }

        if registry_units.is_empty() {
            return Ok(());
        }

        let removed = self.remove(registry_units).await?;

        let mut mature = vec![];
        let mut pending = vec![];
        let mut stasis = vec![];

        removed.into_iter().for_each(|entry| match entry {
            RegistryUnitVariant::Mature(registry_unit) => {
                mature.push(registry_unit);
            }
            RegistryUnitVariant::Pending(registry_unit) => {
                pending.push(registry_unit);
            }
            RegistryUnitVariant::Stasis(registry_unit) => {
                stasis.push(registry_unit);
            }
        });

        let mature = HashMap::group_from(mature.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        let pending = HashMap::group_from(pending.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));
        let stasis = HashMap::group_from(stasis.into_iter().map(|registry_unit| (registry_unit.transaction_id(), registry_unit)));

        for (txid, registry_units) in mature.into_iter() {
            let record = TransactionRecord::new_external(self, txid, &registry_units);
            self.processor().notify(Events::Maturity { record }).await?;
        }

        for (txid, registry_units) in pending.into_iter() {
            let record = TransactionRecord::new_reorg(self, txid, &registry_units);
            self.processor().notify(Events::Reorg { record }).await?;
        }

        for (txid, registry_units) in stasis.into_iter() {
            let record = TransactionRecord::new_stasis(self, txid, &registry_units);
            self.processor().notify(Events::Stasis { record }).await?;
        }

        Ok(())
    }

    pub async fn register_addresses(&self, addresses: &[Address]) -> Result<()> {
        if addresses.is_empty() {
            log_error!("registry_unit processor: register for an empty address set");
        }

        let local = self.addresses();

        // addresses are filtered for a known address set where
        // addresses can already be registered with the processor
        // as a part of address space (Scan window) pre-caching.
        let addresses = addresses
            .iter()
            .filter_map(|address| {
                let address = Arc::new(address.clone());
                if local.insert(address.clone()) { Some(address) } else { None }
            })
            .collect::<Vec<_>>();

        if addresses.is_not_empty() {
            self.processor().register_addresses(addresses, self).await?;
        }

        Ok(())
    }

    pub async fn unregister_addresses(&self, addresses: Vec<Address>) -> Result<()> {
        if !addresses.is_empty() {
            let local = self.addresses();
            let addresses = addresses.clone().into_iter().map(Arc::new).collect::<Vec<_>>();
            self.processor().unregister_addresses(addresses.clone()).await?;
            addresses.iter().for_each(|address| {
                local.remove(address);
            });
        } else {
            log_warn!("registry_unit processor: unregister for an empty address set")
        }

        Ok(())
    }

    pub async fn scan_and_register_addresses(&self, addresses: Vec<Address>, current_daa_score: Option<u64>) -> Result<()> {
        self.register_addresses(&addresses).await?;
        let resp = self.processor().rpc_api().get_registry_by_addresses(addresses).await?;
        let refs: Vec<RegistryUnitRef> = resp.into_iter().map(RegistryUnitRef::from).collect();
        let current_daa_score = current_daa_score.or_else(|| {
                self.processor()
                    .current_daa_score()
            }).ok_or(Error::MissingDaaScore("Expecting DAA score or initialized RegistryUnitProcessor when invoking scan_and_register_addresses() - You might be accessing RegistryUnitProcessor APIs before it is initialized (see `registry_unit-proc-start` event)"))?;
        self.extend_from_scan(refs, current_daa_score).await?;
        self.update_balance().await?;
        Ok(())
    }

    pub async fn get_registry_units(&self, addresses: Option<Vec<Address>>, min_amount_kana: Option<u64>) -> Result<Vec<RegistryUnit>> {
        let registry_units = &self.context().mature;
        let mut amount = 0;
        if let Some(addresses) = &addresses {
            if let Some(min_amount_kana) = min_amount_kana {
                let mut amount = 0;
                let filtered_registry_units = registry_units
                    .iter()
                    .filter_map(|registry_unit| {
                        if let Some(address) = registry_unit.address()
                            && addresses.contains(&address)
                            && amount < min_amount_kana
                        {
                            amount += registry_unit.amount();
                            return Some(registry_unit.entry().clone());
                        }

                        None
                    })
                    .collect();
                return Ok(filtered_registry_units);
            } else {
                let filtered_registry_units = registry_units
                    .iter()
                    .filter_map(|registry_unit| {
                        if let Some(address) = registry_unit.address()
                            && addresses.contains(&address)
                        {
                            return Some(registry_unit.entry().clone());
                        }
                        None
                    })
                    .collect();
                return Ok(filtered_registry_units);
            }
        }
        if let Some(min_amount_kana) = min_amount_kana {
            let filtered_registry_units = registry_units
                .iter()
                .filter_map(|registry_unit| {
                    if amount < min_amount_kana {
                        amount += registry_unit.amount();
                        return Some(registry_unit.entry().clone());
                    }
                    None
                })
                .collect();
            return Ok(filtered_registry_units);
        }
        Ok(registry_units.iter().map(|registry_unit| registry_unit.entry().clone()).collect())
    }
}

impl Eq for RegistryUnitContext {}

impl PartialEq for RegistryUnitContext {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl std::hash::Hash for RegistryUnitContext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl Ord for RegistryUnitContext {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id().cmp(other.id_as_ref())
    }
}

impl PartialOrd for RegistryUnitContext {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
