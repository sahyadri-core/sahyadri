use super::tx::MempoolTransaction;
use sahyadri_consensus_core::tx::{TransactionId, RegistryRef};
use std::collections::HashMap;

/// MempoolTransactionCollection maps a transaction id to a mempool transaction
pub(crate) type MempoolTransactionCollection = HashMap<TransactionId, MempoolTransaction>;

/// OutpointIndex maps an outpoint to a transaction id
pub(crate) type OutpointIndex = HashMap<RegistryRef, TransactionId>;
