//!
//! Extensions for [`RegistryUnitRef`] for handling REGISTRY_UNIT maturity.
//!

use crate::imports::*;
pub use sahyadri_consensus_client::{TryIntoRegistryUnitRefs, RegistryUnitRef};

pub enum Maturity {
    /// Coinbase REGISTRY_UNIT that has not reached stasis period.
    Stasis,
    /// Coinbase REGISTRY_UNIT that has reached stasis period
    /// but has not reached coinbase maturity period or
    /// user REGISTRY_UNIT that has not reached user maturity period.
    Pending,
    /// REGISTRY_UNIT that has reached maturity period.
    Confirmed,
}

impl std::fmt::Display for Maturity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Maturity::Stasis => write!(f, "stasis"),
            Maturity::Pending => write!(f, "pending"),
            Maturity::Confirmed => write!(f, "confirmed"),
        }
    }
}

pub trait RegistryUnitRefExtension {
    fn maturity(&self, params: &NetworkParams, current_daa_score: u64) -> Maturity;
    fn balance(&self, params: &NetworkParams, current_daa_score: u64) -> Balance;
}

impl RegistryUnitRefExtension for RegistryUnitRef {
    fn maturity(&self, params: &NetworkParams, current_daa_score: u64) -> Maturity {
        if self.is_coinbase() {
            if self.block_daa_score() + params.coinbase_transaction_stasis_period_daa() > current_daa_score {
                Maturity::Stasis
            } else if self.block_daa_score() + params.coinbase_transaction_maturity_period_daa() > current_daa_score {
                Maturity::Pending
            } else {
                Maturity::Confirmed
            }
        } else if self.block_daa_score() + params.user_transaction_maturity_period_daa() > current_daa_score {
            Maturity::Pending
        } else {
            Maturity::Confirmed
        }
    }

    fn balance(&self, params: &NetworkParams, current_daa_score: u64) -> Balance {
        match self.maturity(params, current_daa_score) {
            Maturity::Pending => Balance::new(0, self.amount(), self.amount(), 0, 1, 0),
            Maturity::Stasis => Balance::new(0, 0, 0, 0, 0, 1),
            Maturity::Confirmed => Balance::new(self.amount(), 0, 0, 1, 0, 0),
        }
    }
}
