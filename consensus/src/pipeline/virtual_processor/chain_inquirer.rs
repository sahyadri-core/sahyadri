//! Chain-based block inquirer for the account model.
//!
//! Account-model replacement for the REGISTRY_UNIT-era `registry_unit_inquirer.rs`.
//! Provides DAG chain walks needed by transaction-query RPCs, without
//! any REGISTRY_UNIT state.

use std::cmp;

use sahyadri_consensus_core::errors::consensus::{ConsensusError, ConsensusResult};
use sahyadri_core::trace;
use sahyadri_hashes::Hash;

use crate::model::stores::headers::HeaderStoreReader;
use crate::model::stores::selected_chain::SelectedChainStoreReader;

use super::VirtualStateProcessor;

impl VirtualStateProcessor {
    /// Find the chain block whose DAA score matches `target_daa_score`.
    ///
    /// Assumes the caller holds the pruning read lock so that reads on
    /// `selected_chain_store` and `headers_store` are consistent.
    /// Binary-searches the selected chain using the lower bound
    /// `len(segment) <= daa_score(end) - daa_score(start)`.
    pub fn find_accepting_chain_block_hash_at_daa_score(
        &self,
        target_daa_score: u64,
        retention_period_root_hash: Hash,
    ) -> ConsensusResult<Hash> {
        let sc_read = self.selected_chain_store.read();

        let retention_period_root_index = sc_read
            .get_by_hash(retention_period_root_hash)
            .map_err(|_| ConsensusError::MissingData(retention_period_root_hash))?;
        let (tip_index, tip_hash) =
            sc_read.get_tip().map_err(|_| ConsensusError::MissingData(retention_period_root_hash))?;
        let tip_daa_score = self
            .headers_store
            .get_daa_score(tip_hash)
            .map_err(|_| ConsensusError::HeaderNotFound(tip_hash))?;

        let mut low_index = tip_index
            .saturating_sub(tip_daa_score.saturating_sub(target_daa_score))
            .max(retention_period_root_index);
        let mut high_index = tip_index;

        let matching_chain_block_hash = loop {
            let mid = low_index + (high_index - low_index) / 2;

            let hash = sc_read.get_by_index(mid).map_err(|_| {
                trace!("Did not find a hash at index {}", mid);
                ConsensusError::MissingData(retention_period_root_hash)
            })?;

            let daa_score = self.headers_store.get_daa_score(hash).map_err(|_| {
                trace!("Did not find a header with hash {}", hash);
                ConsensusError::HeaderNotFound(hash)
            })?;

            match daa_score.cmp(&target_daa_score) {
                cmp::Ordering::Equal => break hash,
                cmp::Ordering::Greater => high_index = mid - 1,
                cmp::Ordering::Less => low_index = mid + 1,
            }

            if low_index > high_index {
                return Err(ConsensusError::MissingData(tip_hash));
            }
        };

        Ok(matching_chain_block_hash)
    }
}
