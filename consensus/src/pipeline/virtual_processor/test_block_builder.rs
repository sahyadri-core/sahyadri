use std::{ops::Deref, sync::Arc};

use crate::model::stores::{
    pruning::PruningStoreReader, utxo_multisets::UtxoMultisetsStoreReader, virtual_state::VirtualStateStoreReader,
};
use sahyadri_consensus_core::{
    block::BlockTemplate, blockhash::ORIGIN, coinbase::MinerData, errors::block::RuleError, tx::Transaction,
};
use sahyadri_hashes::Hash;

use super::VirtualStateProcessor;

/// Wrapper for virtual processor with util methods for building a block with any parent context
pub struct TestBlockBuilder {
    processor: Arc<VirtualStateProcessor>,
}

impl Deref for TestBlockBuilder {
    type Target = VirtualStateProcessor;

    fn deref(&self) -> &Self::Target {
        &self.processor
    }
}

impl TestBlockBuilder {
    pub fn new(processor: Arc<VirtualStateProcessor>) -> Self {
        Self { processor }
    }

    /// Test-only helper method for building a block template with specific parents
    pub(crate) fn build_block_template_with_parents(
        &self,
        parents: Vec<Hash>,
        miner_data: MinerData,
        txs: Vec<Transaction>,
    ) -> Result<BlockTemplate, RuleError> {
        //
        // In the context of this method "pov virtual" is the virtual block which has `parents` as tips and not the actual virtual
        //
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let finality_point = ORIGIN; // No real finality point since we are not actually building virtual here
        let sink = virtual_state.sahyadri_consensus_data.selected_parent;
        let mut accumulated_diff = sahyadri_consensus_core::utxo::utxo_diff::UtxoDiff::default();
        // Search for the sink block from the PoV of this virtual
        let (pov_sink, virtual_parent_candidates) =
            self.sink_search_algorithm(&virtual_read, &mut accumulated_diff, sink, parents, finality_point, pruning_point);
        let (pov_virtual_parents, pov_virtual_sahyadri_consensus_data) =
            self.pick_virtual_parents(pov_sink, virtual_parent_candidates, pruning_point);
        let _pov_sink_multiset = self.utxo_multisets_store.get(pov_sink).unwrap();
        // Call mein se pub(crate) hatao
        let pov_virtual_state = self.calculate_virtual_state(
            &virtual_read,
            pov_virtual_parents,
            pov_virtual_sahyadri_consensus_data,
            sahyadri_muhash::MuHash::new(),
        )?;

        let dummy_utxo_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default();
        self.validate_block_template_transactions(&txs, &pov_virtual_state, &dummy_utxo_view)?;
        drop(virtual_read);
        self.build_block_template_from_virtual_state(pov_virtual_state, miner_data, txs, vec![])
    }
}
