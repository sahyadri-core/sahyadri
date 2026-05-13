use sahyadri_consensus_core::blockhash::{BlockHashExtensions, ORIGIN};
use sahyadri_hashes::Hash;
use std::sync::Arc;

use crate::model::{
    services::reachability::{MTReachabilityService, ReachabilityService},
    stores::{
        depth::DepthStoreReader,
        sahyadri_consensus::{SahyadriConsensusData, SahyadriConsensusStoreReader},
        headers::HeaderStoreReader,
        reachability::ReachabilityStoreReader,
    },
};

enum BlockDepthType {
    MergeRoot,
    Finality,
}

#[derive(Clone)]
pub struct BlockDepthManager<S: DepthStoreReader, U: ReachabilityStoreReader, V: SahyadriConsensusStoreReader, T: HeaderStoreReader> {
    merge_depth: u64,
    finality_depth: u64,
    genesis_hash: Hash,
    depth_store: Arc<S>,
    reachability_service: MTReachabilityService<U>,
    sahyadri_consensus_store: Arc<V>,
    _headers_store: Arc<T>,
}

impl<S: DepthStoreReader, U: ReachabilityStoreReader, V: SahyadriConsensusStoreReader, T: HeaderStoreReader> BlockDepthManager<S, U, V, T> {
    pub fn new(
        merge_depth: u64,
        finality_depth: u64,
        genesis_hash: Hash,
        depth_store: Arc<S>,
        reachability_service: MTReachabilityService<U>,
        sahyadri_consensus_store: Arc<V>,
        headers_store: Arc<T>,
    ) -> Self {
        Self {
            merge_depth,
            finality_depth,
            genesis_hash,
            depth_store,
            reachability_service,
            sahyadri_consensus_store,
            _headers_store: headers_store,
        }
    }
    pub fn calc_merge_depth_root(&self, sahyadri_consensus_data: &SahyadriConsensusData, pruning_point: Hash) -> Hash {
        self.calculate_block_at_depth(sahyadri_consensus_data, BlockDepthType::MergeRoot, pruning_point)
    }

    pub fn calc_finality_point(&self, sahyadri_consensus_data: &SahyadriConsensusData, pruning_point: Hash) -> Hash {
        self.calculate_block_at_depth(sahyadri_consensus_data, BlockDepthType::Finality, pruning_point)
    }

    fn calculate_block_at_depth(&self, sahyadri_consensus_data: &SahyadriConsensusData, depth_type: BlockDepthType, pruning_point: Hash) -> Hash {
        if sahyadri_consensus_data.selected_parent.is_origin() {
            return ORIGIN;
        }
        let depth = match depth_type {
            BlockDepthType::MergeRoot => self.merge_depth,
            BlockDepthType::Finality => self.finality_depth,
        };
        if sahyadri_consensus_data.blue_score < depth {
            return self.genesis_hash;
        }

        let pp_bs = self.sahyadri_consensus_store.get_blue_score(pruning_point).unwrap();

        if sahyadri_consensus_data.blue_score < pp_bs + depth {
            return ORIGIN;
        }

        if !self.reachability_service.is_chain_ancestor_of(pruning_point, sahyadri_consensus_data.selected_parent) {
            return ORIGIN;
        }

        // We start from the depth/finality point of the selected parent and then walk up the chain.
        let mut current = match depth_type {
            BlockDepthType::MergeRoot => self.depth_store.merge_depth_root(sahyadri_consensus_data.selected_parent).unwrap(),
            BlockDepthType::Finality => self.depth_store.finality_point(sahyadri_consensus_data.selected_parent).unwrap(),
        };

        // In this case we expect the pruning point or a block above it to be the block at depth.
        // Note that above we already verified the chain and distance conditions for this.
        // Additionally observe that if `current` is a valid hash it must not be pruned for the same reason.
        if current == ORIGIN {
            current = pruning_point;
        }

        let required_blue_score = sahyadri_consensus_data.blue_score - depth;

        for chain_block in self.reachability_service.forward_chain_iterator(current, sahyadri_consensus_data.selected_parent, true) {
            if self.sahyadri_consensus_store.get_blue_score(chain_block).unwrap() >= required_blue_score {
                break;
            }

            current = chain_block;
        }

        current
    }

    /// Returns the set of blues which are eligible for "kosherizing" merge bound violating blocks.
    /// By prunality rules, these blocks must have `merge_depth_root` on their selected chain.  
    pub fn kosherizing_blues<'a>(
        &'a self,
        sahyadri_consensus_data: &'a SahyadriConsensusData,
        merge_depth_root: Hash,
    ) -> impl DoubleEndedIterator<Item = Hash> + 'a {
        sahyadri_consensus_data
            .mergeset_blues
            .iter()
            .copied()
            .filter(move |blue| self.reachability_service.is_chain_ancestor_of(merge_depth_root, *blue))
    }
}
