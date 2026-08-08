use futures_util::future::BoxFuture;
use sahyadri_muhash::MuHash;
use std::sync::Arc;

use crate::{
    BlockHashSet, BlueWorkType, ChainPath,
    acceptance_data::{AcceptanceData, MergesetBlockAcceptanceData},
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{Block, BlockTemplate, TemplateBuildMode, TemplateTransactionSelector, VirtualStateApproxId},
    blockstatus::BlockStatus,
    coinbase::MinerData,
    daa_score_timestamp::DaaScoreTimestamp,
    errors::{
        block::{BlockProcessResult, RuleError},
        coinbase::CoinbaseResult,
        consensus::ConsensusResult,
        pruning::PruningImportResult,
        tx::TxResult,
    },
    header::Header,
    mass::{ContextualMasses, NonContextualMasses},
    pruning::{PruningPointProof, PruningPointTrustedData, PruningPointsList, PruningProofMetadata},
    trusted::{ExternalSahyadriConsensusData, TrustedBlock},
    tx::{
        MutableTransaction, Transaction, TransactionId, TransactionIndexType, TransactionOutpoint, TransactionQueryResult,
        TransactionType, UtxoEntry,
    },
};
use sahyadri_hashes::Hash;

pub use self::stats::{BlockCount, ConsensusStats};

pub mod args;
pub mod counters;
pub mod stats;

pub type BlockValidationFuture = BoxFuture<'static, BlockProcessResult<BlockStatus>>;

/// A struct returned by consensus for block validation processing calls
pub struct BlockValidationFutures {
    /// A future triggered when block processing is completed (header and body processing)
    pub block_task: BlockValidationFuture,

    /// A future triggered when DAG state which included this block has been processed by the virtual processor
    /// (exceptions are header-only blocks and trusted blocks which have the future completed before virtual
    /// processing along with the `block_task`)
    pub virtual_state_task: BlockValidationFuture,
}

/// Abstracts the consensus external API
#[allow(unused_variables)]

/// Data Transfer Object for DID Document resolution responses
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDto {
    /// Full DID identifier (e.g., "did:sahyadri:abc123...")
    pub did: String,
    /// Associated CSM blockchain address
    pub csm_address: String,
    /// Dilithium public key (hex encoded)
    pub public_key: String,
    /// DID Document JSON content
    pub document: String,
    /// Whether this DID is currently active
    pub active: bool,
    /// Version number for conflict resolution
    pub version: u64,
    /// Block timestamp when created
    pub created_at: u64,
    /// Block timestamp when last updated
    pub updated_at: u64,
}
pub trait ConsensusApi: Send + Sync {
    fn build_block_template(
        &self,
        _miner_data: MinerData,
        _tx_selector: Box<dyn TemplateTransactionSelector>,
        _build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        unimplemented!()
    }

    fn validate_and_insert_block(&self, _block: Block) -> BlockValidationFutures {
        unimplemented!()
    }

    fn validate_and_insert_trusted_block(&self, _tb: TrustedBlock) -> BlockValidationFutures {
        unimplemented!()
    }

    fn get_account_balance(&self, address: &sahyadri_addresses::Address) -> Option<u64>;

    // ============= SAHYADRI DID METHODS =============
    /// Resolve a DID document by its full DID identifier
    fn get_did_document(&self, did: &str) -> Option<DidDocumentDto>;

    /// Resolve a DID document by its associated CSM address
    fn get_did_by_address(&self, address: &str) -> Option<DidDocumentDto>;
    /// Populates the mempool transaction with maximally found UTXO entry data and proceeds to full transaction
    /// validation if all are found. If validation is successful, also `transaction.calculated_fee` is expected to be populated.
    fn validate_mempool_transaction(&self, _transaction: &mut MutableTransaction, _args: &TransactionValidationArgs) -> TxResult<()> {
        unimplemented!()
    }

    /// Populates the mempool transactions with maximally found UTXO entry data and proceeds to full transactions
    /// validation if all are found. If validation is successful, also `transaction.calculated_fee` is expected to be populated.
    fn validate_mempool_transactions_in_parallel(
        &self,
        _transactions: &mut [MutableTransaction],
        _args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        unimplemented!()
    }

    /// Populates the mempool transaction with maximally found UTXO entry data.
    fn populate_mempool_transaction(&self, _transaction: &mut MutableTransaction) -> TxResult<()> {
        unimplemented!()
    }

    /// Populates the mempool transactions with maximally found UTXO entry data.
    fn populate_mempool_transactions_in_parallel(&self, _transactions: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        unimplemented!()
    }

    fn calculate_transaction_non_contextual_masses(&self, _transaction: &Transaction) -> NonContextualMasses {
        unimplemented!()
    }

    fn calculate_transaction_contextual_masses(&self, _transaction: &MutableTransaction) -> Option<ContextualMasses> {
        unimplemented!()
    }

    /// Returns an aggregation of consensus stats. Designed to be a fast call.
    fn get_stats(&self) -> ConsensusStats {
        unimplemented!()
    }

    fn get_virtual_daa_score(&self) -> u64 {
        unimplemented!()
    }

    fn get_virtual_bits(&self) -> u32 {
        unimplemented!()
    }

    fn get_virtual_past_median_time(&self) -> u64 {
        unimplemented!()
    }

    fn get_virtual_merge_depth_root(&self) -> Option<Hash> {
        unimplemented!()
    }

    /// Returns the `BlueWork` threshold at which blocks with lower or equal blue work are considered
    /// to be un-mergeable by current virtual state.
    /// (Note: in some rare cases when the node is unsynced the function might return zero as the threshold)
    fn get_virtual_merge_depth_blue_work_threshold(&self) -> BlueWorkType {
        unimplemented!()
    }

    fn get_sink(&self) -> Hash {
        unimplemented!()
    }

    fn get_sink_timestamp(&self) -> u64 {
        unimplemented!()
    }

    fn get_sink_blue_score(&self) -> u64 {
        unimplemented!()
    }

    fn get_sink_daa_score_timestamp(&self) -> DaaScoreTimestamp {
        unimplemented!()
    }

    fn get_current_block_color(&self, _hash: Hash) -> Option<bool> {
        unimplemented!()
    }

    fn get_virtual_state_approx_id(&self) -> VirtualStateApproxId {
        unimplemented!()
    }

    /// retention period root refers to the earliest block from which the current node has full header & block data
    fn get_retention_period_root(&self) -> Hash {
        unimplemented!()
    }

    fn estimate_block_count(&self) -> BlockCount {
        unimplemented!()
    }

    /// Gets the virtual chain paths from `low` to the `sink` hash, or until `chain_path_added_limit` is reached
    ///
    /// Note:
    ///     1) `chain_path_added_limit` will populate removed fully, and then the added chain path, up to `chain_path_added_limit` amount of hashes.
    ///     1.1) use `None to impose no limit with optimized backward chain iteration, for better performance in cases where batching is not required.
    fn get_virtual_chain_from_block(&self, _low: Hash, _chain_path_added_limit: Option<usize>) -> ConsensusResult<ChainPath> {
        unimplemented!()
    }

    fn get_chain_block_samples(&self) -> Vec<DaaScoreTimestamp> {
        unimplemented!()
    }

    /// Returns the fully populated transaction with the given txid which was accepted at the provided accepting_block_daa_score.
    /// The argument `accepting_block_daa_score` is expected to be the DAA score of the accepting chain block of `txid`.
    /// Note: If the transaction vec is None, the function returns all accepted transactions.
    fn get_transactions_by_accepting_daa_score(
        &self,
        _accepting_daa_score: u64,
        _tx_ids: Option<Vec<TransactionId>>,
        _tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_transactions_by_block_acceptance_data(
        &self,
        _accepting_block: Hash,
        _block_acceptance_data: MergesetBlockAcceptanceData,
        _tx_ids: Option<Vec<TransactionId>>,
        _tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_transactions_by_accepting_block(
        &self,
        _accepting_block: Hash,
        _tx_ids: Option<Vec<TransactionId>>,
        _tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_virtual_parents(&self) -> BlockHashSet {
        unimplemented!()
    }

    fn get_virtual_parents_len(&self) -> usize {
        unimplemented!()
    }

    fn get_virtual_utxos(
        &self,
        _from_outpoint: Option<TransactionOutpoint>,
        _chunk_size: usize,
        _skip_first: bool,
    ) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        unimplemented!()
    }

    fn get_tips(&self) -> Vec<Hash> {
        unimplemented!()
    }

    fn get_tips_len(&self) -> usize {
        unimplemented!()
    }

    fn modify_coinbase_payload(&self, _payload: Vec<u8>, _miner_data: &MinerData) -> CoinbaseResult<Vec<u8>> {
        unimplemented!()
    }

    fn calc_transaction_hash_merkle_root(&self, _txs: &[Transaction]) -> Hash {
        unimplemented!()
    }

    fn validate_pruning_proof(&self, _proof: &PruningPointProof, _proof_metadata: &PruningProofMetadata) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn apply_pruning_proof(&self, _proof: PruningPointProof, _trusted_set: &[TrustedBlock]) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn import_pruning_points(&self, _pruning_points: PruningPointsList) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn append_imported_pruning_point_utxos(&self, _utxoset_chunk: &[(TransactionOutpoint, UtxoEntry)], _current_multiset: &mut MuHash) {
        unimplemented!()
    }

    fn import_pruning_point_utxo_set(&self, _new_pruning_point: Hash, _imported_utxo_multiset: MuHash) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn is_chain_ancestor_of(&self, _low: Hash, _high: Hash) -> ConsensusResult<bool> {
        unimplemented!()
    }

    fn get_hashes_between(&self, _low: Hash, _high: Hash, _max_blocks: usize) -> ConsensusResult<(Vec<Hash>, Hash)> {
        unimplemented!()
    }

    fn get_header(&self, _hash: Hash) -> ConsensusResult<Arc<Header>> {
        unimplemented!()
    }

    fn get_headers_selected_tip(&self) -> Hash {
        unimplemented!()
    }

    /// Returns the antipast of block `hash` from the POV of `context`, i.e. `antipast(hash) ∩ past(context)`.
    /// Since this might be an expensive operation for deep blocks, we allow the caller to specify a limit
    /// `max_traversal_allowed` on the maximum amount of blocks to traverse for obtaining the answer
    fn get_antipast_from_pov(&self, _hash: Hash, _context: Hash, _max_traversal_allowed: Option<u64>) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    /// Returns the anticone of block `hash` from the POV of `virtual`
    fn get_anticone(&self, _hash: Hash) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn get_pruning_point_proof(&self) -> Arc<PruningPointProof> {
        unimplemented!()
    }

    fn create_virtual_selected_chain_block_locator(&self, _low: Option<Hash>, _high: Option<Hash>) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn create_block_locator_from_pruning_point(&self, _high: Hash, _limit: usize) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn pruning_point_headers(&self) -> Vec<Arc<Header>> {
        unimplemented!()
    }

    fn get_pruning_point_anticone_and_trusted_data(&self) -> ConsensusResult<Arc<PruningPointTrustedData>> {
        unimplemented!()
    }

    fn get_block(&self, _hash: Hash) -> ConsensusResult<Block> {
        unimplemented!()
    }

    fn get_block_transactions(&self, _hash: Hash, _indices: Option<Vec<TransactionIndexType>>) -> ConsensusResult<Vec<Transaction>> {
        unimplemented!()
    }

    fn get_block_body(&self, _hash: Hash) -> ConsensusResult<Arc<Vec<Transaction>>> {
        unimplemented!()
    }

    fn get_block_even_if_header_only(&self, _hash: Hash) -> ConsensusResult<Block> {
        unimplemented!()
    }

    fn get_sahyadri_consensus_data(&self, _hash: Hash) -> ConsensusResult<ExternalSahyadriConsensusData> {
        unimplemented!()
    }

    fn get_block_children(&self, _hash: Hash) -> Option<Vec<Hash>> {
        unimplemented!()
    }

    fn get_block_parents(&self, _hash: Hash) -> Option<Arc<Vec<Hash>>> {
        unimplemented!()
    }

    fn get_block_status(&self, _hash: Hash) -> Option<BlockStatus> {
        unimplemented!()
    }

    fn get_block_acceptance_data(&self, _hash: Hash) -> ConsensusResult<Arc<AcceptanceData>> {
        unimplemented!()
    }

    /// Returns acceptance data for a set of blocks belonging to the selected parent chain.
    ///
    /// See `self::get_virtual_chain`
    fn get_blocks_acceptance_data(
        &self,
        _hashes: &[Hash],
        _merged_blocks_limit: Option<usize>,
    ) -> ConsensusResult<Vec<Arc<AcceptanceData>>> {
        unimplemented!()
    }

    fn is_chain_block(&self, _hash: Hash) -> ConsensusResult<bool> {
        unimplemented!()
    }

    fn get_pruning_point_utxos(
        &self,
        _expected_pruning_point: Hash,
        _from_outpoint: Option<TransactionOutpoint>,
        _chunk_size: usize,
        _skip_first: bool,
    ) -> ConsensusResult<Vec<(TransactionOutpoint, UtxoEntry)>> {
        unimplemented!()
    }

    fn get_missing_block_body_hashes(&self, _high: Hash) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }
    fn get_body_missing_anticone(&self) -> Vec<Hash> {
        unimplemented!()
    }
    fn clear_body_missing_anticone_set(&self) {
        unimplemented!()
    }

    fn pruning_point(&self) -> Hash {
        unimplemented!()
    }

    fn estimate_network_hashes_per_second(&self, _start_hash: Option<Hash>, _window_size: usize) -> ConsensusResult<u64> {
        unimplemented!()
    }

    fn validate_pruning_points(&self, _syncer_virtual_selected_parent: Hash) -> ConsensusResult<()> {
        unimplemented!()
    }

    fn are_pruning_points_violating_finality(&self, _pp_list: PruningPointsList) -> bool {
        unimplemented!()
    }

    fn creation_timestamp(&self) -> u64 {
        unimplemented!()
    }

    fn finality_point(&self) -> Hash {
        unimplemented!()
    }

    fn clear_pruning_utxo_set(&self) {
        unimplemented!()
    }

    fn set_pruning_utxoset_stable_flag(&self, _val: bool) {
        unimplemented!()
    }

    fn is_pruning_utxoset_stable(&self) -> bool {
        unimplemented!()
    }

    fn is_pruning_point_anticone_fully_synced(&self) -> bool {
        unimplemented!()
    }

    fn is_consensus_in_transitional_ibd_state(&self) -> bool {
        unimplemented!()
    }

    fn intrusive_pruning_point_update(&self, _new_pruning_point: Hash, _syncer_sink: Hash) -> ConsensusResult<()> {
        unimplemented!()
    }

    /// Returns the n most recent pruning points (including the current pruning point)
    fn get_n_last_pruning_points(&self, _n: usize) -> Vec<Hash> {
        unimplemented!()
    }
}

pub type DynConsensus = Arc<dyn ConsensusApi>;
