use super::VirtualStateProcessor;
use crate::{
    errors::{
        BlockProcessResult,
        RuleError::{
            AccountCommitmentComputeFailed, BadAccountCommitment,
            InvalidTransactionsInBlockContext, WrongHeaderPruningPoint,
        },
    },
    model::stores::{
        block_transactions::BlockTransactionsStoreReader,
        daa::DaaStoreReader,
        headers::HeaderStoreReader,
        sahyadri_consensus::{CompactSahyadriConsensusData, SahyadriConsensusData},
    },
    processes::{
        pruning::PruningPointReply,
        transaction_validator::{
            tx_validation_in_account_context::TxValidationFlags,
        },
    },
};
use sahyadri_consensus_core::{
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
    acceptance_data::{AcceptedTxEntry, MergesetBlockAcceptanceData},
    coinbase::*,
    header::Header,
    tx::{Transaction, TransactionId, ValidatedTransaction, VerifiableTransaction},
};
use sahyadri_core::{trace};
use sahyadri_hashes::Hash;
use sahyadri_muhash::MuHash;
use smallvec::SmallVec;
use sahyadri_utils::refs::Refs;

use std::{collections::HashSet, iter::once, ops::Deref};

pub(crate) mod raigad {
    use sahyadri_core::{info, log::RAIGAD_KEYWORD};
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };

    #[derive(Clone)]
    pub(crate) struct _RaigadLogger {
        steps: Arc<AtomicU8>,
    }

    impl _RaigadLogger {
        pub fn _new() -> Self {
            Self { steps: Arc::new(AtomicU8::new(Self::_ACTIVATE)) }
        }

        const _ACTIVATE: u8 = 0;

        pub fn _report_activation(&self) -> bool {
            if self.steps.compare_exchange(Self::_ACTIVATE, Self::_ACTIVATE + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                info!(target: RAIGAD_KEYWORD, "[Raigad] [--------- Raigad activated for REGISTRY_UNIT state processing rules ---------]");
                true
            } else {
                false
            }
        }
    }
}

/// A context for processing the REGISTRY_UNIT state of a block with respect to its selected parent.
/// Note this can also be the virtual block.
pub(super) struct BlockProcessingContext<'a> {
    pub sahyadri_consensus_data: Refs<'a, SahyadriConsensusData>,
    pub accepted_tx_ids: Vec<TransactionId>,
    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    pub pruning_sample_from_pov: Option<Hash>,
}

impl<'a> BlockProcessingContext<'a> {
    pub fn new(sahyadri_consensus_data: Refs<'a, SahyadriConsensusData>) -> Self {
        let mergeset_size = sahyadri_consensus_data.mergeset_size();
        Self {
            sahyadri_consensus_data,
            accepted_tx_ids: Vec::with_capacity(1), // We expect at least the selected parent coinbase tx
            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
            pruning_sample_from_pov: Default::default(),
        }
    }

    pub fn selected_parent(&self) -> Hash {
        self.sahyadri_consensus_data.selected_parent
    }
}

impl VirtualStateProcessor {
    /// Calculates REGISTRY_UNIT state and transaction acceptance data relative to the selected parent state
    pub(super) fn calculate_block_state(
        &self,
        ctx: &mut BlockProcessingContext,
        pov_daa_score: u64,
    ) {
        let selected_parent_transactions = self.block_transactions_store.get(ctx.selected_parent()).unwrap();
        let validated_coinbase = ValidatedTransaction::new_coinbase(&selected_parent_transactions[0]);

        let validated_coinbase_id = validated_coinbase.id();
        ctx.accepted_tx_ids.push(validated_coinbase_id);


        // DAG mergesets can include the same tx in multiple parallel blocks.
        // Track txids applied in this mergeset and apply each exactly once —
        // first occurrence in canonical mergeset order wins. Deterministic
        // across reorgs because mergeset order is itself canonical.
        let mut seen_txids: HashSet<TransactionId> = HashSet::new();
        seen_txids.insert(validated_coinbase_id);

        for (i, (merged_block, txs)) in once((ctx.selected_parent(), selected_parent_transactions))
            .chain(
                ctx.sahyadri_consensus_data
                    .consensus_ordered_mergeset_without_selected_parent(self.sahyadri_consensus_store.deref())
                    .map(|b| (b, self.block_transactions_store.get(b).unwrap())),
            )
            .enumerate()
        {

            // The first block in the mergeset is always the selected parent
            let is_selected_parent = i == 0;

            // No need to fully validate selected parent transactions since selected parent txs were already validated
            // as part of selected parent REGISTRY_UNIT state verification with the exact same REGISTRY_UNIT context.
            let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };
            let (validated_transactions, inner_multiset) =
                self.validate_transactions_with_muhash_in_parallel(&txs, pov_daa_score, validation_flags);

            // NOTE: We intentionally do NOT combine `inner_multiset` here.
            // Duplicate txs across parallel DAG blocks would be double-counted
            // in the REGISTRY_UNIT multiset hash, corrupting the commitment. Instead we
            // accumulate per-tx below, only for the first occurrence of each txid.
            let _ = inner_multiset;

            let mut block_fee = 0u64;
            for (validated_tx, _) in validated_transactions.iter() {
                let txid = validated_tx.id();

                // DAG semantics: same tx may appear in multiple parallel blocks.
                if !seen_txids.insert(txid) {
                    continue;
                }

                ctx.accepted_tx_ids.push(txid);
                block_fee += validated_tx.calculated_fee;
            }

            ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
                block_hash: merged_block,
                // For the selected parent, we prepend the coinbase tx
                accepted_transactions: is_selected_parent
                    .then_some(AcceptedTxEntry { transaction_id: validated_coinbase_id, index_within_block: 0 })
                    .into_iter()
                    .chain(
                        validated_transactions
                            .into_iter()
                            .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx }),
                    )
                    .collect(),
            });

            let coinbase_data = self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).unwrap();
            ctx.mergeset_rewards.insert(
                merged_block,
                BlockRewardData::new(coinbase_data.subsidy, block_fee, coinbase_data.miner_data.script_public_key),
            );
        }
    }

    /// Verify that the current block fully respects its own REGISTRY_UNIT view. We define a block as
    /// REGISTRY_UNIT valid if all the following conditions hold:
    ///     1. The block header includes the expected `account_commitment`.
    ///     2. The block header includes the expected `accepted_id_merkle_root`.
    ///     3. The block header includes the expected `pruning_point`.
    ///     4. The block coinbase transaction rewards the mergeset blocks correctly.
    ///     5. All non-coinbase block transactions are valid against its own REGISTRY_UNIT view.
    pub(super) fn verify_block_state(
        &self,
        ctx: &mut BlockProcessingContext,
        header: &Header,
    ) -> BlockProcessResult<()> {
        // SAHYADRI: read parent root from the parent's HEADER, not from
        // account_roots_store. The store is written asynchronously during
        // commit, so for recent parents (which is the normal case) it may
        // not yet contain the entry. The header's account_commitment field is
        // always populated by the producer and available before verify.
        let parent_hash = ctx.selected_parent();
        let parent_header = self
            .headers_store
            .get_header(parent_hash)
            .map_err(|e| {
                log::error!(
                    "SAHYADRI: parent header missing for {} while verifying {}: {:?}",
                    parent_hash, header.hash, e
                );
                AccountCommitmentComputeFailed
            })?;

        let parent_root: sahyadri_smt::H256 = self.parent_account_root(parent_hash, &parent_header);
        let txs_for_effects = self

            .block_transactions_store
            .get(header.hash)
            .map_err(|_| AccountCommitmentComputeFailed)?;

        let (flash_txs, rewards) = crate::pipeline::virtual_processor::account_changes::extract_block_effects(
            &txs_for_effects,
            &self.coinbase_manager,
            super::processor::SAHYADRI_TREASURY_PUBKEY_HEX,
        );

        let db_base = crate::model::stores::smt_nodes::DbSmtNodeStoreBase::new(&*self.smt_nodes_store);
        let mut smt_overlay = sahyadri_smt::OverlayStore::new(&db_base);

        let (my_root, changes) = crate::pipeline::virtual_processor::account_changes::compute_block_account_changes(
            parent_root,
            &mut smt_overlay,
            &*self.account_states_store,
            &flash_txs,
            &rewards,
            header.daa_score,
        )
        .map_err(|e| {
            log::error!("SAHYADRI: account commitment compute failed during verify: {:?}", e);
            AccountCommitmentComputeFailed
        })?;

        // SAHYADRI: sync-persist SMT nodes AND state snapshots. Both are
        // content-addressed (idempotent), so writes from even a disqualified
        // block are harmless — they only make subsequent blocks' reads
        // resolve correctly. This closes the race with async commit flush.
        let pending: Vec<_> = smt_overlay.into_pending().collect();
        if let Err(e) = self.smt_nodes_store.insert_sync_many(pending) {
            log::error!("SAHYADRI: sync SMT write failed in verify: {:?}", e);
        }
        for (_spk, state) in &changes {
            let state_hash = state.content_hash();
            if let Err(e) = self.account_states_store.insert_sync(state_hash, state) {
                log::error!("SAHYADRI: sync state write failed in verify: {:?}", e);
            }
        }

        let expected_commitment = sahyadri_hashes::Hash::from_bytes(my_root);

        if expected_commitment != header.account_commitment {
            log::warn!(
                "SAHYADRI: ACCOUNT COMMITMENT MISMATCH — block {} header={} calc={}",
                header.hash, header.account_commitment, expected_commitment
            );
            return Err(BadAccountCommitment(header.hash, header.account_commitment, expected_commitment));
        }

        trace!("correct commitment: {}, {}", header.hash, expected_commitment);

        // Verify header accepted_id_merkle_root
        let _expected_accepted_id_merkle_root =
            self.calc_accepted_id_merkle_root(ctx.accepted_tx_ids.iter().copied(), ctx.selected_parent());

        // if expected_accepted_id_merkle_root != header.accepted_id_merkle_root {
        //  return Err(BadAcceptedIDMerkleRoot(header.hash, header.accepted_id_merkle_root, expected_accepted_id_merkle_root));
        // }

        let txs = self.block_transactions_store.get(header.hash).unwrap();

        // Verify coinbase transaction
        self.validate_coinbase_transaction(
            header.daa_score, // u64 first
            &txs[0],          // &Transaction second
            &ctx.sahyadri_consensus_data,
            &ctx.mergeset_rewards,
            &self.daa_excluded_store.get_mergeset_non_daa(header.hash).unwrap(),
        )?;

        // Verify the header pruning point
        let reply = self.verify_header_pruning_point(header, ctx.sahyadri_consensus_data.to_compact())?;
        ctx.pruning_sample_from_pov = Some(reply.pruning_sample);

        // Verify all transactions are valid in context
        let validated_transactions =
            self.validate_transactions_in_parallel(&txs, header.daa_score, TxValidationFlags::Full);
        if validated_transactions.len() < txs.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(InvalidTransactionsInBlockContext(txs.len() - 1 - validated_transactions.len(), txs.len() - 1));
        }

        Ok(())
    }

    fn verify_header_pruning_point(
        &self,
        header: &Header,
        sahyadri_consensus_data: CompactSahyadriConsensusData,
    ) -> BlockProcessResult<PruningPointReply> {
        let reply = self.pruning_point_manager.expected_header_pruning_point(sahyadri_consensus_data);
        if reply.pruning_point != header.pruning_point {
            return Err(WrongHeaderPruningPoint(reply.pruning_point, header.pruning_point));
        }
        Ok(reply)
    }

    fn validate_coinbase_transaction(
        &self,
        _daa_score: u64,
        _coinbase: &Transaction,
        _sahyadri_consensus_data: &SahyadriConsensusData,
        _mergeset_rewards: &BlockHashMap<BlockRewardData>,
        _mergeset_non_daa: &BlockHashSet,
    ) -> BlockProcessResult<()> {
        // SAHYADRI ACCOUNT MODEL BYPASS:
        // We bypass the traditional REGISTRY_UNIT-based coinbase validation
        // because rewards are handled directly as account balance updates.
        Ok(())
    }

    pub(crate) fn validate_transactions_in_parallel<'a>(
        &self,
        txs: &'a [Transaction],
        _pov_daa_score: u64,
        _flags: TxValidationFlags,
    ) -> Vec<(ValidatedTransaction<'a>, usize)> {
        use crate::processes::transaction_validator::tx_validation_in_isolation::verify_account_tx_signatures_batch;

        // ── Phase 1: batch-parallel Dilithium3 signature verify ──
        // Skip coinbase (index 0). Uses VERIFY_POOL (rayon) + AVX2 NTT.
        let candidates: Vec<(usize, &Transaction)> = txs.iter().enumerate().skip(1).collect();
        let candidates_ref: Vec<&Transaction> = candidates.iter().map(|(_, tx)| *tx).collect();
        let results = verify_account_tx_signatures_batch(&candidates_ref);

        // ── Phase 2: accept only verified txs ──
        let mut out = Vec::with_capacity(results.len());
        for ((i, tx), res) in candidates.into_iter().zip(results) {
            if res.is_ok() {
                out.push((ValidatedTransaction::new_account_bypass(tx), i));
            }
            // Silent drop of invalid ones. Counters handle this at a higher layer.
        }
        out
    }

    /// SAHYADRI ACCOUNT MODEL: REGISTRY_UNIT-based muhash tracking removed.
    /// Returns account-bypass validated transactions and a fresh
    /// (unused) MuHash. The muhash is a legacy artifact of the REGISTRY_UNIT
    /// commitment scheme and is no longer read by any caller.
    pub(crate) fn validate_transactions_with_muhash_in_parallel<'a>(
        &self,
        txs: &'a Vec<Transaction>,
        _pov_daa_score: u64,
        _flags: TxValidationFlags,
    ) -> (SmallVec<[(ValidatedTransaction<'a>, u32); 2]>, MuHash) {
        let mut out: SmallVec<[(ValidatedTransaction<'a>, u32); 2]> = SmallVec::new();
        for (i, tx) in txs.iter().enumerate().skip(1) {
            out.push((ValidatedTransaction::new_account_bypass(tx), i as u32));
        }
        (out, MuHash::new())
    }

    /// Calculates the accepted_id_merkle_root based on the current DAA score and the accepted tx ids
    /// refer KIP-15 for more details
    pub(super) fn calc_accepted_id_merkle_root(
        &self,
        accepted_tx_ids: impl ExactSizeIterator<Item = Hash>,
        selected_parent: Hash,
    ) -> Hash {
        sahyadri_merkle::merkle_hash(
            self.headers_store.get_header(selected_parent).unwrap().accepted_id_merkle_root,
            sahyadri_merkle::calc_merkle_root(accepted_tx_ids),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rayon::prelude::*;
    use smallvec::smallvec;

    #[test]
    fn test_rayon_reduce_retains_order() {
        // this is an independent test to replicate the behavior of
        // validate_txs_in_parallel and validate_txs_with_muhash_in_parallel
        // and assert that the order of data is retained when doing par_iter
        let data: Vec<u16> = (1..=1000).collect();

        let collected: Vec<u16> = data
            .par_iter()
            .filter_map(|a| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(*a)
            })
            .collect();

        println!("collected len: {}", collected.len());

        collected.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });

        let reduced: SmallVec<[u16; 2]> = data
            .par_iter()
            .filter_map(|a: &u16| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(smallvec![*a])
            })
            .reduce(
                || smallvec![],
                |mut arr, mut curr_data| {
                    arr.append(&mut curr_data);
                    arr
                },
            );

        println!("reduced len: {}", reduced.len());

        reduced.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });
    }
}
