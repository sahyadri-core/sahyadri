// SAHYADRI: DID support
use crate::{
    consensus::{
        services::{
            ConsensusServices, DbBlockDepthManager, DbDagTraversalManager, DbParentsManager, DbPruningPointManager,
            DbSahyadriConsensusManager, DbWindowManager,
        },
        storage::ConsensusStorage,
    },
    constants::BLOCK_VERSION,
    errors::RuleError,
    model::{
        services::{
            reachability::{MTReachabilityService, ReachabilityService},
            relations::MTRelationsService,
        },
        stores::{
            DB,
            acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore},
            account_store::{AccountStore, AccountStoreReader, DbAccountStore},
            did_store::{DidDocument, DidStore, DidStoreReader, DbDidStore},
            block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore},
            block_window_cache::{BlockWindowCacheStore, BlockWindowCacheWriter},
            daa::DbDaaStore,
            depth::{DbDepthStore, DepthStoreReader},
            headers::{DbHeadersStore, HeaderStoreReader},
            past_pruning_points::DbPastPruningPointsStore,
            pruning::{DbPruningStore, PruningStoreReader},
            pruning_meta::PruningMetaStores,
            pruning_samples::DbPruningSamplesStore,
            reachability::DbReachabilityStore,
            relations::{DbRelationsStore, RelationsStoreReader},
            sahyadri_consensus::{DbSahyadriConsensusStore, SahyadriConsensusData, SahyadriConsensusStoreReader},
            selected_chain::{DbSelectedChainStore, SelectedChainStore},
            statuses::{DbStatusesStore, StatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            tips::{DbTipsStore, TipsStoreReader},
            utxo_diffs::{DbUtxoDiffsStore, UtxoDiffsStoreReader},
            utxo_multisets::{DbUtxoMultisetsStore, UtxoMultisetsStoreReader},
            virtual_state::{LkgVirtualState, VirtualState, VirtualStateStoreReader, VirtualStores},
        },
    },
    params::Params,
    pipeline::{
        ProcessingCounters, deps_manager::VirtualStateProcessingMessage, pruning_processor::processor::PruningProcessingMessage,
        virtual_processor::utxo_validation::UtxoProcessingContext,
    },
    processes::{
        coinbase::CoinbaseManager,
        sahyadri_consensus::ordering::SortableBlock,
        transaction_validator::{TransactionValidator, errors::TxResult, tx_validation_in_account_context::TxValidationFlags},
        window::WindowManager,
    },
};
use once_cell::unsync::Lazy;
// ═══════════════════════════════════════════════════════
// PARALLEL VERIFICATION (Rayon + AVX2 for High TPS)
// ═══════════════════════════════════════════════════════
use std::sync::LazyLock;
use num_cpus;

/// Global thread pool for parallel Dilithium3 signature verification
static VERIFY_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads((num_cpus::get() - 1).max(1))
        .thread_name(|idx| format!("sahyadri-sigverify-{idx}"))
        .build()
        .expect("Failed to create Sahyadri verification thread pool")
});
use sahyadri_consensus_core::{
    BlockHashSet, ChainPath,
    acceptance_data::AcceptanceData,
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockstatus::BlockStatus::{StatusDisqualifiedFromChain, StatusUTXOValid},
    coinbase::MinerData,
    config::genesis::GenesisBlock,
    header::Header,
    merkle::calc_hash_merkle_root,
    mining_rules::MiningRules,
    pruning::PruningPointsList,
    tx::{MutableTransaction, Transaction},
    utxo::{utxo_diff::UtxoDiff, utxo_view::UtxoView},
};
use sahyadri_consensus_notify::{
    notification::{
        NewBlockTemplateNotification, Notification, SinkBlueScoreChangedNotification, UtxosChangedNotification,
        VirtualChainChangedNotification, VirtualDaaScoreChangedNotification,
    },
    root::ConsensusNotificationRoot,
};
use sahyadri_consensusmanager::SessionLock;
use sahyadri_core::{debug, info, time::unix_now, trace, warn};
use sahyadri_database::prelude::{StoreError, StoreResultExt, StoreResultUnitExt};
use sahyadri_dilithium::{DilithiumKeyPair, DilithiumSignature, PUBKEY_SIZE, SAHYADRI_MODE, SIG_SIZE};

// TODO: Replace with treasury Dilithium pubkey hex (1952 bytes = 3904 hex chars)
// Until set, 100% reward goes to miner
const SAHYADRI_TREASURY_PUBKEY_HEX: &str = "2d980235b2e054a227bed91b20bad2592859ec1581c1b3fa9c494c5138f058195202e59335416cf6c650dd1dc5e53479e1f7d815c147ab0990bee8bb7a57dd43ef87484d656760888f68ca40d220d3256bc76a0acb109e47056976c45bfbc80992e0a6f6626f9318cf0b940cdbcb38f9850ad60e345f968fd0229099adc4e4d12abc40762f2ad711f4edcd1daa4e144a9f5b3275ea97c0d64d3fb607d2868cceb91fa1bcacf981e29051f63811eed7ca941a3e0e00dca6892608f8bb8ceeed22c5839adeac8b856cd942b2f0ec0e3b88c4fbbb40ce581c0ef3dde590081b970f7d952de92a4fa80fa5ae92f31ca69b6d8c51b70cfa453083516ed8df8e50ff60a7fa88fd092be563fd3b1bd239e5e0a85bb18039b6350d27b2665684aad09faa7f3703e9d49fa658a3b338aadb43755c5f4322acd27f314ff59bd3fbaad0c0e4b3231a04ddeabd7165f4609a63af2e69f84df36c6a56a50cc93b4d9d6579315ef11dc297b96923daf177262981821429c4296a2f9d8d79ad06ba866ca95b2b51e0b766402e4619387ea770e2a67d725df18aa552bf84dbf2ea3aaf567df880041e01257e81855fff92afd48c5cba600703ceaf25bccf5f2b487a8cb46ac721bfc157910e39e5d4579b7a03daf1cb0b91a20f15306dfd7730d9c9e86e4805d11545d912e388fb533368cc0877a719791033929d9020e35bc11bd7cd4837cdb6b75437235fb65c7e0c6759c51d25c2d12ff56cc2603d393bbe71198f1b48cff60dc7d263fc5cc2a39f2c446cb4548ae42956fdd1aa787ce7515f5050d6a46c29aae3d053caa63b3faf2fe6e25b6b0d004520be02629ff93c9252dbda7f086c1316a7d6a3f08fd2fbfbae7d658120864395fcd76dd37c88ec9fdfc464117fdffec3fff90c17c81f3f43dcf94cb08cc30116c8b1748affd4648530609e2db1092684990f4391ad7f4623b22d86061959ff624a1c0d25a09b2e90052a59a4cce059861f4dae7651cd5abf0921e8aff1035eb62792e1df3388bebc24ebd290df0629907c1f4a39b6464369b785960d41568103b615e612d5eacf589f6aa856de4721a1870baae1e17d0224f3c584a1e971f54c54f48725399bac72cf77beda2a09e1ebb94dd718188f4adeeb3706c12245fe196f15dfae8c2b399bbc336cebaefe2829ae2bba13ef00cdb3d2ccfdc683a71e80696fd94b2ab4b670c49ca1d0138fece2d66a30f90fcdd79d16506846a4b24a49e5d02a04ddc9c6e5417083d911443c2b7a3f27f20a16702806598a6894571b9bbddd29b084210b31b7d1dbb6cab1153b926d524ec11d962bc2bfd52ba5876ff12520db879e938fd637fc4d85e1b793ead8c441f5b7b1cf8999aa434e1126844e593a59d301405ac55020c3832e0b7cdf0ea59e9d5025b6c2b63b7664246ee0237c6b3f1a8b704e41257fc37e5c883cf354e994d45b5e18443219df5eb853009a9c2ca179536d5fc668560a6bc0d840fd7e14caf8740c27894c52be062d8b9a8f8d836c472405b891101bb16e04d36d64acdf6919a8261d56ffd161717725ba28ff86e718d87e68a6d1f8f7876eee50e7a3d6a80e3a6a2829cf92a600f6915db9cf528693c24927283d40974ded9a5782203e4b84c15e1a4172066ed013780bceaf1007a4fcb1bd2e9b962ee1868968f6a45057d5bb6d2b46d61ccd914a63cbc4f3e92452566c97902e9ab7c10fcb15074f339eb55251f9299b39630c4a945399704846e3a997efa7f8e05595cec9285c4db39b2d8f7b552eb305a5db339e962ff319072f3878874d589f6ee81c8f23bc888738801317adec5930266ab609d6bed62fb195a7a3c199c367258e4fed5a32a6b3a96f5bb0945908871983a8fae8e2a0438a462043ca21a524d09f1ee763e8a98d48ae74125059cef889ab7b0a406c1823be6c5bca56e26e951588ee3e91497fb12ec50b2a8ed0444d219790628c5abcea0275884e39c943305b596cabfac5b5c81fbd393165ed89b0affb61d95051784943f7b944ea199eebc5e3d83bf67a873762a37812ccdbc82cfdca1c1fe29d8bbde8d67a44d10168600105c3b9c2726c158070b4a9fedbb4aa9dd3993e2f0e72ce78422636b32089d3e3d68cd23dbcc7388f3a3ab2b9bd8d75628a2ad568f08e51b0115fa9d954cd4268e5e693dcd3145400aaa1514e4a45d3672c18a07712c97ffde07c81c2de29e046bfdbfcd37c719eb02ed656dea808c885c61c0f822685f965283f9cdc4609f00b1e05ed7ae7e65d89d16772da4ce4b177d0c7ae6d81550f33c580b4c94a9911f17de4449068903ad9f2738fcd686967e9c2ac647ff46d376a6ce0fdef8dbb7dae4ddfcd9c6cefd106b1f3ff76ecac2aee84c7c8b5be663dee91766d60253732e156993b9d24a3a36c30fb596ffa1dcf8a728662f5b51dacf69e0c03d74aed62a9ffb76f8c55c772249b22ca904d8efddc122fa5f822c258e5e4b3cff7e0574dd2cedf5e8c78708b69e9e78518ce2f04b0fcc1e537902126f41ec8f636b7dff9158327819658d1d8a82d6b13127d1abbaa17b5b85cfb1218ca68bf939bf8354869ddd68a088cafca0a3a0a1c377fd6692bbfd792eb5d39f33226ab87a4f67d548191bb8e57c66f2ae2ea09673441fb2e27b68226382da98314facfca9d1313939acdc98271c2faec100b02ba5b05a63a44cf03ec8b4f12a5aa7d78c438d3f87bfa60e7231b2baf2adb7ddf32cfdb3c0788acc468780134e5727471fe07f870a682633f3fbae7";
use sahyadri_hashes::{Hash, ZERO_HASH};
use sahyadri_muhash::MuHash;
use sahyadri_notify::{events::EventType, notifier::Notify};
use sha2::{Digest, Sha256};

use super::errors::{PruningImportError, PruningImportResult};
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use itertools::Itertools;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use rand::{Rng, seq::SliceRandom};
use rayon::{
    ThreadPool,
    prelude::{IntoParallelRefMutIterator, ParallelIterator},
};
use rocksdb::WriteBatch;
use sahyadri_utils::binary_heap::BinaryHeapExtensions;
use std::{
    cmp::min,
    collections::{BinaryHeap, HashMap, VecDeque},
    ops::Deref,
    sync::{Arc, atomic::Ordering},
};

pub struct VirtualStateProcessor {
    // Channels
    receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
    pruning_sender: CrossbeamSender<PruningProcessingMessage>,
    pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // DB
    db: Arc<DB>,

    // Config
    pub(super) genesis: GenesisBlock,
    pub(super) max_block_parents: u8,
    pub(super) mergeset_size_limit: u64,

    // Stores
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) sahyadri_consensus_store: Arc<DbSahyadriConsensusStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) daa_excluded_store: Arc<DbDaaStore>,
    pub(super) block_transactions_store: Arc<DbBlockTransactionsStore>,
    pub(super) pruning_point_store: Arc<RwLock<DbPruningStore>>,
    pub(super) past_pruning_points_store: Arc<DbPastPruningPointsStore>,
    pub(super) body_tips_store: Arc<RwLock<DbTipsStore>>,
    pub(super) depth_store: Arc<DbDepthStore>,
    pub(super) selected_chain_store: Arc<RwLock<DbSelectedChainStore>>,
    pub(super) pruning_samples_store: Arc<DbPruningSamplesStore>,

    // Utxo-related stores
    pub(super) utxo_diffs_store: Arc<DbUtxoDiffsStore>,
    pub(super) utxo_multisets_store: Arc<DbUtxoMultisetsStore>,
    pub(super) acceptance_data_store: Arc<DbAcceptanceDataStore>,
    pub(super) account_store: Arc<DbAccountStore>,
    pub(super) did_store: Arc<DbDidStore>,
    pub(super) virtual_stores: Arc<RwLock<VirtualStores>>,
    pub(super) pruning_meta_stores: Arc<RwLock<PruningMetaStores>>,

    /// The "last known good" virtual state. To be used by any logic which does not want to wait
    /// for a possible virtual state write to complete but can rather settle with the last known state
    pub lkg_virtual_state: LkgVirtualState,

    // Managers and services
    pub(super) sahyadri_consensus_manager: DbSahyadriConsensusManager,
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) relations_service: MTRelationsService<DbRelationsStore>,
    pub(super) dag_traversal_manager: DbDagTraversalManager,
    pub(super) window_manager: DbWindowManager,
    pub(super) coinbase_manager: CoinbaseManager,
    pub(super) transaction_validator: TransactionValidator,
    pub(super) pruning_point_manager: DbPruningPointManager,
    pub(super) parents_manager: DbParentsManager,
    pub(super) depth_manager: DbBlockDepthManager,

    // block window caches
    pub(super) block_window_cache_for_difficulty: Arc<BlockWindowCacheStore>,
    pub(super) block_window_cache_for_past_median_time: Arc<BlockWindowCacheStore>,

    // Pruning lock
    pub(super) pruning_lock: SessionLock,

    // Notifier
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    counters: Arc<ProcessingCounters>,

    // Mining Rule
    _mining_rules: Arc<MiningRules>,
}

impl VirtualStateProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
        pruning_sender: CrossbeamSender<PruningProcessingMessage>,
        pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,
        thread_pool: Arc<ThreadPool>,
        params: &Params,
        db: Arc<DB>,
        storage: &Arc<ConsensusStorage>,
        services: &Arc<ConsensusServices>,
        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
        mining_rules: Arc<MiningRules>,
    ) -> Self {
        Self {
            receiver,
            pruning_sender,
            pruning_receiver,
            thread_pool,

            genesis: params.genesis.clone(),
            max_block_parents: params.max_block_parents(),
            mergeset_size_limit: params.mergeset_size_limit(),

            db,
            statuses_store: storage.statuses_store.clone(),
            headers_store: storage.headers_store.clone(),
            sahyadri_consensus_store: storage.sahyadri_consensus_store.clone(),
            daa_excluded_store: storage.daa_excluded_store.clone(),
            block_transactions_store: storage.block_transactions_store.clone(),
            pruning_point_store: storage.pruning_point_store.clone(),
            past_pruning_points_store: storage.past_pruning_points_store.clone(),
            body_tips_store: storage.body_tips_store.clone(),
            depth_store: storage.depth_store.clone(),
            selected_chain_store: storage.selected_chain_store.clone(),
            pruning_samples_store: storage.pruning_samples_store.clone(),
            utxo_diffs_store: storage.utxo_diffs_store.clone(),
            utxo_multisets_store: storage.utxo_multisets_store.clone(),
            acceptance_data_store: storage.acceptance_data_store.clone(),
            account_store: storage.account_store.clone(),
            did_store: storage.did_store.clone(),
            virtual_stores: storage.virtual_stores.clone(),
            pruning_meta_stores: storage.pruning_meta_stores.clone(),
            lkg_virtual_state: storage.lkg_virtual_state.clone(),

            block_window_cache_for_difficulty: storage.block_window_cache_for_difficulty.clone(),
            block_window_cache_for_past_median_time: storage.block_window_cache_for_past_median_time.clone(),

            sahyadri_consensus_manager: services.sahyadri_consensus_manager.clone(),
            reachability_service: services.reachability_service.clone(),
            relations_service: services.relations_service.clone(),
            dag_traversal_manager: services.dag_traversal_manager.clone(),
            window_manager: services.window_manager.clone(),
            coinbase_manager: services.coinbase_manager.clone(),
            transaction_validator: services.transaction_validator.clone(),
            pruning_point_manager: services.pruning_point_manager.clone(),
            parents_manager: services.parents_manager.clone(),
            depth_manager: services.depth_manager.clone(),

            pruning_lock,
            notification_root,
            counters,
            _mining_rules: mining_rules,
        }
    }

    pub fn worker(self: &Arc<Self>) {
        'outer: while let Ok(msg) = self.receiver.recv() {
            if msg.is_exit_message() {
                break;
            }

            // Once a task arrived, collect all pending tasks from the channel.
            // This is done since virtual processing is not a per-block
            // operation, so it benefits from max available info

            let messages: Vec<VirtualStateProcessingMessage> = std::iter::once(msg).chain(self.receiver.try_iter()).collect();
            trace!("virtual processor received {} tasks", messages.len());

            self.resolve_virtual();

            let statuses_read = self.statuses_store.read();
            for msg in messages {
                match msg {
                    VirtualStateProcessingMessage::Exit => break 'outer,
                    VirtualStateProcessingMessage::Process(task, virtual_state_result_transmitter) => {
                        // We don't care if receivers were dropped
                        let status = match statuses_read.get(task.block().hash()).optional() {
                            Ok(Some(s)) => s,
                            _ => {
                                continue;
                            }
                        };
                        let _ = virtual_state_result_transmitter.send(Ok(status));
                    }
                };
            }
        }

        // Pass the exit signal on to the following processor
        if let Err(e) = self.pruning_sender.send(PruningProcessingMessage::Exit) {
            log::error!("SAHYADRI: failed to send Exit to pruning processor: {:?}", e);
        }
    }

    fn resolve_virtual(self: &Arc<Self>) {
        let pruning_point = match self.pruning_point_store.read().pruning_point().optional() {
            Ok(Some(pp)) => pp,
            _ => {
                log::error!("SAHYADRI: CRITICAL — pruning point not found in resolve_virtual");
                return;
            }
        };
        let virtual_read = self.virtual_stores.upgradable_read();
        let prev_state = match virtual_read.state.get().optional() {
            Ok(Some(s)) => s,
            _ => {
                log::error!("SAHYADRI: CRITICAL — virtual state not found");
                return;
            }
        };
        let finality_point = self.virtual_finality_point(&prev_state.sahyadri_consensus_data, pruning_point);

        // PRUNE SAFETY: in order to avoid locking the prune lock throughout virtual resolving we make sure
        // to only process blocks in the future of the finality point (F) which are never pruned (since finality depth << pruning depth).
        // This is justified since:
        //      1. Tips which are not in the future of F definitely don't have F on their chain
        //         hence cannot become the next sink (due to finality violation).
        //      2. Such tips cannot be merged by virtual since they are violating the merge depth
        //         bound (merge depth <= finality depth).
        // (both claims are true by induction for any block in their past as well)
        let prune_guard = self.pruning_lock.blocking_read();
        let tips = self
            .body_tips_store
            .read()
            .get()
            .unwrap_or_else(|_| {
                log::error!("SAHYADRI: CRITICAL — body tips not found");
                std::process::exit(1);
            })
            .read()
            .iter()
            .copied()
            .filter(|&h| self.reachability_service.is_dag_ancestor_of(finality_point, h))
            .collect_vec();
        drop(prune_guard);
        let prev_sink = prev_state.sahyadri_consensus_data.selected_parent;
        let mut accumulated_diff = sahyadri_consensus_core::utxo::utxo_diff::UtxoDiff::default();

        let (new_sink, virtual_parent_candidates) =
            self.sink_search_algorithm(&virtual_read, &mut accumulated_diff, prev_sink, tips, finality_point, pruning_point);
        let (virtual_parents, virtual_sahyadri_consensus_data) =
            self.pick_virtual_parents(new_sink, virtual_parent_candidates, pruning_point);
        if virtual_sahyadri_consensus_data.selected_parent != new_sink {
            log::error!("SAHYADRI: CRITICAL — virtual parent mismatch: expected {}, got {}", new_sink, virtual_sahyadri_consensus_data.selected_parent);
            return;
        }

        let sink_multiset = match self.utxo_multisets_store.get(new_sink) {
            Ok(m) => m,
            Err(e) => {
                log::error!("SAHYADRI: CRITICAL — failed to get sink multiset: {:?}", e);
                return;
            }
        };
        let chain_path = self.dag_traversal_manager.calculate_chain_path(prev_sink, new_sink, None);
        let sink_sahyadri_consensus_data = Lazy::new(|| self.sahyadri_consensus_store.get_data(new_sink).unwrap_or_else(|e| {
            log::error!("SAHYADRI: CRITICAL — failed to get sink consensus data: {:?}", e);
            std::process::exit(1);
        }));
        // Cache the DAA and Median time windows of the sink for future use, as well as prepare for virtual's window calculations
        self.cache_sink_windows(new_sink, prev_sink, &sink_sahyadri_consensus_data);

        let new_virtual_state = match self
            .calculate_and_commit_virtual_state(
                virtual_read,
                virtual_parents,
                virtual_sahyadri_consensus_data,
                sink_multiset,
                &mut accumulated_diff,
                &chain_path,
            )
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("SAHYADRI: CRITICAL — calculate_and_commit_virtual_state failed: {:?}", e);
                return;
            }
        };

        let compact_sink_sahyadri_consensus_data = if let Some(sink_sahyadri_consensus_data) = Lazy::get(&sink_sahyadri_consensus_data)
        {
            // If we had to retrieve the full data, we convert it to compact
            sink_sahyadri_consensus_data.to_compact()
        } else {
            // Else we query the compact data directly.
            self.sahyadri_consensus_store.get_compact_data(new_sink).unwrap_or_else(|e| {
                log::error!("SAHYADRI: CRITICAL — failed to get sink compact data: {:?}", e);
                std::process::exit(1);
            })
        };

        // Update the pruning processor about the virtual state change
        // Empty the channel before sending the new message. If pruning processor is busy, this step makes sure
        // the internal channel does not grow with no need (since we only care about the most recent message)
        let _consume = self.pruning_receiver.try_iter().count();
        if let Err(e) = self.pruning_sender
            .send(PruningProcessingMessage::Process { sink_sahyadri_consensus_data: compact_sink_sahyadri_consensus_data })
        {
            log::error!("SAHYADRI: failed to send Process to pruning processor: {:?}", e);
        }

        // Emit notifications
        let accumulated_diff = Arc::new(accumulated_diff);
        let virtual_parents = Arc::new(new_virtual_state.parents.clone());
        self.notification_root
            .notify(Notification::NewBlockTemplate(NewBlockTemplateNotification {}))
            .unwrap_or_else(|e| log::error!("SAHYADRI: notification channel send failed: {:?}", e));
        self.notification_root
            .notify(Notification::UtxosChanged(UtxosChangedNotification::new(accumulated_diff, virtual_parents)))
            .unwrap_or_else(|e| log::error!("SAHYADRI: notification channel send failed: {:?}", e));
        self.notification_root
            .notify(Notification::SinkBlueScoreChanged(SinkBlueScoreChangedNotification::new(
                compact_sink_sahyadri_consensus_data.blue_score,
            )))
            .unwrap_or_else(|e| log::error!("SAHYADRI: notification channel send failed: {:?}", e));
        self.notification_root
            .notify(Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification::new(new_virtual_state.daa_score)))
            .unwrap_or_else(|e| log::error!("SAHYADRI: notification channel send failed: {:?}", e));
        if self.notification_root.has_subscription(EventType::VirtualChainChanged) {
            // check for subscriptions before the heavy lifting
            let added_chain_blocks_acceptance_data =
                chain_path.added.iter().copied().map(|added| self.acceptance_data_store.get(added).unwrap()).collect_vec();
            self.notification_root
                .notify(Notification::VirtualChainChanged(VirtualChainChangedNotification::new(
                    chain_path.added.into(),
                    chain_path.removed.into(),
                    Arc::new(added_chain_blocks_acceptance_data),
                )))
                .unwrap_or_else(|e| log::error!("SAHYADRI: notification channel send failed: {:?}", e));
        }
    }

    pub(crate) fn virtual_finality_point(&self, virtual_sahyadri_consensus_data: &SahyadriConsensusData, pruning_point: Hash) -> Hash {
        let finality_point = self.depth_manager.calc_finality_point(virtual_sahyadri_consensus_data, pruning_point);
        if self.reachability_service.is_chain_ancestor_of(pruning_point, finality_point) {
            finality_point
        } else {
            // At the beginning of IBD when virtual finality point might be below the pruning point
            // or disagreeing with the pruning point chain, we take the pruning point itself as the finality point
            pruning_point
        }
    }

    /// Calculates the UTXO state of `to` starting from the state of `from`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `from` from virtual.
    /// The function returns the top-most UTXO-valid block on `chain(to)` which is ideally
    /// `to` itself (with the exception of returning `from` if `to` is already known to be UTXO disqualified).
    /// When returning it is guaranteed that `diff` holds the diff of the returned block from virtual
    fn calculate_utxo_state_relatively(&self, _stores: &VirtualStores, diff: &mut UtxoDiff, from: Hash, to: Hash) -> Hash {
        // Avoid reorging if disqualified status is already known
        if self.statuses_store.read().get(to).unwrap() == StatusDisqualifiedFromChain {
            return from;
        }

        let mut split_point: Option<Hash> = None;

        // Walk down to the reorg split point
        for current in self.reachability_service.default_backward_chain_iterator(from) {
            if self.reachability_service.is_chain_ancestor_of(current, to) {
                split_point = Some(current);
                break;
            }

            let mergeset_diff = self.utxo_diffs_store.get(current).unwrap();
            // Apply the diff in reverse
            diff.with_diff_in_place(&mergeset_diff.as_reversed()).unwrap();
        }

        let split_point = match split_point {
            Some(sp) => sp,
            None => {
                log::error!("SAHYADRI: CRITICAL — chain iterator did not reach reorg split point");
                return Default::default();
            }
        };
        debug!("VIRTUAL PROCESSOR, found split point: {split_point}");

        // A variable holding the most recent UTXO-valid block on `chain(to)` (note that it's maintained such
        // that 'diff' is always its UTXO diff from virtual)
        let mut diff_point = split_point;

        // Walk back up to the new virtual selected parent candidate
        let mut chain_block_counter = 0;
        let mut chain_disqualified_counter = 0;
        for (selected_parent, current) in self.reachability_service.forward_chain_iterator(split_point, to, true).tuple_windows() {
            if selected_parent != diff_point {
                // This indicates that the selected parent is disqualified, propagate up and continue
                let statuses_guard = self.statuses_store.upgradable_read();
                if statuses_guard.get(current).unwrap() != StatusDisqualifiedFromChain {
                    RwLockUpgradableReadGuard::upgrade(statuses_guard).set(current, StatusDisqualifiedFromChain).unwrap();
                    chain_disqualified_counter += 1;
                }
                continue;
            }

            match self.utxo_diffs_store.get(current) {
                Ok(mergeset_diff) => {
                    diff.with_diff_in_place(mergeset_diff.deref()).unwrap();
                    diff_point = current;
                }
                Err(StoreError::KeyNotFound(_)) => {
                    if self.statuses_store.read().get(current).unwrap() == StatusDisqualifiedFromChain {
                        // Current block is already known to be disqualified
                        continue;
                    }

                    let header = self.headers_store.get_header(current).unwrap();
                    let mergeset_data = self.sahyadri_consensus_store.get_data(current).unwrap();
                    let pov_daa_score = header.daa_score;

                    let selected_parent_multiset_hash = self.utxo_multisets_store.get(selected_parent).unwrap();
                    let selected_parent_utxo_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default(); // DHYAN DE: Maine '_' hata diya!

                    let mut ctx = UtxoProcessingContext::new(mergeset_data.into(), selected_parent_multiset_hash);

                    self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, pov_daa_score);
                    let res = self.verify_expected_utxo_state(&mut ctx, &selected_parent_utxo_view, &header);

                    if let Err(rule_error) = res {
                        info!("Block {} is disqualified from virtual chain: {}", current, rule_error);
                        self.statuses_store.write().set(current, StatusDisqualifiedFromChain).unwrap();
                        chain_disqualified_counter += 1;
                    } else {
                        debug!("VIRTUAL PROCESSOR, UTXO validated for {current}");

                        // Accumulate the diff
                        diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();
                        // Update the diff point
                        diff_point = current;
                        // Commit UTXO data for current chain block
                        self.commit_utxo_state(
                            current,
                            ctx.mergeset_diff,
                            ctx.multiset_hash,
                            ctx.mergeset_acceptance_data,
                            ctx.pruning_sample_from_pov.unwrap_or_else(|| {
                                log::error!("SAHYADRI: pruning_sample_from_pov is None");
                                Default::default()
                            }),
                        );
                        // Count the number of UTXO-processed chain blocks
                        chain_block_counter += 1;
                    }
                }
                Err(err) => panic!("unexpected error {err}"),
            }
        }
        // Report counters
        self.counters.chain_block_counts.fetch_add(chain_block_counter, Ordering::Relaxed);
        if chain_disqualified_counter > 0 {
            self.counters.chain_disqualified_counts.fetch_add(chain_disqualified_counter, Ordering::Relaxed);
        }

        diff_point
    }

    fn commit_utxo_state(
        &self,
        current: Hash,
        mergeset_diff: UtxoDiff,
        multiset: MuHash,
        acceptance_data: AcceptanceData,
        pruning_sample_from_pov: Hash,
    ) {
        let mut batch = WriteBatch::default();
        self.utxo_diffs_store.insert_batch(&mut batch, current, Arc::new(mergeset_diff)).unwrap();
        self.utxo_multisets_store.insert_batch(&mut batch, current, multiset).unwrap();
        self.acceptance_data_store.insert_batch(&mut batch, current, Arc::new(acceptance_data)).unwrap();
        // Note we call idempotent since this field can be populated during IBD with headers proof
        self.pruning_samples_store.insert_batch(&mut batch, current, pruning_sample_from_pov).idempotent().unwrap();
        let write_guard = self.statuses_store.set_batch(&mut batch, current, StatusUTXOValid).unwrap();
        self.db.write(batch).unwrap();
        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(write_guard);
    }

    fn calculate_and_commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        virtual_parents: Vec<Hash>,
        virtual_sahyadri_consensus_data: SahyadriConsensusData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        chain_path: &ChainPath,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let new_virtual_state =
            self.calculate_virtual_state(&virtual_read, virtual_parents, virtual_sahyadri_consensus_data, selected_parent_multiset)?;
        self.commit_virtual_state(virtual_read, new_virtual_state.clone(), accumulated_diff, chain_path);
        Ok(new_virtual_state)
    }

    // The new Account-Based Virtual State calculation
    pub(crate) fn calculate_virtual_state(
        &self,
        _virtual_stores: &VirtualStores,
        virtual_parents: Vec<Hash>,
        virtual_sahyadri_consensus_data: SahyadriConsensusData,
        selected_parent_multiset: MuHash,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let virtual_daa_window = self.window_manager.block_daa_window(&virtual_sahyadri_consensus_data)?;
        let virtual_bits = self.window_manager.calculate_difficulty_bits(&virtual_sahyadri_consensus_data, &virtual_daa_window);
        let virtual_past_median_time = self.window_manager.calc_past_median_time(&virtual_sahyadri_consensus_data)?.0;

        // Use Default to avoid Hash-Registry errors
        let mergeset_rewards = sahyadri_consensus_core::BlockHashMap::default();

        let empty_miner_data = sahyadri_consensus_core::coinbase::MinerData {
            script_public_key: sahyadri_consensus_core::tx::ScriptPublicKey::new(0, sahyadri_consensus_core::tx::ScriptVec::new()),
            extra_data: vec![],
        };

        // Get the account balances
        let account_diff = self
            .coinbase_manager
            .expected_coinbase_transaction(
                virtual_daa_window.daa_score,
                empty_miner_data,
                &virtual_sahyadri_consensus_data,
                &mergeset_rewards,
                &virtual_daa_window.mergeset_non_daa,
            )
            .unwrap_or_default();

        let accepted_tx_ids = Vec::new();

        Ok(Arc::new(VirtualState::new(
            virtual_parents,
            virtual_daa_window.daa_score,
            virtual_bits,
            virtual_past_median_time,
            selected_parent_multiset,
            account_diff,
            accepted_tx_ids,
            mergeset_rewards,
            virtual_daa_window.mergeset_non_daa,
            virtual_sahyadri_consensus_data,
        )))
    }

    fn commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        new_virtual_state: Arc<VirtualState>,
        _accumulated_diff: &UtxoDiff,
        chain_path: &ChainPath,
    ) {
        let mut batch = WriteBatch::default();
        for (address_str, balance_change) in new_virtual_state.account_diff.iter() {
            let address = sahyadri_addresses::Address::constructor(address_str);
            let script_public_key = sahyadri_txscript::pay_to_address_script(&address);
                {
                    if let Err(e) = self.account_store.update_balance_batch(&mut batch, &script_public_key, *balance_change) {
                        log::error!("SAHYADRI: Failed to apply account diff: {:?}", e);
                        continue;
                    }
                }
        }
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        let mut selected_chain_write = self.selected_chain_store.write();

        // ---------------------------------------------------------
        // SAHYADRI ACCOUNT MODEL: TRANSACTION EXECUTION ENGINE
        // ---------------------------------------------------------

        // 1. REORG HANDLING: Deduct everything from blocks that are removed from the main chain
        for &hash in chain_path.removed.iter() {
            if let Ok(txs) = self.block_transactions_store.get(hash) {
                for (i, tx) in txs.iter().enumerate() {
                    // Reverse the outputs (Deduct what was wrongly added)
                    for output in tx.outputs.iter() {
                        let amount = -(output.value as i64); // Negative to deduct
                            {
                                if let Err(e) = self.account_store.update_balance_batch(&mut batch, &output.script_public_key, amount) {
                                    log::error!("SAHYADRI: CRITICAL — failed to reverse balance during reorg: {:?}", e);
                                    continue;
                                }
                            }
                    }

                    if i > 0 {
                        // Refund the sender and roll back their nonce, mirroring the apply path
                        let min_payload = PUBKEY_SIZE + 8 + SIG_SIZE;
                        if tx.payload.len() >= min_payload {
                            let sig_start = tx.payload.len() - SIG_SIZE;
                            let sender_pubkey = &tx.payload[..sig_start - 8];
                            let sender_spk = sahyadri_consensus_core::tx::ScriptPublicKey::from_vec(0, sender_pubkey.to_vec());

                            let mut total_spent: u64 = tx.gas;
                            for output in tx.outputs.iter() {
                                total_spent += output.value;
                            }

                              {
                                  if let Err(e) = self.account_store.update_balance_batch(&mut batch, &sender_spk, total_spent as i64) {
                                      log::error!("SAHYADRI: CRITICAL — failed to refund sender during reorg: {:?}", e);
                                      continue;
                                  }
                              }
                              {
                                  if let Err(e) = self.account_store.decrement_nonce_batch(&mut batch, &sender_spk) {
                                      log::error!("SAHYADRI: CRITICAL — failed to roll back nonce during reorg: {:?}", e);
                                  }
                              }
                        } else {
                            log::error!(
                                "SAHYADRI: reorg refund skipped — undersized payload ({} bytes) for tx in removed block",
                                tx.payload.len()
                            );
                        }
                    }
                }
            }
        }

        // 2. NEW BLOCKS: Process Miners & User Transactions
        for &hash in chain_path.added.iter() {
            if let Ok(txs) = self.block_transactions_store.get(hash) {
                for (i, tx) in txs.iter().enumerate() {
                    // ==========================================
                    // FIX 1: MINER REWARD
                    // ==========================================
                    if i == 0 {
                        if let Ok(coinbase_data) = self.coinbase_manager.deserialize_coinbase_payload(&tx.payload) {
                            // 1. 
                            let total_reward = coinbase_data.subsidy;

                            if total_reward > 0 {
                                // 2.
                                let dev_fee = if SAHYADRI_TREASURY_PUBKEY_HEX.is_empty() { 0 } else { total_reward / 50 };
                                let miner_reward = total_reward - dev_fee;

                                // 3.
                                     {
                                         if let Err(e) = self.account_store.update_balance_batch(&mut batch, &coinbase_data.miner_data.script_public_key, miner_reward as i64) {
                                             log::error!("SAHYADRI: CRITICAL — failed to credit miner reward: {:?}", e);
                                             continue;
                                         }
                                     }

                                let mut treasury_pubkey_bytes = vec![0u8; PUBKEY_SIZE];
                                if faster_hex::hex_decode(SAHYADRI_TREASURY_PUBKEY_HEX.as_bytes(), &mut treasury_pubkey_bytes).is_ok() {
                                    let treasury_spk = sahyadri_consensus_core::tx::ScriptPublicKey::from_vec(0, treasury_pubkey_bytes);
                                    {
                                        if let Err(e) = self.account_store.update_balance_batch(&mut batch, &treasury_spk, dev_fee as i64) {
                                            log::error!("SAHYADRI: CRITICAL — failed to credit treasury: {:?}", e);
                                        }
                                    }
                                } else {
                                    log::error!("SAHYADRI: failed to decode treasury pubkey hex — dev_fee {} NOT credited this block", dev_fee);
                                }

                                log::debug!("SAHYADRI REWARD: Added {} Kana to Miner! (Dev Fee: {})", miner_reward, dev_fee);
                            }
                        } else {
                            println!("SAHYADRI REWARD ERROR: Failed to decode coinbase payload!");
                        }
                    }
                    // ==========================================
                    // FIX 2: USER TRANSACTIONS
                    // ==========================================
                    else {
                        // SAHYADRI: DID transaction check — must come first
                        let is_did_tx = tx.payload.len() > 4 && (
                            &tx.payload[..4] == b"DCRT" ||
                            &tx.payload[..4] == b"DUPD" ||
                            &tx.payload[..4] == b"DDEC"
                        );

                        if is_did_tx && tx.payload.len() >= 20 {
                            let did_tx_type = &tx.payload[..4];

                            match did_tx_type {
                                b"DCRT" => {
                                    log::info!("SAHYADRI: Processing DID_CREATE transaction");
                                    if tx.payload.len() < 100 { continue; }

                                    let mut offset = 4;
                                    let did_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + did_len > tx.payload.len() { continue; }
                                    let did = String::from_utf8_lossy(&tx.payload[offset..offset+did_len]).to_string();
                                    offset += did_len;

                                    const DILITHIUM_PUBKEY_SIZE: usize = 1952;
                                    if offset + DILITHIUM_PUBKEY_SIZE > tx.payload.len() { continue; }
                                    let did_pubkey = &tx.payload[offset..offset+DILITHIUM_PUBKEY_SIZE];
                                    offset += DILITHIUM_PUBKEY_SIZE;

                                    let addr_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + addr_len > tx.payload.len() { continue; }
                                    let csm_address = String::from_utf8_lossy(&tx.payload[offset..offset+addr_len]).to_string();
                                    offset += addr_len;

                                    let doc_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + doc_len > tx.payload.len() { continue; }
                                    let document = String::from_utf8_lossy(&tx.payload[offset..offset+doc_len]).to_string();

                                    const DILITHIUM_SIG_SIZE: usize = SIG_SIZE;
                                    let sig_start = tx.payload.len() - DILITHIUM_SIG_SIZE;
                                    let sig_bytes = &tx.payload[sig_start..];

                                    let sighash = {
                                        let mut h = Sha256::new();
                                        h.update(b"SAHYADRI_DID_CREATE_V1");
                                        h.update(&tx.payload[..sig_start]);
                                        h.finalize()
                                    };

                                    let sig = DilithiumSignature::from_slice(sig_bytes);

                                    // PARALLEL VERIFY (Rayon + AVX2)
                                    let is_valid = VERIFY_POOL.install(|| {
                                        DilithiumKeyPair::verify(did_pubkey, &sig, &sighash, b"", SAHYADRI_MODE)
                                    });
                                    if !is_valid {
                                        log::warn!("SAHYADRI: DID_CREATE invalid signature");
                                        continue;
                                    }

                                    if self.did_store.is_active(&did).unwrap_or(false) {
                                        log::warn!("SAHYADRI: DID already exists: {}", did);
                                        continue;
                                    }

                                    let now = unix_now();
                                    let did_doc = DidDocument {
                                        did: did.clone(),
                                        csm_address,
                                        public_key: faster_hex::hex_string(did_pubkey),
                                        document,
                                        purposes: vec!["authentication".to_string()],
                                        services: vec![],
                                        active: true,
                                        created_at: now,
                                        updated_at: now,
                                        version: 1,
                                    };

            {
                                        if let Err(e) = self.did_store.set_batch(&mut batch, &did_doc) {
                                            log::error!("SAHYADRI: CRITICAL — failed to store DID: {:?}", e);
                                            continue;
                                        }
                                    }

                                    log::info!("SAHYADRI: DID created: {}", did);
                                }

                                b"DUPD" => {
                                    log::info!("SAHYADRI: Processing DID_UPDATE");
                                    if tx.payload.len() < 100 { continue; }

                                    let mut offset = 4;
                                    let did_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + did_len > tx.payload.len() { continue; }
                                    let did = String::from_utf8_lossy(&tx.payload[offset..offset+did_len]).to_string();

                                    let existing_doc = match self.did_store.get_by_did(&did) {
                                        Ok(Some(doc)) => doc,
                                        _ => { continue; }
                                    };

                                    offset += did_len;
                                    let doc_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + doc_len > tx.payload.len() { continue; }
                                    let new_document = String::from_utf8_lossy(&tx.payload[offset..offset+doc_len]).to_string();

                                    const DILITHIUM_SIG_SIZE: usize = SIG_SIZE;
                                    let sig_bytes = &tx.payload[tx.payload.len()-DILITHIUM_SIG_SIZE..];
                                    let orig_pk = existing_doc.public_key.as_bytes().to_vec();

                                    let sig = DilithiumSignature::from_slice(sig_bytes);

                                    let sighash = {
                                        let mut h = Sha256::new();
                                        h.update(b"SAHYADRI_DID_UPDATE_V1");
                                        h.update(&did);
                                        h.update(&new_document);
                                        h.finalize()
                                    };

                                    let is_valid = VERIFY_POOL.install(|| {
                                        DilithiumKeyPair::verify(&orig_pk, &sig, &sighash, b"", SAHYADRI_MODE)
                                    });
                                    if !is_valid {
                                        continue;
                                    }

                                    let mut updated = existing_doc;
                                    updated.document = new_document;
                                    updated.updated_at = unix_now();
                                    updated.version += 1;

                                    self.did_store.update_batch(&mut batch, &updated).ok();
                                    log::info!("SAHYADRI: DID updated: {}", did);
                                }

                                b"DDEC" => {
                                    log::info!("SAHYADRI: Processing DID_DEACTIVATE");
                                    if tx.payload.len() < 50 { continue; }

                                    let mut offset = 4;
                                    let did_len = u32::from_le_bytes(tx.payload[offset..offset+4].try_into().map_err(|_| log::error!("SAHYADRI: malformed payload slice")).ok().unwrap_or([0u8; 4])) as usize;
                                    offset += 4;
                                    if offset + did_len > tx.payload.len() { continue; }
                                    let did = String::from_utf8_lossy(&tx.payload[offset..offset+did_len]).to_string();

                                    let existing = match self.did_store.get_by_did(&did) {
                                        Ok(Some(d)) => d,
                                        _ => { continue; }
                                    };

                                    const DILITHIUM_SIG_SIZE: usize = SIG_SIZE;
                                    let sig_bytes = &tx.payload[tx.payload.len()-DILITHIUM_SIG_SIZE..];
                                    let orig_pk = existing.public_key.as_bytes().to_vec();
                                    let sig = DilithiumSignature::from_slice(sig_bytes);

                                    let sighash = {
                                        let mut h = Sha256::new();
                                        h.update(b"SAHYADRI_DID_DEACTIVATE_V1");
                                        h.update(&did);
                                        h.finalize()
                                    };

                                    let is_valid = VERIFY_POOL.install(|| {
                                        DilithiumKeyPair::verify(&orig_pk, &sig, &sighash, b"", SAHYADRI_MODE)
                                    });
                                    if !is_valid {
                                        continue;
                                    }

                                    self.did_store.deactivate_batch(&mut batch, &did).ok();
                                    log::info!("SAHYADRI: DID deactivated: {}", did);
                                }

                                _ => {}
                            }
                            continue;
                        }

                        let min_payload = PUBKEY_SIZE + 8 + SIG_SIZE;
                        if tx.payload.len() < min_payload {
                            log::warn!(
                                "SAHYADRI: skipping account tx — undersized payload ({} bytes) in commit_virtual_state",
                                tx.payload.len()
                            );
                            continue;
                        }

                        let sig_start = tx.payload.len() - SIG_SIZE;
                        let nonce_start = sig_start - 8;
                        let sender_pubkey = &tx.payload[..nonce_start];
                        let expected_nonce = u64::from_le_bytes(match tx.payload[nonce_start..sig_start].try_into() {
                                                        Ok(b) => b,
                                                        Err(_) => {
                                                            log::error!("SAHYADRI: malformed nonce slice in account tx");
                                                            continue;
                                                        }
                                                    });
                        let sig_bytes = &tx.payload[sig_start..];
                        let sender_spk = sahyadri_consensus_core::tx::ScriptPublicKey::from_vec(0, sender_pubkey.to_vec());

                        // Defense-in-depth: re-verify Dilithium signature
                        {
                            let signable_payload = &tx.payload[..sig_start];
                            log::warn!("SIGNABLE PAYLOAD LEN: {}", signable_payload.len());
                            log::warn!("SENDER PUBKEY LEN: {}", sender_pubkey.len());    
                            let sighash = {
                                let mut h = Sha256::new();
                                h.update(b"SAHYADRI_ACCOUNT_TX_V1");
                                h.update(tx.version.to_le_bytes());
                                for output in &tx.outputs {
                                    h.update(output.value.to_le_bytes());
                                    h.update(output.script_public_key.version.to_le_bytes());
                                    let s = output.script_public_key.script();
                                    h.update((s.len() as u64).to_le_bytes());
                                    h.update(s);
                                }
                                h.update(tx.lock_time.to_le_bytes());
                                h.update(tx.subnetwork_id.as_bytes());
                                h.update(tx.gas.to_le_bytes());
                                h.update((signable_payload.len() as u64).to_le_bytes());
                                h.update(signable_payload);
                                h.finalize()
                            };
                            log::warn!("SAHYADRI SIGHASH: {:02x?}", sighash);
                            log::warn!("SPK VERSION: {}", tx.outputs[0].script_public_key.version);
                            log::warn!("NODE SIGHASH: {:02x?}", sighash);
                            log::warn!("NODE SENDER PUBKEY LEN: {}", sender_pubkey.len());
                            log::warn!("NODE SENDER PUBKEY FIRST 40: {:02x?}", &sender_pubkey[..20.min(sender_pubkey.len())]);
                            log::warn!("NODE SIGNABLE PAYLOAD LEN: {}", signable_payload.len());
                            log::warn!("NODE SIG FIRST 20: {:02x?}", &sig_bytes[..20.min(sig_bytes.len())]);

                            let sig = DilithiumSignature::from_slice(sig_bytes);
                            let is_valid = VERIFY_POOL.install(|| {
                                DilithiumKeyPair::verify(sender_pubkey, &sig, &sighash, b"", SAHYADRI_MODE)
                            });
                            if !is_valid {
                                log::warn!("SAHYADRI: skipping account tx — invalid signature in commit_virtual_state");
                                continue;
                            }
                        }

                        // Verify nonce
                        let current_nonce = match self.account_store.get_nonce(&sender_spk) {
                            Ok(n) => n,
                            Err(e) => {
                                log::warn!("SAHYADRI: skipping account tx — failed to read nonce: {:?}", e);
                                continue;
                            }
                        };
                        if expected_nonce != current_nonce {
                            log::warn!(
                                "SAHYADRI: skipping invalid account tx — nonce mismatch (have {}, tx claims {})",
                                current_nonce, expected_nonce
                            );
                            continue;
                        }

                        // Verify balance
                        let mut total_spent: u64 = 0;
                        for output in tx.outputs.iter() {
                            total_spent += output.value;
                        }
                        total_spent += tx.gas;
                        let balance = match self.account_store.get_balance(&sender_spk) {
                            Ok(b) => b,
                            Err(e) => {
                                log::warn!("SAHYADRI: skipping account tx — failed to read balance: {:?}", e);
                                continue;
                            }
                        };
                        if balance < total_spent {
                            log::warn!(
                                "SAHYADRI: skipping invalid account tx — insufficient balance (have {}, need {})",
                                balance, total_spent
                            );
                            continue;
                        }

                        // All checks passed — apply state changes
                        for output in tx.outputs.iter() {
                            let amount = output.value as i64;
                          {
                              if let Err(e) = self.account_store.update_balance_batch(&mut batch, &output.script_public_key, amount) {
                                  log::error!("SAHYADRI: CRITICAL — failed to credit receiver: {:?}", e);
                                  break;
                              }
                          }
                        }
                          {
                              if let Err(e) = self.account_store.increment_nonce_batch(&mut batch, &sender_spk) {
                                  log::error!("SAHYADRI: CRITICAL — failed to increment nonce: {:?}", e);
                              }
                          }
                        self.account_store
                            .increment_nonce_batch(&mut batch, &sender_spk)
                            .expect("SAHYADRI: CRITICAL — failed to increment nonce");
                    }
                }
            }
        }

                    
        // ==========================================

        // Update virtual state
        if let Err(e) = virtual_write.state.set_batch(&mut batch, new_virtual_state) {
                log::error!("SAHYADRI: CRITICAL — failed to set virtual state: {:?}", e);
                return;
            }

        // Update the virtual selected chain
        if let Err(e) = selected_chain_write.apply_changes(&mut batch, chain_path) {
                log::error!("SAHYADRI: CRITICAL — failed to apply chain changes: {:?}", e);
                return;
            }

        // Flush the batch changes to RocksDB (Transaction Commit)
        if let Err(e) = self.db.write(batch) {
                log::error!("SAHYADRI: CRITICAL — DB write failed in commit_virtual_state: {:?}", e);
                return;
            }

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(virtual_write);
        drop(selected_chain_write);
    }

    /// Caches the DAA and Median time windows of the sink block (if needed). Following, virtual's window calculations will
    /// naturally hit the cache finding the sink's windows and building upon them.
    fn cache_sink_windows(
        &self,
        new_sink: Hash,
        prev_sink: Hash,
        sink_sahyadri_consensus_data: &impl Deref<Target = Arc<SahyadriConsensusData>>,
    ) {
        // We expect that the `new_sink` is cached (or some close-enough ancestor thereof) if it is equal to the `prev_sink`,
        // Hence we short-circuit the check of the keys in such cases, thereby reducing the access of the read-lock
        if new_sink != prev_sink {
            // this is only important for ibd performance, as we incur expensive cache misses otherwise.
            // this occurs because we cannot rely on header processing to pre-cache in this scenario.
            if !self.block_window_cache_for_difficulty.contains_key(&new_sink) {
                self.block_window_cache_for_difficulty
                    .insert(new_sink, self.window_manager.block_daa_window(sink_sahyadri_consensus_data.deref()).unwrap().window);
            };

            if !self.block_window_cache_for_past_median_time.contains_key(&new_sink) {
                self.block_window_cache_for_past_median_time
                    .insert(new_sink, self.window_manager.calc_past_median_time(sink_sahyadri_consensus_data.deref()).unwrap().1);
            };
        }
    }

    /// Returns the max number of tips to consider as virtual parents in a single virtual resolve operation.
    ///
    /// Guaranteed to be `>= self.max_block_parents`
    fn max_virtual_parent_candidates(&self, max_block_parents: usize) -> usize {
        // Limit to max_block_parents x 3 candidates. This way we avoid going over thousands of tips when the network isn't healthy.
        // There's no specific reason for a factor of 3, and its not a consensus rule, just an estimation for reducing the amount
        // of candidates considered.
        max_block_parents * 3
    }

    /// Searches for the next valid sink block (SINK = Virtual selected parent). The search is performed
    /// in the inclusive past of `tips`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `prev_sink` from virtual.
    /// The function returns with `diff` being the diff of the new sink from previous virtual.
    /// In addition to the found sink the function also returns a queue of additional virtual
    /// parent candidates ordered in descending blue work order.
    pub(super) fn sink_search_algorithm(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        prev_sink: Hash,
        tips: Vec<Hash>,
        finality_point: Hash,
        pruning_point: Hash,
    ) -> (Hash, VecDeque<Hash>) {
        // TODO (relaxed): additional tests

        let mut heap = tips
            .into_iter()
            .map(|block| SortableBlock { hash: block, blue_work: self.sahyadri_consensus_store.get_blue_work(block).unwrap() })
            .collect::<BinaryHeap<_>>();

        // The initial diff point is the previous sink
        let mut diff_point = prev_sink;

        // We maintain the following invariant: `heap` is an antichain.
        // It holds at step 0 since tips are an antichain, and remains through the loop
        // since we check that every pushed block is not in the past of current heap
        // (and it can't be in the future by induction)
        loop {
            let candidate = match heap.pop() {
                Some(s) => s.hash,
                None => {
                    log::error!("SAHYADRI: CRITICAL — sink heap is empty during GHOSTDAG");
                    return (Default::default(), Default::default());
                }
            };
            if self.reachability_service.is_chain_ancestor_of(finality_point, candidate) {
                diff_point = self.calculate_utxo_state_relatively(stores, diff, diff_point, candidate);
                if diff_point == candidate {
                    // This indicates that candidate has valid UTXO state and that `diff` represents its diff from virtual

                    // All blocks with lower blue work than filtering_root are:
                    // 1. not in its future (bcs blue work is monotonic),
                    // 2. will be removed eventually by the bounded merge check.
                    // Hence as an optimization we prefer removing such blocks in advance to allow valid tips to be considered.
                    let filtering_root = self.depth_store.merge_depth_root(candidate).unwrap();
                    let filtering_blue_work = self.sahyadri_consensus_store.get_blue_work(filtering_root).unwrap_or_default();
                    return (
                        candidate,
                        heap.into_sorted_iter().take_while(|s| s.blue_work >= filtering_blue_work).map(|s| s.hash).collect(),
                    );
                } else {
                    debug!("Block candidate {} has invalid UTXO state and is ignored from Virtual chain.", candidate)
                }
            } else if finality_point != pruning_point {
                // `finality_point == pruning_point` indicates we are at IBD start hence no warning required
                warn!("Finality Violation Detected. Block {} violates finality and is ignored from Virtual chain.", candidate);
            }
            // PRUNE SAFETY: see comment within [`resolve_virtual`]
            let prune_guard = self.pruning_lock.blocking_read();
            for parent in self.relations_service.get_parents(candidate).unwrap().iter().copied() {
                if self.reachability_service.is_dag_ancestor_of(finality_point, parent)
                    && !self.reachability_service.is_dag_ancestor_of_any(parent, &mut heap.iter().map(|sb| sb.hash))
                {
                    heap.push(SortableBlock { hash: parent, blue_work: self.sahyadri_consensus_store.get_blue_work(parent).unwrap() });
                }
            }
            drop(prune_guard);
        }
    }

    /// Picks the virtual parents according to virtual parent selection pruning constrains.
    /// Assumes:
    ///     1. `selected_parent` is a UTXO-valid block
    ///     2. `candidates` are an antichain ordered in descending blue work order
    ///     3. `candidates` do not contain `selected_parent` and `selected_parent.blue work > max(candidates.blue_work)`  
    pub(super) fn pick_virtual_parents(
        &self,
        selected_parent: Hash,
        mut candidates: VecDeque<Hash>,
        pruning_point: Hash,
    ) -> (Vec<Hash>, SahyadriConsensusData) {
        // TODO (relaxed): additional tests

        // Mergeset increasing might traverse DAG areas which are below the finality point and which theoretically
        // can borderline with pruned data, hence we acquire the prune lock to ensure data consistency. Note that
        // the final selected mergeset can never be pruned (this is the essence of the prunality proof), however
        // we might touch such data prior to validating the bounded merge rule. All in all, this function is short
        // enough so we avoid making further optimizations
        let _prune_guard = self.pruning_lock.blocking_read();
        let max_block_parents = self.max_block_parents as usize;
        let mergeset_size_limit = self.mergeset_size_limit;
        let max_candidates = self.max_virtual_parent_candidates(max_block_parents);

        // Prioritize half the blocks with highest blue work and pick the rest randomly to ensure diversity between nodes
        if candidates.len() > max_candidates {
            // make_contiguous should be a no op since the deque was just built
            let slice = candidates.make_contiguous();

            // Keep slice[..max_block_parents / 2] as is, choose max_candidates - max_block_parents / 2 in random
            // from the remainder of the slice while swapping them to slice[max_block_parents / 2..max_candidates].
            //
            // Inspired by rand::partial_shuffle (which lacks the guarantee on chosen elements location).
            for i in max_block_parents / 2..max_candidates {
                let j = rand::thread_rng().gen_range(i..slice.len()); // i < max_candidates < slice.len()
                slice.swap(i, j);
            }

            // Truncate the unchosen elements
            candidates.truncate(max_candidates);
        } else if candidates.len() > max_block_parents / 2 {
            // Fallback to a simpler algo in this case
            candidates.make_contiguous()[max_block_parents / 2..].shuffle(&mut rand::thread_rng());
        }

        let mut virtual_parents = Vec::with_capacity(min(max_block_parents, candidates.len() + 1));
        virtual_parents.push(selected_parent);
        let mut mergeset_size = 1; // Count the selected parent

        // Try adding parents as long as mergeset size and number of parents limits are not reached
        while let Some(candidate) = candidates.pop_front() {
            if mergeset_size >= mergeset_size_limit || virtual_parents.len() >= max_block_parents {
                break;
            }
            match self.mergeset_increase(&virtual_parents, candidate, mergeset_size_limit - mergeset_size) {
                MergesetIncreaseResult::Accepted { increase_size } => {
                    mergeset_size += increase_size;
                    virtual_parents.push(candidate);
                }
                MergesetIncreaseResult::Rejected { new_candidate } => {
                    // If we already have a candidate in the past of new candidate then skip.
                    if self.reachability_service.is_any_dag_ancestor(&mut candidates.iter().copied(), new_candidate) {
                        continue; // TODO (optimization): not sure this check is needed if candidates invariant as antichain is kept
                    }
                    // Remove all candidates which are in the future of the new candidate
                    candidates.retain(|&h| !self.reachability_service.is_dag_ancestor_of(new_candidate, h));
                    candidates.push_back(new_candidate);
                }
            }
        }
        assert!(mergeset_size <= mergeset_size_limit);
        assert!(virtual_parents.len() <= max_block_parents);
        self.remove_bounded_merge_breaking_parents(virtual_parents, pruning_point)
    }

    fn mergeset_increase(&self, selected_parents: &[Hash], candidate: Hash, budget: u64) -> MergesetIncreaseResult {
        /*
        Algo:
            Traverse past(candidate) \setminus past(selected_parents) and make
            sure the increase in mergeset size is within the available budget
        */

        let candidate_parents = self.relations_service.get_parents(candidate).unwrap();
        let mut queue: VecDeque<_> = candidate_parents.iter().copied().collect();
        let mut visited: BlockHashSet = queue.iter().copied().collect();
        let mut mergeset_increase = 1u64; // Starts with 1 to count for the candidate itself

        while let Some(current) = queue.pop_front() {
            if self.reachability_service.is_dag_ancestor_of_any(current, &mut selected_parents.iter().copied()) {
                continue;
            }
            mergeset_increase += 1;
            if mergeset_increase > budget {
                return MergesetIncreaseResult::Rejected { new_candidate: current };
            }

            let current_parents = self.relations_service.get_parents(current).unwrap();
            for &parent in current_parents.iter() {
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        MergesetIncreaseResult::Accepted { increase_size: mergeset_increase }
    }

    fn remove_bounded_merge_breaking_parents(
        &self,
        mut virtual_parents: Vec<Hash>,
        current_pruning_point: Hash,
    ) -> (Vec<Hash>, SahyadriConsensusData) {
        let mut sahyadri_consensus_data = self.sahyadri_consensus_manager.sahyadri_consensus(&virtual_parents);
        let merge_depth_root = self.depth_manager.calc_merge_depth_root(&sahyadri_consensus_data, current_pruning_point);
        let mut kosherizing_blues: Option<Vec<Hash>> = None;
        let mut bad_reds = Vec::new();

        //
        // Note that the code below optimizes for the usual case where there are no merge-bound-violating blocks.
        //

        // Find red blocks violating the merge bound and which are not kosherized by any blue
        for red in sahyadri_consensus_data.mergeset_reds.iter().copied() {
            if self.reachability_service.is_dag_ancestor_of(merge_depth_root, red) {
                continue;
            }
            // Lazy load the kosherizing blocks since this case is extremely rare
            if kosherizing_blues.is_none() {
                kosherizing_blues = Some(self.depth_manager.kosherizing_blues(&sahyadri_consensus_data, merge_depth_root).collect());
            }
            if !self.reachability_service.is_dag_ancestor_of_any(red, &mut kosherizing_blues.as_ref().unwrap().iter().copied()) {
                bad_reds.push(red);
            }
        }

        if !bad_reds.is_empty() {
            // Remove all parents which lead to merging a bad red
            virtual_parents.retain(|&h| !self.reachability_service.is_any_dag_ancestor(&mut bad_reds.iter().copied(), h));
            // Recompute sahyadri_consensus data since parents changed
            sahyadri_consensus_data = self.sahyadri_consensus_manager.sahyadri_consensus(&virtual_parents);
        }

        (virtual_parents, sahyadri_consensus_data)
    }

    fn validate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
        virtual_daa_score: u64,
        virtual_past_median_time: u64,
        args: &TransactionValidationArgs,
    ) -> TxResult<()> {
        self.transaction_validator.validate_tx_in_isolation(&mutable_tx.tx)?;
        self.transaction_validator.validate_tx_in_header_context_with_args(
            &mutable_tx.tx,
            virtual_daa_score,
            virtual_past_median_time,
        )?;
        self.validate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view, virtual_daa_score, args)?;
        Ok(())
    }

    pub fn validate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;
        let dummy_utxo_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default(); // SAHYADRI ACCOUNT BYPASS

        self.thread_pool.install(|| {
            self.validate_mempool_transaction_impl(mutable_tx, &dummy_utxo_view, virtual_daa_score, virtual_past_median_time, args)
        })
    }

    pub fn validate_mempool_transactions_in_parallel(
        &self,
        mutable_txs: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;

        self.thread_pool.install(|| {
            let dummy_utxo_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default(); // SAHYADRI ACCOUNT BYPASS
            mutable_txs
                .par_iter_mut()
                .map(|mtx| {
                    self.validate_mempool_transaction_impl(
                        mtx,
                        &dummy_utxo_view,
                        virtual_daa_score,
                        virtual_past_median_time,
                        args.get(&mtx.id()),
                    )
                })
                .collect::<Vec<TxResult<()>>>()
        })
    }

    pub fn populate_mempool_transaction(&self, _mutable_tx: &mut MutableTransaction) -> TxResult<()> {
        Ok(())
    }

    pub fn build_block_template(
        &self,
        miner_data: MinerData,
        mut tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        //
        // TODO (relaxed): additional tests
        //

        // We call for the initial tx batch before acquiring the virtual read lock,
        // optimizing for the common case where all txs are valid. Following selection calls
        // are called within the lock in order to preserve validness of already validated txs
        let mut txs = tx_selector.select_transactions();
        let mut calculated_fees = Vec::with_capacity(txs.len());
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();

        let invalid_transactions = HashMap::new();
        let virtual_utxo_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default();
        let results = self.validate_block_template_transactions(&txs, &virtual_state, &virtual_utxo_view);
        for (_tx, _res) in txs.iter().zip(results) {}

        let mut has_rejections = !invalid_transactions.is_empty();
        if has_rejections {
            txs.retain(|tx| !invalid_transactions.contains_key(&tx.id()));
        }

        while has_rejections {
            has_rejections = false;
            let next_batch = tx_selector.select_transactions();

            // SAHYADRI ACCOUNT MODEL BYPASS
            // We assume all selected txs in the batch are valid and have a fee of 0.
            for tx in next_batch.into_iter() {
                txs.push(tx);
                calculated_fees.push(0); // Dummy fee
            }
        }

        match (build_mode, tx_selector.is_successful()) {
            (TemplateBuildMode::Standard, false) => return Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)),
            (TemplateBuildMode::Standard, true) | (TemplateBuildMode::Infallible, _) => {}
        }

        // At this point we can safely drop the read lock
        drop(virtual_read);

        // Build the template
        self.build_block_template_from_virtual_state(virtual_state, miner_data, txs, calculated_fees)
    }

    pub(crate) fn validate_block_template_transactions(
        &self,
        _txs: &[Transaction],
        _virtual_state: &VirtualState,
        _utxo_view: &impl UtxoView,
    ) -> Result<(), RuleError> {
        // SAHYADRI ACCOUNT MODEL: All transactions are considered valid at this stage.
        Ok(())
    }

    pub(crate) fn build_block_template_from_virtual_state(
        &self,
        virtual_state: Arc<VirtualState>,
        miner_data: MinerData,
        txs: Vec<Transaction>,
        calculated_fees: Vec<u64>,
    ) -> Result<BlockTemplate, RuleError> {
        // [`calc_block_parents`] can use deep blocks below the pruning point for this calculation, so we
        // need to hold the pruning lock.
        let _prune_guard = self.pruning_lock.blocking_read();
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let header_pruning_point =
            self.pruning_point_manager.expected_header_pruning_point(virtual_state.sahyadri_consensus_data.to_compact()).pruning_point;
        let _coinbase = self
            .coinbase_manager
            .expected_coinbase_transaction(
                virtual_state.daa_score,
                miner_data.clone(),
                &virtual_state.sahyadri_consensus_data,
                &virtual_state.mergeset_rewards,
                &virtual_state.mergeset_non_daa,
            )
            .unwrap();

        // --- SAHYADRI HYBRID SURGERY (ACCOUNT + OBJECT MODEL) ---
        let mut txs = txs;

        let blue_score = virtual_state.sahyadri_consensus_data.blue_score;
        let subsidy = self.coinbase_manager.calc_block_subsidy(blue_score);
        let dynamic_payload = self
            .coinbase_manager
            .serialize_coinbase_payload(&sahyadri_consensus_core::coinbase::CoinbaseData {
                blue_score,
                subsidy,
                miner_data: miner_data.clone(),
            })
            .unwrap_or_else(|_| {
                let mut p = blue_score.to_le_bytes().to_vec();
                p.resize(32, 0);
                p
            });

        let state_receipt = Transaction::new(
            0,                                                        // version
            vec![],                                                   // inputs
            vec![],                                                   // outputs
            0,                                                        // lock_time
            sahyadri_consensus_core::subnets::SUBNETWORK_ID_COINBASE, // Network tag
            0,                                                        // gas
            dynamic_payload,
        );

        txs.insert(0, state_receipt);
        // --------------------------------------------------------

        let version = BLOCK_VERSION;
        let parents_by_level = self.parents_manager.calc_block_parents(pruning_point, &virtual_state.parents);
        let hash_merkle_root = calc_hash_merkle_root(txs.iter());

        let accepted_id_merkle_root = self.calc_accepted_id_merkle_root(
            virtual_state.accepted_tx_ids.iter().copied(),
            virtual_state.sahyadri_consensus_data.selected_parent,
        );
        let utxo_commitment = virtual_state.multiset.clone().finalize();
        // Past median time is the exclusive lower bound for valid block time, so we increase by 1 to get the valid min
        let min_block_time = virtual_state.past_median_time + 1;
        let header = Header::new_finalized(
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            u64::max(min_block_time, unix_now()),
            virtual_state.bits,
            0,
            virtual_state.daa_score,
            virtual_state.sahyadri_consensus_data.blue_work,
            virtual_state.sahyadri_consensus_data.blue_score,
            header_pruning_point,
        );
        let selected_parent_hash = virtual_state.sahyadri_consensus_data.selected_parent;
        let selected_parent_timestamp = self.headers_store.get_timestamp(selected_parent_hash).unwrap();
        let selected_parent_daa_score = self.headers_store.get_daa_score(selected_parent_hash).unwrap();
        Ok(BlockTemplate::new(
            MutableBlock::new(header, txs),
            miner_data,
            false, // coinbase.has_red_reward is bypassed for the initial account model
            selected_parent_timestamp,
            selected_parent_daa_score,
            selected_parent_hash,
            calculated_fees,
        ))
    }

    /// Make sure pruning point-related stores are initialized
    pub fn init(self: &Arc<Self>) {
        let pruning_point_read = self.pruning_point_store.upgradable_read();
        if pruning_point_read.pruning_point().optional().unwrap().is_none() {
            let mut pruning_point_write = RwLockUpgradableReadGuard::upgrade(pruning_point_read);
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            let mut batch = WriteBatch::default();
            self.past_pruning_points_store.insert_batch(&mut batch, 0, self.genesis.hash).idempotent().unwrap();
            pruning_point_write.set_batch(&mut batch, self.genesis.hash, 0).unwrap();
            pruning_point_write.set_retention_checkpoint(&mut batch, self.genesis.hash).unwrap();
            pruning_point_write.set_retention_period_root(&mut batch, self.genesis.hash).unwrap();
            pruning_meta_write.set_utxoset_position(&mut batch, self.genesis.hash).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_point_write);
            drop(pruning_meta_write);
        }
    }

    /// Initializes UTXO state of genesis and points virtual at genesis.
    /// Note that pruning point-related stores are initialized by `init`
    pub fn process_genesis(self: &Arc<Self>) {
        // Write the UTXO state of genesis
        self.commit_utxo_state(self.genesis.hash, UtxoDiff::default(), MuHash::new(), AcceptanceData::default(), ZERO_HASH);

        // Init the virtual selected chain store
        let mut batch = WriteBatch::default();
        let mut selected_chain_write = self.selected_chain_store.write();
        selected_chain_write.init_with_pruning_point(&mut batch, self.genesis.hash).unwrap();
        self.db.write(batch).unwrap();
        drop(selected_chain_write);

        // Init virtual state
        self.commit_virtual_state(
            self.virtual_stores.upgradable_read(),
            Arc::new(VirtualState::from_genesis(
                &self.genesis,
                self.sahyadri_consensus_manager.sahyadri_consensus(&[self.genesis.hash]),
            )),
            &Default::default(),
            &Default::default(),
        );
    }

    /// Finalizes the pruning point utxoset state and imports the pruning point utxoset *to* virtual utxoset
    pub fn import_pruning_point_utxo_set(
        &self,
        new_pruning_point: Hash,
        mut imported_utxo_multiset: MuHash,
    ) -> PruningImportResult<()> {
        info!("Importing the UTXO set of the pruning point {}", new_pruning_point);
        let new_pruning_point_header = self.headers_store.get_header(new_pruning_point).unwrap();
        let imported_utxo_multiset_hash = imported_utxo_multiset.finalize();
        if imported_utxo_multiset_hash != new_pruning_point_header.utxo_commitment {
            return Err(PruningImportError::ImportedMultisetHashMismatch(
                new_pruning_point_header.utxo_commitment,
                imported_utxo_multiset_hash,
            ));
        }

        {
            // Set the pruning point utxoset position to the new point we just verified
            let mut batch = WriteBatch::default();
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            pruning_meta_write.set_utxoset_position(&mut batch, new_pruning_point).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_meta_write);
        }

        {
            // Copy the pruning-point UTXO set into virtual's UTXO set
            let pruning_meta_read = self.pruning_meta_stores.read();
            let _virtual_write = self.virtual_stores.write();

            // virtual_write.utxo_set.clear().unwrap();
            for _chunk in &pruning_meta_read.utxo_set.iterator().map(|iter_result| iter_result.unwrap()).chunks(1000) {
                // virtual_write.utxo_set.write_from_iterator_without_cache(chunk).unwrap();
            }
        }

        let virtual_read = self.virtual_stores.upgradable_read();

        // Validate transactions of the pruning point itself
        let dummy_view = sahyadri_consensus_core::utxo::utxo_collection::UtxoCollection::default();
        let new_pruning_point_transactions = vec![]; // SAHYADRI ACCOUNT BYPASS: Dummy variable
        let validated_transactions = self.validate_transactions_in_parallel(
            &new_pruning_point_transactions,
            &dummy_view,
            new_pruning_point_header.daa_score,
            TxValidationFlags::Full,
        );

        if validated_transactions.len() < new_pruning_point_transactions.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(PruningImportError::NewPruningPointTxErrors);
        }

        {
            // Submit partial UTXO state for the pruning point.
            // Note we only have and need the multiset; acceptance data and utxo-diff are irrelevant.
            let mut batch = WriteBatch::default();
            self.utxo_multisets_store.set_batch(&mut batch, new_pruning_point, imported_utxo_multiset.clone()).unwrap();

            let statuses_write = self.statuses_store.set_batch(&mut batch, new_pruning_point, StatusUTXOValid).unwrap();
            self.db.write(batch).unwrap();
            drop(statuses_write);
        }

        // Calculate the virtual state, treating the pruning point as the only virtual parent
        let virtual_parents = vec![new_pruning_point];
        let virtual_sahyadri_consensus_data = self.sahyadri_consensus_manager.sahyadri_consensus(&virtual_parents);

        self.calculate_and_commit_virtual_state(
            virtual_read,
            virtual_parents,
            virtual_sahyadri_consensus_data,
            imported_utxo_multiset.clone(),
            &mut UtxoDiff::default(),
            &ChainPath::default(),
        )?;

        Ok(())
    }

    pub fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        // Ideally we would want to check if the last known pruning point has the finality point
        // in its chain, but in some cases it's impossible: let `lkp` be the last known pruning
        // point from the list, and `fup` be the first unknown pruning point (the one following `lkp`).
        // fup.blue_score - lkp.blue_score ≈ finality_depth (±k), so it's possible for `lkp` not to
        // have the finality point in its past. So we have no choice but to check if `lkp`
        // has `finality_point.finality_point` in its chain (in the worst case `fup` is one block
        // above the current finality point, and in this case `lkp` will be a few blocks above the
        // finality_point.finality_point), meaning this function can only detect finality violations
        // in depth of 2*finality_depth, and can give false negatives for smaller finality violations.
        let current_pp = self.pruning_point_store.read().pruning_point().unwrap();
        let vf = self.virtual_finality_point(&self.lkg_virtual_state.load().sahyadri_consensus_data, current_pp);
        let vff = self.depth_manager.calc_finality_point(&self.sahyadri_consensus_store.get_data(vf).unwrap(), current_pp);

        let last_known_pp = pp_list.iter().rev().find(|pp| match self.statuses_store.read().get(pp.hash).optional().unwrap() {
            Some(status) => status.is_valid(),
            None => false,
        });

        if let Some(last_known_pp) = last_known_pp {
            !self.reachability_service.is_chain_ancestor_of(vff, last_known_pp.hash)
        } else {
            // If no pruning point is known, there's definitely a finality violation
            // (normally at least genesis should be known).
            true
        }
    }

    /// Executes `op` within the thread pool associated with this processor.
    pub fn install<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        self.thread_pool.install(op)
    }
}

enum MergesetIncreaseResult {
    Accepted { increase_size: u64 },
    Rejected { new_candidate: Hash },
}
