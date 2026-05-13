use indexmap::IndexSet;
use itertools::Itertools;
use sahyadri_consensus::consensus::Consensus;
use sahyadri_consensus::model::stores::virtual_state::VirtualStateStoreReader;
use sahyadri_consensus::params::Params;
use sahyadri_consensus_core::api::ConsensusApi;
use sahyadri_consensus_core::block::{Block, TemplateBuildMode, TemplateTransactionSelector};
use sahyadri_consensus_core::coinbase::MinerData;
use sahyadri_consensus_core::mass::MassCalculator;
use sahyadri_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use sahyadri_consensus_core::tx::{
    ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use sahyadri_consensus_core::utxo::utxo_view::UtxoView;
use sahyadri_core::trace;
use sahyadri_utils::sim::{Environment, Process, Resumption, Suspension};
use rand::Rng;
use rand::rngs::ThreadRng;
use rand_distr::{Distribution, Exp};
use std::cmp::max;
use std::iter::once;
use std::sync::Arc;

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs) }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap()
    }

    fn reject_selection(&mut self, _tx_id: sahyadri_consensus_core::tx::TransactionId) {
        unimplemented!()
    }

    fn is_successful(&self) -> bool {
        true
    }
}

pub struct Miner {
    // ID
    pub(super) id: u64,

    // Consensus
    pub(super) consensus: Arc<Consensus>,
    pub(super) _params: Params,

    // Miner data
    miner_data: MinerData,
    _secret_key: secp256k1::SecretKey,

    // UTXO data related to this miner
    possible_unspent_outpoints: IndexSet<TransactionOutpoint>,

    // Rand
    dist: Exp<f64>, // The time interval between Poisson(lambda) events distributes ~Exp(lambda)
    rng: ThreadRng,

    // Counters
    num_blocks: u64,
    sim_time: u64,

    // Config
    _target_txs_per_block: u64,
    target_blocks: Option<u64>,
    max_cached_outpoints: usize,
    _long_payload: bool,

    // Mass calculator
    _mass_calculator: MassCalculator,
}

impl Miner {
    pub fn new(
        id: u64,
        bps: f64,
        hashrate: f64,
        sk: secp256k1::SecretKey,
        pk: secp256k1::PublicKey,
        consensus: Arc<Consensus>,
        params: &Params,
        target_txs_per_block: u64,
        target_blocks: Option<u64>,
        long_payload: bool,
    ) -> Self {
        let (schnorr_public_key, _) = pk.x_only_public_key();
        let script_pub_key_script = once(0x20).chain(schnorr_public_key.serialize()).chain(once(0xac)).collect_vec(); // TODO: Use script builder when available to create p2pk properly
        let script_pub_key_script_vec = ScriptVec::from_slice(&script_pub_key_script);
        Self {
            id,
            consensus,
            _params: params.clone(),
            miner_data: MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&script_pub_key_script_vec)), Vec::new()),
            _secret_key: sk,
            possible_unspent_outpoints: IndexSet::new(),
            dist: Exp::new(bps * hashrate).unwrap(),
            rng: rand::thread_rng(),
            num_blocks: 0,
            sim_time: 0,
            _target_txs_per_block: target_txs_per_block,
            target_blocks,
            _long_payload: long_payload,
            max_cached_outpoints: 10_000,
            _mass_calculator: MassCalculator::new(
                params.mass_per_tx_byte,
                params.mass_per_script_pub_key_byte,
                params.mass_per_sig_op,
                params.storage_mass_parameter,
            ),
        }
    }

    fn build_new_block(&mut self, timestamp: u64) -> Block {
        let txs = self.build_txs();
        let nonce = self.id;
        let session = self.consensus.acquire_session();
        let mut block_template = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard)
            .expect("simulation txs are selected in sync with virtual state and are expected to be valid");
        drop(session);
        block_template.block.header.timestamp = timestamp; // Use simulation time rather than real time
        block_template.block.header.nonce = nonce;
        block_template.block.header.finalize();
        block_template.block.to_immutable()
    }

    fn build_txs(&mut self) -> Vec<Transaction> {
        let virtual_read = self.consensus.virtual_stores.read();
        let _virtual_state = virtual_read.state.get().unwrap(); 

        // ---------------------------------------------------------
        // SAHYADRI ACCOUNT MODEL FIX
        // UTXO (`utxo_set` and `possible_unspent_outpoints`) has been removed.
        // In the Account model, transactions use Balances and Nonces.
        // ---------------------------------------------------------

        let txs = Vec::new();

        // TODO for Simulator: 
        // 1. Fetch simulator account balances from `self.consensus.account_store()`
        // 2. Build `tx.payload` as `[sender_script_bytes][nonce_bytes]`
        // 3. Push to `txs` vector.

        txs
    }

    fn _get_spendable_entry(
        &self,
        utxo_view: &impl UtxoView,
        outpoint: TransactionOutpoint,
        virtual_daa_score: u64,
    ) -> Option<UtxoEntry> {
        let entry = utxo_view.get(&outpoint)?;
        if entry.amount < 2
            || (entry.is_coinbase
                && (virtual_daa_score as i64 - entry.block_daa_score as i64) <= self._params.coinbase_maturity() as i64)
        {
            return None;
        }
        Some(entry)
    }

    fn _create_unsigned_tx(&self, outpoint: TransactionOutpoint, input_amount: u64, multiple_outputs: bool) -> Transaction {
        Transaction::new_non_finalized(
            0,
            vec![TransactionInput::new(outpoint, vec![], 0, 0)],
            if multiple_outputs && input_amount > 4 {
                vec![
                    TransactionOutput::new(input_amount / 2, self.miner_data.script_public_key.clone()),
                    TransactionOutput::new(input_amount / 2 - 1, self.miner_data.script_public_key.clone()),
                ]
            } else {
                vec![TransactionOutput::new(input_amount - 1, self.miner_data.script_public_key.clone())]
            },
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )
    }

    pub fn mine(&mut self, env: &mut Environment<Block>) -> Suspension {
        let block = self.build_new_block(env.now());
        env.broadcast(self.id, block);
        self.sample_mining_interval()
    }

    fn sample_mining_interval(&mut self) -> Suspension {
        Suspension::Timeout(max((self.dist.sample(&mut self.rng) * 1000.0) as u64, 1))
    }

    fn process_block(&mut self, block: Block, env: &mut Environment<Block>) -> Suspension {
        for tx in block.transactions.iter() {
            for (i, output) in tx.outputs.iter().enumerate() {
                if output.script_public_key.eq(&self.miner_data.script_public_key) {
                    if self.possible_unspent_outpoints.len() == self.max_cached_outpoints {
                        self.possible_unspent_outpoints.swap_remove_index(self.rng.gen_range(0..self.max_cached_outpoints));
                    }
                    self.possible_unspent_outpoints.insert(TransactionOutpoint::new(tx.id(), i as u32));
                }
            }
        }
        if self.report_progress(env) {
            Suspension::Halt
        } else {
            let session = self.consensus.acquire_session();
            let status = futures::executor::block_on(self.consensus.validate_and_insert_block(block).virtual_state_task).unwrap();
            assert!(status.is_utxo_valid_or_pending());
            drop(session);
            Suspension::Idle
        }
    }

    fn report_progress(&mut self, env: &mut Environment<Block>) -> bool {
        self.num_blocks += 1;
        if let Some(target_blocks) = self.target_blocks
            && self.num_blocks > target_blocks
        {
            return true; // Exit
        }
        if self.id != 0 {
            return false;
        }
        if self.num_blocks.is_multiple_of(50) || self.sim_time / 5000 != env.now() / 5000 {
            trace!("Simulation time: {}\tGenerated {} blocks", env.now() as f64 / 1000.0, self.num_blocks);
        }
        self.sim_time = env.now();
        false
    }
}

impl Process<Block> for Miner {
    fn resume(&mut self, resumption: Resumption<Block>, env: &mut Environment<Block>) -> Suspension {
        match resumption {
            Resumption::Initial => self.sample_mining_interval(),
            Resumption::Scheduled => self.mine(env),
            Resumption::Message(block) => self.process_block(block, env),
        }
    }
}
