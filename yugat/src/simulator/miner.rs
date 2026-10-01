use indexmap::IndexSet;
use itertools::Itertools;
use rand::Rng;
use rand::rngs::ThreadRng;
use rand_distr::{Distribution, Exp};
use sahyadri_consensus::consensus::Consensus;
use sahyadri_consensus::model::stores::virtual_state::VirtualStateStoreReader;
use sahyadri_consensus::params::Params;
use sahyadri_consensus_core::api::ConsensusApi;
use sahyadri_consensus_core::block::{Block, TemplateBuildMode, TemplateTransactionSelector};
use sahyadri_consensus_core::coinbase::MinerData;
use sahyadri_consensus_core::mass::MassCalculator;
use sahyadri_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId};
use sahyadri_core::trace;
use sahyadri_utils::sim::{Environment, Process, Resumption, Suspension};
use sha2::Digest;
use std::cmp::max;
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

    fn reject_selection(&mut self, _tx_id: TransactionId) {
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
    _keypair: sahyadri_dilithium::DilithiumKeyPair,

    /// Script public keys this miner controls. Populated from coinbase
    /// outputs seen in processed blocks. In the account model there is no
    /// per-outpoint tracking — spendability is resolved against the on-chain
    /// `AccountState` balance at build-tx time.
    owned_script_keys: IndexSet<ScriptPublicKey>,

    // Rand
    dist: Exp<f64>, // The time interval between Poisson(lambda) events distributes ~Exp(lambda)
    rng: ThreadRng,

    // Counters
    num_blocks: u64,
    sim_time: u64,

    // Config
    _target_txs_per_block: u64,
    target_blocks: Option<u64>,
    max_cached_script_keys: usize,
    _long_payload: bool,

    // Mass calculator
    _mass_calculator: MassCalculator,
}

impl Miner {
    pub fn new(
        id: u64,
        bps: f64,
        hashrate: f64,
        keypair: sahyadri_dilithium::DilithiumKeyPair,
        consensus: Arc<Consensus>,
        params: &Params,
        target_txs_per_block: u64,
        target_blocks: Option<u64>,
        long_payload: bool,
    ) -> Self {
        let pk_hash = sha2::Sha256::digest(keypair.public_key());
        let script_pub_key_script =
            std::iter::once(0x14u8).chain(pk_hash[0..20].iter().copied()).chain(std::iter::once(0xac)).collect_vec();
        let script_pub_key_script_vec = ScriptVec::from_slice(&script_pub_key_script);
        Self {
            id,
            consensus,
            _params: params.clone(),
            miner_data: MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&script_pub_key_script_vec)), Vec::new()),
            _keypair: keypair,
            owned_script_keys: IndexSet::new(),
            dist: Exp::new(bps * hashrate).unwrap(),
            rng: rand::thread_rng(),
            num_blocks: 0,
            sim_time: 0,
            _target_txs_per_block: target_txs_per_block,
            target_blocks,
            _long_payload: long_payload,
            max_cached_script_keys: 10_000,
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

        // ─────────────────────────────────────────────────────────────
        // SAHYADRI ACCOUNT MODEL
        //
        // In the account model there is no per-outpoint tracking. A tx is
        // signed by the sender's ML-DSA-65 pubkey, and validation reads the
        // sender's `AccountState` (balance + recent_flashes) directly from
        // the SMT-backed account store.
        //
        // TODO(simulator):
        //   1. For each sender in `owned_script_keys`, fetch its AccountState
        //      via `consensus.account_store().get(&spk)`.
        //   2. Construct a FlashTransaction (see consensus_core::tx::FlashTransaction)
        //      with pubkey/recipient/amount/fee/expiry/salt/signature.
        //   3. Push `flash_tx.to_transaction()` into `txs`.
        //
        // Until the simulator needs to actually submit txs, we return empty.
        // ─────────────────────────────────────────────────────────────
        Vec::new()
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
        // Track coinbase outputs paid to us — in the account model this is
        // equivalent to recording that "we own this script_public_key".
        for tx in block.transactions.iter() {
            for output in tx.outputs.iter() {
                if output.script_public_key == self.miner_data.script_public_key {
                    if self.owned_script_keys.len() == self.max_cached_script_keys {
                        self.owned_script_keys.swap_remove_index(self.rng.gen_range(0..self.max_cached_script_keys));
                    }
                    self.owned_script_keys.insert(output.script_public_key.clone());
                }
            }
        }
        if self.report_progress(env) {
            Suspension::Halt
        } else {
            let session = self.consensus.acquire_session();
            let status = futures::executor::block_on(self.consensus.validate_and_insert_block(block).virtual_state_task).unwrap();
            assert!(status.is_state_valid_or_pending());
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
