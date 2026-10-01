use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use clap::{Arg, ArgAction, Command};
use itertools::Itertools;
use parking_lot::Mutex;
use rand::Rng;
use rand::RngCore;
use rayon::prelude::*;
use sahyadri_addresses::{Address, Prefix, Version};
use sahyadri_consensus_core::{
    config::params::TESTNET_PARAMS,
    constants::{KANA_PER_SAHYADRI, TX_VERSION},
    network::NetworkType,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, Transaction, TransactionInput, RegistryRef, TransactionOutput, RegistryUnit},
};
use sahyadri_core::{info, sahyadrid_env::version, time::unix_now, warn};
use sahyadri_dilithium::{DilithiumKeyPair, generate_keypair, generate_keypair_from_seed};
use sahyadri_grpc_client::{ClientPool, GrpcClient};
use sahyadri_notify::subscription::context::SubscriptionContext;
use sahyadri_rpc_core::{RpcRegistryUnit, api::rpc::RpcApi, notify::mode::NotificationMode};
use sahyadri_txscript::pay_to_address_script;
use sha2::{Digest, Sha256};
use tokio::time::{Instant, MissedTickBehavior, interval};

const DEFAULT_SEND_AMOUNT: u64 = 10 * KANA_PER_SAHYADRI;
const FEE_RATE: u64 = 10;
const MILLIS_PER_TICK: u64 = 10;
const ADDRESS_VERSION: Version = Version::PubKeyDilithium;

struct Stats {
    num_txs: usize,
    num_registry_units: usize,
    registry_units_amount: u64,
    num_outs: usize,
    since: u64,
}

pub struct Args {
    pub private_key: Option<String>,
    pub tps: u64,
    pub rpc_server: String,
    pub threads: u8,
    pub unleashed: bool,
    pub addr: Option<String>,
    pub priority_fee: u64,
    pub randomize_fee: bool,
    pub payload_size: usize,
    pub network: NetworkType,
}

impl Args {
    fn parse() -> Self {
        let m = cli().get_matches();
        let network = m.get_one::<String>("network").cloned().unwrap();
        let network_type = NetworkType::from_str(&network).expect("Invalid network type");
        let default_rpc_server = format!("localhost:{}", network_type.default_rpc_port());

        Args {
            private_key: m.get_one::<String>("private-key").cloned(),
            tps: m.get_one::<u64>("tps").cloned().unwrap(),
            network: network_type,
            rpc_server: m.get_one::<String>("rpcserver").cloned().unwrap_or(default_rpc_server),
            threads: m.get_one::<u8>("threads").cloned().unwrap(),
            unleashed: m.get_one::<bool>("unleashed").cloned().unwrap_or(false),
            addr: m.get_one::<String>("addr").cloned(),
            priority_fee: m.get_one::<u64>("priority-fee").cloned().unwrap_or(0),
            randomize_fee: m.get_one::<bool>("randomize-fee").cloned().unwrap_or(false),
            payload_size: m.get_one::<usize>("payload-size").cloned().unwrap_or(0),
        }
    }
}

pub fn cli() -> Command {
    Command::new("garud")
        .about(format!("{} (garud) v{}", env!("CARGO_PKG_DESCRIPTION"), version()))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("private-key").long("private-key").short('k').value_name("private-key").help("Private key in hex format"))
        .arg(
            Arg::new("tps")
                .long("tps")
                .short('t')
                .value_name("tps")
                .default_value("1")
                .value_parser(clap::value_parser!(u64))
                .help("Transactions per second"),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .short('n')
                .value_name("network")
                .default_value("testnet")
                .value_parser(["testnet", "devnet"])
                .help("Network to use (testnet or devnet)"),
        )
        .arg(
            Arg::new("rpcserver")
                .long("rpcserver")
                .short('s')
                .value_name("rpcserver")
                .help("RPC server (defaults: testnet=16210, devnet=16610"),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .default_value("2")
                .value_parser(clap::value_parser!(u8))
                .help("The number of threads to use for TX generation. Set to 0 to use 1 thread per core. Default is 2."),
        )
        .arg(Arg::new("unleashed").long("unleashed").action(ArgAction::SetTrue).hide(true).help("Allow higher TPS"))
        .arg(Arg::new("addr").long("to-addr").short('a').value_name("addr").help("address to send to"))
        .arg(
            Arg::new("priority-fee")
                .long("priority-fee")
                .short('f')
                .value_name("priority-fee")
                .default_value("0")
                .value_parser(clap::value_parser!(u64))
                .help("Transaction priority fee"),
        )
        .arg(
            Arg::new("randomize-fee")
                .long("randomize-fee")
                .short('r')
                .value_name("randomize-fee")
                .action(ArgAction::SetTrue)
                .default_value("false")
                .help("Randomize transaction priority fee"),
        )
        .arg(
            Arg::new("payload-size")
                .long("payload-size")
                .short('p')
                .value_name("payload-size")
                .hide(true)
                .default_value("0")
                .value_parser(clap::value_parser!(usize))
                .help("Randomized payload size"),
        )
}

async fn new_rpc_client(subscription_context: &SubscriptionContext, address: &str) -> GrpcClient {
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", address),
        Some(subscription_context.clone()),
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .unwrap()
}

struct ClientPoolArg {
    tx: Transaction,
    stats: Arc<Mutex<Stats>>,
    selected_registry_units_len: usize,
    selected_registry_units_amount: u64,
    pending_len: usize,
    registry_units_len: usize,
}

struct TxConfig {
    priority_fee: u64,
    randomize_fee: bool,
    payload_size: usize,
}

#[tokio::main]
async fn main() {
    sahyadri_core::log::init_logger(None, "");
    let args = Args::parse();

    let address_prefix = Prefix::from(args.network);

    let stats = Arc::new(Mutex::new(Stats { num_txs: 0, since: unix_now(), num_registry_units: 0, registry_units_amount: 0, num_outs: 0 }));
    let subscription_context = SubscriptionContext::new();
    let rpc_client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", args.rpc_server),
        Some(subscription_context.clone()),
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .expect("Critical error: failed to connect to the RPC server.");

    info!("Connected to RPC");

    let mut pending: HashMap<RegistryRef, Instant> = HashMap::new();

    let dilithium_keypair = if let Some(private_key_hex) = args.private_key {
        let mut seed = [0u8; 32];
        faster_hex::hex_decode(private_key_hex.as_bytes(), &mut seed).unwrap();
        generate_keypair_from_seed(&seed)
    } else {
        let kp = generate_keypair().expect("Failed to generate Dilithium keypair");
        let pk_hash = Sha256::digest(kp.public_key());
        let sahyadri_addr = Address::new(address_prefix, ADDRESS_VERSION, &pk_hash[0..20]);
        info!(
            "Generated Dilithium keypair and address {}. Send some funds to this address and rerun garud with `--private-key <seed-hex>`",
            String::from(&sahyadri_addr),
        );
        return;
    };

    let pk_hash = Sha256::digest(dilithium_keypair.public_key());
    let sahyadri_addr = Address::new(address_prefix, ADDRESS_VERSION, &pk_hash[0..20]);

    let sahyadri_to_addr =
        args.addr.as_ref().map_or_else(|| sahyadri_addr.clone(), |addr_str| Address::try_from(addr_str.clone()).unwrap());

    (args.payload_size <= 20000).then_some(()).expect("payload-size can be max 20000");

    let tx_config = TxConfig { priority_fee: args.priority_fee, randomize_fee: args.randomize_fee, payload_size: args.payload_size };

    rayon::ThreadPoolBuilder::new().num_threads(args.threads as usize).build_global().unwrap();

    let mut log_message = format!(
        "Using Garud with:\n\
        \tnetwork: {}\n\
        \tpubkey: {}\n\
        \tfrom address: {}",
        args.network,
        sahyadri_dilithium::pubkey_to_hex(&dilithium_keypair),
        String::from(&sahyadri_addr)
    );
    if args.addr.is_some() {
        log_message.push_str(&format!("\n\tto address: {}", String::from(&sahyadri_to_addr)));
    }
    if args.priority_fee != 0 {
        log_message.push_str(&format!(
            "\n\tpriority fee: {} SOMPS {}",
            tx_config.priority_fee,
            if tx_config.randomize_fee { "[randomize]" } else { "" }
        ));
    }
    if args.payload_size != 0 {
        log_message.push_str(&format!("\n\tpayload size: {} random bytes", tx_config.payload_size,));
    }
    info!("{}", log_message);

    let info = rpc_client.get_sahyadri_dag_info().await.expect("Failed to get block dag info.");

    let coinbase_maturity = match info.network.suffix {
        Some(11) => panic!("TN11 is not supported on this version"),
        None | Some(_) => TESTNET_PARAMS.coinbase_maturity(),
    };
    info!(
        "Node block-DAG info: \n\tNetwork: {}, \n\tBlock count: {}, \n\tHeader count: {}, \n\tDifficulty: {},
\tMedian time: {}, \n\tDAA score: {}, \n\tPruning point: {}, \n\tTips: {}, \n\t{} virtual parents: ...{}, \n\tCoinbase maturity: {}",
        info.network,
        info.block_count,
        info.header_count,
        info.difficulty,
        info.past_median_time,
        info.virtual_daa_score,
        info.pruning_point_hash,
        info.tip_hashes.len(),
        info.virtual_parent_hashes.len(),
        info.virtual_parent_hashes.last().unwrap(),
        coinbase_maturity,
    );

    const CLIENT_POOL_SIZE: usize = 8;
    let mut rpc_clients = Vec::with_capacity(CLIENT_POOL_SIZE);
    for _ in 0..CLIENT_POOL_SIZE {
        rpc_clients.push(Arc::new(new_rpc_client(&subscription_context, &args.rpc_server).await));
    }

    let submit_tx_pool = ClientPool::new(rpc_clients, 1000);
    let _ = submit_tx_pool.start(|c, arg: ClientPoolArg| async move {
        let ClientPoolArg { tx, stats, selected_registry_units_len, selected_registry_units_amount, pending_len, registry_units_len } = arg;
        match c.submit_transaction(tx.as_ref().into(), false).await {
            Ok(_) => {
                let mut stats = stats.lock();
                stats.num_txs += 1;
                stats.num_registry_units += selected_registry_units_len;
                stats.registry_units_amount += selected_registry_units_amount;
                stats.num_outs += tx.outputs.len();
                let now = unix_now();
                let time_past = now - stats.since;
                if time_past > 10_000 {
                    info!(
                        "Tx rate: {:.1}/sec, avg REGISTRY_UNIT amount: {}, avg REGISTRY_UNITs per tx: {}, avg outs per tx: {}, estimated available REGISTRY_UNITs: {}",
                        1000f64 * (stats.num_txs as f64) / (time_past as f64),
                        stats.registry_units_amount / stats.num_registry_units as u64,
                        stats.num_registry_units / stats.num_txs,
                        stats.num_outs / stats.num_txs,
                        registry_units_len.saturating_sub(pending_len),
                    );
                    stats.since = now;
                    stats.num_txs = 0;
                    stats.num_registry_units = 0;
                    stats.registry_units_amount = 0;
                    stats.num_outs = 0;
                }
            }
            Err(e) => {
                let mut tx = tx;
                tx.finalize();
                warn!("RPC error when submitting {}: {}", tx.id(), e);
            }
        }
        false
    });
    let tx_sender = submit_tx_pool.sender();

    let target_tps = args.tps.min(if args.unleashed { u64::MAX } else { 100 });
    let should_tick_per_second = target_tps * MILLIS_PER_TICK / 1000 == 0;
    let avg_txs_per_tick = if should_tick_per_second { target_tps } else { target_tps * MILLIS_PER_TICK / 1000 };
    let mut registry_units = refresh_registry_units(&rpc_client, sahyadri_addr.clone(), &mut pending, coinbase_maturity).await;
    let mut ticker = interval(Duration::from_millis(if should_tick_per_second { 1000 } else { MILLIS_PER_TICK }));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut maximize_inputs = false;
    let mut last_refresh = unix_now();
    // This allows us to keep track of the REGISTRY_UNITs we already tried to use for this period
    // until the REGISTRY_UNITs are refreshed. At that point, this will be reset as well.
    let mut next_available_registry_unit_index = 0;
    // Tracker so we can try to send as close as possible to the target TPS
    let mut remaining_txs_in_interval = target_tps;

    loop {
        ticker.tick().await;
        maximize_inputs = should_maximize_inputs(maximize_inputs, &registry_units, &pending);
        let txs_to_send = if remaining_txs_in_interval > avg_txs_per_tick * 2 {
            remaining_txs_in_interval -= avg_txs_per_tick;
            avg_txs_per_tick
        } else {
            let count = remaining_txs_in_interval;
            remaining_txs_in_interval = target_tps;
            count
        };

        let now = unix_now();
        let has_funds = maybe_send_tx(
            txs_to_send,
            &tx_sender,
            sahyadri_to_addr.clone(),
            &mut registry_units,
            &mut pending,
            dilithium_keypair.clone(),
            stats.clone(),
            maximize_inputs,
            &mut next_available_registry_unit_index,
            &tx_config,
        )
        .await;
        if !has_funds {
            info!("Has not enough funds");
        }
        if !has_funds || now - last_refresh > 60_000 {
            info!("Refetching REGISTRY_UNIT set");
            tokio::time::sleep(Duration::from_millis(100)).await; // We don't want this operation to be too frequent since its heavy on the node, so we wait some time before executing it.
            registry_units = refresh_registry_units(&rpc_client, sahyadri_addr.clone(), &mut pending, coinbase_maturity).await;
            last_refresh = unix_now();
            next_available_registry_unit_index = 0;
            pause_if_mempool_is_full(&rpc_client).await;
        }
        clean_old_pending_outpoints(&mut pending);
    }
}

fn should_maximize_inputs(
    old_value: bool,
    registry_units: &[(RegistryRef, RegistryUnit)],
    pending: &HashMap<RegistryRef, Instant>,
) -> bool {
    let estimated_registry_units = if registry_units.len() > pending.len() { registry_units.len() - pending.len() } else { 0 };
    if !old_value && estimated_registry_units > 1_000_000 {
        info!("Starting to maximize inputs");
        true
    } else if old_value && estimated_registry_units < 500_000 {
        info!("Stopping to maximize inputs");
        false
    } else {
        old_value
    }
}

async fn pause_if_mempool_is_full(rpc_client: &GrpcClient) {
    loop {
        let mempool_size = rpc_client.get_info().await.unwrap().mempool_size;
        if mempool_size < 200_000 {
            break;
        }

        const PAUSE_DURATION: u64 = 10;
        info!("Mempool has {} entries. Pausing for {} seconds to reduce mempool pressure", mempool_size, PAUSE_DURATION);
        tokio::time::sleep(Duration::from_secs(PAUSE_DURATION)).await;
    }
}

async fn refresh_registry_units(
    rpc_client: &GrpcClient,
    sahyadri_addr: Address,
    pending: &mut HashMap<RegistryRef, Instant>,
    coinbase_maturity: u64,
) -> Vec<(RegistryRef, RegistryUnit)> {
    populate_pending_outpoints_from_mempool(rpc_client, sahyadri_addr.clone(), pending).await;
    fetch_spendable_registry_units(rpc_client, sahyadri_addr, coinbase_maturity, pending).await
}

async fn populate_pending_outpoints_from_mempool(
    rpc_client: &GrpcClient,
    sahyadri_addr: Address,
    pending_outpoints: &mut HashMap<RegistryRef, Instant>,
) {
    let entries = rpc_client.get_mempool_entries_by_addresses(vec![sahyadri_addr], true, false).await.unwrap();
    let now = Instant::now();

    for entry in entries {
        for entry in entry.sending {
            for input in entry.transaction.inputs {
                pending_outpoints.insert(input.previous_outpoint.into(), now);
            }
        }
    }
}

async fn fetch_spendable_registry_units(
    rpc_client: &GrpcClient,
    sahyadri_addr: Address,
    coinbase_maturity: u64,
    pending: &mut HashMap<RegistryRef, Instant>,
) -> Vec<(RegistryRef, RegistryUnit)> {
    let resp = rpc_client.get_registry_by_addresses(vec![sahyadri_addr]).await.unwrap();
    let dag_info = rpc_client.get_sahyadri_dag_info().await.unwrap();

    let mut registry_units = resp.into_iter()
        .filter(|entry| {
            is_registry_unit_spendable(&entry.registry_unit_entry, dag_info.virtual_daa_score, coinbase_maturity)
        })
        .map(|entry| (RegistryRef::from(entry.outpoint), RegistryUnit::from(entry.registry_unit_entry)))
        // Eliminates REGISTRY_UNITs we already tried to spend so we don't try to spend them again in this period
        .filter(|(outpoint,_)| !pending.contains_key(outpoint))
        .collect::<Vec<_>>();
    registry_units.sort_by_key(|b| std::cmp::Reverse(b.1.amount));
    registry_units
}

fn is_registry_unit_spendable(entry: &RpcRegistryUnit, virtual_daa_score: u64, coinbase_maturity: u64) -> bool {
    let needed_confs = if !entry.is_coinbase {
        10
    } else {
        coinbase_maturity * 2 // TODO: We should compare with sink blue score in the case of coinbase
    };
    entry.block_daa_score + needed_confs < virtual_daa_score
}

async fn maybe_send_tx(
    txs_to_send: u64,
    tx_sender: &async_channel::Sender<ClientPoolArg>,
    sahyadri_addr: Address,
    registry_units: &mut [(RegistryRef, RegistryUnit)],
    pending: &mut HashMap<RegistryRef, Instant>,
    dilithium_keypair: DilithiumKeyPair,
    stats: Arc<Mutex<Stats>>,
    maximize_inputs: bool,
    next_available_registry_unit_index: &mut usize,
    tx_config: &TxConfig,
) -> bool {
    let num_outs = if maximize_inputs { 1 } else { 2 };

    let mut has_fund = false;

    let selected_registry_units_groups = (0..txs_to_send)
        .map(|_| {
            let (selected_registry_units, selected_amount) =
                select_registry_units(registry_units, DEFAULT_SEND_AMOUNT, num_outs, maximize_inputs, next_available_registry_unit_index, tx_config);
            if selected_amount == 0 {
                return None;
            }

            // If any iteration successfully selected REGISTRY_UNITs, we assume to still
            // have funds in this tick
            has_fund = true;

            let now = Instant::now();
            for input in selected_registry_units.iter() {
                pending.insert(input.0, now);
            }

            Some((selected_registry_units, selected_amount))
        })
        .collect::<Vec<_>>();

    if !has_fund {
        return false;
    }

    let txs = selected_registry_units_groups
        .into_par_iter()
        .map(|registry_unit_option| {
            if let Some((selected_registry_units, selected_amount)) = registry_unit_option {
                let tx = generate_tx(
                    dilithium_keypair.clone(),
                    &selected_registry_units,
                    selected_amount,
                    num_outs,
                    &sahyadri_addr,
                    tx_config.payload_size,
                );

                return Some((tx, selected_registry_units.len(), selected_registry_units.into_iter().map(|(_, entry)| entry.amount).sum::<u64>()));
            }

            None
        })
        .collect::<Vec<_>>();

    for (tx, selected_registry_units_len, selected_registry_units_amount) in txs.into_iter().flatten() {
        tx_sender
            .send(ClientPoolArg {
                tx,
                stats: stats.clone(),
                selected_registry_units_len,
                selected_registry_units_amount,
                pending_len: pending.len(),
                registry_units_len: registry_units.len(),
            })
            .await
            .unwrap();
    }

    true
}

fn clean_old_pending_outpoints(pending: &mut HashMap<RegistryRef, Instant>) {
    let now = Instant::now();
    pending.retain(|_, &mut time| now.duration_since(time) <= Duration::from_secs(3600));
}

fn required_fee(num_registry_units: usize, num_outs: u64) -> u64 {
    FEE_RATE * estimated_mass(num_registry_units, num_outs)
}

fn estimated_mass(num_registry_units: usize, num_outs: u64) -> u64 {
    200 + 34 * num_outs + 1000 * (num_registry_units as u64)
}

fn generate_tx(
    dilithium_keypair: DilithiumKeyPair,
    registry_units: &[(RegistryRef, RegistryUnit)],
    send_amount: u64,
    num_outs: u64,
    sahyadri_addr: &Address,
    payload_size: usize,
) -> Transaction {
    let script_public_key = pay_to_address_script(sahyadri_addr);
    let inputs = registry_units
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect_vec();

    let outputs = (0..num_outs)
        .map(|_| TransactionOutput { value: send_amount / num_outs, script_public_key: script_public_key.clone() })
        .collect_vec();
    let mut data = vec![0u8; payload_size];
    rand::thread_rng().fill_bytes(&mut data);
    let unsigned_tx = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, data);
    let signed_tx = sign(
        MutableTransaction::with_entries(unsigned_tx, registry_units.iter().map(|(_, entry)| entry.clone()).collect_vec()),
        &dilithium_keypair,
    );
    signed_tx.tx
}

fn select_registry_units(
    registry_units: &[(RegistryRef, RegistryUnit)],
    min_amount: u64,
    num_outs: u64,
    maximize_registry_units: bool,
    next_available_registry_unit_index: &mut usize,
    tx_config: &TxConfig,
) -> (Vec<(RegistryRef, RegistryUnit)>, u64) {
    const MAX_REGISTRY_UNITS: usize = 8;
    let mut selected_amount: u64 = 0;
    let mut selected = Vec::new();
    let mut rng = rand::thread_rng();

    while next_available_registry_unit_index < &mut registry_units.len() {
        let (outpoint, entry) = registry_units[*next_available_registry_unit_index].clone();
        selected_amount += entry.amount;
        selected.push((outpoint, entry));

        let fee = required_fee(selected.len(), num_outs);
        let priority_fee = if tx_config.randomize_fee && tx_config.priority_fee > 0 {
            rng.gen_range(0..tx_config.priority_fee)
        } else {
            tx_config.priority_fee
        };

        *next_available_registry_unit_index += 1;

        if selected_amount >= min_amount + fee + priority_fee && (!maximize_registry_units || selected.len() == MAX_REGISTRY_UNITS) {
            return (selected, selected_amount - fee - priority_fee);
        }

        if selected.len() > MAX_REGISTRY_UNITS {
            return (vec![], 0);
        }
    }

    (vec![], 0)
}
