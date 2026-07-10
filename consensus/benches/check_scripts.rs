#![allow(dead_code, unused_imports, unused_variables)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use sahyadri_consensus::model::stores::account_store::{AccountStore, DbAccountStore};
use sahyadri_consensus::processes::transaction_validator::TransactionValidator;
use sahyadri_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use sahyadri_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use sahyadri_database::create_temp_db;
use sahyadri_database::prelude::ConnBuilder;
use smallvec::smallvec;
use std::sync::Arc;

fn mock_account_tx(payload_size: usize) -> Transaction {
    Transaction::new(
        0,
        vec![],
        vec![TransactionOutput {
            value: 1000,
            script_public_key: ScriptPublicKey::new(0, smallvec![0x14; 22]),
        }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![0u8; payload_size],
    )
}

fn mock_payment_tx(payload_size: usize) -> Transaction {
    let mut payload = vec![0u8; payload_size];
    let nonce_bytes = 1u64.to_le_bytes();
    payload[payload_size - 8..].copy_from_slice(&nonce_bytes);
    Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint::new(
                sahyadri_consensus_core::tx::TransactionId::from_bytes([0u8; 32]),
                0,
            ),
            signature_script: vec![0u8; 2420],
            sequence: 0,
            sig_op_count: 1,
        }],
        vec![TransactionOutput {
            value: 500,
            script_public_key: ScriptPublicKey::new(0, smallvec![0x14; 22]),
        }],
        1615462089000,
        SUBNETWORK_ID_NATIVE,
        1000,
        payload,
    )
}

fn benchmark_all(c: &mut Criterion) {
    let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
    let account_store = Arc::new(DbAccountStore::new(db.clone(), 10000));
    let validator = TransactionValidator::new_for_tests(
        1000, 1000, 1650, 1000, 100, 1000,
        sahyadri_consensus_core::KType::from(10u16),
        Default::default(),
        account_store.clone(),
    );

    // ── BENCH 1: Isolation validation latency ──
    let mut g1 = c.benchmark_group("1_isolation_validation");
    g1.sampling_mode(SamplingMode::Flat);
    for &sz in &[32, 256, 1024, 4096] {
        let tx = mock_account_tx(sz);
        g1.throughput(Throughput::Elements(1));
        g1.bench_function(format!("payload_{}b", sz), |b| {
            b.iter(|| validator.validate_tx_in_isolation(black_box(&tx)));
        });
    }
    let pay_tx = mock_payment_tx(256);
    g1.throughput(Throughput::Elements(1));
    g1.bench_function("payment_tx_256b", |b| {
        b.iter(|| validator.validate_tx_in_isolation(black_box(&pay_tx)));
    });
    g1.finish();

    // ── BENCH 2: Balance store operations ──
    let mut g2 = c.benchmark_group("2_balance_store");
    g2.sampling_mode(SamplingMode::Flat);
    let spk = ScriptPublicKey::new(0, smallvec![0x14; 22]);

    g2.throughput(Throughput::Elements(1));
    g2.bench_function("update_balance_batch", |b| {
        let mut batch = rocksdb::WriteBatch::default();
        b.iter(|| {
            let _ = account_store.update_balance_batch(&mut batch, &spk, 1000);
        });
    });

    g2.throughput(Throughput::Elements(1));
    g2.bench_function("increment_nonce_batch", |b| {
        let mut batch = rocksdb::WriteBatch::default();
        b.iter(|| {
            let _ = account_store.increment_nonce_batch(&mut batch, &spk);
        });
    });
    g2.finish();

    // ── BENCH 3: Simulated block processing (100 txs) ──
    let mut g3 = c.benchmark_group("3_block_100txs");
    g3.sampling_mode(SamplingMode::Flat);
    g3.throughput(Throughput::Elements(100));

    let txs: Vec<Transaction> = (0..100).map(|i| mock_account_tx(256)).collect();
    g3.bench_function("validate_100_txs", |b| {
        b.iter(|| {
            for tx in &txs {
                let _ = validator.validate_tx_in_isolation(black_box(tx));
            }
        });
    });

    let mut batch = rocksdb::WriteBatch::default();
    g3.bench_function("balance_updates_100_txs", |b| {
        b.iter(|| {
            batch = rocksdb::WriteBatch::default();
            for tx in &txs {
                for output in tx.outputs.iter() {
                    let _ = account_store.update_balance_batch(&mut batch, &output.script_public_key, output.value as i64);
                }
            }
        });
    });
    g3.finish();

    // ── BENCH 4: DB commit (actual disk write) ──
    let mut g4 = c.benchmark_group("4_db_commit");
    g4.sampling_mode(SamplingMode::Flat);
    g4.throughput(Throughput::Elements(1));
    g4.bench_function("write_batch_100_ops", |b| {
        b.iter(|| {
            let mut batch = rocksdb::WriteBatch::default();
            for i in 0..100 {
                let key = format!("bench_key_{}", i);
                batch.put(key.as_bytes(), b"1000");
            }
            db.write(batch).unwrap();
        });
    });
    g4.finish();

    drop(validator);
    drop(account_store);
    drop(db);
    drop(lifetime);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_output_color(true)
        .measurement_time(std::time::Duration::new(10, 0));
    targets = benchmark_all
}

criterion_main!(benches);
