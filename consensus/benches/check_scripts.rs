#![allow(dead_code, unused_imports, unused_variables)]
use sahyadri_database::create_temp_db;
use sahyadri_database::prelude::ConnBuilder;
use criterion::{Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use sahyadri_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput};
use sahyadri_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use sahyadri_consensus::processes::transaction_validator::TransactionValidator;

// Generates a mock transaction using the Account model.
// Inputs are empty, and the payload contains native sovereign data (e.g., Web5 DIDs).
fn mock_account_tx(payload_size: usize) -> Transaction {
    Transaction::new(
        0, // version
        vec![], // Empty inputs for pure account transactions
        vec![], // Outputs
        0, // lock_time
        SUBNETWORK_ID_NATIVE,
        0, // gas (must be 0 as per Sahyadri L1 rules)
        vec![0u8; payload_size], // Payload for Decentralized Identifiers (DIDs)
    )
}

fn benchmark_tx_isolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Transaction Isolation Validation");
    group.sampling_mode(SamplingMode::Flat);

    // Initialize an In-Memory State Database for Zero-Latency Benchmarking.
    // This ensures we measure pure CPU processing speed (TPS) and L1 rules, 
    // without getting bottlenecked by SSD/Disk I/O read/write speeds.
    let db = sahyadri_database::create_temp_db!(sahyadri_database::prelude::ConnBuilder::default().with_files_limit(10)).1;
    let account_store = std::sync::Arc::new(sahyadri_consensus::model::stores::account_store::DbAccountStore::new(
        db.clone(),
        10000, // L1 Cache size
    ));

    let validator = TransactionValidator::new_for_tests(
        1000, 1000, 1650, 1000, 100, 1000, sahyadri_consensus_core::KType::from(10u16), Default::default(), account_store
    );


    // Benchmark different payload sizes (e.g., small DID vs large Verifiable Credential)
    for payload_size in [32, 256, 1024, 4096] {
        let tx = mock_account_tx(payload_size);
        group.bench_function(format!("payload_size: {payload_size} bytes"), |b| {
            b.iter(|| {
                // Testing the core L1 rule engine (Anti-spam, fee checks, etc.)
                let _ = validator.validate_tx_in_isolation(black_box(&tx));
            })
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_output_color(true).measurement_time(std::time::Duration::new(10, 0));
    targets = benchmark_tx_isolation
}

criterion_main!(benches);
