//! SyncWave benchmark — measures snapshot export, serialize, verify
//! on synthetic state sizes.
//!
//! Run: cargo bench -p sahyadri-smt --bench sync_wave_bench
//! Or:  cargo test -p sahyadri-smt --release run_actual_benchmark -- --nocapture

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sahyadri_smt::{update, MemStore, Node, NodeStore, EMPTY};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::time::Instant;

fn synthetic_kv(seed: u64) -> ([u8; 32], [u8; 32]) {
    let mut key_h = Sha3_256::new();
    key_h.update(b"SYNTH_KEY");
    key_h.update(seed.to_le_bytes());
    let key: [u8; 32] = key_h.finalize().into();

    let mut val_h = Sha3_256::new();
    val_h.update(b"SYNTH_VALUE");
    val_h.update(seed.to_le_bytes());
    let val: [u8; 32] = val_h.finalize().into();

    (key, val)
}

fn build_synthetic_smt(size: u64) -> (MemStore, [u8; 32]) {
    let mut store = MemStore::default();
    let mut root = EMPTY;
    for i in 0..size {
        let (k, v) = synthetic_kv(i);
        root = update(&mut store, root, &k, Some(v)).expect("smt update");
    }
    (store, root)
}

fn collect_nodes(store: &MemStore, root: [u8; 32]) -> Vec<([u8; 32], Node)> {
    let mut out = Vec::new();
    let mut visited = HashMap::new();
    let mut stack = vec![root];
    while let Some(h) = stack.pop() {
        if h == EMPTY || visited.contains_key(&h) {
            continue;
        }
        visited.insert(h, ());
        if let Some(node) = store.get(&h) {
            match &node {
                Node::Leaf { .. } => {}
                Node::Branch { left, right } => {
                    stack.push(*left);
                    stack.push(*right);
                }
            }
            out.push((h, node));
        }
    }
    out
}

fn verify_snapshot(nodes: &[([u8; 32], Node)], root: [u8; 32]) -> bool {
    let index: HashMap<[u8; 32], &Node> = nodes.iter().map(|(h, n)| (*h, n)).collect();

    let mut stack = vec![root];
    let mut visited = HashMap::new();
    while let Some(h) = stack.pop() {
        if h == EMPTY || visited.contains_key(&h) {
            continue;
        }
        visited.insert(h, ());
        let Some(node) = index.get(&h) else {
            return false;
        };

        match node {
            Node::Leaf { key, value } => {
                let recomputed = sahyadri_smt::hash_leaf(key, value);
                if recomputed != h {
                    return false;
                }
            }
            Node::Branch { left, right } => {
                let recomputed = sahyadri_smt::hash_branch(left, right);
                if recomputed != h {
                    return false;
                }
                stack.push(*left);
                stack.push(*right);
            }
        }
    }
    true
}

/// Manual serialization using Node::encode() — fixed-size 65 bytes per node
/// (1 tag byte + 32+32 for leaf, or 1 tag + 32+32 for branch).
fn serialize_nodes(nodes: &[([u8; 32], Node)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 65);
    for (hash, node) in nodes {
        out.extend_from_slice(hash);
        out.extend_from_slice(&node.encode());
    }
    out
}

fn bench_sync_wave_full(c: &mut Criterion) {
    let sizes: &[u64] = &[1_000, 10_000, 100_000];

    let mut group = c.benchmark_group("syncwave_full");
    for &size in sizes {
        let (store, root) = build_synthetic_smt(size);

        group.throughput(Throughput::Elements(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let t0 = Instant::now();
                let nodes = collect_nodes(&store, root);
                let export_time = t0.elapsed();

                let t1 = Instant::now();
                let bytes = serialize_nodes(&nodes);
                let serialize_time = t1.elapsed();

                let t2 = Instant::now();
                let ok = verify_snapshot(&nodes, root);
                let verify_time = t2.elapsed();
                assert!(ok);

                (nodes.len(), bytes.len(), export_time, serialize_time, verify_time)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sync_wave_full);
criterion_main!(benches);

#[test]
fn run_actual_benchmark() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("SyncWave — Actual Benchmark Numbers");
    println!("═══════════════════════════════════════════════════════");
    println!(
        "{:>10} | {:>10} | {:>12} | {:>12} | {:>12} | {:>12}",
        "accounts", "smt_nodes", "snapshot_MB", "export_ms", "serialize_ms", "verify_ms"
    );
    println!("{}", "-".repeat(80));

    for &size in &[1_000u64, 10_000, 100_000] {
        let (store, root) = build_synthetic_smt(size);

        let t0 = Instant::now();
        let nodes = collect_nodes(&store, root);
        let export_time = t0.elapsed();

        let t1 = Instant::now();
        let bytes = serialize_nodes(&nodes);
        let serialize_time = t1.elapsed();

        let t2 = Instant::now();
        let ok = verify_snapshot(&nodes, root);
        let verify_time = t2.elapsed();
        assert!(ok);

        let snapshot_mb = bytes.len() as f64 / 1_000_000.0;

        println!(
            "{:>10} | {:>10} | {:>12.4} | {:>12.3} | {:>12.3} | {:>12.3}",
            size,
            nodes.len(),
            snapshot_mb,
            export_time.as_secs_f64() * 1000.0,
            serialize_time.as_secs_f64() * 1000.0,
            verify_time.as_secs_f64() * 1000.0,
        );
    }

    println!("{}", "-".repeat(80));
    println!("Node encoding: 65 bytes each (1 tag + 32 + 32)");
    println!("Transfer time = serialize time (loopback equivalent)");
    println!("═══════════════════════════════════════════════════════\n");
}
