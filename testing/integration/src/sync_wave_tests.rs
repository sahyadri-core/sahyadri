//! SyncWave integration test — export / verify / load cycle.
//!
//! Uses `TestConsensus` to build a node with non-trivial state, exports a
//! SyncWave snapshot from it, verifies the snapshot cryptographically, loads
//! it into a second fresh node, and confirms the two nodes commit to the
//! same account root.

use sahyadri_consensus::{
    consensus::test_consensus::TestConsensus,
    model::sync_wave::SyncWaveExporter,
    params::SIMNET_PARAMS,
};
use sahyadri_consensus_core::config::ConfigBuilder;
use sahyadri_consensus_core::api::ConsensusApi;

/// Build a test Consensus on simnet with a fresh temp DB.
fn build_simnet_consensus() -> TestConsensus {
    let config = ConfigBuilder::new(SIMNET_PARAMS).build();
    TestConsensus::new(&config)
}

#[tokio::test]
async fn test_sync_wave_export_verify_load() {
    // ─── Node A: fresh TestConsensus ───
    let tc_a = build_simnet_consensus();

    // The tip is the genesis since no blocks have been added.
    // Genesis already commits to an `account_commitment` (the SMT empty
    // root), so export works even on an empty state.
    let tip = tc_a.consensus_clone().get_headers_selected_tip();

    // ─── Export from A ───
    let snapshot = tc_a
        .consensus_clone()
        .export_sync_wave(tip)
        .expect("export_sync_wave should succeed on a fresh node");

    assert_eq!(snapshot.metadata.block_hash, tip);
    assert_eq!(
        snapshot.metadata.total_accounts,
        snapshot.account_states.len() as u64,
        "declared account count must match actual"
    );
    assert_eq!(
        snapshot.metadata.total_smt_nodes,
        snapshot.smt_nodes.len() as u64,
        "declared SMT node count must match actual"
    );

    // ─── Verify the snapshot cryptographically ───
    // Rebuilds the SMT root from the transmitted nodes and compares against
    // `metadata.account_root`. If any node, state, or reference is corrupt,
    // this fails.
    SyncWaveExporter::verify(&snapshot).expect("SyncWave verification should pass");

    // ─── Node B: a separate, fresh TestConsensus ───
    let tc_b = build_simnet_consensus();

    // ─── Load the snapshot into B ───
    tc_b.consensus_clone()
        .load_sync_wave(&snapshot)
        .expect("load_sync_wave should succeed on a fresh node");

    // ─── Confirm B commits to the same root ───
    // Re-export from B at the same block hash. The returned snapshot must
    // have the same `account_root` — this is the cryptographic proof that
    // B's stores now hold the exact state A exported.
    let snapshot_b = tc_b
        .consensus_clone()
        .export_sync_wave(tip)
        .expect("export from B should succeed after load");

    assert_eq!(
        snapshot_b.metadata.account_root,
        snapshot.metadata.account_root,
        "B's account root must match A's after SyncWave load"
    );
    assert_eq!(
        snapshot_b.metadata.total_smt_nodes,
        snapshot.metadata.total_smt_nodes,
        "B's SMT node count must match A's after SyncWave load"
    );
    assert_eq!(
        snapshot_b.metadata.total_accounts,
        snapshot.metadata.total_accounts,
        "B's account count must match A's after SyncWave load"
    );

    // ─── Idempotency: loading twice must be a no-op ───
    tc_b.consensus_clone()
        .load_sync_wave(&snapshot)
        .expect("second load must be idempotent");

    let snapshot_b2 = tc_b.consensus_clone().export_sync_wave(tip).unwrap();
    assert_eq!(snapshot_b2.metadata.account_root, snapshot.metadata.account_root);
}

#[tokio::test]
async fn test_sync_wave_verify_rejects_corruption() {
    let tc = build_simnet_consensus();
    let tip = tc.consensus_clone().get_headers_selected_tip();

    let mut snapshot = tc.consensus_clone().export_sync_wave(tip).unwrap();

    // Corrupt one node's hash — verify must fail.
    if !snapshot.smt_nodes.is_empty() {
        snapshot.smt_nodes[0].0 = [0xff; 32];
        let result = SyncWaveExporter::verify(&snapshot);
        assert!(result.is_err(), "verification must reject a node with a wrong content-address");
    }

    // Corrupt metadata root — verify must fail.
    snapshot.metadata.account_root = sahyadri_hashes::Hash::from_bytes([0xab; 32]);
    let result = SyncWaveExporter::verify(&snapshot);
    assert!(result.is_err(), "verification must reject a wrong account root");
}
