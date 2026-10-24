//! Path A scaling: does aggregate_batch handle N proofs?
//! N=10, 100, 1000 — measure time + memory.

use p3_goldilocks::Goldilocks;
use p3_uni_stark::Proof;
use sahyadri_plonky3::aggregate::{aggregate_batch, verify_root_proof};
use sahyadri_plonky3::config::SahyadriStarkConfig;
use sahyadri_plonky3::sahyadrix_pow::blake3_block::{
    Blake3BlockAir, blake3_compress_native,
};
use sahyadri_plonky3::sahyadrix_pow::blake3_prover::{
    prove_blake3_block, pack_public_inputs,
};

#[test]
#[ignore]
fn aggregate_batch_scaling() {
    for n in [10usize] {
        println!("\n=== N={} ===", n);
        let t0 = std::time::Instant::now();

        let mut cvs = vec![[0x11u8; 32]; n + 1];
        let mut blocks = vec![[0u8; 64]; n];
        for i in 0..n {
            let mut b = [0x22u8; 64];
            b[0] = (i & 0xFF) as u8;
            b[1] = ((i >> 8) & 0xFF) as u8;
            blocks[i] = b;
            cvs[i + 1] = blake3_compress_native(&cvs[i], &blocks[i], 0, 64, 0);
        }

        let mut proofs: Vec<Proof<SahyadriStarkConfig>> = Vec::with_capacity(n);
        let mut pubs: Vec<Vec<Goldilocks>> = Vec::with_capacity(n);
        for i in 0..n {
            proofs.push(prove_blake3_block(&cvs[i], &blocks[i], 0, 64, 0, &cvs[i+1]));
            pubs.push(pack_public_inputs(&cvs[i], &blocks[i], 0u64, 64u32, 0u32, &cvs[i+1]));
        }
        let t_prove = t0.elapsed();
        println!("  prove {} proofs: {:?}", n, t_prove);

        let t1 = std::time::Instant::now();
        let air = Blake3BlockAir;
        let root = aggregate_batch(proofs, pubs, &air, 32)
            .expect("aggregate_batch failed");
        let t_agg = t1.elapsed();
        println!("  aggregate_batch N={}: {:?}", n, t_agg);
        println!("  verify: {:?}", {
            let t = std::time::Instant::now();
            let r = verify_root_proof(&root);
            (t.elapsed(), r.is_ok())
        });
        let size = bincode::serialize(&root.0).unwrap().len();
        println!("  proof size: {} KB", size / 1024);
    }
}
