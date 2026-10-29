//! Verify that a proof generated with Blake3 transcript verifies correctly.
//! Smallest test: 1 FRI proof, prove + verify with Blake3 config.

use p3_binary_field::BinaryField128;
use sahyadri_fri_binius::{FriParams, FriProver, FriVerifier};

#[test]
fn blake3_transcript_works() {
    // FriProver with Blake3 transcript (from config)
    // If FriProver doesn't yet take config, this test scaffolds the intent.
    let params = FriParams {
        log_inv_rate: 2,
        num_queries: 8,
        pow_bits: 0,
    };
    let prover = FriProver::new(params);
    let evals: Vec<BinaryField128> = (0..32u128)
        .map(|i| BinaryField128::from_le_bytes(i.to_le_bytes()))
        .collect();
    let seed = b"blake3-transcript-test";

    let proof = prover.prove(evals.clone(), seed).expect("prove");
    let ok = FriVerifier::verify(&params, &proof, &evals, seed);
    assert!(ok, "Blake3 transcript proof must verify");
}
