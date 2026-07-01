//! Dilithium STARK Configuration — Goldilocks field
//!
//! Switched from BabyBear (p ≈ 2^31) to Goldilocks (p ≈ 2^64)
//! so that Q² = 8380417² ≈ 2^46 fits natively in the field,
//! enabling Z_q multiplication as a single STARK constraint.

use p3_challenger::DuplexChallenger;
use p3_field::PrimeCharacteristicRing;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// ── Field types ──────────────────────────────────────────────

/// Base field: Goldilocks, p = 2^64 - 2^32 + 1 ≈ 1.84 × 10^19
pub type F = Goldilocks;

/// Extension field for FRI: degree-2 binomial extension of Goldilocks.
/// Goldilocks does NOT implement BinomiallyExtendable<4>, only <2>.
pub type EF = BinomialExtensionField<Goldilocks, 2>;

// ── Poseidon2 hash ──────────────────────────────────────────

/// Poseidon2 permutation for Goldilocks, width 8.
/// Round counts are baked into the type.
pub type Perm = Poseidon2Goldilocks<8>;

/// Sponge hash: width=8, rate=4, output=4 field elements per hash.
pub type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;

/// Compression: 2 digests of 4 elements → 1 digest of width 8.
pub type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;

// ── Merkle trees ─────────────────────────────────────────────

/// Packed field type (SIMD or scalar fallback).
pub type Packing = <F as Field>::Packing;

/// Value Merkle tree commitment scheme (4 digest elements per node).
pub type ValMmcs = MerkleTreeMmcs<Packing, Packing, MyHash, MyCompress, 4>;

/// Challenge Merkle tree: wraps ValMmcs for extension field (EF) challenges.
pub type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;

// ── DFT ──────────────────────────────────────────────────────

/// Discrete Fourier Transform for Goldilocks.
pub type Dft = Radix2DitParallel<F>;

// ── Challenger ───────────────────────────────────────────────

/// Duplex sponge challenger for Fiat-Shamir: width=8, rate=4.
pub type Challenger = DuplexChallenger<F, Perm, 8, 4>;

// ── PCS ─────────────────────────────────────────────────────

/// FRI-based polynomial commitment scheme.
pub type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;

// ── Stark config ─────────────────────────────────────────────

/// Top-level Dilithium STARK configuration.
/// Replaces the old `BabyBearKeccakConfig`.
pub type DilithiumStarkConfig = StarkConfig<Pcs, EF, Challenger>;

// ── FRI parameters ──────────────────────────────────────────

/// FRI blowup factor: 2^2 = 4× expansion.
pub const LOG_BLOWUP: usize = 2;

/// Number of FRI queries for soundness.
pub const NUM_QUERIES: usize = 50;

/// Proof-of-work bits for FRI.
pub const PROOF_OF_WORK_BITS: usize = 16;

use rand::rngs::SmallRng;
use rand::SeedableRng;

/// Build a deterministic DilithiumStarkConfig.
/// Both prover and verifier call this — same seed = same Poseidon2 round keys.
pub fn build_stark_config() -> DilithiumStarkConfig {
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);

    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let fri_params = p3_fri::create_benchmark_fri_params_zk(challenge_mmcs);

    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    DilithiumStarkConfig::new(pcs, challenger)
}

/// Derive 3 public challenge field elements from the 32-byte commitment root.
/// Returns (challenge, alpha, beta) used by the AIR for Fiat-Shamir binding.
pub fn derive_public_challenges(commitment_root: &[u8; 32]) -> (F, F, F) {
    let challenge = F::from_u64(u64::from_le_bytes(
        commitment_root[0..8].try_into().unwrap(),
    ));
    let alpha = F::from_u64(u64::from_le_bytes(
        commitment_root[8..16].try_into().unwrap(),
    ));
    let beta = F::from_u64(u64::from_le_bytes(
        commitment_root[16..24].try_into().unwrap(),
    ));
    (challenge, alpha, beta)
}
