//! Dilithium STARK Configuration — Goldilocks field
//!
//! MUST match p3-recursion's builtin `GoldilocksD2Poseidon2BinaryConfig`:
//!   - MMCS perm:      Poseidon2Goldilocks<8>, width=8, rate=4, digest=4, arity=2
//!   - Challenger perm: Poseidon2Goldilocks<8>, width=8, rate=4
//!   - Constants:      fixed_goldilocks_poseidon2_8() (Xoshiro seed 1)

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_field::PrimeCharacteristicRing;
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::builtin_config::fixed_goldilocks_poseidon2_8;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// ── Field types ──────────────────────────────────────────────
pub type F = Goldilocks;
pub type EF = BinomialExtensionField<Goldilocks, 2>;

// ── Perms (BOTH W8, matching builtin) ────────────────────────
pub type Perm = Poseidon2Goldilocks<8>;
pub type MmcsPerm = Poseidon2Goldilocks<8>;

// MMCS sponge — WIDTH=8, RATE=4, OUT=4
pub type MyHash = PaddingFreeSponge<MmcsPerm, 8, 4, 4>;

// MMCS compression — N=2, CHUNK=4, WIDTH=8
pub type MyCompress = TruncatedPermutation<MmcsPerm, 2, 4, 8>;

// ── Packing ──────────────────────────────────────────────────
pub type Packing = <F as Field>::Packing;

// ── MMCS ─────────────────────────────────────────────────────
pub type ValMmcs = MerkleTreeMmcs<Packing, Packing, MyHash, MyCompress, 2, 4>;
pub type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;

// ── DFT ──────────────────────────────────────────────────────
pub type Dft = Radix2DitParallel<F>;

// ── Challenger ───────────────────────────────────────────────
pub type Challenger = DuplexChallenger<F, Perm, 8, 4>;

// ── PCS ──────────────────────────────────────────────────────
pub type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;

/// Generic Sahyadri STARK config, shared by all sub-STARKs.
/// The name is generic even though the parameter list is fixed.
pub type SahyadriStarkConfig = StarkConfig<Pcs, EF, Challenger>;

// ── Config ───────────────────────────────────────────────────
pub type DilithiumStarkConfig = SahyadriStarkConfig;

// ── Constants ────────────────────────────────────────────────
pub const LOG_BLOWUP: usize = 3;
pub const DIGEST_ELEMS: usize = 4;
pub const NUM_QUERIES: usize = 60;
pub const PROOF_OF_WORK_BITS: usize = 20;

// ── Builder ──────────────────────────────────────────────────
pub fn build_stark_config() -> DilithiumStarkConfig {
    // Same fixed constants the builtin uses — bit-for-bit identical.
    let mmcs_perm = fixed_goldilocks_poseidon2_8();
    let perm = fixed_goldilocks_poseidon2_8();

    let hash = MyHash::new(mmcs_perm.clone());
    let compress = MyCompress::new(mmcs_perm);
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let fri_params = p3_fri::FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: PROOF_OF_WORK_BITS,
        batch_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    DilithiumStarkConfig::new(pcs, challenger)
}

/// Derive 3 public challenge field elements from the 32-byte commitment root.
pub fn derive_public_challenges(commitment_root: &[u8; 32]) -> (F, F, F) {
    let challenge = F::from_u64(u64::from_le_bytes(commitment_root[0..8].try_into().unwrap()));
    let alpha = F::from_u64(u64::from_le_bytes(commitment_root[8..16].try_into().unwrap()));
    let beta = F::from_u64(u64::from_le_bytes(commitment_root[16..24].try_into().unwrap()));
    (challenge, alpha, beta)
}
