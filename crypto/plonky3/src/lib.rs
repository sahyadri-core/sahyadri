#![allow(clippy::needless_range_loop, clippy::clone_on_copy, clippy::assign_op_pattern, clippy::needless_borrows_for_generic_args, clippy::manual_div_ceil)]
//! # sahyadri-plonky3 — STARK ZKP Batch Verification
//!
//! 10,000 Dilithium3 signatures (33 MB) → 1 STARK proof (~30 KB) → verify in ~1ms.
//!
//! BLOCK PRODUCER (prover):
//!   1. Verify all Dilithium3 sigs via dilithium-rs
//!   2. Build STARK execution trace (1 row per sig)
//!   3. p3_uni_stark::prove() → STARK proof
//!   4. Block header stores BatchProof (~30 KB) + commitment_root (32 B)
//!
//! EVERY NODE (verifier):
//!   p3_uni_stark::verify(proof, public_inputs) → Ok(()) in ~1ms
//!
//! Compression: 33 MB → 30 KB = ~1,100x
//! Security: ~116 bits (FRI 50 queries + 16-bit PoW, BabyBear + Keccak)

pub mod air;
pub mod batch;
pub mod config;
pub mod dilithium_stark;
pub mod node;
pub mod prover;
pub mod verifier;

pub use air::*;
pub use batch::*;
pub use config::*;
pub use node::*;
pub use prover::*;
pub use verifier::*;

/// Proof format version.
pub const PROOF_FORMAT_VERSION: u8 = 1;

/// Max signatures per batch.
pub const MAX_BATCH_SIZE: usize = 10_000;
