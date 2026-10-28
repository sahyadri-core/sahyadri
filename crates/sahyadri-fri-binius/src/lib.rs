//! # Sahyadri FRI-Binius
//!
//! Binary-native polynomial commitment scheme using FRI folding over
//! GF(2) ⊂ GF(4) ⊂ ... ⊂ GF(2^128) tower.
//!
//! ## Design
//!
//! 1. **Commit**: Encode multilinear polynomial into binary tower matrix,
//!    build Merkle tree with Poseidon2b-style hashing.
//! 2. **Fold**: FRI folding over binary additive domains (Cantor basis).
//! 3. **Query**: Sample indices, prove evaluation paths.
//! 4. **Verify**: Replay folding and check Merkle paths.
//!
//! ## Security
//!
//! Conjectured soundness O(log d + λ·log log d) queries with
//! log_inv_rate = 2 and grinding.
//!
//! ## Status
//!
//! Phase 1: foundation (types, Merkle, basic folding).
//! Phase 2: full FRI protocol + all rounds.
//! Phase 3: recursive verifier circuit.
//! Phase 4: Binius-style ring-switching.

pub mod pcs;
pub mod fri;
pub mod merkle;
pub mod bytes;
pub mod error;
pub mod fold_air;
pub mod merkle_path_air;
pub mod merkle_path_bus_air;
pub mod grinding_air;
pub mod fri_verifier_air;
pub mod fri_verifier_air_v2;
pub mod poseidon2b_compression;
pub mod serialize;

pub use pcs::{FriBiniusPcs, FriBiniusParams, FriBiniusCommitment, FriBiniusOpening};
pub use fri::{FriParams, FriProof, FriProver, FriVerifier};
pub use error::FriBiniusError;
pub use fold_air::FoldAir;
pub use merkle_path_air::MerklePathAir;
pub use grinding_air::GrindingAir;
pub use fri_verifier_air::FriVerifierAir;
pub use fri_verifier_air_v2::FriVerifierAirV2;
pub use serialize::{proof_to_bytes, proof_from_bytes};
pub use bytes::{Block128Bytes, block_from_bytes};

/// Base field type for the commitment scheme.
pub type BaseField = p3_binary_field::BinaryField128;

/// Extension field for challenges. Uses tower GF(2^256) when available.
/// Falls back to GF(2^128) for Phase 1.
pub type ChallengeField = p3_binary_field::BinaryField128;
