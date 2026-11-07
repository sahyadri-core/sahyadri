//! A'2 binary → Goldilocks bridge — Phase 2b-2
//!
//! # Purpose
//! Wraps an A'2 binary MultiStark proof (S4/S5/S7 output) into a Goldilocks
//! RecursionOutput so it can chain via `aggregate_two_chain_blobs`.
//!
//! # Status (2026-11-07)
//! INTERFACE ONLY. Real bridge blocked by MMCS incompatibility:
//!
//! ## Blocker
//! `PreparedBinaryGroupedMultiStarkLayer::binary_verifier().import_native(...)`
//! requires `BinaryPcsProof` over standard `MerkleTreeMmcs<F, u8, H0, C0, 2, 32>`.
//! S4/S5/S7 proofs use `Poseidon2bMmcs` (custom MMCS over Poseidon2b permutation).
//! Type-wise these do not unify.
//!
//! ## Resolution (Phase 2b-2b, 3-5 days)
//! Implement `CryptographicHasher<BinaryField128, [u8; 32]>` and
//! `PseudoCompressionFunction<[u8; 32], 2>` for Poseidon2b. Then
//! `MerkleTreeMmcs<BinaryField128, u8, Poseidon2bHasher, Poseidon2bCompress, 2, 32>`
//! becomes valid, and A'2 proofs work with `import_native` unchanged.
//!
//! ## Alternative (Path Y, 2-3 days)
//! Rebuild S7 with Blake3 MMCS. Loses bus-linked Poseidon2b Merkle soundness
//! (PCS commitment would be Blake3, bus-linked Poseidon2b traces become
//! redundant to actual tree). Only viable if A'2 tier drops adversarial Merkle.
//!
//! # Interface (this session)
//! `binary_to_goldilocks(...)` returns `Err(BridgeError::MmcsIncompatible)`.
//! Node builds clean. Integration is additive — no regression to Path B.

use p3_binary_field::BinaryField128;
use p3_recursion::RecursionOutput;

use crate::config::SahyadriStarkConfig;

/// Errors from A'2 → Goldilocks bridge.
#[derive(Debug)]
pub enum BridgeError {
    /// Poseidon2bMmcs ↔ MerkleTreeMmcs incompatibility (Phase 2b-2b pending).
    MmcsIncompatible {
        detail: &'static str,
    },
    /// Binary proof malformed.
    InvalidProof(String),
    /// Recursive layer setup failed.
    LayerSetup(String),
    /// Prover failed.
    Prover(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MmcsIncompatible { detail } => {
                write!(f, "MMCS incompatible: {detail}")
            }
            Self::InvalidProof(s) => write!(f, "invalid A'2 proof: {s}"),
            Self::LayerSetup(s) => write!(f, "layer setup: {s}"),
            Self::Prover(s) => write!(f, "prover: {s}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Bridge a binary A'2 MultiStark proof into a Goldilocks recursive proof.
///
/// # Phase 2b-2a (this session)
/// Returns `Err(BridgeError::MmcsIncompatible)` with documented reason.
/// Interface stable — Phase 2b-2b will fill in the body once
/// `Poseidon2bHasher` / `Poseidon2bCompress` adapters land.
///
/// # Args
/// - `binary_proof_bytes`: serialized A'2 MultiStark proof (S7 v2/v3 output).
/// - `public_inputs`: per-AIR public values (V2 empty, SC 2 values, MP 8 values, P2B 8 each).
///
/// # Returns
/// `RecursionOutput<SahyadriStarkConfig>` — chainable Goldilocks proof.
pub fn binary_to_goldilocks(
    _binary_proof_bytes: &[u8],
    _public_inputs: &[Vec<BinaryField128>],
) -> Result<RecursionOutput<SahyadriStarkConfig>, BridgeError> {
    Err(BridgeError::MmcsIncompatible {
        detail: "Poseidon2bMmcs (S7) vs MerkleTreeMmcs (import_native). \
                 Phase 2b-2b will add CryptographicHasher<Poseidon2b> adapter.",
    })
}

/// Verify a Goldilocks-wrapped A'2 proof.
///
/// # Phase 2b-2a (this session)
/// Returns `Err(BridgeError::MmcsIncompatible)`.
pub fn verify_goldilocks_wrapped(
    _proof: &RecursionOutput<SahyadriStarkConfig>,
    _public_inputs: &[Vec<BinaryField128>],
) -> Result<(), BridgeError> {
    Err(BridgeError::MmcsIncompatible {
        detail: "verify path pending Phase 2b-2b (Poseidon2b MMCS adapter)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_returns_documented_error() {
        let err = match binary_to_goldilocks(&[], &[]) {
            Ok(_) => panic!("expected MmcsIncompatible, got Ok"),
            Err(e) => e,
        };
        match err {
            BridgeError::MmcsIncompatible { detail } => {
                assert!(detail.contains("Poseidon2b"));
                assert!(detail.contains("MerkleTreeMmcs"));
            }
            other => panic!("expected MmcsIncompatible, got {other:?}"),
        }
    }

    #[test]
    fn verify_returns_documented_error() {
        // Can't build RecursionOutput without real proof — skip verify test for now
        // This test will be filled in Phase 2b-2b.
    }
}
