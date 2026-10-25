//! # Sahyadri IVC Core
//!
//! Incrementally verifiable computation — the recursion foundation
//! for Sahyadri's binary-native proof stack.
//!
//! ## Design
//!
//! Two layers:
//! 1. **Step circuit** — one transition (block production, PoW, sig check)
//! 2. **Recursive verifier** — verifies previous proof in-circuit
//!
//! ## Model
//!
//! ```text
//! State_0 ──[C]──► State_1 ──[C]──► ... ──► State_n
//!    │               │                        │
//!    π_0             π_1                     π_n
//! ```
//!
//! Where π_i proves "there exist witnesses w_i such that C(State_{i-1}, w_i) = State_i
//! AND π_{i-1} is valid".
//!
//! ## Status
//!
//! Phase 1: types + traits.
//! Phase 2: circuit construction.
//! Phase 3: prover integration.

use serde::{Deserialize, Serialize};

pub mod public_io;
pub mod traits;

pub use public_io::{PublicIO, PublicIOLayout};
pub use traits::{StepCircuit, RecursiveVerifier};

/// A recursive proof at a given step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveProof {
    /// Step index.
    pub step: u64,
    /// Commitment to the public input/output pair.
    pub public_commitment: [u8; 32],
    /// Opaque proof bytes (FRI-Binius serialized).
    pub proof_bytes: Vec<u8>,
}

/// Full proof chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChain {
    pub proofs: Vec<RecursiveProof>,
    pub initial_state_commitment: [u8; 32],
    pub final_state_commitment: [u8; 32],
}

impl ProofChain {
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}
