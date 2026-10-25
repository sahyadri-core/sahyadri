//! Traits for IVC circuits.

use crate::public_io::PublicIO;

/// A step circuit — one transition of state.
pub trait StepCircuit {
    /// Witness type.
    type Witness;

    /// Execute the circuit step and return the output I/O.
    fn step(&self, io: &PublicIO, witness: &Self::Witness) -> PublicIO;
}

/// A recursive verifier — verifies a previous proof inside the circuit.
pub trait RecursiveVerifier {
    /// Proof type.
    type Proof;

    /// Verifier key.
    type VerifierKey;

    /// Verify a proof against a public I/O commitment.
    fn verify(&self, vk: &Self::VerifierKey, proof: &Self::Proof, io_commitment: &[u8; 32]) -> bool;
}
