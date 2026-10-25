//! # Sahyadri IVC Prover
//!
//! Prover-side IVC implementation using Sahyadri FRI-Binius.
//!
//! ## Status
//!
//! Phase 1 (today): prover struct + step chaining interface.
//! Phase 2: circuit construction from FRI-Binius verifier.
//! Phase 3: end-to-end Blake3 PoW recursion.

use sahyadri_fri_binius::FriBiniusParams;
use sahyadri_ivc_core::{
    public_io::{PublicIO, PublicIOLayout},
    traits::{RecursiveVerifier, StepCircuit},
    ProofChain, RecursiveProof,
};

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("setup: {0}")]
    Setup(String),
    #[error("step: {0}")]
    Step(String),
    #[error("verify: {0}")]
    Verify(String),
}

/// Prover configuration.
#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub fri_params: FriBiniusParams,
    pub io_layout: PublicIOLayout,
    pub max_steps: u64,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            fri_params: FriBiniusParams::default(),
            io_layout: PublicIOLayout {
                input_bytes: 32,
                output_bytes: 32,
            },
            max_steps: 1_000_000,
        }
    }
}

/// Prover for one IVC chain.
pub struct IvcProver<C: StepCircuit, V: RecursiveVerifier> {
    pub config: ProverConfig,
    pub circuit: C,
    pub verifier: V,
    pub chain: ProofChain,
    _io_phantom: core::marker::PhantomData<PublicIO>,
}

impl<C: StepCircuit, V: RecursiveVerifier> IvcProver<C, V> {
    /// Initialize a new chain from the initial state.
    pub fn new(config: ProverConfig, circuit: C, verifier: V, initial_io: &PublicIO) -> Self {
        let chain = ProofChain {
            proofs: Vec::new(),
            initial_state_commitment: initial_io.commit(),
            final_state_commitment: initial_io.commit(),
        };
        Self {
            config,
            circuit,
            verifier,
            chain,
            _io_phantom: core::marker::PhantomData,
        }
    }

    /// Perform one IVC step. Returns the new I/O.
    ///
    /// Phase 1: executes circuit, updates chain metadata.
    /// Phase 2: adds FRI-Binius proving.
    pub fn step(&mut self, io: &PublicIO, witness: &C::Witness) -> Result<PublicIO, ProverError> {
        // 1. Execute step circuit
        let new_io = self.circuit.step(io, witness);
        if new_io.step != io.step + 1 {
            return Err(ProverError::Step(format!(
                "step mismatch: expected {}, got {}",
                io.step + 1,
                new_io.step
            )));
        }

        // 2. Compute I/O commitment
        let commitment = new_io.commit();

        // 3. TODO Phase 2: build FRI-Binius proof over
        //    "circuit.step valid AND previous proof valid"
        let proof = RecursiveProof {
            step: new_io.step,
            public_commitment: commitment,
            proof_bytes: Vec::new(), // Phase 2 fills this
        };

        self.chain.proofs.push(proof);
        self.chain.final_state_commitment = commitment;

        Ok(new_io)
    }

    /// Verify the entire chain (native, O(N)).
    pub fn verify_chain(&self) -> Result<(), ProverError> {
        let mut prev_commitment = self.chain.initial_state_commitment;
        for (i, proof) in self.chain.proofs.iter().enumerate() {
            if proof.public_commitment == [0u8; 32] {
                return Err(ProverError::Verify(format!("proof {i} has empty commitment")));
            }
            prev_commitment = proof.public_commitment;
        }
        if prev_commitment != self.chain.final_state_commitment {
            return Err(ProverError::Verify("final commitment mismatch".into()));
        }
        Ok(())
    }

    pub fn chain_len(&self) -> usize {
        self.chain.proofs.len()
    }
}
