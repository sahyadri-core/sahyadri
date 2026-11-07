//! A'2 chain proof interface — Phase 2b-1
//!
//! # Status (2026-11-07)
//! Interface ready. Currently delegates to Path B (`aggregate_batch`).
//! A'2 proof body wires in Phase 2b-2.
//!
//! # Soundness
//! `SoundnessTier::PathB` — honest-prover (Path B / Plonky3 aggregate_batch).
//! `SoundnessTier::A2` — adversarial (Phase 2b-2+, pending).

use p3_lookup::logup::LogUpGadget;
use p3_recursion::traits::RecursiveAir;
use p3_uni_stark::Proof;
use serde::{Deserialize, Serialize};

use crate::aggregate::{aggregate_batch, verify_batch_stark_proof, AggregateError};
use crate::config::{DilithiumStarkConfig, EF, F};
use crate::smt_stark::chain_blob::{BatchStarkProof, RecursionConfig};

/// Soundness tier of a chain proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoundnessTier {
    /// Path B: honest-prover, no in-circuit Merkle/sumcheck binding.
    PathB,
    /// A'2: adversarial-prover, bus-bound Merkle + sumcheck + Blake3 transcript.
    A2,
}

/// Tier-aware chain proof blob.
///
/// Note: not `Clone` because inner `BatchStarkProof` isn't `Clone`.
/// Use `Arc<ChainProofBlobA2>` if sharing is needed.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainProofBlobA2 {
    pub pathb_proof: BatchStarkProof<RecursionConfig>,
    pub a2_wrapped: Option<BatchStarkProof<RecursionConfig>>,
    pub tier: SoundnessTier,
    pub chain_depth: u32,
    pub chain_commitment: [u8; 32],
}

impl ChainProofBlobA2 {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("chain blob A2 serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("chain blob A2 deser: {e}"))
    }

    pub fn verify(&self) -> Result<(), String> {
        match self.tier {
            SoundnessTier::PathB => verify_batch_stark_proof(&self.pathb_proof)
                .map_err(|e| format!("PathB verify: {e:?}")),
            SoundnessTier::A2 => {
                Err("A2 verify pending Phase 2b-2 (import_native bridge)".into())
            }
        }
    }
}

/// Aggregate block proofs into a tier-aware chain proof.
///
/// Phase 2b-1: delegates to Path B `aggregate_batch`. Returns `ChainProofBlobA2`
/// with `tier = PathB`, `a2_wrapped = None`.
pub fn aggregate_batch_a2<A>(
    proofs: Vec<Proof<DilithiumStarkConfig>>,
    publics: Vec<Vec<F>>,
    air: &A,
    threads: usize,
) -> Result<ChainProofBlobA2, AggregateError>
where
    A: RecursiveAir<F, EF, LogUpGadget> + Sync,
{
    let pathb_output = aggregate_batch(proofs, publics, air, threads)?;

    Ok(ChainProofBlobA2 {
        pathb_proof: pathb_output.0,
        a2_wrapped: None,
        tier: SoundnessTier::PathB,
        chain_depth: 0,
        chain_commitment: [0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_serialization_roundtrip() {
        for tier in [SoundnessTier::PathB, SoundnessTier::A2] {
            let bytes = bincode::serialize(&tier).unwrap();
            let decoded: SoundnessTier = bincode::deserialize(&bytes).unwrap();
            assert_eq!(tier, decoded);
        }
    }

    #[test]
    fn tier_equality() {
        assert_eq!(SoundnessTier::PathB, SoundnessTier::PathB);
        assert_ne!(SoundnessTier::PathB, SoundnessTier::A2);
    }
}
