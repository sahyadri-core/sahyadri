//! FRI folding over binary tower fields.
//!
//! ## Phase 1 (working)
//!
//! - Single fold function with correct algebraic structure.
//! - Fold round representation.
//! - Placeholder proof structure.
//!
//! ## Phase 2 (next)
//!
//! - Multi-round folding.
//! - Query generation + verification.
//! - Challenge sampling with grinding.
//! - Full proof serialization.

use p3_binary_field::BinaryField128 as Block128;

/// One fold round's polynomial (as evaluation vector, before folding).
#[derive(Debug, Clone)]
pub struct FoldRound {
    /// Current evaluation domain (as a power-of-two length).
    pub log_len: usize,
    /// Evaluations at this round.
    pub evals: Vec<Block128>,
    /// Challenge used to fold this round (empty for first round).
    pub challenge: Option<Block128>,
}

/// Complete FRI proof.
#[derive(Debug, Clone)]
pub struct FriProof {
    pub rounds: Vec<FoldRound>,
    pub final_poly: Vec<Block128>,
}

/// FRI prover.
pub struct FriProver {
    pub log_inv_rate: usize,
    pub num_queries: usize,
    pub folding_factor: usize,
}

impl FriProver {
    pub fn new(log_inv_rate: usize, num_queries: usize, folding_factor: usize) -> Self {
        Self {
            log_inv_rate,
            num_queries,
            folding_factor,
        }
    }

    /// Fold one round: given evals and challenge, produce the folded evals.
    ///
    /// Binary FRI: uses additive folding. For a challenge alpha,
    /// f_folded[i] = f[2i] + alpha * f[2i+1].
    pub fn fold_round(evals: &[Block128], challenge: Block128) -> Vec<Block128> {
        let n = evals.len() / 2;
        let mut folded = Vec::with_capacity(n);
        for i in 0..n {
            folded.push(evals[2 * i] + challenge * evals[2 * i + 1]);
        }
        folded
    }

    /// Prove: fold n rounds and return all intermediates.
    pub fn prove(&self, mut evals: Vec<Block128>, challenges: &[Block128]) -> FriProof {
        let mut rounds = Vec::with_capacity(challenges.len());
        for &ch in challenges {
            let log_len = evals.len().trailing_zeros() as usize;
            rounds.push(FoldRound {
                log_len,
                evals: evals.clone(),
                challenge: Some(ch),
            });
            if evals.len() <= 2 {
                break;
            }
            evals = Self::fold_round(&evals, ch);
        }
        let log_len = evals.len().trailing_zeros() as usize;
        rounds.push(FoldRound {
            log_len,
            evals: evals.clone(),
            challenge: None,
        });
        FriProof {
            rounds,
            final_poly: evals,
        }
    }
}

/// FRI verifier.
pub struct FriVerifier {
    pub log_inv_rate: usize,
    pub num_queries: usize,
}

impl FriVerifier {
    pub fn new(log_inv_rate: usize, num_queries: usize) -> Self {
        Self {
            log_inv_rate,
            num_queries,
        }
    }

    /// Replay folding and check consistency.
    pub fn verify(&self, proof: &FriProof, challenges: &[Block128]) -> bool {
        if proof.rounds.len() < 2 {
            return false;
        }
        let mut current_evals = proof.rounds[0].evals.clone();
        for (i, &ch) in challenges.iter().enumerate() {
            if i + 1 >= proof.rounds.len() {
                break;
            }
            let expected = FriProver::fold_round(&current_evals, ch);
            if i + 1 < proof.rounds.len() - 1 {
                if expected != proof.rounds[i + 1].evals {
                    return false;
                }
            }
            current_evals = expected;
        }
        current_evals == proof.final_poly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn fe(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    fn evals() -> Vec<Block128> {
        (0..16u128).map(|n: u128| Block128::from_le_bytes(n.to_le_bytes())).collect()
    }

    #[test]
    fn single_fold_correct() {
        let evs = evals();
        let ch = fe(7);
        let folded = FriProver::fold_round(&evs, ch);
        assert_eq!(folded.len(), 8);
        for i in 0..8 {
            let expected = evs[2 * i] + ch * evs[2 * i + 1];
            assert_eq!(folded[i], expected);
        }
    }

    #[test]
    fn proof_verifies() {
        let evs = evals();
        let challenges = vec![fe(2), fe(3), fe(4)];
        let prover = FriProver::new(2, 8, 2);
        let verifier = FriVerifier::new(2, 8);
        let proof = prover.prove(evs, &challenges);
        assert!(verifier.verify(&proof, &challenges));
    }

    #[test]
    fn tampered_proof_fails() {
        let evs = evals();
        let challenges = vec![fe(2), fe(3)];
        let prover = FriProver::new(2, 8, 2);
        let verifier = FriVerifier::new(2, 8);
        let mut proof = prover.prove(evs, &challenges);
        if !proof.final_poly.is_empty() {
            proof.final_poly[0] = fe(999);
        }
        assert!(!verifier.verify(&proof, &challenges));
    }
}
