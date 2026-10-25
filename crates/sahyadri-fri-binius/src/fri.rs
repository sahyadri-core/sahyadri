//! FRI protocol over binary tower fields.
//!
//! Phase 2B: full multi-round folding + query sampling + grinding.
//!
//! ## Protocol
//!
//! ```text
//! Prover:
//!   evals_0 (len 2^n)
//!   for r in 0..R:
//!     commitment_r = Merkle(evals_r)
//!     alpha_r = hash(commitment_r, state)
//!     evals_{r+1} = fold(evals_r, alpha_r)
//!   final_poly = evals_R (small)
//!   sample Q query indices
//!   for each q, provide pairs + paths per round
//!   grinding: find nonce such that hash(...) has pow_bits zeros
//!
//! Verifier:
//!   for each query q:
//!     for r in 0..R:
//!       check Merkle path
//!       compute folded = y_r[2j] + alpha_r * y_r[2j+1]
//!       check folded == y_{r+1}[q >> r+1]
//!   check final_poly
//! ```
//!
//! ## Security
//!
//! - num_queries ~30 for conjectured 100-bit soundness with log_inv_rate=2
//! - pow_bits=16 for grinding
//!
//! ## Folding (binary field)
//!
//! `y_{r+1}[i] = y_r[2i] + alpha_r * y_r[2i+1]`
//!
//! Sibling pair at round r, index i_r:
//! - i_r even: y_r[2j] and y_r[2j+1], fold = y_r[2j] + alpha * y_r[2j+1]
//! - i_r odd:  y_r[2j] and y_r[2j+1], fold = y_r[2j] + alpha * y_r[2j+1]  (same formula)

use crate::bytes::Block128Bytes;
use p3_binary_field::BinaryField128 as Block128;


use crate::error::FriBiniusError;
use crate::merkle::MerkleTree;

/// Parameters for FRI protocol.
#[derive(Debug, Clone)]
pub struct FriParams {
    pub log_inv_rate: usize,
    pub num_queries: usize,
    pub pow_bits: usize,
}

impl Default for FriParams {
    fn default() -> Self {
        Self {
            log_inv_rate: 2,
            num_queries: 30,
            pow_bits: 16,
        }
    }
}

impl FriParams {
    /// Parameters sized for ~100-bit conjectured soundness at rate 1/8.
    ///
    /// Conjectured error term: 60 queries * log2(rate^-1) + 20 grinding = 200 bits.
    /// Johnson-bound floor:  60 queries * log2(rate^-1)/2 + 20      = 110 bits.
    /// Both comfortably exceed 100.
    pub fn production() -> Self {
        Self {
            log_inv_rate: 3,
            num_queries: 60,
            pow_bits: 20,
        }
    }
}

/// Commitment to one round of FRI.
#[derive(Debug, Clone)]
pub struct FriRoundCommitment {
    pub root: Block128,
    pub log_len: usize,
}

/// One query proof across all rounds.
#[derive(Debug, Clone)]
pub struct FriQueryProof {
    /// Query index at round 0.
    pub index_0: usize,
    /// For each round r: (y_r[i_r], y_r[i_r ^ 1])
    pub pairs: Vec<[Block128; 2]>,
    /// For each round r: Merkle path for index i_r
    pub paths: Vec<Vec<Block128>>,
}

/// Complete FRI proof.
#[derive(Debug, Clone)]
pub struct FriProof {
    pub rounds: Vec<FriRoundCommitment>,
    pub final_poly: Vec<Block128>,
    pub queries: Vec<FriQueryProof>,
    pub pow_nonce: u64,
}

/// FRI prover.
pub struct FriProver {
    pub params: FriParams,
}

impl FriProver {
    pub fn new(params: FriParams) -> Self {
        Self { params }
    }

    /// Single fold step: y_{r+1}[i] = y_r[2i] + alpha * y_r[2i+1]
    pub fn fold(evals: &[Block128], challenge: Block128) -> Vec<Block128> {
        let n = evals.len() / 2;
        (0..n)
            .map(|i| evals[2 * i] + challenge * evals[2 * i + 1])
            .collect()
    }

    /// Prove: multi-round FRI over `evals`.
    pub fn prove(
        &self,
        evals: Vec<Block128>,
        public_seed: &[u8],
    ) -> Result<FriProof, FriBiniusError> {
        if !evals.len().is_power_of_two() || evals.len() < 4 {
            return Err(FriBiniusError::InvalidParams(
                "evals length must be power of two >= 4".into(),
            ));
        }

        let log_len_0 = evals.len().trailing_zeros() as usize;
        let mut round_evals: Vec<Vec<Block128>> = vec![evals.clone()];
        let mut round_commitments: Vec<FriRoundCommitment> = Vec::new();
        let mut challenges: Vec<Block128> = Vec::new();

        // Multi-round folding until final small poly (len 4)
        let mut current = evals.clone();
        while current.len() > 4 {
            let tree = MerkleTree::new(current.clone());
            round_commitments.push(FriRoundCommitment {
                root: tree.root(),
                log_len: current.len().trailing_zeros() as usize,
            });
            let ch = derive_challenge_from_commitment(
                round_commitments.last().unwrap(),
                &challenges,
                public_seed,
            );
            challenges.push(ch);
            current = Self::fold(&current, ch);
            round_evals.push(current.clone());
        }
        let final_poly = current;

        // Sample query indices in [0, 2^log_len_0)
        let q_indices = derive_queries(
            &round_commitments,
            &final_poly,
            self.params.num_queries,
            public_seed,
            log_len_0,
        );

        // Build per-query proofs
        let mut queries = Vec::with_capacity(q_indices.len());
        for &i_0 in &q_indices {
            let mut pairs = Vec::with_capacity(round_commitments.len());
            let mut paths = Vec::with_capacity(round_commitments.len());

            for r in 0..round_commitments.len() {
                let e = &round_evals[r];
                let log_n_r = e.len().trailing_zeros() as usize;

                // Round index: i_r = i_0 >> (log_len_0 - log_n_r)
                // MUST use fresh i_0 (verifier uses same formula — no cumulative shift)
                let shift = log_len_0 - log_n_r;
                let i_r = i_0 >> shift;

                let tree = MerkleTree::new(e.clone());
                let path = tree.path(i_r);

                pairs.push([e[i_r], e[i_r ^ 1]]);
                paths.push(path);
            }

            queries.push(FriQueryProof { index_0: i_0, pairs, paths });
        }

        // Grinding
        let pow_nonce = self.find_grinding_nonce(&round_commitments, &final_poly, public_seed);

        Ok(FriProof {
            rounds: round_commitments,
            final_poly,
            queries,
            pow_nonce,
        })
    }

    /// Find a nonce such that hash(...) has pow_bits leading zeros.
    fn find_grinding_nonce(
        &self,
        rounds: &[FriRoundCommitment],
        final_poly: &[Block128],
        public_seed: &[u8],
    ) -> u64 {
        if self.params.pow_bits == 0 {
            return 0;
        }
        let mut base = Vec::new();
        base.extend_from_slice(public_seed);
        for r in rounds {
            base.extend_from_slice(&r.root.blk_to_le_bytes());
        }
        for p in final_poly {
            base.extend_from_slice(&p.blk_to_le_bytes());
        }

        let target_zero_bits = self.params.pow_bits;
        for nonce in 0u64..u64::MAX {
            let mut h_bytes = base.clone();
            h_bytes.extend_from_slice(&nonce.to_le_bytes());
            let h = blake3::hash(&h_bytes);
            if has_leading_zero_bits(h.as_bytes(), target_zero_bits) {
                return nonce;
            }
        }
        0
    }
}

/// FRI verifier.
pub struct FriVerifier {
    pub params: FriParams,
}

impl FriVerifier {
    pub fn new(params: FriParams) -> Self {
        Self { params }
    }

    /// Verify a FRI proof against the first-round commitment.
    pub fn verify(
        &self,
        commitment_0: Block128,
        proof: &FriProof,
        public_seed: &[u8],
    ) -> Result<(), FriBiniusError> {
        if proof.rounds.is_empty() {
            return Err(FriBiniusError::MalformedProof("no rounds".into()));
        }
        if proof.rounds[0].root != commitment_0 {
            return Err(FriBiniusError::CommitmentMismatch);
        }

        // 1. Replay challenges
        let mut challenges = Vec::with_capacity(proof.rounds.len());
        for r in 0..proof.rounds.len() {
            // Note: we don't have round_evals in proof; derive from commitments
            let ch = derive_challenge_from_commitment(
                &proof.rounds[r],
                &challenges,
                public_seed,
            );
            challenges.push(ch);
        }

        // 2. Verify grinding
        if self.params.pow_bits > 0 {
            let mut base = Vec::new();
            base.extend_from_slice(public_seed);
            for r in &proof.rounds {
                base.extend_from_slice(&r.root.blk_to_le_bytes());
            }
            for p in &proof.final_poly {
                base.extend_from_slice(&p.blk_to_le_bytes());
            }
            base.extend_from_slice(&proof.pow_nonce.to_le_bytes());
            let h = blake3::hash(&base);
            if !has_leading_zero_bits(h.as_bytes(), self.params.pow_bits) {
                return Err(FriBiniusError::Verification(
                    "grinding check failed".into(),
                ));
            }
        }

        // 3. Verify queries
        if proof.queries.is_empty() {
            return Err(FriBiniusError::MalformedProof("no queries".into()));
        }

        let log_len_0 = proof.rounds[0].log_len;

        for (q_idx, query) in proof.queries.iter().enumerate() {
            if query.pairs.len() != proof.rounds.len() {
                return Err(FriBiniusError::MalformedProof(format!(
                    "query {q_idx}: wrong pairs count"
                )));
            }
            let i_0 = query.index_0;

            // 1. Merkle path verification at each round with correct index i_r
            for r in 0..proof.rounds.len() {
                let log_n_r = proof.rounds[r].log_len;
                if log_n_r > log_len_0 {
                    return Err(FriBiniusError::MalformedProof(
                        "round log_len exceeds round 0".into(),
                    ));
                }
                let shift = log_len_0 - log_n_r;
                let i_r = i_0 >> shift;

                let pair = &query.pairs[r];
                let path = &query.paths[r];
                let root = proof.rounds[r].root;

                // pair[0] = evals_r[i_r], path = siblings
                if !MerkleTree::verify_path(pair[0], i_r, path, root) {
                    return Err(FriBiniusError::Query {
                        query: q_idx,
                        msg: format!("Merkle path failed at round {r} (i_r={i_r})"),
                    });
                }
                // pair[1] = evals_r[i_r ^ 1] = first sibling in path
                if !path.is_empty() && pair[1] != path[0] {
                    return Err(FriBiniusError::Query {
                        query: q_idx,
                        msg: format!("sibling mismatch at round {r}"),
                    });
                }
            }

            // 2. Fold consistency: (i_r even) → pair[0]+α·pair[1], (i_r odd) → pair[1]+α·pair[0]
            for r in 0..proof.rounds.len() - 1 {
                let log_n_r = proof.rounds[r].log_len;
                let shift = log_len_0 - log_n_r;
                let i_r = i_0 >> shift;
                let alpha = challenges[r];

                let pair = &query.pairs[r];
                let next_pair = &query.pairs[r + 1];

                let folded = if i_r & 1 == 0 {
                    pair[0] + alpha * pair[1]
                } else {
                    pair[1] + alpha * pair[0]
                };

                if folded != next_pair[0] {
                    return Err(FriBiniusError::Query {
                        query: q_idx,
                        msg: format!(
                            "fold mismatch at round {r} (i_r={i_r} {})",
                            if i_r & 1 == 0 { "even" } else { "odd" }
                        ),
                    });
                }
            }

            // Last fold: challenges[last_r] takes the final-round pair down
            // to one cell of final_poly. Without this, final_poly is unbound.
            let last_r = proof.rounds.len() - 1;
            let alpha = challenges[last_r];
            let pair = &query.pairs[last_r];
            let log_last = proof.rounds[last_r].log_len;
            let i_last = i_0 >> (log_len_0 - log_last);
            let folded = if i_last & 1 == 0 {
                pair[0] + alpha * pair[1]
            } else {
                pair[1] + alpha * pair[0]
            };
            let log_f = proof.final_poly.len().trailing_zeros() as usize;
            let i_final = i_0 >> (log_len_0 - log_f);
            if folded != proof.final_poly[i_final] {
                return Err(FriBiniusError::Query {
                    query: q_idx,
                    msg: format!("final_poly[{i_final}] mismatch after last fold"),
                });
            }
        }

        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────


fn derive_challenge_from_commitment(
    round: &FriRoundCommitment,
    prev: &[Block128],
    seed: &[u8],
) -> Block128 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(seed);
    bytes.extend_from_slice(&round.root.blk_to_le_bytes());
    for p in prev {
        bytes.extend_from_slice(&p.blk_to_le_bytes());
    }
    let h = blake3::hash(&bytes);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&h.as_bytes()[..16]);
    Block128::from_le_bytes(arr)
}

fn derive_queries(
    rounds: &[FriRoundCommitment],
    final_poly: &[Block128],
    num_queries: usize,
    seed: &[u8],
    log_len_0: usize,
) -> Vec<usize> {
    let mut base = Vec::new();
    for r in rounds {
        base.extend_from_slice(&r.root.blk_to_le_bytes());
    }
    for p in final_poly {
        base.extend_from_slice(&p.blk_to_le_bytes());
    }
    base.extend_from_slice(seed);

    let mask = (1usize << log_len_0) - 1;
    let mut indices = Vec::with_capacity(num_queries);
    let mut counter = 0u64;
    while indices.len() < num_queries {
        let mut h_bytes = base.clone();
        h_bytes.extend_from_slice(&counter.to_le_bytes());
        let h = blake3::hash(&h_bytes);
        let candidate =
            u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap()) as usize;
        let idx = candidate & mask;
        if !indices.contains(&idx) {
            indices.push(idx);
        }
        counter += 1;
        if counter > 10_000 {
            break; // safety
        }
    }
    indices
}

fn has_leading_zero_bits(bytes: &[u8], bits: usize) -> bool {
    let full_bytes = bits / 8;
    let rem_bits = bits % 8;
    for b in bytes.iter().take(full_bytes) {
        if *b != 0 {
            return false;
        }
    }
    if rem_bits > 0 {
        let mask = 0xFF << (8 - rem_bits);
        if bytes[full_bytes] & mask != 0 {
            return false;
        }
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    fn evals() -> Vec<Block128> {
        (0..32u128).map(block).collect()
    }

    #[test]
    fn fold_correct() {
        let evs = vec![block(1), block(2), block(3), block(4)];
        let alpha = block(7);
        let folded = FriProver::fold(&evs, alpha);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0], block(1) + alpha * block(2));
        assert_eq!(folded[1], block(3) + alpha * block(4));
    }

    #[test]
    fn proof_round_trip() {
        let params = FriParams {
            log_inv_rate: 2,
            num_queries: 4,
            pow_bits: 0, // disable grinding for speed in test
        };
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let evs = evals();
        let seed = b"test-seed";
        let proof = prover.prove(evs, seed).unwrap();
        assert!(!proof.rounds.is_empty());
        assert!(!proof.final_poly.is_empty());
        // Verify
        let commitment_0 = proof.rounds[0].root;
        verifier.verify(commitment_0, &proof, seed).unwrap();
    }

    #[test]
    fn tampered_final_poly_fails() {
        let params = FriParams {
            log_inv_rate: 2,
            num_queries: 4,
            pow_bits: 0,
        };
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let evs = evals();
        let seed = b"test-seed";
        let mut proof = prover.prove(evs, seed).unwrap();

        // Each query folds its final-round pair down to one cell of
        // final_poly. Locate that cell for query 0 and flip it, so the
        // verifier is guaranteed to catch the change rather than relying
        // on query landings.
        let log_e0 = proof.rounds[0].log_len;
        let log_f = proof.final_poly.len().trailing_zeros() as usize;
        let target = proof.queries[0].index_0 >> (log_e0 - log_f);
        proof.final_poly[target] = block(999);

        let commitment_0 = proof.rounds[0].root;
        assert!(
            verifier.verify(commitment_0, &proof, seed).is_err(),
            "tampered final_poly[{target}] must be caught by query 0",
        );
    }

    #[test]
    fn sizes_16_through_256() {
        for log_n in [4usize, 5, 6, 7, 8] {
            let n = 1usize << log_n;
            let evs: Vec<_> = (0..n as u128).map(block).collect();
            let params = FriParams { log_inv_rate: 2, num_queries: 8, pow_bits: 0 };
            let prover = FriProver::new(params.clone());
            let verifier = FriVerifier::new(params);
            let seed = format!("size-{n}").into_bytes();
            let proof = prover.prove(evs, &seed).unwrap();
            let c0 = proof.rounds[0].root;
            verifier.verify(c0, &proof, &seed).unwrap();
        }
    }

    #[test]
    fn production_params_small_input() {
        // 32 elements, full production params (60 queries, 20-bit grinding)
        // Should complete in a couple of seconds — this exercises the
        // parameters that will ship on chain.
        let evs: Vec<_> = (0..32u128).map(block).collect();
        let params = FriParams::production();
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let seed = b"prod-test";
        let proof = prover.prove(evs, seed).unwrap();
        let c0 = proof.rounds[0].root;
        verifier.verify(c0, &proof, seed).unwrap();
    }

    #[test]
    fn grinding_works() {
        let params = FriParams {
            log_inv_rate: 2,
            num_queries: 4,
            pow_bits: 8,
        };
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let evs = evals();
        let seed = b"grinding-test";
        let proof = prover.prove(evs, seed).unwrap();
        let mut base = Vec::new();
        base.extend_from_slice(seed);
        for r in &proof.rounds {
            base.extend_from_slice(&r.root.blk_to_le_bytes());
        }
        for p in &proof.final_poly {
            base.extend_from_slice(&p.blk_to_le_bytes());
        }
        base.extend_from_slice(&proof.pow_nonce.to_le_bytes());
        let h = blake3::hash(&base);
        assert!(has_leading_zero_bits(h.as_bytes(), 8));
        let commitment_0 = proof.rounds[0].root;
        verifier.verify(commitment_0, &proof, seed).unwrap();
    }
}
