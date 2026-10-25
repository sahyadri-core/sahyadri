//! Top-level FRI-Binius PCS interface.

use crate::error::FriBiniusError;
use crate::fri::{FriProof, FriProver, FriVerifier};
use crate::merkle::{Block128, MerkleTree};

/// Parameters for the PCS.
#[derive(Debug, Clone)]
pub struct FriBiniusParams {
    pub log_inv_rate: usize,
    pub num_queries: usize,
    pub folding_factor: usize,
    pub log_blowup: usize,
}

impl Default for FriBiniusParams {
    fn default() -> Self {
        Self {
            log_inv_rate: 2,
            num_queries: 64,
            folding_factor: 2,
            log_blowup: 1,
        }
    }
}

/// Commitment to a polynomial.
#[derive(Debug, Clone, Copy)]
pub struct FriBiniusCommitment {
    pub root: Block128,
}

/// Opening of a polynomial at a point.
#[derive(Debug, Clone)]
pub struct FriBiniusOpening {
    pub fri_proof: FriProof,
    pub path: Vec<Block128>,
    pub index: usize,
}

/// The PCS.
pub struct FriBiniusPcs {
    pub params: FriBiniusParams,
}

impl FriBiniusPcs {
    pub fn new(params: FriBiniusParams) -> Self {
        Self { params }
    }

    /// Commit to evaluation vector. Returns commitment + tree.
    pub fn commit(&self, evals: Vec<Block128>) -> (FriBiniusCommitment, MerkleTree) {
        let tree = MerkleTree::new(evals);
        (FriBiniusCommitment { root: tree.root() }, tree)
    }

    /// Open at index.
    pub fn open(
        &self,
        tree: &MerkleTree,
        index: usize,
        challenges: &[Block128],
    ) -> Result<FriBiniusOpening, FriBiniusError> {
        if index >= tree.leaves.len() {
            return Err(FriBiniusError::InvalidParams(format!(
                "index {index} >= leaves {}",
                tree.leaves.len()
            )));
        }
        let prover = FriProver::new(
            self.params.log_inv_rate,
            self.params.num_queries,
            self.params.folding_factor,
        );
        let fri_proof = prover.prove(tree.leaves.clone(), challenges);
        let path = tree.path(index);
        Ok(FriBiniusOpening {
            fri_proof,
            path,
            index,
        })
    }

    /// Verify opening.
    pub fn verify(
        &self,
        commitment: &FriBiniusCommitment,
        opening: &FriBiniusOpening,
        challenges: &[Block128],
    ) -> bool {
        // 1. Merkle path
        if !MerkleTree::verify_path(
            opening.fri_proof.rounds[0].evals[opening.index],
            opening.index,
            &opening.path,
            commitment.root,
        ) {
            return false;
        }
        // 2. FRI fold
        let verifier = FriVerifier::new(self.params.log_inv_rate, self.params.num_queries);
        verifier.verify(&opening.fri_proof, challenges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn fe(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    #[test]
    fn commit_and_open_round_trip() {
        let pcs = FriBiniusPcs::new(FriBiniusParams::default());
        let evals: Vec<_> = (0..16u128).map(|n: u128| Block128::from_le_bytes(n.to_le_bytes())).collect();
        let (commitment, tree) = pcs.commit(evals);
        let challenges = vec![fe(2), fe(3)];
        let opening = pcs.open(&tree, 5, &challenges).unwrap();
        assert!(pcs.verify(&commitment, &opening, &challenges));
    }

    #[test]
    fn tampered_opening_fails() {
        let pcs = FriBiniusPcs::new(FriBiniusParams::default());
        let evals: Vec<_> = (0..16u128).map(|n: u128| Block128::from_le_bytes(n.to_le_bytes())).collect();
        let (commitment, tree) = pcs.commit(evals);
        let challenges = vec![fe(2), fe(3)];
        let mut opening = pcs.open(&tree, 5, &challenges).unwrap();
        opening.index = 6;
        assert!(!pcs.verify(&commitment, &opening, &challenges));
    }
}
