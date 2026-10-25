//! Top-level FRI-Binius PCS interface.
//!
//! Phase 2B: multi-round FRI + query sampling + grinding.

use crate::error::FriBiniusError;
use crate::fri::{FriParams, FriProof, FriProver, FriVerifier};
use crate::merkle::{Block128, MerkleTree};

/// Parameters for the PCS.
#[derive(Debug, Clone)]
pub struct FriBiniusParams {
    pub fri: FriParams,
}

impl Default for FriBiniusParams {
    fn default() -> Self {
        Self {
            fri: FriParams::default(),
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
    pub leaf: Block128,
    pub leaf_path: Vec<Block128>,
    pub leaf_index: usize,
}

/// The PCS.
pub struct FriBiniusPcs {
    pub params: FriBiniusParams,
}

impl FriBiniusPcs {
    pub fn new(params: FriBiniusParams) -> Self {
        Self { params }
    }

    /// Commit to evaluation vector.
    pub fn commit(&self, evals: Vec<Block128>) -> (FriBiniusCommitment, MerkleTree) {
        let tree = MerkleTree::new(evals);
        (
            FriBiniusCommitment { root: tree.root() },
            tree,
        )
    }

    /// Open at index: full FRI proof + direct Merkle path.
    pub fn open(
        &self,
        tree: &MerkleTree,
        index: usize,
        seed: &[u8],
    ) -> Result<FriBiniusOpening, FriBiniusError> {
        if index >= tree.leaves.len() {
            return Err(FriBiniusError::InvalidParams(format!(
                "index {index} >= leaves {}",
                tree.leaves.len()
            )));
        }
        let prover = FriProver::new(self.params.fri.clone());
        let fri_proof = prover.prove(tree.leaves.clone(), seed)?;
        let leaf_path = tree.path(index);
        Ok(FriBiniusOpening {
            fri_proof,
            leaf: tree.leaves[index],
            leaf_path,
            leaf_index: index,
        })
    }

    /// Verify opening.
    pub fn verify(
        &self,
        commitment: &FriBiniusCommitment,
        opening: &FriBiniusOpening,
        seed: &[u8],
    ) -> Result<(), FriBiniusError> {
        // 1. Direct leaf path
        if !MerkleTree::verify_path(
            opening.leaf,
            opening.leaf_index,
            &opening.leaf_path,
            commitment.root,
        ) {
            return Err(FriBiniusError::Query {
                query: opening.leaf_index,
                msg: "leaf path verification failed".into(),
            });
        }

        // 2. FRI proof verification
        let verifier = FriVerifier::new(self.params.fri.clone());
        verifier.verify(commitment.root, &opening.fri_proof, seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::FriParams;

    fn block(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    fn small_params() -> FriBiniusParams {
        FriBiniusParams {
            fri: FriParams {
                log_inv_rate: 2,
                num_queries: 4,
                pow_bits: 0,
            },
        }
    }

    #[test]
    fn commit_open_round_trip() {
        let pcs = FriBiniusPcs::new(small_params());
        let evals: Vec<_> = (0..32u128).map(block).collect();
        let (commitment, tree) = pcs.commit(evals);
        let seed = b"pcs-test";
        let opening = pcs.open(&tree, 5, seed).unwrap();
        pcs.verify(&commitment, &opening, seed).unwrap();
    }

    #[test]
    fn tampered_leaf_fails() {
        let pcs = FriBiniusPcs::new(small_params());
        let evals: Vec<_> = (0..32u128).map(block).collect();
        let (commitment, tree) = pcs.commit(evals);
        let seed = b"pcs-test";
        let mut opening = pcs.open(&tree, 5, seed).unwrap();
        opening.leaf = block(9999);
        assert!(pcs.verify(&commitment, &opening, seed).is_err());
    }

    #[test]
    fn wrong_commitment_fails() {
        let pcs = FriBiniusPcs::new(small_params());
        let evals: Vec<_> = (0..32u128).map(block).collect();
        let (_, tree) = pcs.commit(evals);
        let seed = b"pcs-test";
        let opening = pcs.open(&tree, 5, seed).unwrap();
        let wrong_commitment = FriBiniusCommitment { root: block(0xDEAD) };
        assert!(pcs.verify(&wrong_commitment, &opening, seed).is_err());
    }
}
