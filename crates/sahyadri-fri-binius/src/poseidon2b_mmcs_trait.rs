//! Poseidon2bMmcs as a proper `Mmcs<F>` trait implementation.
//!
//! Wraps the existing standalone `Poseidon2bMmcs` in the Plonky3 `Mmcs`
//! trait so it can be used as inner of `GroupedCodewordMmcs` and hence
//! inside `BinaryPcs`.
//!
//! # Design
//! - `Commitment` = `Digest` ([Block128; 2], 32 bytes)
//! - `ProverData<M>` = tree + matrices (for opening)
//! - `Proof` = single path ([Digest])
//! - `MultiProof` = merged paths for multi-index opening
//!
//! # Soundness
//! Same as standalone Poseidon2bMmcs: 128-bit collision-resistance via
//! Poseidon2b permutation in GF(2^128).
//!
//! # Status (Session 1 scaffold)
//! - [x] Struct + type definitions
//! - [x] `commit` (build full tree)
//! - [x] `open_batch` / `verify_batch` (single index)
//! - [x] `open_multi_batch` / `verify_multi_batch` (multi index)
//! - [x] `get_matrices` (return original matrices)
//! - [ ] `MultiProof` compact form (currently full paths)
//! - [ ] `Error` variants for all failure modes
//! - [ ] `Matrix` trait bound tuning (needs `Matrix<T>` impl)
//!
//! # Honest scope
//! This gets the type-level trait impl working so `GroupedCodewordMmcs<Poseidon2bMmcs>`
//! type-checks. Full compact multi-proof + integration with BinaryPcs is Session 2.

use p3_binary_field::BinaryField128 as F;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::Dimensions;
use p3_matrix::Matrix;
use p3_poseidon2b::poseidon2b_permutation;
use p3_field::PrimeCharacteristicRing;
use core::fmt::Debug;

use crate::poseidon2b_compression::MERKLE_DOMAIN;

pub type Digest = [F; 2];

// ============================================================================
// Compression (reuse standalone logic)
// ============================================================================

#[inline]
fn compress(a: F, b: F) -> F {
    let mut state = [a, b, F::ZERO, F::from_le_bytes((MERKLE_DOMAIN as u128).to_le_bytes())];
    poseidon2b_permutation(&mut state);
    state[0] + state[1]
}

#[inline]
fn hash_pair(l: Digest, r: Digest) -> Digest {
    [compress(l[0], r[0]), compress(l[1], r[1])]
}

#[inline]
fn hash_leaf(value: F) -> Digest {
    [compress(value, F::ZERO), compress(F::ZERO, value)]
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, Clone)]
pub enum Poseidon2bMmcsError {
    DimensionMismatch,
    PathLengthMismatch,
    IndexOutOfBounds,
    CommitmentMismatch,
}

// ============================================================================
// Prover data
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Poseidon2bProverData<M> {
    /// Full Merkle tree as flat Vec (leaf level first, then upper levels).
    tree: Vec<Digest>,
    /// Original matrices (for get_matrices).
    matrices: Vec<M>,
    /// Per-matrix log height (parallel to matrices).
    log_heights: Vec<usize>,
    /// Per-matrix start offset in tree.
    offsets: Vec<usize>,
}

// ============================================================================
// Proof types
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Poseidon2bProof {
    /// Sibling digests from leaf up to root.
    pub siblings: Vec<Digest>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Poseidon2bMultiProof {
    /// One path per index; each path is (index, siblings).
    /// TODO Session 2: merge shared ancestors for compactness.
    pub paths: Vec<(usize, Vec<Digest>)>,
}

// ============================================================================
// The Mmcs impl
// ============================================================================

#[derive(Clone)]
pub struct Poseidon2bMmcs;

impl Poseidon2bMmcs {
    pub fn new() -> Self { Self }

    /// Build tree for `leaves` (padded to power-of-two).
    fn build_tree(&self, leaves: &[F]) -> (Digest, Vec<Digest>) {
        let n = leaves.len().next_power_of_two();
        let mut level: Vec<Digest> = (0..n)
            .map(|i| hash_leaf(leaves.get(i).copied().unwrap_or(F::ZERO)))
            .collect();

        let mut tree = level.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks(2) {
                next.push(hash_pair(chunk[0], chunk[1]));
            }
            tree.extend_from_slice(&next);
            level = next;
        }
        (level[0], tree)
    }

    /// Extract path for one index.
    fn extract_path(&self, tree: &[Digest], n: usize, index: usize) -> Vec<Digest> {
        let mut path = Vec::new();
        let mut idx = index;
        let mut level_start = 0usize;
        let mut level_size = n;

        while level_size > 1 {
            let sib_idx = idx ^ 1;
            path.push(tree[level_start + sib_idx]);
            level_start += level_size;
            level_size >>= 1;
            idx >>= 1;
        }
        path
    }

    /// Verify one path.
    fn verify_path(&self, root: &Digest, index: usize, value: F, path: &[Digest]) -> bool {
        let mut curr = hash_leaf(value);
        let mut idx = index;
        for sib in path {
            curr = if idx & 1 == 0 {
                hash_pair(curr, *sib)
            } else {
                hash_pair(*sib, curr)
            };
            idx >>= 1;
        }
        &curr == root
    }
}

impl Mmcs<F> for Poseidon2bMmcs {
    type ProverData<M> = Poseidon2bProverData<M>;
    type Commitment = Digest;
    type Proof = Poseidon2bProof;
    type MultiProof = Poseidon2bMultiProof;
    type Error = Poseidon2bMmcsError;

    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        assert_eq!(inputs.len(), 1, "Poseidon2bMmcs commits one matrix per call");
        let matrix = inputs.into_iter().next().unwrap();
        assert_eq!(matrix.width(), 1, "expected width-1 codeword");

        let height = matrix.height();
        assert!(height.is_power_of_two(), "expected power-of-two height");

        // Flatten matrix to Vec<F>
        let leaves: Vec<F> = (0..height)
            .map(|r| matrix.get(r, 0).unwrap_or(F::ZERO))
            .collect();

        let (root, tree) = self.build_tree(&leaves);

        let prover_data = Poseidon2bProverData {
            tree,
            matrices: vec![matrix],
            log_heights: vec![height.trailing_zeros() as usize],
            offsets: vec![0],
        };

        (root, prover_data)
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        data.matrices.iter().collect()
    }

    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        let matrix = &data.matrices[0];
        let height = matrix.height();
        assert!(index < height, "index out of bounds");

        let value = matrix.get(index, 0).unwrap_or(F::ZERO);
        let path = self.extract_path(&data.tree, height, index);

        BatchOpening::new(vec![vec![value]], Poseidon2bProof { siblings: path })
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        assert_eq!(dimensions.len(), 1, "expected one dimension");
        let dim = dimensions[0];
        if index >= dim.height {
            return Err(Poseidon2bMmcsError::IndexOutOfBounds);
        }

        if opening.opened_values.len() != 1 || opening.opened_values[0].len() != 1 {
            return Err(Poseidon2bMmcsError::DimensionMismatch);
        }

        let value = opening.opened_values[0][0];
        if self.verify_path(commitment, index, value, &opening.opening_proof.siblings) {
            Ok(())
        } else {
            Err(Poseidon2bMmcsError::CommitmentMismatch)
        }
    }

    fn open_multi_batch<M: Matrix<F>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<F>>>, Self::MultiProof) {
        let matrix = &data.matrices[0];
        let height = matrix.height();

        let rows: Vec<Vec<Vec<F>>> = indices
            .iter()
            .map(|&i| {
                assert!(i < height);
                vec![vec![matrix.get(i, 0).unwrap_or(F::ZERO)]]
            })
            .collect();

        let paths: Vec<(usize, Vec<Digest>)> = indices
            .iter()
            .map(|&i| (i, self.extract_path(&data.tree, height, i)))
            .collect();

        (rows, Poseidon2bMultiProof { paths })
    }

    fn verify_multi_batch<R: AsRef<[F]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        opening_proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        assert_eq!(dimensions.len(), 1);
        let dim = dimensions[0];

        if indices.len() != opened_values.len() || indices.len() != opening_proof.paths.len() {
            return Err(Poseidon2bMmcsError::DimensionMismatch);
        }

        for (q, &index) in indices.iter().enumerate() {
            if index >= dim.height {
                return Err(Poseidon2bMmcsError::IndexOutOfBounds);
            }
            if opened_values[q].len() != 1 {
                return Err(Poseidon2bMmcsError::DimensionMismatch);
            }
            let row_ref = opened_values[q][0].as_ref();
            if row_ref.len() != 1 {
                return Err(Poseidon2bMmcsError::DimensionMismatch);
            }
            let value = row_ref[0];
            let (_, ref path) = opening_proof.paths[q];
            if path.len() != (dim.height.trailing_zeros() as usize) {
                return Err(Poseidon2bMmcsError::PathLengthMismatch);
            }
            if !self.verify_path(commitment, index, value, path) {
                return Err(Poseidon2bMmcsError::CommitmentMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::dense::RowMajorMatrix;

    fn blk(n: u128) -> F { F::from_le_bytes(n.to_le_bytes()) }

    fn make_matrix(values: Vec<F>) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(values, 1)
    }

    #[test]
    fn commit_and_single_verify() {
        let mmcs = Poseidon2bMmcs::new();
        let leaves: Vec<F> = (0..16u128).map(blk).collect();
        let matrix = make_matrix(leaves.clone());

        let (root, prover_data) = mmcs.commit(vec![matrix.clone()]);

        // Verify each leaf
        for i in 0..16 {
            let opening = mmcs.open_batch(i, &prover_data);
            let dims = vec![Dimensions { width: 1, height: 16 }];
            let opening_ref = BatchOpeningRef {
                opened_values: &opening.opened_values,
                opening_proof: &opening.opening_proof,
            };
            mmcs.verify_batch(&root, &dims, i, opening_ref)
                .unwrap_or_else(|_| panic!("index {} should verify", i));
        }
    }

    #[test]
    fn tampered_value_rejected() {
        let mmcs = Poseidon2bMmcs::new();
        let leaves: Vec<F> = (0..16u128).map(blk).collect();
        let matrix = make_matrix(leaves);

        let (root, prover_data) = mmcs.commit(vec![matrix]);
        let opening = mmcs.open_batch(7, &prover_data);

        // Tamper: change the opened value
        let mut bad_opening = opening.clone();
        bad_opening.opened_values[0][0] = blk(999);

        let dims = vec![Dimensions { width: 1, height: 16 }];
        let bad_ref = BatchOpeningRef {
            opened_values: &bad_opening.opened_values,
            opening_proof: &bad_opening.opening_proof,
        };
        let result = mmcs.verify_batch(&root, &dims, 7, bad_ref);
        assert!(result.is_err(), "tampered value must be rejected");
    }

    #[test]
    fn multi_batch_works() {
        let mmcs = Poseidon2bMmcs::new();
        let leaves: Vec<F> = (0..16u128).map(blk).collect();
        let matrix = make_matrix(leaves);

        let (root, prover_data) = mmcs.commit(vec![matrix]);
        let indices = [3usize, 7, 11, 15];

        let (rows, multi_proof) = mmcs.open_multi_batch(&indices, &prover_data);

        // Convert rows to refs format for verify
        let row_refs: Vec<Vec<&[F]>> = rows
            .iter()
            .map(|r| r.iter().map(|v| v.as_slice()).collect())
            .collect();

        let dims = vec![Dimensions { width: 1, height: 16 }];
        mmcs.verify_multi_batch(&root, &dims, &indices, &row_refs, &multi_proof)
            .expect("multi batch should verify");
    }
}
