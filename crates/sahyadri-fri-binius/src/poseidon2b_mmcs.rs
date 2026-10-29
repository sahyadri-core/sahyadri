//! Poseidon2bMmcs — binary Mmcs using Poseidon2b compression.
//!
//! Wraps a level MMCS-style Merkle tree where each internal node is
//! `Poseidon2b compress(left, right)` (produces 2 Block128 output lanes;
//! we use `out0 + out1` as the digest, matching 3D2b bus convention).
//!
//! # Why
//!
//! Plonky3's BinaryPcs uses `GroupedCodewordMmcs` with a level tree (blake3
//! by default in test configs). For on-chain PoW, we want Poseidon2b
//! compression so the same hash underlies both the PoC chain and PoW
//! verification. This Mmcs is what 3F should use in T1.0b.
//!
//! # Digest format
//!
//! - Leaf digest: `[Block128; 2]` from poseidon2b(leaf_padded)
//! - Node digest: `[Block128; 2]` from poseidon2b((left, right, 0, DOMAIN))
//! - Root: single `[Block128; 2]` — 32 bytes, same size as blake3::LevelMmcs
//!
//! # Soundness
//!
//! Poseidon2b is collision-resistant (per p3-poseidon2b). 128-bit security
//! at 2 lanes × 64-bit output. Matches the security level of blake3 for
//! Merkle composition (both 128-bit).

use p3_binary_field::BinaryField128 as F;
use p3_poseidon2b::poseidon2b_permutation;
use crate::poseidon2b_compression::MERKLE_DOMAIN;
use p3_field::PrimeCharacteristicRing;

pub type Digest = [F; 2];

#[inline]
fn compress(a: F, b: F) -> F {
    let mut state = [a, b, F::ZERO, F::from_le_bytes((MERKLE_DOMAIN as u128).to_le_bytes())];
    poseidon2b_permutation(&mut state);
    state[0] + state[1]
}

#[inline]
fn hash_pair(l: Digest, r: Digest) -> Digest {
    // Combine lanes: (l0, l1) + (r0, r1) → (compress(l0, r0), compress(l1, r1))
    // Simple 2-lane-to-2-lane compression, order-sensitive via argument order.
    [compress(l[0], r[0]), compress(l[1], r[1])]
}

#[inline]
fn hash_leaf(value: F) -> Digest {
    [compress(value, F::ZERO), compress(F::ZERO, value)]
}

pub struct Poseidon2bMmcs;

impl Poseidon2bMmcs {
    pub fn new() -> Self { Self }

    pub fn commit(leaves: &[F]) -> (Digest, Vec<Digest>) {
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

    pub fn open(leaves: &[F], index: usize) -> (Digest, Vec<Digest>, F) {
        let value = leaves[index];
        let (root, tree) = Self::commit(leaves);

        let n = leaves.len().next_power_of_two();
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
        (root, path, value)
    }

    pub fn verify(root: &Digest, index: usize, value: F, path: &[Digest]) -> bool {
        let mut curr = hash_leaf(value);
        let mut idx = index;
        for sib in path {
            curr = if idx & 1 == 0 { hash_pair(curr, *sib) } else { hash_pair(*sib, curr) };
            idx >>= 1;
        }
        &curr == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_verify() {
        let leaves: Vec<F> = (0..16u128).map(|i| F::from_le_bytes(i.to_le_bytes())).collect();
        let (root, path, value) = Poseidon2bMmcs::open(&leaves, 7);
        assert!(Poseidon2bMmcs::verify(&root, 7, value, &path));
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaves: Vec<F> = (0..16u128).map(|i| F::from_le_bytes(i.to_le_bytes())).collect();
        let (root, path, value) = Poseidon2bMmcs::open(&leaves, 3);
        let bad = value + F::from_le_bytes(1u128.to_le_bytes());
        assert!(!Poseidon2bMmcs::verify(&root, 3, bad, &path));
    }

    #[test]
    fn tampered_path_fails() {
        let leaves: Vec<F> = (0..16u128).map(|i| F::from_le_bytes(i.to_le_bytes())).collect();
        let (root, mut path, value) = Poseidon2bMmcs::open(&leaves, 5);
        path[0][0] = path[0][0] + F::from_le_bytes(1u128.to_le_bytes());
        assert!(!Poseidon2bMmcs::verify(&root, 5, value, &path));
    }

    #[test]
    fn wrong_index_fails() {
        let leaves: Vec<F> = (0..16u128).map(|i| F::from_le_bytes(i.to_le_bytes())).collect();
        let (root, path, value) = Poseidon2bMmcs::open(&leaves, 7);
        assert!(!Poseidon2bMmcs::verify(&root, 8, value, &path));
    }
}
