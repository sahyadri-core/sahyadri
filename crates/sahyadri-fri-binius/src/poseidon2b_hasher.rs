//! Poseidon2b as `CryptographicHasher` + `PseudoCompressionFunction` for
//! standard `MerkleTreeMmcs<F, u8, H, C, 2, 32>`.
//!
//! # Purpose
//! `PreparedBinaryGroupedMultiStarkLayer::import_native` requires `BinaryPcsProof`
//! over `MerkleTreeMmcs<F, u8, H, C, 2, 32>`. Our A'2 proofs use `Poseidon2bMmcs`
//! (custom, `Digest = [F; 2]`). This adapter exposes the same field-level Poseidon2b
//! compression as `MerkleTreeMmcs` traits so A'2 proofs can be imported.
//!
//! # Structure
//! - `Poseidon2bMmcs::Digest = [F; 2]` = 32 bytes (2 × 16-byte field elements)
//! - `hash_leaf(a) = [compress(a, 0), compress(0, a)]`
//! - `hash_pair([l0,l1], [r0,r1]) = [compress(l0, r0), compress(l1, r1)]`
//!
//! Both traits below reproduce this exactly. Unit test compares against
//! `Poseidon2bMmcs::commit(leaves)` root.
//!
//! # Caveat (Phase 2b-2b S7 rebuild)
//! `MerkleTreeMmcs` tree does 2 compressions per internal node (2× Poseidon2bBusAir
//! producers per level). S4/S5 `MerklePathAir` does 1 (single-F digests). After
//! hasher/compressor land, S7 must be rebuilt with `[F; 2]` tree — separate session.

use p3_binary_field::BinaryField128;
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2b::poseidon2b_permutation;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::poseidon2b_compression::MERKLE_DOMAIN;

/// Field-level Poseidon2b compression — identical to `Poseidon2bMmcs::compress`.
#[inline]
fn field_compress(a: BinaryField128, b: BinaryField128) -> BinaryField128 {
    let mut state = [
        a,
        b,
        BinaryField128::ZERO,
        BinaryField128::from_le_bytes((MERKLE_DOMAIN as u128).to_le_bytes()),
    ];
    poseidon2b_permutation(&mut state);
    state[0] + state[1]
}

/// Field element to 16-byte little-endian representation.
#[inline]
fn field_to_bytes(f: BinaryField128) -> [u8; 16] {
    // BinaryField128 is repr(transparent) over u128 in this crate.
    unsafe { core::mem::transmute_copy(&f) }
}

/// 16-byte little-endian to field element.
#[inline]
fn bytes_to_field(b: &[u8]) -> BinaryField128 {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&b[..16]);
    BinaryField128::from_le_bytes(arr)
}

/// Poseidon2b hasher matching `Poseidon2bMmcs::hash_leaf` semantics.
///
/// # Digest layout
/// 32 bytes = `[compress(leaf, 0) || compress(0, leaf)]` (2 × 16-byte LE).
#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2bFieldHash;

impl CryptographicHasher<BinaryField128, [u8; 32]> for Poseidon2bFieldHash {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = BinaryField128>,
    {
        let items: Vec<BinaryField128> = input.into_iter().collect();

        let (d0, d1) = if items.is_empty() {
            // Empty input: hash of zero
            (
                field_compress(BinaryField128::ZERO, BinaryField128::ZERO),
                field_compress(BinaryField128::ZERO, BinaryField128::ZERO),
            )
        } else if items.len() == 1 {
            // Single leaf: matches hash_leaf(a)
            let a = items[0];
            (
                field_compress(a, BinaryField128::ZERO),
                field_compress(BinaryField128::ZERO, a),
            )
        } else {
            // Multi-item: fold pair-wise starting from hash_leaf(first)
            let mut acc = (
                field_compress(items[0], BinaryField128::ZERO),
                field_compress(BinaryField128::ZERO, items[0]),
            );
            let mut i = 1;
            while i + 1 < items.len() {
                acc = (field_compress(acc.0, items[i]), field_compress(acc.1, items[i + 1]));
                i += 2;
            }
            if i < items.len() {
                acc = (field_compress(acc.0, items[i]), field_compress(acc.1, BinaryField128::ZERO));
            }
            acc
        };

        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&field_to_bytes(d0));
        out[16..].copy_from_slice(&field_to_bytes(d1));
        out
    }
}

/// Poseidon2b compressor matching `Poseidon2bMmcs::hash_pair` semantics.
///
/// # Input / output layout
/// `compress([l0 || l1], [r0 || r1]) = compress(l0, r0) || compress(l1, r1)`
/// (each 16 bytes LE).
#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2bFieldCompress;

impl PseudoCompressionFunction<[u8; 32], 2> for Poseidon2bFieldCompress {
    fn compress(&self, input: [[u8; 32]; 2]) -> [u8; 32] {
        let l0 = bytes_to_field(&input[0][..16]);
        let l1 = bytes_to_field(&input[0][16..]);
        let r0 = bytes_to_field(&input[1][..16]);
        let r1 = bytes_to_field(&input[1][16..]);
        let c0 = field_compress(l0, r0);
        let c1 = field_compress(l1, r1);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&field_to_bytes(c0));
        out[16..].copy_from_slice(&field_to_bytes(c1));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2b_mmcs::Poseidon2bMmcs;

    fn make_leaves(n: u128) -> Vec<BinaryField128> {
        (0..n)
            .map(|i| BinaryField128::from_le_bytes((i * 0x1111 + 0xDEAD).to_le_bytes()))
            .collect()
    }

    #[test]
    fn tree_root_matches_poseidon2b_mmcs() {
        let leaves = make_leaves(16);
        let (mmcs_root, _) = Poseidon2bMmcs::commit(&leaves);

        let hasher = Poseidon2bFieldHash;
        let compressor = Poseidon2bFieldCompress;
        let mut level: Vec<[u8; 32]> =
            leaves.iter().map(|&l| hasher.hash_item(l)).collect();
        while level.len() > 1 {
            let next: Vec<[u8; 32]> = level
                .chunks(2)
                .map(|p| compressor.compress([p[0], p[1]]))
                .collect();
            level = next;
        }
        let tree_root = level[0];

        let mut expected = [0u8; 32];
        expected[..16].copy_from_slice(&field_to_bytes(mmcs_root[0]));
        expected[16..].copy_from_slice(&field_to_bytes(mmcs_root[1]));
        assert_eq!(
            tree_root, expected,
            "MerkleTreeMmcs-style root must match Poseidon2bMmcs::commit"
        );
    }

    #[test]
    fn tree_root_matches_poseidon2b_mmcs_various_sizes() {
        for n in [1u128, 2, 4, 8, 32] {
            let leaves = make_leaves(n);
            let (mmcs_root, _) = Poseidon2bMmcs::commit(&leaves);
            let hasher = Poseidon2bFieldHash;
            let compressor = Poseidon2bFieldCompress;
            let mut level: Vec<[u8; 32]> =
                leaves.iter().map(|&l| hasher.hash_item(l)).collect();
            while level.len() > 1 {
                let next: Vec<[u8; 32]> = level
                    .chunks(2)
                    .map(|p| compressor.compress([p[0], p[1]]))
                    .collect();
                level = next;
            }
            let mut expected = [0u8; 32];
            expected[..16].copy_from_slice(&field_to_bytes(mmcs_root[0]));
            expected[16..].copy_from_slice(&field_to_bytes(mmcs_root[1]));
            assert_eq!(level[0], expected, "size {} mismatch", n);
        }
    }

    #[test]
    fn compressor_is_deterministic() {
        let c = Poseidon2bFieldCompress;
        let l = [0x11u8; 32];
        let r = [0x22u8; 32];
        assert_eq!(c.compress([l, r]), c.compress([l, r]));
    }

    #[test]
    fn compressor_is_order_sensitive() {
        let c = Poseidon2bFieldCompress;
        let l = [0x11u8; 32];
        let r = [0x22u8; 32];
        assert_ne!(c.compress([l, r]), c.compress([r, l]));
    }

    #[test]
    fn hasher_is_deterministic() {
        let h = Poseidon2bFieldHash;
        let leaf = BinaryField128::from_le_bytes(0xABCDEFu128.to_le_bytes());
        assert_eq!(h.hash_item(leaf), h.hash_item(leaf));
    }

    #[test]
    fn hasher_handles_empty_input() {
        let h = Poseidon2bFieldHash;
        let d = h.hash_iter(std::iter::empty());
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn compressor_trait_lanes_default() {
        // Ensure LANES defaults to 1 (scalar implementation)
        assert_eq!(<Poseidon2bFieldCompress as PseudoCompressionFunction<[u8; 32], 2>>::LANES, 1);
        assert_eq!(<Poseidon2bFieldHash as CryptographicHasher<BinaryField128, [u8; 32]>>::LANES, 1);
    }
}
