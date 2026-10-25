//! Poseidon2b compression for Merkle tree.
//!
//! Phase 2A: real 2-to-1 compression using Poseidon2b permutation
//! over GF(2^128).
//!
//! Design (sponge-style):
//!   state[0] = a
//!   state[1] = b
//!   state[2] = 0 (capacity)
//!   state[3] = domain tag (capacity)
//!   permute(state)
//!   output = state[0] + state[1]

use p3_binary_field::BinaryField128 as Block128;
use p3_poseidon2b::poseidon2b_permutation;

/// State size for Poseidon2b params128_t4 (from p3-poseidon2b/params.rs).
const STATE_SIZE: usize = 4;

/// Domain separation tag: "MERKLE" + 0x01
const MERKLE_DOMAIN: u128 = 0x4D45_524B_4C45_0001;

/// Compress two field elements into one using Poseidon2b.
///
/// Merkle tree node compression: `h(a, b) = squeeze(permute([a, b, 0, tag]))`.
pub fn compress(a: Block128, b: Block128) -> Block128 {
    let mut state: [Block128; STATE_SIZE] = [
        a,
        b,
        Block128::from_le_bytes([0u8; 16]),
        Block128::from_le_bytes(MERKLE_DOMAIN.to_le_bytes()),
    ];
    poseidon2b_permutation(&mut state);
    state[0] + state[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    #[test]
    fn compress_deterministic() {
        let a = block(1);
        let b = block(2);
        assert_eq!(compress(a, b), compress(a, b));
    }

    #[test]
    fn compress_order_matters() {
        let a = block(1);
        let b = block(2);
        assert_ne!(compress(a, b), compress(b, a));
    }

    #[test]
    fn compress_avalanche() {
        let h1 = compress(block(1), block(100));
        let h2 = compress(block(2), block(100));
        assert_ne!(h1, h2);
    }

    #[test]
    fn compress_no_collapse() {
        // The Feistel bug: h(1, x) = 1 for all x. Poseidon2b should not.
        let h1 = compress(block(1), block(2));
        let h2 = compress(block(1), block(3));
        assert_ne!(h1, h2, "Poseidon2b must not collapse first-arg-1");
    }
}
