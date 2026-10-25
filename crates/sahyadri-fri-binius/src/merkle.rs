//! Poseidon2b Merkle tree over BinaryField128.

use p3_binary_field::BinaryField128;

pub type Block128 = BinaryField128;

/// Simple binary Merkle tree.
pub struct MerkleTree {
    pub leaves: Vec<Block128>,
    pub layers: Vec<Vec<Block128>>,
}

impl MerkleTree {
    /// Build tree from leaves. Leaves must be power-of-two count.
    pub fn new(mut leaves: Vec<Block128>) -> Self {
        if leaves.is_empty() {
            leaves.push(Block128::from_le_bytes([0u8; 16]));
        }
        while !leaves.len().is_power_of_two() {
            leaves.push(Block128::from_le_bytes([0u8; 16]));
        }
        let mut layers = vec![leaves.clone()];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let next: Vec<Block128> = prev
                .chunks(2)
                .map(|pair| hash_pair(pair[0], pair[1]))
                .collect();
            layers.push(next);
        }
        Self { leaves, layers }
    }

    pub fn root(&self) -> Block128 {
        *self.layers.last().unwrap().last().unwrap()
    }

    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Generate Merkle path for leaf index.
    pub fn path(&self, mut index: usize) -> Vec<Block128> {
        let mut path = Vec::with_capacity(self.depth());
        for layer in self.layers.iter().take(self.layers.len() - 1) {
            path.push(layer[index ^ 1]);
            index >>= 1;
        }
        path
    }

    /// Verify a Merkle path.
    pub fn verify_path(
        leaf: Block128,
        mut index: usize,
        path: &[Block128],
        root: Block128,
    ) -> bool {
        let mut cur = leaf;
        for &sibling in path {
            cur = if index & 1 == 0 {
                hash_pair(cur, sibling)
            } else {
                hash_pair(sibling, cur)
            };
            index >>= 1;
        }
        cur == root
    }
}

/// Hash two field elements. Phase 1 uses 3-round Feistel with x^3 S-box.
/// Phase 2 swaps to Poseidon2b permutation.
///
/// Note: simple `a*b + a + b` collapses in binary field (h(1, x) = 1 for all x),
/// so we use a Feistel structure with cube S-box for non-linearity.
pub fn hash_pair(a: Block128, b: Block128) -> Block128 {
    let c1 = Block128::from_le_bytes([0x5Au8; 16]);
    let c2 = Block128::from_le_bytes([0xA5u8; 16]);
    let mut x = a + c1;
    let mut y = b + c2;
    for _ in 0..3 {
        let x3 = x * x * x;
        y = y + x3 + c1;
        let y3 = y * y * y;
        x = x + y3 + c2;
    }
    x + y + c1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    #[allow(dead_code)]
    fn fe(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    fn leaf(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    #[test]
    fn build_and_root() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3), leaf(4)]);
        assert_eq!(tree.depth(), 2);
        let root = tree.root();
        assert_ne!(root, leaf(0));
    }

    #[test]
    fn path_verifies() {
        let leaves: Vec<_> = (0..8).map(leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        for i in 0..8 {
            let path = tree.path(i);
            assert!(MerkleTree::verify_path(leaves[i], i, &path, root));
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaves: Vec<_> = (0..4).map(leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        let path = tree.path(2);
        assert!(!MerkleTree::verify_path(leaf(999), 2, &path, root));
    }
}
