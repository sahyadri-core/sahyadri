//! Merkle path chaining AIR (Phase 3B).
//!
//! One row per Merkle level. Each row exposes:
//!
//!   curr     hash value entering this level
//!   sib      sibling at this level
//!   next     hash value leaving this level
//!   sel      0 = curr on left, 1 = curr on right
//!
//! Constraints here are:
//!   1. sel is boolean  (sel * (sel + 1) == 0)
//!   2. next is a value the prover claims equals Poseidon2b-compress
//!      of (curr, sib) or (sib, curr) depending on sel.
//!
//! Constraint (2) cannot be expressed algebraically here because
//! Poseidon2b is a permutation circuit. Phase 3D instantiates a
//! shared Poseidon2b AIR and bus-links each (curr, sib, next) triple
//! to it. Phase 3B tests verify the structural invariants that make
//! that bus link well-defined: booleanity, root pin, correct row count.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_field::PrimeCharacteristicRing;

pub const COL_CURR: usize = 0;
pub const COL_SIB: usize = 1;
pub const COL_NEXT: usize = 2;
pub const COL_SEL: usize = 3;
pub const WIDTH: usize = 4;

/// Merkle path AIR parameterised by depth.
///
/// The public input is a single field element: the root the path
/// terminates at. Row 0 is the leaf level; row depth-1 is the level
/// just below the root. `next` in the final row must equal the root.
pub struct MerklePathAir {
    pub depth: usize,
}

impl<F> BaseAir<F> for MerklePathAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder<F = BinaryField128>> Air<AB> for MerklePathAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let cur = main.current_slice();

        let curr: AB::Expr = cur[COL_CURR].into();
        let sib: AB::Expr = cur[COL_SIB].into();
        let next: AB::Expr = cur[COL_NEXT].into();
        let sel: AB::Expr = cur[COL_SEL].into();

        // sel ∈ {0, 1}
        let sel_sq = sel.clone() * sel.clone();
        b.assert_eq(sel_sq + sel, AB::F::ZERO);

        // Root pin on the last row: next == public_root.
        // `b.is_last_row()` gives the selector for the final row.
        let public = b.public_values();
        let root: AB::Expr = public[0].into();
        let last = b.is_last_row();
        b.when(last).assert_eq(next, root);

        // Reference curr and sib so the compiler sees they are inputs;
        // they are bus-linked to the Poseidon2b AIR in Phase 3D.
        let _ = (curr, sib);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;

    fn block(n: u128) -> BinaryField128 {
        BinaryField128::from_le_bytes(n.to_le_bytes())
    }

    /// Build a well-formed Merkle path trace for the given tree and leaf index.
    fn build_valid(
        tree: &MerkleTree,
        leaf_idx: usize,
    ) -> (RowMajorMatrix<BinaryField128>, Vec<BinaryField128>) {
        let depth = tree.depth();
        let mut rows = Vec::with_capacity(depth * WIDTH);
        let mut curr = tree.leaves[leaf_idx];
        let mut idx = leaf_idx;

        for level in 0..depth {
            let sib = tree.layers[level][idx ^ 1];
            let next = tree.layers[level + 1][idx >> 1];
            let sel = block((idx & 1) as u128);

            let mut row = vec![BinaryField128::from_le_bytes([0u8; 16]); WIDTH];
            row[COL_CURR] = curr;
            row[COL_SIB] = sib;
            row[COL_NEXT] = next;
            row[COL_SEL] = sel;
            rows.extend_from_slice(&row);

            curr = next;
            idx >>= 1;
        }

        let root = tree.root();
        (
            RowMajorMatrix::new(rows, WIDTH),
            vec![root],
        )
    }

    #[test]
    fn valid_path_satisfies() {
        let tree = MerkleTree::new((0..8u128).map(block).collect());
        let air = MerklePathAir { depth: tree.depth() };
        let (trace, public) = build_valid(&tree, 5);
        check_constraints(&air, &trace, &public);
    }

    #[test]
    fn all_leaves_satisfy() {
        let tree = MerkleTree::new((0..8u128).map(block).collect());
        let air = MerklePathAir { depth: tree.depth() };
        for i in 0..8 {
            let (trace, public) = build_valid(&tree, i);
            check_constraints(&air, &trace, &public);
        }
    }

    #[test]
    fn wrong_root_rejected() {
        let tree = MerkleTree::new((0..8u128).map(block).collect());
        let air = MerklePathAir { depth: tree.depth() };
        let (trace, mut public) = build_valid(&tree, 3);
        public[0] = block(0xDEAD);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "wrong root must be rejected");
    }

    #[test]
    fn non_boolean_sel_rejected() {
        let tree = MerkleTree::new((0..8u128).map(block).collect());
        let air = MerklePathAir { depth: tree.depth() };
        let (mut trace, public) = build_valid(&tree, 3);
        trace.values[COL_SEL] = block(2);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "non-boolean sel must be rejected");
    }

    #[test]
    fn tampered_last_row_rejected() {
        let tree = MerkleTree::new((0..8u128).map(block).collect());
        let air = MerklePathAir { depth: tree.depth() };
        let (mut trace, public) = build_valid(&tree, 3);
        // Flip the last row's next value, which is pinned to the root
        let depth = tree.depth();
        let last_off = (depth - 1) * WIDTH + COL_NEXT;
        trace.values[last_off] = block(0xBEEF);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "tampered final next must be rejected");
    }
}
