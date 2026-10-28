//! Bus-linked Merkle path AIR (Phase 3D2c).
//!
//! Wraps the plain `MerklePathAir` (structural constraints: booleanity, root
//! pin) with a **bus Pull** on `MERKLE_COMPRESS`. The consumer side of the
//! bus matches the producer in `p3_recursion::frost_gkr::poseidon2b_bus_air`.
//!
//! # Multiset argument
//!
//! For every row, this AIR pulls `(curr, sib, next)` from `MERKLE_COMPRESS`.
//! The `Poseidon2bBusAir` producer pushes the same tuple for every Poseidon2b
//! permutation it validates. MultiStark's bus multiset equality forces:
//!
//!   | Pulls | == | Pushes |  (as multisets)
//!
//! So every Merkle-path row must correspond to a real Poseidon2b compression
//! of `(curr, sib) -> next`. If a prover fabricates a leaf (changes `curr`),
//! the pull tuple won't match any push, breaking the multiset equality, and
//! the composed verifier rejects.
//!
//! # Width / public inputs
//!
//! Same as `MerklePathAir`: WIDTH = 4 (curr, sib, next, sel), 1 public (root).
//! The bus Pull is an additional constraint channel, not a column.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_field::PrimeCharacteristicRing;

use crate::merkle_path_air::{
    MerklePathAir, COL_CURR, COL_NEXT, COL_SEL, COL_SIB,
};

/// Bus channel for Merkle compression tuples.
///
/// The string is identical to `p3_recursion::frost_gkr::poseidon2b_bus_air::
/// MERKLE_COMPRESS`. Keeping a matching string is the whole linking
/// mechanism — Plonky3's `BusName` hashes to the string identity.
pub const MERKLE_COMPRESS: BusName<'static> = BusName::new("sahyadri_merkle_compress");

pub struct MerklePathBusAir {
    pub depth: usize,
}

impl<F> BaseAir<F> for MerklePathBusAir {
    fn width(&self) -> usize {
        <MerklePathAir as BaseAir<F>>::width(&MerklePathAir { depth: self.depth })
    }
    fn num_public_values(&self) -> usize {
        <MerklePathAir as BaseAir<F>>::num_public_values(&MerklePathAir { depth: self.depth })
    }
}

impl<AB> Air<AB> for MerklePathBusAir
where
    AB: AirBuilder<F = BinaryField128> + BusInteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        // 1. Structural constraints (booleanity of sel, root pin).
        MerklePathAir { depth: self.depth }.eval(b);

        // 2. Pull the compression tuple (curr, sib, next) from MERKLE_COMPRESS.
        //    Copy into owned Expr first — the borrow pattern from Poseidon2bAir.
        let (curr, sib, next) = {
            let main = b.main();
            let cur = main.current_slice();
            let curr: AB::Expr = cur[COL_CURR].into();
            let sib: AB::Expr = cur[COL_SIB].into();
            let next: AB::Expr = cur[COL_NEXT].into();
            (curr, sib, next)
        };

        b.push_bus_interaction(
            MERKLE_COMPRESS,
            BusDirection::Pull,
            [curr, sib, next],
            BusActivation::Always,
        );

        // Silence unused selector; sel is used by the inner MerklePathAir,
        // we re-read only to keep the constant wired for documentation.
        let _ = COL_SEL;
        let _ = <AB::F as PrimeCharacteristicRing>::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    fn blk(n: u128) -> BinaryField128 {
        BinaryField128::from_le_bytes(n.to_le_bytes())
    }

    #[test]
    fn width_and_public_match_plain() {
        let plain_w = <MerklePathAir as BaseAir<BinaryField128>>::width(&MerklePathAir { depth: 3 });
        let bus_w = <MerklePathBusAir as BaseAir<BinaryField128>>::width(&MerklePathBusAir { depth: 3 });
        assert_eq!(bus_w, plain_w);

        let plain_p = <MerklePathAir as BaseAir<BinaryField128>>::num_public_values(&MerklePathAir { depth: 3 });
        let bus_p = <MerklePathBusAir as BaseAir<BinaryField128>>::num_public_values(&MerklePathBusAir { depth: 3 });
        assert_eq!(bus_p, plain_p);
    }

    #[test]
    fn bus_name_is_constructible() {
        // Bus linkage depends on identical `BusName::new("...")` strings
        // in this crate and in `p3_recursion::frost_gkr::poseidon2b_bus_air`.
        // The string literal is verified manually against the producer.
        // Plonky3's multi-stark multiset equality at runtime is the
        // authoritative linkage check (3D2d).
        let _ = MERKLE_COMPRESS;
    }

    // Full bus-linkage test runs in the recursion crate (3D2d) because that's
    // where both Push (Poseidon2bBusAir) and Pull (this AIR) coexist.
    // Its negative case (fake leaf rejected) is 3D2e.

    #[test]
    fn merkle_tree_sanity_3_levels() {
        // Build an 8-leaf tree and confirm depth=3 path exists.
        let leaves: Vec<_> = (0..8u128).map(blk).collect();
        let tree = MerkleTree::new(leaves);
        assert_eq!(tree.depth(), 3);
    }
}
