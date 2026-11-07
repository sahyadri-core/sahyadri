//! MerklePathBusAir2F — Merkle path AIR for `[F;2]` (32-byte) digests.
//!
//! # Purpose
//! `MerkleTreeMmcs<F, u8, Poseidon2bFieldHash, Poseidon2bFieldCompress, 2, 32>`
//! uses 32-byte digests = 2 field elements. Each tree node is a pair `(F, F)`.
//! This AIR PULLs two `(curr, sib, parent)` tuples per real row, one per lane,
//! matching `Poseidon2bFieldCompress::compress([[l0,l1],[r0,r1]]) =
//! [compress(l0,r0), compress(l1,r1)]`.
//!
//! # Difference from MerklePathBusAir (1F)
//! - 1F: WIDTH=4, 1 Pull per row `(curr, sib, parent)`
//! - 2F: WIDTH=7, 2 Pulls per row `(curr0,sib0,parent0)` + `(curr1,sib1,parent1)`
//!
//! # Bus
//! Both Pulls go to the same `sahyadri_merkle_compress` bus.
//! `Poseidon2bBusAir` producers PUSH `(a, b, compress(a,b))` once per instance.
//! Bus multiset equality forces every 2F path tuple lane to correspond to
//! a real Poseidon2b compression — this is what makes the path admissible.
//!
//! # Padding
//! Rows with `is_real = 0` emit **no** Pull (gated by `BusActivation::Boolean`).
//! Both lanes share the same `is_real` flag, so a real path level always
//! contributes exactly 2 Pulls and a padding row exactly 0.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_field::PrimeCharacteristicRing;

/// Bus channel — must match `Poseidon2bBusAir` push name
/// (`p3_recursion::frost_gkr::poseidon2b_bus_air::MERKLE_COMPRESS`).
pub const MERKLE_COMPRESS: BusName<'static> = BusName::new("sahyadri_merkle_compress");

// ── Column layout (WIDTH = 7) ──

/// Lane 0: current node field element 0.
pub const MP2_CURR0: usize = 0;
/// Lane 1: current node field element 1.
pub const MP2_CURR1: usize = 1;
/// Lane 0: sibling field element 0.
pub const MP2_SIB0: usize = 2;
/// Lane 1: sibling field element 1.
pub const MP2_SIB1: usize = 3;
/// Lane 0: parent field element 0 (claimed = compress(curr0, sib0)).
pub const MP2_PARENT0: usize = 4;
/// Lane 1: parent field element 1 (claimed = compress(curr1, sib1)).
pub const MP2_PARENT1: usize = 5;
/// Real-row marker. 1 on path levels, 0 on padding.
pub const MP2_IS_REAL: usize = 6;

/// Column count.
pub const MP2_WIDTH: usize = 7;
/// Public input count.
pub const MP2_NUM_PUBLIC: usize = 0;

/// Merkle path AIR for `[F;2]` digests.
///
/// Each row = one tree level. Two Pulls per real row:
/// - Lane 0: `(curr0, sib0, parent0)`
/// - Lane 1: `(curr1, sib1, parent1)`
///
/// Padding rows (`is_real = 0`) contribute nothing to the bus.
pub struct MerklePathBusAir2F;

impl<Fb> BaseAir<Fb> for MerklePathBusAir2F {
    fn width(&self) -> usize {
        MP2_WIDTH
    }
    fn num_public_values(&self) -> usize {
        MP2_NUM_PUBLIC
    }
}

impl<AB: AirBuilder<F = BinaryField128> + BusInteractionBuilder> Air<AB>
    for MerklePathBusAir2F
{
    fn eval(&self, b: &mut AB) {
        let zero = AB::F::ZERO;

        // Extract all columns in one borrow scope so we can push afterward.
        let (curr0, curr1, sib0, sib1, parent0, parent1, is_real) = {
            let main = b.main();
            let cur = main.current_slice();
            (
                AB::Expr::from(cur[MP2_CURR0]),
                AB::Expr::from(cur[MP2_CURR1]),
                AB::Expr::from(cur[MP2_SIB0]),
                AB::Expr::from(cur[MP2_SIB1]),
                AB::Expr::from(cur[MP2_PARENT0]),
                AB::Expr::from(cur[MP2_PARENT1]),
                AB::Expr::from(cur[MP2_IS_REAL]),
            )
        };

        // C0: is_real booleanity — required by BusActivation::Boolean.
        b.assert_eq(is_real.clone() * is_real.clone() + is_real.clone(), zero);

        // C1: Lane 0 Pull — (curr0, sib0, parent0) when is_real = 1.
        b.push_bus_interaction(
            MERKLE_COMPRESS,
            BusDirection::Pull,
            [curr0, sib0, parent0],
            BusActivation::Boolean(is_real.clone()),
        );

        // C2: Lane 1 Pull — (curr1, sib1, parent1) when is_real = 1.
        b.push_bus_interaction(
            MERKLE_COMPRESS,
            BusDirection::Pull,
            [curr1, sib1, parent1],
            BusActivation::Boolean(is_real),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;

    type F = BinaryField128;

    fn build_valid_trace() -> (RowMajorMatrix<F>, ()) {
        // 2 real rows + 2 padding rows.
        let mut values = vec![F::ZERO; 4 * MP2_WIDTH];
        // Row 0: real
        values[MP2_CURR0] = F::from_le_bytes(3u128.to_le_bytes());
        values[MP2_CURR1] = F::from_le_bytes(5u128.to_le_bytes());
        values[MP2_SIB0] = F::from_le_bytes(7u128.to_le_bytes());
        values[MP2_SIB1] = F::from_le_bytes(11u128.to_le_bytes());
        values[MP2_PARENT0] = F::from_le_bytes(13u128.to_le_bytes());
        values[MP2_PARENT1] = F::from_le_bytes(17u128.to_le_bytes());
        values[MP2_IS_REAL] = F::ONE;
        // Row 1: real
        values[MP2_WIDTH + MP2_CURR0] = F::from_le_bytes(19u128.to_le_bytes());
        values[MP2_WIDTH + MP2_CURR1] = F::from_le_bytes(23u128.to_le_bytes());
        values[MP2_WIDTH + MP2_SIB0] = F::from_le_bytes(29u128.to_le_bytes());
        values[MP2_WIDTH + MP2_SIB1] = F::from_le_bytes(31u128.to_le_bytes());
        values[MP2_WIDTH + MP2_PARENT0] = F::from_le_bytes(37u128.to_le_bytes());
        values[MP2_WIDTH + MP2_PARENT1] = F::from_le_bytes(41u128.to_le_bytes());
        values[MP2_WIDTH + MP2_IS_REAL] = F::ONE;
        // Rows 2, 3: padding (is_real = 0)
        (RowMajorMatrix::new(values, MP2_WIDTH), ())
    }

    fn expect_reject<F2: FnOnce()>(f: F2, msg: &str) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        assert!(r.is_err(), "{}", msg);
    }

    #[test]
    fn layout_constants() {
        assert_eq!(MP2_WIDTH, 7);
        assert_eq!(MP2_NUM_PUBLIC, 0);
        assert_eq!(MP2_IS_REAL, 6);
    }

    #[test]
    fn valid_trace_passes() {
        // Note: `check_constraints` only checks local constraints + bus balance
        // when a bus context is active. Standalone here it validates C0 (booleanity).
        let (trace, _) = build_valid_trace();
        let air = MerklePathBusAir2F;
        // No bus context in `check_constraints`, so we only test local constraints.
        // Bus balance is exercised by the MultiStark test in S7 rebuild.
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    fn non_boolean_is_real_rejected() {
        let (mut trace, _) = build_valid_trace();
        trace.values[MP2_IS_REAL] = F::from_le_bytes(2u128.to_le_bytes());
        expect_reject(
            || {
                let air = MerklePathBusAir2F;
                check_constraints(&air, &trace, &[]);
            },
            "non-boolean is_real must fail C0",
        );
    }

    #[test]
    fn padding_rows_are_silent() {
        // Padding rows carry all-zero lane data + is_real = 0. The AIR must
        // accept them (no constraint violated; bus activation is Boolean(0)).
        let (trace, _) = build_valid_trace();
        let air = MerklePathBusAir2F;
        check_constraints(&air, &trace, &[]);
    }
}
