//! FRI verifier AIR v2 (Phase 3D part 2a).
//!
//! Adds the real final_poly binding that Phase 3D part 1 was missing.
//! Instead of pinning `next == root` on the last row (an artificial check),
//! the last row must satisfy:
//!
//!   next == select(final_poly, i_final)
//!
//! where i_final is the query's projection into final_poly, encoded as a
//! one-hot selector (s0, s1, s2, s3). final_poly cells are public inputs.
//!
//! Constraint inventory (per row):
//!   1. sel, is_last, s0..s3 are boolean                        (6)
//!   2. s_i * s_j == 0 for i < j                                (6)
//!   3. is_last * (s0 + s1 + s2 + s3 + 1) == 0                   (1)
//!   4. next == pair0 + y + alpha * (pair1 + y)
//!      where y = sel * (pair0 + pair1)                          (1)
//!   5. is_last * (next + s0*fp0 + s1*fp1 + s2*fp2 + s3*fp3) == 0 (1)
//!
//! Total 15 constraints. All are low degree. AIR width = 10 columns;
//! public inputs = 4 (final_poly cells).
//!
//! Merkle binding (tying pair0, pair1 to a committed codeword) is Phase
//! 3D part 2b, which instantiates Poseidon2bAir and bus-links the two.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

pub const COL_PAIR0: usize = 0;
pub const COL_PAIR1: usize = 1;
pub const COL_ALPHA: usize = 2;
pub const COL_NEXT: usize = 3;
pub const COL_SEL: usize = 4;
pub const COL_IS_LAST: usize = 5;
pub const COL_S0: usize = 6;
pub const COL_S1: usize = 7;
pub const COL_S2: usize = 8;
pub const COL_S3: usize = 9;
pub const WIDTH: usize = 10;

/// Number of final_poly cells.
pub const FINAL_POLY_LEN: usize = 4;
/// Public input count = final_poly cells.
pub const NUM_PUBLIC: usize = FINAL_POLY_LEN;

pub struct FriVerifierAirV2;

impl<F> BaseAir<F> for FriVerifierAirV2 {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }
}

impl<AB: AirBuilder> Air<AB> for FriVerifierAirV2
where
    AB::F: PrimeCharacteristicRing,
{
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let cur = main.current_slice();

        let pair0: AB::Expr = cur[COL_PAIR0].into();
        let pair1: AB::Expr = cur[COL_PAIR1].into();
        let alpha: AB::Expr = cur[COL_ALPHA].into();
        let next: AB::Expr = cur[COL_NEXT].into();
        let sel: AB::Expr = cur[COL_SEL].into();
        let is_last: AB::Expr = cur[COL_IS_LAST].into();
        let s = [
            AB::Expr::from(cur[COL_S0]),
            AB::Expr::from(cur[COL_S1]),
            AB::Expr::from(cur[COL_S2]),
            AB::Expr::from(cur[COL_S3]),
        ];

        // 1. Booleanity of the six selector columns.
        let one = AB::F::ONE;
        for v in [&sel, &is_last, &s[0], &s[1], &s[2], &s[3]] {
            let sq = v.clone() * v.clone();
            b.assert_eq(sq + v.clone(), AB::F::ZERO);
        }

        // 2. Pairwise disjointness: at most one s_i can be 1.
        for i in 0..FINAL_POLY_LEN {
            for j in (i + 1)..FINAL_POLY_LEN {
                let prod = s[i].clone() * s[j].clone();
                b.assert_eq(prod, AB::F::ZERO);
            }
        }

        // 3. On the last row, exactly one selector must be 1.
        let selector_sum = s[0].clone() + s[1].clone() + s[2].clone() + s[3].clone();
        let sum_plus_one = selector_sum + one.clone();
        b.assert_eq(is_last.clone() * sum_plus_one, AB::F::ZERO);

        // 4. Fold equation (same as Phase 3A).
        let x = pair0.clone() + pair1.clone();
        let y = sel * x;
        let z = alpha * (pair1 + y.clone());
        let folded = pair0 + y + z;
        b.assert_eq(next.clone(), folded);

        // 5. Binding: on the last row, next == selected final_poly cell.
        let public = b.public_values();
        let fp: [AB::Expr; FINAL_POLY_LEN] = [
            public[0].into(),
            public[1].into(),
            public[2].into(),
            public[3].into(),
        ];
        let selected = s[0].clone() * fp[0].clone()
            + s[1].clone() * fp[1].clone()
            + s[2].clone() * fp[2].clone()
            + s[3].clone() * fp[3].clone();
        let diff = next + selected;
        b.assert_eq(is_last * diff, AB::F::ZERO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;
    use crate::bytes::Block128Bytes;
    use p3_binary_field::BinaryField128;

    fn as_u128(x: BinaryField128) -> u128 {
        u128::from_le_bytes(x.blk_to_le_bytes())
    }

    fn b(n: u128) -> BinaryField128 {
        BinaryField128::from_le_bytes(n.to_le_bytes())
    }

    struct Row {
        pair0: BinaryField128,
        pair1: BinaryField128,
        alpha: BinaryField128,
        next: BinaryField128,
        sel: BinaryField128,
        is_last: BinaryField128,
        s: [BinaryField128; FINAL_POLY_LEN],
    }

    impl Row {
        fn fold_only(pair0: u128, pair1: u128, alpha: u128, sel: u8) -> Self {
            let p0 = b(pair0);
            let p1 = b(pair1);
            let a = b(alpha);
            let next = if sel == 0 {
                p0 + a * p1
            } else {
                p1 + a * p0
            };
            Row {
                pair0: p0,
                pair1: p1,
                alpha: a,
                next,
                sel: b(sel as u128),
                is_last: b(0),
                s: [b(0); FINAL_POLY_LEN],
            }
        }

    }

    fn build(rows: Vec<Row>) -> RowMajorMatrix<BinaryField128> {
        let mut values = Vec::with_capacity(rows.len() * WIDTH);
        for r in rows {
            let mut row = [BinaryField128::from_le_bytes([0u8; 16]); WIDTH];
            row[COL_PAIR0] = r.pair0;
            row[COL_PAIR1] = r.pair1;
            row[COL_ALPHA] = r.alpha;
            row[COL_NEXT] = r.next;
            row[COL_SEL] = r.sel;
            row[COL_IS_LAST] = r.is_last;
            row[COL_S0] = r.s[0];
            row[COL_S1] = r.s[1];
            row[COL_S2] = r.s[2];
            row[COL_S3] = r.s[3];
            values.extend_from_slice(&row);
        }
        RowMajorMatrix::new(values, WIDTH)
    }

    fn public(fp: [u128; 4]) -> Vec<BinaryField128> {
        vec![b(fp[0]), b(fp[1]), b(fp[2]), b(fp[3])]
    }

    #[test]
    fn valid_fold_plus_final_binding() {
        // pick pair/alpha/sel so that fold gives fp3
        let pair0 = 10u128;
        let pair1 = 20u128;
        let alpha = 3u128;
        let sel = 0u8;
        let folded = b(pair0) + b(alpha) * b(pair1);

        // pick a final_poly that includes this folded value at index 2
        // (any index works; we pick 2 for variety)
        let fp = [b(1), b(2), folded, b(99)];
        let fp_u = [
            as_u128(fp[0]),
            as_u128(fp[1]),
            as_u128(fp[2]),
            as_u128(fp[3]),
        ];

        // row 0: intermediate fold (is_last=0, no selectors)
        let r0 = Row::fold_only(pair0, pair1, alpha, sel);
        // row 1: final round (is_last=1, selects fp[2])
        let mut r1 = Row::fold_only(pair0, pair1, alpha, sel);
        r1.is_last = b(1);
        r1.s[2] = b(1);
        r1.next = folded;

        let trace = build(vec![r0, r1]);
        let air = FriVerifierAirV2;
        check_constraints(&air, &trace, &public(fp_u));
    }

    #[test]
    fn wrong_final_poly_rejected() {
        let pair0 = 10u128;
        let pair1 = 20u128;
        let alpha = 3u128;
        let sel = 0u8;
        let folded = b(pair0) + b(alpha) * b(pair1);

        let fp_correct = [b(1), b(2), folded, b(99)];
        let fp_u = [
            as_u128(fp_correct[0]),
            as_u128(fp_correct[1]),
            as_u128(fp_correct[2]),
            as_u128(fp_correct[3]),
        ];

        let mut r1 = Row::fold_only(pair0, pair1, alpha, sel);
        r1.is_last = b(1);
        r1.s[2] = b(1);
        r1.next = b(0xDEAD); // wrong value, not matching fp[2]

        let trace = build(vec![r1]);
        let air = FriVerifierAirV2;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public(fp_u));
        }));
        assert!(r.is_err(), "wrong next vs final_poly must fail");
    }

    #[test]
    fn two_selectors_rejected_by_pairwise() {
        let pair0 = 10u128;
        let pair1 = 20u128;
        let alpha = 3u128;
        let sel = 0u8;
        let folded = b(pair0) + b(alpha) * b(pair1);

        let fp = [b(1), b(2), folded, b(99)];
        let fp_u = [
            as_u128(fp[0]),
            as_u128(fp[1]),
            as_u128(fp[2]),
            as_u128(fp[3]),
        ];

        let mut r1 = Row::fold_only(pair0, pair1, alpha, sel);
        r1.is_last = b(1);
        r1.s[0] = b(1);
        r1.s[2] = b(1); // two selectors = 1, violates pairwise
        r1.next = folded;

        let trace = build(vec![r1]);
        let air = FriVerifierAirV2;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public(fp_u));
        }));
        assert!(r.is_err(), "two active selectors must fail");
    }

    #[test]
    fn no_selector_on_last_row_rejected() {
        let pair0 = 10u128;
        let pair1 = 20u128;
        let alpha = 3u128;
        let sel = 0u8;
        let folded = b(pair0) + b(alpha) * b(pair1);
        let fp = [b(1), b(2), folded, b(99)];
        let fp_u = [
            as_u128(fp[0]),
            as_u128(fp[1]),
            as_u128(fp[2]),
            as_u128(fp[3]),
        ];

        let mut r1 = Row::fold_only(pair0, pair1, alpha, sel);
        r1.is_last = b(1);
        // all selectors left zero
        r1.next = folded;

        let trace = build(vec![r1]);
        let air = FriVerifierAirV2;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public(fp_u));
        }));
        assert!(r.is_err(), "missing selector on last row must fail");
    }

    #[test]
    fn intermediate_rows_accept_any_fold() {
        // Non-last rows have no selectors and don't bind to final_poly.
        let rows = vec![
            Row::fold_only(10, 20, 3, 0),
            Row::fold_only(11, 21, 5, 1),
            Row::fold_only(12, 22, 7, 0),
        ];
        // No row is last, so no final_poly binding applies.
        let trace = build(rows);
        let air = FriVerifierAirV2;
        let public_any = public([0, 0, 0, 0]);
        check_constraints(&air, &trace, &public_any);
    }
}
