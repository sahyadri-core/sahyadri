//! Combined FRI verifier AIR (Phase 3D, part 1).
//!
//! One row per (query, round). Enforces:
//!
//!   1. sel and is_last are boolean
//!   2. fold equation: next = fold(pair0, pair1, alpha, sel)
//!   3. root pin: is_last * (next XOR root) == 0
//!
//! Merkle-path opening is checked by the companion Poseidon2b compression
//! AIR in Phase 3D part 2. The two AIRs share (pair0, pair1) cells via a
//! bus, so neither alone is sound but the composed verifier is.
//!
//! This AIR only knows about the fold-and-pin structure; it does not
//! commit to the codeword. That binding lives in the composed prover.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_field::PrimeCharacteristicRing;

pub const COL_PAIR0: usize = 0;
pub const COL_PAIR1: usize = 1;
pub const COL_ALPHA: usize = 2;
pub const COL_NEXT: usize = 3;
pub const COL_SEL: usize = 4;
pub const COL_IS_LAST: usize = 5;
pub const WIDTH: usize = 6;

/// Number of final_poly cells exposed as public input. The production
/// FRI stops folding at length 4.
pub const FINAL_POLY_LEN: usize = 4;

/// Public inputs: root (= final_poly[0..4] region as one element for the
/// standalone test) plus the final codeword. In production the root is
/// the commitment and final_poly is the direct output.
pub const NUM_PUBLIC: usize = 1 + FINAL_POLY_LEN;

pub struct FriVerifierAir {
    pub num_rounds: usize,
}

impl<F> BaseAir<F> for FriVerifierAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }
}

impl<AB: AirBuilder<F = BinaryField128>> Air<AB> for FriVerifierAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let cur = main.current_slice();

        let pair0: AB::Expr = cur[COL_PAIR0].into();
        let pair1: AB::Expr = cur[COL_PAIR1].into();
        let alpha: AB::Expr = cur[COL_ALPHA].into();
        let next: AB::Expr = cur[COL_NEXT].into();
        let sel: AB::Expr = cur[COL_SEL].into();
        let is_last: AB::Expr = cur[COL_IS_LAST].into();

        // 1. Booleanity of the two selectors.
        let sel_sq = sel.clone() * sel.clone();
        b.assert_eq(sel_sq + sel.clone(), AB::F::ZERO);
        let last_sq = is_last.clone() * is_last.clone();
        b.assert_eq(last_sq + is_last.clone(), AB::F::ZERO);

        // 2. Fold equation. Same algebra as Phase 3A:
        //    y = sel * (pair0 + pair1)
        //    folded = pair0 + y + alpha * (pair1 + y)
        let x = pair0.clone() + pair1.clone();
        let y = sel * x;
        let z = alpha * (pair1 + y.clone());
        let folded = pair0 + y + z;
        b.assert_eq(next.clone(), folded);

        // 3. Root pin on the last round of each query.
        //    Characteristic-2 subtraction equals addition, so
        //    (next == root) is the same as (next + root == 0).
        let public = b.public_values();
        let root: AB::Expr = public[0].into();
        let diff = next + root;
        let pinned = is_last * diff;
        b.assert_eq(pinned, AB::F::ZERO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Block128Bytes;
    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;

    fn block(n: u128) -> BinaryField128 {
        BinaryField128::from_le_bytes(n.to_le_bytes())
    }

    fn as_u128(x: BinaryField128) -> u128 {
        u128::from_le_bytes(x.blk_to_le_bytes())
    }

    fn fold(p0: BinaryField128, p1: BinaryField128, alpha: BinaryField128, sel: u8) -> BinaryField128 {
        if sel == 0 {
            p0 + alpha * p1
        } else {
            p1 + alpha * p0
        }
    }

    struct Row {
        pair0: BinaryField128,
        pair1: BinaryField128,
        alpha: BinaryField128,
        next: BinaryField128,
        sel: BinaryField128,
        is_last: BinaryField128,
    }

    fn make_row(p0: u128, p1: u128, alpha: u128, sel: u8, is_last: u8, override_next: Option<u128>) -> Row {
        let p0b = block(p0);
        let p1b = block(p1);
        let ab = block(alpha);
        let folded = fold(p0b, p1b, ab, sel);
        Row {
            pair0: p0b,
            pair1: p1b,
            alpha: ab,
            next: override_next.map(block).unwrap_or(folded),
            sel: block(sel as u128),
            is_last: block(is_last as u128),
        }
    }

    fn build_trace(rows: Vec<Row>) -> RowMajorMatrix<BinaryField128> {
        let mut values = Vec::with_capacity(rows.len() * WIDTH);
        for r in rows {
            let mut row = vec![BinaryField128::from_le_bytes([0u8; 16]); WIDTH];
            row[COL_PAIR0] = r.pair0;
            row[COL_PAIR1] = r.pair1;
            row[COL_ALPHA] = r.alpha;
            row[COL_NEXT] = r.next;
            row[COL_SEL] = r.sel;
            row[COL_IS_LAST] = r.is_last;
            values.extend_from_slice(&row);
        }
        RowMajorMatrix::new(values, WIDTH)
    }

    fn public_from_root(root: BinaryField128) -> Vec<BinaryField128> {
        let mut p = vec![BinaryField128::from_le_bytes([0u8; 16]); NUM_PUBLIC];
        p[0] = root;
        p
    }

    #[test]
    fn valid_single_query_trace() {
        // Simulate a 2-round fold. The query starts at pair (10, 20), gets
        // folded with alpha=3 → 10+3*20. Then a final round pins to root.
        let alpha = 3u128;
        let sel = 0u8;
        let p0: u128 = 10;
        let p1: u128 = 20;
        let folded = fold(block(p0), block(p1), block(alpha), sel);

        // Final round pins next to a root.
        let root = folded;

        let rows = vec![
            make_row(p0, p1, alpha, sel, 1, Some(as_u128(folded))),
        ];
        let trace = build_trace(rows);
        let public = public_from_root(root);
        let air = FriVerifierAir { num_rounds: 1 };
        check_constraints(&air, &trace, &public);
    }

    #[test]
    fn tampered_fold_fails() {
        let alpha = 3u128;
        let sel = 0u8;
        let p0: u128 = 10;
        let p1: u128 = 20;
        let folded = fold(block(p0), block(p1), block(alpha), sel);

        // Override `next` with a value that breaks the fold equation.
        let rows = vec![make_row(p0, p1, alpha, sel, 1, Some(as_u128(folded) ^ 1))];
        let trace = build_trace(rows);
        let public = public_from_root(folded);
        let air = FriVerifierAir { num_rounds: 1 };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "tampered fold next must fail");
    }

    #[test]
    fn wrong_root_pin_fails() {
        let alpha = 3u128;
        let sel = 0u8;
        let p0: u128 = 10;
        let p1: u128 = 20;
        let folded = fold(block(p0), block(p1), block(alpha), sel);

        let rows = vec![make_row(p0, p1, alpha, sel, 1, Some(as_u128(folded)))];
        let trace = build_trace(rows);
        // Public root is deliberately wrong.
        let public = public_from_root(block(0xDEAD));
        let air = FriVerifierAir { num_rounds: 1 };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "root pin mismatch must fail");
    }

    #[test]
    fn non_boolean_sel_fails() {
        let alpha = 3u128;
        let p0: u128 = 10;
        let p1: u128 = 20;

        let mut row = make_row(p0, p1, alpha, 0, 1, None);
        row.sel = block(2); // not in {0,1}
        let public = public_from_root(row.next);
        let trace = build_trace(vec![row]);
        let air = FriVerifierAir { num_rounds: 1 };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "non-boolean sel must fail");
    }

    #[test]
    fn non_boolean_is_last_fails() {
        let alpha = 3u128;
        let p0: u128 = 10;
        let p1: u128 = 20;

        let mut row = make_row(p0, p1, alpha, 0, 0, None);
        row.is_last = block(3);
        let public = public_from_root(row.next);
        let trace = build_trace(vec![row]);
        let air = FriVerifierAir { num_rounds: 1 };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&air, &trace, &public);
        }));
        assert!(r.is_err(), "non-boolean is_last must fail");
    }
}
