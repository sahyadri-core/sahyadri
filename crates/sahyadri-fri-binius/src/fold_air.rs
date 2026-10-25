//! FRI fold constraint AIR.
//!
//! One row per (query, round) of a FRI proof. Given the pair
//! `(y_r[i_r], y_r[i_r^1])`, the challenge `alpha_r`, and the parity
//! of `i_r`, constrain the next-round value:
//!
//!   even: y_{r+1}[i_{r+1}] = y_r[i_r]   + alpha * y_r[i_r^1]
//!   odd:  y_{r+1}[i_{r+1}] = y_r[i_r^1] + alpha * y_r[i_r]
//!
//! Written as a single polynomial identity with a parity selector
//! (binary field arithmetic uses XOR, so subtraction is addition):
//!
//!   let x = pair0 + pair1
//!   let y = sel * x
//!   let z = alpha * (pair0 + y)
//!   next == pair1 + y + z
//!
//! Soundness comes from composition with the Merkle-path AIR (Phase 3B):
//! this AIR alone constrains the fold equation but does not tie the leaves
//! to a committed codeword. Both AIRs share leaves via a bus argument.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_field::PrimeCharacteristicRing;

pub const COL_PAIR0: usize = 0;
pub const COL_PAIR1: usize = 1;
pub const COL_ALPHA: usize = 2;
pub const COL_SEL: usize = 3;
pub const COL_NEXT: usize = 4;
pub const WIDTH: usize = 8;

pub struct FoldAir;

impl<F> BaseAir<F> for FoldAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder<F = BinaryField128>> Air<AB> for FoldAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let cur = main.current_slice();
        let pair0 = cur[COL_PAIR0].into();
        let pair1 = cur[COL_PAIR1].into();
        let alpha = cur[COL_ALPHA].into();
        let sel = cur[COL_SEL].into();
        let next = cur[COL_NEXT].into();

        // sel must be 0 or 1: sel * (sel + 1) == 0
        let sel_sq = sel.clone() * sel.clone();
        b.assert_eq(sel_sq + sel.clone(), AB::F::ZERO);

        // Identity:  next = pair0 + y + alpha * (pair1 + y)
        // where y = sel * (pair0 + pair1).
        //
        //   sel = 0  ->  pair0 + alpha * pair1
        //   sel = 1  ->  (pair0 + pair0 + pair1) + alpha * (pair1 + pair0 + pair1)
        //              = pair1 + alpha * pair0
        let x = pair0.clone() + pair1.clone();
        let y = sel * x;
        let z = alpha * (pair1 + y.clone());
        let rhs = pair0 + y + z;

        b.assert_eq(next, rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;

    fn block(n: u128) -> BinaryField128 {
        BinaryField128::from_le_bytes(n.to_le_bytes())
    }

    fn build_row(
        pair0: BinaryField128,
        pair1: BinaryField128,
        alpha: BinaryField128,
        sel: BinaryField128,
        next: BinaryField128,
    ) -> Vec<BinaryField128> {
        let mut v = vec![BinaryField128::from_le_bytes([0u8; 16]); WIDTH];
        v[COL_PAIR0] = pair0;
        v[COL_PAIR1] = pair1;
        v[COL_ALPHA] = alpha;
        v[COL_SEL] = sel;
        v[COL_NEXT] = next;
        v
    }

    fn fold(
        pair0: BinaryField128,
        pair1: BinaryField128,
        alpha: BinaryField128,
        sel: u8,
    ) -> BinaryField128 {
        if sel == 0 {
            pair0 + alpha * pair1
        } else {
            pair1 + alpha * pair0
        }
    }

    #[test]
    fn even_row_satisfies() {
        let pair0 = block(7);
        let pair1 = block(11);
        let alpha = block(5);
        let next = fold(pair0, pair1, alpha, 0);
        let row = build_row(pair0, pair1, alpha, block(0), next);
        let trace = RowMajorMatrix::new(row, WIDTH);
        check_constraints(&FoldAir, &trace, &[]);
    }

    #[test]
    fn odd_row_satisfies() {
        let pair0 = block(7);
        let pair1 = block(11);
        let alpha = block(5);
        let next = fold(pair0, pair1, alpha, 1);
        let row = build_row(pair0, pair1, alpha, block(1), next);
        let trace = RowMajorMatrix::new(row, WIDTH);
        check_constraints(&FoldAir, &trace, &[]);
    }

    #[test]
    fn tampered_next_rejected() {
        let pair0 = block(7);
        let pair1 = block(11);
        let alpha = block(5);
        let next = fold(pair0, pair1, alpha, 0) + block(1);
        let row = build_row(pair0, pair1, alpha, block(0), next);
        let trace = RowMajorMatrix::new(row, WIDTH);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&FoldAir, &trace, &[]);
        }));
        assert!(r.is_err(), "tampered next must be rejected");
    }

    #[test]
    fn non_boolean_selector_rejected() {
        let pair0 = block(7);
        let pair1 = block(11);
        let alpha = block(5);
        let next = fold(pair0, pair1, alpha, 0);
        let row = build_row(pair0, pair1, alpha, block(2), next);
        let trace = RowMajorMatrix::new(row, WIDTH);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&FoldAir, &trace, &[]);
        }));
        assert!(r.is_err(), "non-boolean sel must be rejected");
    }

    #[test]
    fn wrong_parity_rejected() {
        // Compute next under even fold, but claim odd selector
        let pair0 = block(7);
        let pair1 = block(11);
        let alpha = block(5);
        let next_even = fold(pair0, pair1, alpha, 0);
        let next_odd = fold(pair0, pair1, alpha, 1);
        assert_ne!(next_even, next_odd, "parity must change result for distinct inputs");
        let row = build_row(pair0, pair1, alpha, block(1), next_even);
        let trace = RowMajorMatrix::new(row, WIDTH);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(&FoldAir, &trace, &[]);
        }));
        assert!(r.is_err(), "wrong parity next must be rejected");
    }
}
