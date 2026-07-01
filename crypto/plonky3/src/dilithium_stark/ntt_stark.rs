//! NTT STARK AIR: Constrains NTT butterfly operations for Dilithium verification.
//!
//! Trace layout (6 columns):
//!   0: stage     - current NTT stage (0..LOG_N)
//!   1: position  - butterfly position within stage
//!   2: even_val  - value on the "even" wire (before/after)
//!   3: odd_val   - value on the "odd" wire (before/after)
//!   4: twiddle   - twiddle factor (constant within butterfly pair)
//!   5: marker    - 0 = before butterfly, 1 = after butterfly
//!
//! Each butterfly uses 2 consecutive rows.
//! Total rows = LOG_N stages x N rows/stage = 8 x 256 = 2048.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use crate::config::F;

/// Number of rows in the NTT trace: LOG_N stages x N rows per stage (2 per butterfly).
pub const NTT_TRACE_ROWS: usize = 2048;

/// NTT STARK AIR.
///
/// Constrains that each butterfly pair satisfies:
/// - Forward:  new_even = even + twiddle * odd;  new_odd = even - twiddle * odd
/// - Inverse:  new_even = even + odd;            new_odd = (even - odd) * twiddle
pub struct NttAir {
    pub is_inverse: bool,
}

impl<F> BaseAir<F> for NttAir {
    fn width(&self) -> usize {
        6 // stage, position, even_val, odd_val, twiddle, marker
    }
}

impl<AB> Air<AB> for NttAir
where
    AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();

        // Row-0: marker must be 0
        builder.assert_zero(local[5].clone());

        // Transition constraints
        let mut wt = builder.when_transition();
        wt.assert_zero(next[5].clone() - AB::F::ONE);
        wt.assert_zero(local[0].clone() - next[0].clone());
        wt.assert_zero(local[1].clone() - next[1].clone());
        wt.assert_zero(local[4].clone() - next[4].clone());

        if self.is_inverse {
            let even = local[2].clone();
            let odd = local[3].clone();
            let tw = local[4].clone();
            wt.assert_zero(next[2].clone() - (even.clone() + odd.clone()));
            wt.assert_zero(next[3].clone() - (even - odd) * tw);
        } else {
            let even = local[2].clone();
            let odd = local[3].clone();
            let tw = local[4].clone();
            let t = tw * odd;
            wt.assert_zero(next[2].clone() - (even.clone() + t.clone()));
            wt.assert_zero(next[3].clone() - (even - t));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field_zq::build_ntt_trace;
    use super::super::params::N;

    #[test]
    fn test_ntt_trace_shape() {
        let input: [u32; N] = [42u32; N];
        let trace = build_ntt_trace(&input, false);

        assert_eq!(trace.len(), NTT_TRACE_ROWS, "trace must have {} rows", NTT_TRACE_ROWS);
        for (i, row) in trace.iter().enumerate() {
            assert_eq!(row.len(), 6, "row {} must have 6 columns", i);
        }
    }

    #[test]
    fn test_forward_butterfly_correctness() {
        let input: [u32; N] = [7u32; N];
        let trace = build_ntt_trace(&input, false);

        for i in (0..NTT_TRACE_ROWS).step_by(2) {
            // trace[row][col]: 0=stage, 1=position, 2=even, 3=odd, 4=twiddle, 5=marker
            assert_eq!(trace[i][5], F::ZERO, "row {} marker must be 0", i);
            assert_eq!(trace[i + 1][5], F::ONE, "row {} marker must be 1", i + 1);

            assert_eq!(trace[i][4], trace[i + 1][4], "twiddle mismatch row {}", i);
            assert_eq!(trace[i][0], trace[i + 1][0], "stage mismatch row {}", i);
            assert_eq!(trace[i][1], trace[i + 1][1], "position mismatch row {}", i);

            let even = trace[i][2];
            let odd = trace[i][3];
            let w = trace[i][4];
            let t = w * odd;
            assert_eq!(trace[i + 1][2], even + t, "forward even mismatch row {}", i);
            assert_eq!(trace[i + 1][3], even - t, "forward odd mismatch row {}", i);
        }
    }

    #[test]
    fn test_inverse_butterfly_correctness() {
        let input: [u32; N] = [13u32; N];
        let trace = build_ntt_trace(&input, true);

        for i in (0..NTT_TRACE_ROWS).step_by(2) {
            assert_eq!(trace[i][5], F::ZERO, "row {} marker must be 0", i);
            assert_eq!(trace[i + 1][5], F::ONE, "row {} marker must be 1", i + 1);

            let even = trace[i][2];
            let odd = trace[i][3];
            let w = trace[i][4];

            assert_eq!(trace[i + 1][2], even + odd, "inverse even mismatch row {}", i);
            assert_eq!(trace[i + 1][3], (even - odd) * w, "inverse odd mismatch row {}", i);
        }
    }
}
