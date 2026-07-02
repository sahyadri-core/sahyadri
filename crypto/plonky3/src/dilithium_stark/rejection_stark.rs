//! Rejection Sampling / Norm Bound STARK AIR.
//!
//! Verifies absolute value computation for Z_q coefficients:
//!   |c| = c      if c <= Q/2
//!   |c| = Q - c  if c >  Q/2
//!
//! Trace layout (4 columns, N=256 rows):
//!   0: index       - coefficient index (0..N-1)
//!   1: coeff       - c[i] in [0, Q-1]
//!   2: is_negative - 1 if c[i] > Q/2, else 0
//!   3: abs_val     - |c[i]|

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use super::params::{N, Q};
use crate::config::F;

pub const REJECTION_TRACE_ROWS: usize = N;

pub fn build_rejection_trace(coeffs: &[u32; N]) -> Vec<Vec<F>> {
    let mut rows = Vec::with_capacity(N);
    for i in 0..N {
        let c = coeffs[i];
        let is_neg = if c > (Q / 2) { 1u32 } else { 0u32 };
        let abs_val = if is_neg == 1 { Q - c } else { c };
        rows.push(vec![F::from_u64(i as u64), F::from_u64(c as u64), F::from_u64(is_neg as u64), F::from_u64(abs_val as u64)]);
    }
    rows
}

pub struct RejectionAir;

impl<F> BaseAir<F> for RejectionAir {
    fn width(&self) -> usize {
        4
    }
}

impl<AB> Air<AB> for RejectionAir
where
    AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();

        let index = local[0].clone();
        let coeff = local[1].clone();
        let is_neg = local[2].clone();
        let abs_val = local[3].clone();

        // Helper: u64 -> AB::Expr  (never use raw Goldilocks in constraints)
        let ce = |v: u64| AB::Expr::from(F::from_u64(v));

        // 1. is_negative is boolean: is_neg * (1 - is_neg) = 0
        let one = ce(1);
        builder.assert_zero(is_neg.clone() * (one.clone() - is_neg.clone()));

        // 2. abs_val = coeff + is_neg * (Q - 2*coeff)
        let q_expr = ce(Q as u64);
        let two_coeff = coeff.clone() + coeff.clone();
        builder.assert_zero(abs_val.clone() - coeff.clone() - is_neg.clone() * (q_expr - two_coeff));

        // 3. Index increment: next_index - current_index - 1 = 0
        {
            let mut wt = builder.when_transition();
            let next_index = next[0].clone();
            wt.assert_zero(next_index - index.clone() - one);
        }

        // 4. First row: index = 0
        {
            let mut first = builder.when_first_row();
            first.assert_zero(index.clone());
        }

        // 5. Last row: index = N-1
        {
            let mut last = builder.when_last_row();
            last.assert_zero(index - ce((N - 1) as u64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejection_trace_shape() {
        let coeffs = [42u32; N];
        let trace = build_rejection_trace(&coeffs);
        assert_eq!(trace.len(), REJECTION_TRACE_ROWS);
        for (i, row) in trace.iter().enumerate() {
            assert_eq!(row.len(), 4, "row {} must have 4 columns", i);
        }
    }

    #[test]
    fn test_rejection_correctness() {
        let mut coeffs = [0u32; N];
        for i in 0..N {
            coeffs[i] = if i < N / 2 { (i * 1000) as u32 % (Q / 2) } else { Q - (i * 1000) as u32 % (Q / 2) };
        }
        let trace = build_rejection_trace(&coeffs);
        for i in 0..N {
            assert_eq!(trace[i][0], F::from_u64(i as u64));
            let c = coeffs[i];
            let expected_abs = if c > Q / 2 { Q - c } else { c };
            assert_eq!(trace[i][3], F::from_u64(expected_abs as u64), "abs_val mismatch at {}", i);
            let _is_neg = if c > Q / 2 { 1u64 } else { 0u64 };
            let expected = if c > Q / 2 { (Q as u64) - (c as u64) } else { c as u64 };
            assert_eq!(trace[i][3], F::from_u64(expected), "decomp mismatch at {}", i);
        }
    }
}
