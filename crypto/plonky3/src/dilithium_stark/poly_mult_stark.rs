//! Polynomial Multiplication STARK AIR.
//!
//! Constrains point-wise polynomial multiplication in NTT domain:
//!   c[i] = (a[i] * b[i]) mod Q  for each i in 0..N-1
//!
//! Trace layout (6 columns, N=256 rows):
//!   0: index     - coefficient index (0..N-1)
//!   1: a_val     - first operand coefficient
//!   2: b_val     - second operand coefficient
//!   3: quotient  - (a_val * b_val) / Q
//!   4: result    - (a_val * b_val) % Q = c[i]
//!   5: padding   - reserved for future use

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use crate::config::F;
use super::params::{N, Q};

/// Number of rows for polynomial multiplication trace.
pub const POLY_MULT_TRACE_ROWS: usize = N;

/// Build trace for point-wise polynomial multiplication in Z_q.
pub fn build_poly_mult_trace(a: &[u32; N], b: &[u32; N]) -> Vec<Vec<F>> {
    let mut rows = Vec::with_capacity(N);
    for i in 0..N {
        let prod = (a[i] as u64) * (b[i] as u64);
        let q = (prod / (Q as u64)) as u32;
        let r = (prod % (Q as u64)) as u32;
        rows.push(vec![
            F::from_u64(i as u64),
            F::from_u64(a[i] as u64),
            F::from_u64(b[i] as u64),
            F::from_u64(q as u64),
            F::from_u64(r as u64),
            F::ZERO,
        ]);
    }
    rows
}

/// Polynomial Multiplication AIR.
///
/// Constraints:
///   1. a * b = quotient * Q + result  (in Goldilocks field)
///   2. Index increments by 1 per row
///   3. First row index = 0
pub struct PolyMultAir;

impl<F> BaseAir<F> for PolyMultAir {
    fn width(&self) -> usize {
        6
    }
}

impl<AB> Air<AB> for PolyMultAir
where
    AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();

        // Core constraint: a * b = q * Q + result
        let a = local[1].clone();
        let b = local[2].clone();
        let q = local[3].clone();
        let c = local[4].clone();
        let q_field = F::from_u64(Q as u64);
        builder.assert_zero(a * b - q * q_field - c);

        // Boundary: first row index = 0
        let mut first = builder.when_first_row();
        first.assert_zero(local[0].clone());

        // Transition: index increments by 1
        let mut wt = builder.when_transition();
        wt.assert_zero(local[0].clone() - next[0].clone() + AB::F::ONE);

        // Last row: index = N - 1
        let mut last = builder.when_last_row();
        last.assert_zero(local[0].clone() - F::from_u64((N - 1) as u64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field_zq::mul_q;

    #[test]
    fn test_poly_mult_trace_shape() {
        let a = [42u32; N];
        let b = [7u32; N];
        let trace = build_poly_mult_trace(&a, &b);
        assert_eq!(trace.len(), POLY_MULT_TRACE_ROWS);
        for (i, row) in trace.iter().enumerate() {
            assert_eq!(row.len(), 6, "row {} must have 6 columns", i);
        }
    }

    #[test]
    fn test_poly_mult_correctness() {
        let mut a = [0u32; N];
        let mut b = [0u32; N];
        for i in 0..N {
            a[i] = (i as u32 * 12345 + 67) % Q;
            b[i] = (i as u32 * 67890 + 43) % Q;
        }
        let trace = build_poly_mult_trace(&a, &b);
        for i in 0..N {
            assert_eq!(trace[i][0], F::from_u64(i as u64));
            let expected = mul_q(a[i], b[i]);
            assert_eq!(trace[i][4], F::from_u64(expected as u64));
            // decomposition: a * b = q * Q + result
            assert_eq!(
                trace[i][1] * trace[i][2],
                trace[i][3] * F::from_u64(Q as u64) + trace[i][4]
            );
        }
    }
}
