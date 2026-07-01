//! Matrix-Vector Multiplication STARK AIR.
//!
//! Constrains: t_i[k] = sum_{j=0}^{L-1} (A[i][j][k] * s[j][k]) mod Q
//!
//! Trace layout (9 columns, K*N*L = 6400 rows):
//!   0: out_idx   - output polynomial index (0..K-1)
//!   1: coeff_idx - coefficient index (0..N-1)
//!   2: in_idx    - input polynomial index (0..L-1)
//!   3: a_val     - A[out_idx][in_idx][coeff_idx]
//!   4: s_val     - s[in_idx][coeff_idx]
//!   5: quotient  - (a_val * s_val) / Q
//!   6: product   - (a_val * s_val) % Q
//!   7: prev_acc  - accumulator before this step (0 when in_idx=0)
//!   8: new_acc   - accumulator after this step

use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use crate::config::F;
use super::params::{K, L, N, Q};

/// Total trace rows: K × N × L.
pub const MATRIX_VEC_TRACE_ROWS: usize = 8192;

/// Build trace for matrix-vector multiplication in Z_q.
pub fn build_matrix_vec_trace(
    a_matrix: &[[[u32; N]; L]; K],
    s_vec: &[[u32; N]; L],
) -> Vec<Vec<F>> {
    let mut rows = Vec::with_capacity(MATRIX_VEC_TRACE_ROWS);
    for i in 0..K {
        for k in 0..N {
            let mut acc: u32 = 0;
            for j in 0..L {
                let a_val = a_matrix[i][j][k];
                let s_val = s_vec[j][k];
                let prev_acc = acc;
                let prod_u64 = (a_val as u64) * (s_val as u64);
                let quotient = (prod_u64 / (Q as u64)) as u32;
                let product = (prod_u64 % (Q as u64)) as u32;
                let sum = (prev_acc as u64) + (product as u64);
                let new_acc = if sum >= Q as u64 {
                    (sum - Q as u64) as u32
                } else {
                    sum as u32
                };
                rows.push(vec![
                    F::from_u64(i as u64),
                    F::from_u64(k as u64),
                    F::from_u64(j as u64),
                    F::from_u64(a_val as u64),
                    F::from_u64(s_val as u64),
                    F::from_u64(quotient as u64),
                    F::from_u64(product as u64),
                    F::from_u64(prev_acc as u64),
                    F::from_u64(new_acc as u64),
                ]);
                acc = new_acc;
            }
        }
    }
    let padded_h = rows.len().next_power_of_two();
    if padded_h > rows.len() {
        let fa = rows.last().unwrap()[8];
        let pad = vec![F::from_u64((K-1) as u64), F::from_u64((N-1) as u64), F::from_u64((L-1) as u64), F::ZERO, F::ZERO, F::ZERO, F::ZERO, fa, fa];
        rows.resize(padded_h, pad);
    }

    rows
}

/// Matrix-Vector Multiplication AIR.
pub struct MatrixVecAir;

impl<F> BaseAir<F> for MatrixVecAir {
    fn width(&self) -> usize {
        9
    }
}

impl<AB> Air<AB> for MatrixVecAir
where
    AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();

        let in_idx = local[2].clone();
        let a = local[3].clone();
        let s = local[4].clone();
        let q = local[5].clone();
        let prod = local[6].clone();
        let prev_acc = local[7].clone();
        let new_acc = local[8].clone();

        // 1. a * s = quotient * Q + product
        let q_f = F::from_u64(Q as u64);
        builder.assert_zero(a * s - q * q_f.clone() - prod.clone());

        // 2. Carry check
        let sum = prev_acc.clone() + prod;
        let diff = sum - new_acc.clone();
        builder.assert_zero(diff.clone() * (diff - q_f));

        // 3. prev_acc = 0 when in_idx = 0
        let one = AB::F::ONE;
        let mut sel = in_idx.clone() - one.clone();
        for m in 2u64..(L as u64) {
            sel = sel * (in_idx.clone() - F::from_u64(m));
        }
        builder.assert_zero(prev_acc * sel);

        // 4-5. Transition (direct condition multiply, no FilteredAirBuilder)
        let l_minus_1 = F::from_u64((L - 1) as u64);
        let is_trans = builder.is_transition();
        let in_not_last = in_idx - l_minus_1;
        let in_increments = local[2].clone() - next[2].clone() + one;
        builder.assert_zero(is_trans.clone() * in_not_last * in_increments);
        builder.assert_zero(is_trans.clone() * (next[2].clone() * (next[7].clone() - new_acc)));

        // 6. First row boundaries (direct condition multiply)
        let is_first = builder.is_first_row();
        builder.assert_zero(is_first.clone() * local[0].clone());
        builder.assert_zero(is_first.clone() * local[1].clone());
        builder.assert_zero(is_first * local[2].clone());

        // 7. Last row boundaries (direct condition multiply)
        let is_last = builder.is_last_row();
        builder.assert_zero(is_last.clone() * (local[0].clone() - F::from_u64((K - 1) as u64)));
        builder.assert_zero(is_last.clone() * (local[1].clone() - F::from_u64((N - 1) as u64)));
        builder.assert_zero(is_last * (local[2].clone() - l_minus_1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field_zq::{add_q, mul_q};

    #[test]
    fn test_matrix_vec_trace_shape() {
        let a_matrix = [[[0u32; N]; L]; K];
        let s_vec = [[0u32; N]; L];
        let trace = build_matrix_vec_trace(&a_matrix, &s_vec);
        assert_eq!(trace.len(), MATRIX_VEC_TRACE_ROWS);
        for (i, row) in trace.iter().enumerate() {
            assert_eq!(row.len(), 9, "row {} must have 9 columns", i);
        }
    }

    #[test]
    fn test_matrix_vec_correctness() {
        let mut a_matrix = [[[0u32; N]; L]; K];
        let mut s_vec = [[0u32; N]; L];
        for i in 0..K {
            for j in 0..L {
                for k in 0..N {
                    a_matrix[i][j][k] = ((i * L + j) * 1000 + k) as u32 % Q;
                }
            }
        }
        for j in 0..L {
            for k in 0..N {
                s_vec[j][k] = ((j + 1) * 500 + k) as u32 % Q;
            }
        }
        let trace = build_matrix_vec_trace(&a_matrix, &s_vec);

        for i in 0..K {
            for k in 0..N {
                let mut expected_acc: u32 = 0;
                for j in 0..L {
                    let row_idx = i * N * L + k * L + j;
                    let row = &trace[row_idx];
                    assert_eq!(row[0], F::from_u64(i as u64));
                    assert_eq!(row[1], F::from_u64(k as u64));
                    assert_eq!(row[2], F::from_u64(j as u64));
                    assert_eq!(row[7], F::from_u64(expected_acc as u64));
                    let product = mul_q(a_matrix[i][j][k], s_vec[j][k]);
                    assert_eq!(row[6], F::from_u64(product as u64));
                    let expected_new = add_q(expected_acc, product);
                    assert_eq!(row[8], F::from_u64(expected_new as u64));
                    expected_acc = expected_new;
                }
            }
        }
    }
}
