//! Top-level Dilithium3 (ML-DSA-65) verification STARK orchestrator.
//!
//! Chains sub-STARKs: MatrixVec → NTT(fwd) → PolyMult → NTT(inv) → NormBound → Rejection

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use super::field_zq::{self, build_ntt_trace};
use super::matrix_vec_stark::build_matrix_vec_trace;
use super::params::*;
use super::poly_mult_stark::build_poly_mult_trace;
use super::rejection_stark::build_rejection_trace;
use crate::config::F;

// ── Sub-trace row counts ─────────────────────────────────

pub const AZ_ROWS: usize = 8192;
pub const NTT_ROWS: usize = LOG_N * N;
pub const POLY_MULT_ROWS: usize = N;
pub const NORM_ROWS: usize = N;
pub const TOTAL_VERIFY_ROWS: usize = AZ_ROWS + 2 * NTT_ROWS + POLY_MULT_ROWS + 3 * NORM_ROWS;

// ── Verification traces ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationTraces {
    pub az_trace: Vec<Vec<F>>,
    pub ntt_t1_trace: Vec<Vec<F>>,
    pub poly_ct1_trace: Vec<Vec<F>>,
    pub ntt_inv_ct1_trace: Vec<Vec<F>>,
    pub norm_z1_trace: Vec<Vec<F>>,
    pub norm_z2_trace: Vec<Vec<F>>,
    pub rejection_h_trace: Vec<Vec<F>>,
}

// ── Helpers ──────────────────────────────────────────────

fn pointwise_mul_q(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        r[i] = field_zq::mul_q(a[i], b[i]);
    }
    r
}

fn high_bits_q(r: u32, alpha: u32) -> u32 {
    let offset = (alpha - 1) / 2;
    let v = if (r as u64) + (offset as u64) >= Q as u64 { (r as u64 + offset as u64) - Q as u64 } else { r as u64 + offset as u64 };
    (v / alpha as u64) as u32
}

pub fn compute_w1_prime(az: &[u32; N], t1_tilde: &[u32; N]) -> [u32; N] {
    let mut w1 = [0u32; N];
    for i in 0..N {
        let diff = field_zq::sub_q(az[i], t1_tilde[i]);
        w1[i] = high_bits_q(diff, 2 * GAMMA2);
    }
    w1
}

// ── Build all verification traces ────────────────────────

/// z1_vec: L polynomials (signature z1 is a vector in Dilithium)
/// z2_vec: K polynomials
pub fn build_verification_traces(
    z1_vec: &[[u32; N]; L],
    z2_vec: &[[u32; N]; K],
    t1: &[u32; N],
    a_matrix: &[[[u32; N]; L]; K],
    c_tilde: &[u32; N],
    h: &[u32; N],
) -> VerificationTraces {
    // 1. Az = A * z1 (matrix-vector)
    let az_trace = build_matrix_vec_trace(a_matrix, z1_vec);

    // 2. NTT(t1) forward
    let ntt_t1_trace = build_ntt_trace(t1, false);
    let mut t1_ntt = *t1;
    field_zq::ntt_forward(&mut t1_ntt);

    // 3. c_tilde * NTT(t1) point-wise
    let poly_ct1_trace = build_poly_mult_trace(c_tilde, &t1_ntt);
    let ct1_ntt = pointwise_mul_q(c_tilde, &t1_ntt);

    // 4. NTT^{-1}(c_tilde * NTT(t1))
    let ntt_inv_ct1_trace = build_ntt_trace(&ct1_ntt, true);

    // 5. Norm / rejection checks (check first poly of each vec)
    let norm_z1_trace = build_rejection_trace(&z1_vec[0]);
    let norm_z2_trace = build_rejection_trace(&z2_vec[0]);
    let rejection_h_trace = build_rejection_trace(h);

    VerificationTraces { az_trace, ntt_t1_trace, poly_ct1_trace, ntt_inv_ct1_trace, norm_z1_trace, norm_z2_trace, rejection_h_trace }
}

// ── Top-level reconstruction AIR ─────────────────────────

pub struct DilithiumVerifyAir;

impl<Fld> BaseAir<Fld> for DilithiumVerifyAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB> Air<AB> for DilithiumVerifyAir
where
    AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();

        let index = local[0].clone();
        let w1p = local[1].clone();
        let h_val = local[2].clone();

        let ce = |v: u64| AB::Expr::from(F::from_u64(v));

        builder.assert_zero(w1p - h_val);

        {
            let mut wt = builder.when_transition();
            let next_index = next[0].clone();
            wt.assert_zero(next_index - index.clone() - ce(1));
        }
        {
            let mut first = builder.when_first_row();
            first.assert_zero(index.clone());
        }
        {
            let mut last = builder.when_last_row();
            last.assert_zero(index - ce((N - 1) as u64));
        }
    }
}

pub fn build_verify_trace(w1_prime: &[u32; N], h: &[u32; N]) -> Vec<Vec<F>> {
    let mut rows = Vec::with_capacity(N);
    for i in 0..N {
        rows.push(vec![F::from_u64(i as u64), F::from_u64(w1_prime[i] as u64), F::from_u64(h[i] as u64)]);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_row_counts() {
        let z1 = [[1u32; N]; L];
        let z2 = [[1u32; N]; K];
        let t1 = [1u32; N];
        let c_tilde = [1u32; N];
        let h = [1u32; N];
        let a: [[[u32; N]; L]; K] = [[[42u32; N]; L]; K];

        let t = build_verification_traces(&z1, &z2, &t1, &a, &c_tilde, &h);
        assert_eq!(t.az_trace.len(), AZ_ROWS);
        assert_eq!(t.ntt_t1_trace.len(), NTT_ROWS);
        assert_eq!(t.poly_ct1_trace.len(), POLY_MULT_ROWS);
        assert_eq!(t.ntt_inv_ct1_trace.len(), NTT_ROWS);
        assert_eq!(t.norm_z1_trace.len(), NORM_ROWS);
        assert_eq!(t.norm_z2_trace.len(), NORM_ROWS);
        assert_eq!(t.rejection_h_trace.len(), NORM_ROWS);
    }

    #[test]
    fn test_total_row_count() {
        assert_eq!(TOTAL_VERIFY_ROWS, AZ_ROWS + 2 * NTT_ROWS + POLY_MULT_ROWS + 3 * NORM_ROWS);
    }

    #[test]
    fn test_verify_trace_shape() {
        let trace = build_verify_trace(&[0u32; N], &[0u32; N]);
        assert_eq!(trace.len(), N);
        for row in &trace {
            assert_eq!(row.len(), 3);
        }
    }

    #[test]
    fn test_verify_trace_matching() {
        let mut w1p = [0u32; N];
        let mut h = [0u32; N];
        for i in 0..N {
            w1p[i] = (i * 1000) as u32 % Q;
            h[i] = w1p[i];
        }
        let trace = build_verify_trace(&w1p, &h);
        for (i, row) in trace.iter().enumerate() {
            assert_eq!(row[0], F::from_u64(i as u64));
            assert_eq!(row[1], row[2], "mismatch at {}", i);
        }
    }

    #[test]
    fn test_high_bits_zero() {
        assert_eq!(high_bits_q(0, 2 * GAMMA2), 0);
    }

    #[test]
    fn test_high_bits_large() {
        assert_eq!(high_bits_q(261889u32, 2 * GAMMA2), 1);
    }

    #[test]
    fn test_compute_w1_prime_zero() {
        let az = [0u32; N];
        let t1t = [0u32; N];
        let w1 = compute_w1_prime(&az, &t1t);
        assert!(w1.iter().all(|&x| x == 0));
    }
}
