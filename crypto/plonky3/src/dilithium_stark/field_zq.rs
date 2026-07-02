//! Z_q arithmetic emulated in BabyBear field.
//!
//! Since Q = 8380417 < P_babybear = 201326593, every Z_q value
//! fits in one BabyBear field element.
//!
//! Addition/subtraction are trivial (no overflow).
//! Multiplication requires limb decomposition.

use super::params::Q;
use p3_field::PrimeCharacteristicRing;

// ─── Plain Rust (non-STARK) Z_q arithmetic ─────────────────────────

/// Add two Z_q values.
/// Input: a, b in [0, Q-1]
/// Output: (a + b) mod Q
#[inline]
pub fn add_q(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= Q {
        s - Q
    } else {
        s
    }
}

/// Subtract two Z_q values.
#[inline]
pub fn sub_q(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

/// Multiply two Z_q values (Barrett reduction).
/// Uses 64-bit intermediate to avoid overflow.
#[inline]
pub fn mul_q(a: u32, b: u32) -> u32 {
    let prod = (a as u64) * (b as u64);
    barrett_reduce(prod)
}

/// Reduce x mod Q. Q < 2^24 and x < Q^2 < 2^48, fits in u64.
#[inline]
fn barrett_reduce(x: u64) -> u32 {
    (x % (Q as u64)) as u32
}

/// Modular inverse using Fermat's little theorem: a^(q-2) mod q
/// Modular inverse using Fermat's little theorem: a^(q-2) mod q
#[inline]
pub fn inv_q(a: u32) -> u32 {
    pow_q(a, Q - 2)
}

/// Modular exponentiation: base^exp mod q (square-and-multiply).
pub fn pow_q(mut base: u32, mut exp: u32) -> u32 {
    let mut result: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_q(result, base);
        }
        base = mul_q(base, base);
        exp >>= 1;
    }
    result
}

// ─── NTT Twiddle Factor Generation ──────────────────────────────────

/// Primitive root of unity for Z_q.
/// For Q = 8380417, a primitive 256th root of unity exists.
pub fn primitive_root() -> u32 {
    // Q-1 = 8380416 = 2^13 * 1023 = 2^13 * 3 * 11 * 31
    // We need omega such that omega^256 = 1 mod Q
    // and omega^128 != 1 mod Q
    // For Dilithium, zeta = 1753 is used as the primitive root
    1753u32
}

/// Generate NTT twiddle factors: zeta^(2^LOG_N / 2^stage * j) for each stage.
pub fn ntt_twiddles() -> Vec<Vec<u32>> {
    let zeta = primitive_root();
    let zeta_pow = pow_q(zeta, 2); // zeta^((q-1)/256) = primitive 256th root

    let mut twiddles = Vec::with_capacity(LOG_N);
    let mut root = zeta_pow;

    for _stage in 0..LOG_N {
        let mut stage_twiddles = Vec::with_capacity(N / 2);
        let mut w = 1u32;
        for _j in 0..(N / 2) {
            stage_twiddles.push(w);
            w = mul_q(w, root);
        }
        twiddles.push(stage_twiddles);
        root = mul_q(root, root); // square for next stage
    }
    twiddles
}

// ─── NTT / INTT ────────────────────────────────────────────────────

/// Generate inverse NTT twiddle factors (ω^{-2^s * j}).
fn ntt_twiddles_inv() -> Vec<Vec<u32>> {
    let zeta = primitive_root();
    let omega = pow_q(zeta, 2);
    let omega_inv = inv_q(omega);
    let mut twiddles = Vec::with_capacity(LOG_N);
    let mut root = omega_inv;
    for _stage in 0..LOG_N {
        let mut stage_twiddles = Vec::with_capacity(N / 2);
        let mut w = 1u32;
        for _j in 0..(N / 2) {
            stage_twiddles.push(w);
            w = mul_q(w, root);
        }
        twiddles.push(stage_twiddles);
        root = mul_q(root, root);
    }
    twiddles
}

/// Cooley-Tukey NTT over Z_q. In-place, bit-reversed output.
pub fn ntt_forward(coeffs: &mut [u32; N]) {
    let twiddles = ntt_twiddles();

    let mut len = 2usize;

    for stage in 0..LOG_N {
        let half = len / 2;
        for start in (0..N).step_by(len) {
            for j in 0..half {
                let idx_even = start + j;
                let idx_odd = start + j + half;

                let t = mul_q(twiddles[stage][j], coeffs[idx_odd]);
                let e = coeffs[idx_even];
                coeffs[idx_even] = add_q(e, t);
                coeffs[idx_odd] = sub_q(e, t);
            }
        }
        len *= 2;
    }
}

/// Inverse NTT (Gentleman-Sande). In-place, bit-reversed input.
pub fn ntt_inverse(coeffs: &mut [u32; N]) {
    let twiddles = ntt_twiddles_inv();
    let n_inv = inv_q(N as u32);

    let mut len = N;
    for stage in (0..LOG_N).rev() {
        let half = len / 2;
        for start in (0..N).step_by(len) {
            for j in 0..half {
                let idx_even = start + j;
                let idx_odd = start + j + half;

                let t = add_q(coeffs[idx_even], coeffs[idx_odd]);
                let diff = sub_q(coeffs[idx_even], coeffs[idx_odd]);
                coeffs[idx_even] = t;
                coeffs[idx_odd] = mul_q(diff, twiddles[stage][j]);
            }
        }
        len = half;
    }

    // Scale by 1/N
    for c in coeffs.iter_mut() {
        *c = mul_q(*c, n_inv);
    }
}

// ─── STARK Trace Building for NTT ──────────────────────────────────

use crate::config::F;

/// Number of trace columns for NTT gadget.
pub const NTT_TRACE_COLS: usize = 6;
// Col 0: stage
// Col 1: position in stage (start + j)
// Col 2: even index value (a)
// Col 3: odd index value (b)
// Col 4: twiddle factor (w)
// Col 5: result_even or result_odd (alternating rows)

/// Trace rows per NTT: LOG_N stages × N/2 butterflies × 2 rows per butterfly
pub const NTT_TRACE_ROWS_PER_STAGE: usize = N; // N/2 butterflies × 2 rows each
pub const NTT_TRACE_ROWS: usize = LOG_N * NTT_TRACE_ROWS_PER_STAGE; // 8 × 256 = 2048

/// Build STARK trace for one NTT operation.
/// Each butterfly produces 2 rows: (even_result, odd_result).
pub fn build_ntt_trace(input: &[u32; N], is_inverse: bool) -> Vec<Vec<F>> {
    let mut coeffs = *input;
    let twiddles = ntt_twiddles();

    let mut trace_rows: Vec<Vec<F>> = Vec::with_capacity(NTT_TRACE_ROWS);

    let mut len = if is_inverse { N } else { 2usize };
    let start_stage = if is_inverse { LOG_N - 1 } else { 0 };
    let end_stage = if is_inverse { 0 } else { LOG_N };
    let step: isize = if is_inverse { -1 } else { 1 };

    let mut stage = start_stage;
    loop {
        let half = len / 2;
        for start in (0..N).step_by(len) {
            for j in 0..half {
                let idx_even = start + j;
                let idx_odd = start + j + half;

                let a = coeffs[idx_even];
                let b = coeffs[idx_odd];
                let w = twiddles[stage][j];

                // Row 1: before butterfly
                trace_rows.push(vec![
                    F::from_u32(stage as u32),
                    F::from_u32(idx_even as u32),
                    F::from_u32(a),
                    F::from_u32(b),
                    F::from_u32(w),
                    F::ZERO, // placeholder for constraint check
                ]);

                // Compute butterfly
                let t = mul_q(w, b);
                let new_even = if is_inverse { add_q(a, b) } else { add_q(a, t) };
                let new_odd = if is_inverse { mul_q(sub_q(a, b), w) } else { sub_q(a, t) };

                // Row 2: after butterfly
                trace_rows.push(vec![
                    F::from_u32(stage as u32),
                    F::from_u32(idx_even as u32),
                    F::from_u32(new_even),
                    F::from_u32(new_odd),
                    F::from_u32(w),
                    F::ONE, // marker: this is a result row
                ]);

                // Update in-place for next stage
                if !is_inverse {
                    coeffs[idx_even] = new_even;
                    coeffs[idx_odd] = new_odd;
                }
            }
        }

        if is_inverse {
            if stage == end_stage {
                break;
            }
            stage = (stage as isize + step) as usize;
            len = half;
        } else {
            len *= 2;
            if stage + 1 >= end_stage {
                break;
            }
            stage += 1;
        }
    }

    trace_rows
}

use super::params::{LOG_N, N};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_sub_q() {
        assert_eq!(add_q(100, 200), 300);
        assert_eq!(add_q(Q - 1, 1), 0); // wraps around
        assert_eq!(add_q(Q - 1, 2), 1);
        assert_eq!(sub_q(100, 200), Q - 100);
        assert_eq!(sub_q(200, 100), 100);
    }

    #[test]
    fn test_mul_q() {
        assert_eq!(mul_q(100, 200), 20000);
        assert_eq!(mul_q(Q - 1, 1), Q - 1);
        assert_eq!(mul_q(Q - 1, 2), Q - 2);
        assert_eq!(mul_q(Q - 1, Q - 1), 1); // (-1)*(-1) = 1
    }

    #[test]
    fn test_inv_q() {
        let a = 12345u32;
        let inv = inv_q(a);
        assert_eq!(mul_q(a, inv), 1);
    }

    #[test]
    fn test_pow_q() {
        assert_eq!(pow_q(2, 10), 1024 % Q);
        assert_eq!(pow_q(3, 0), 1);
        assert_eq!(pow_q(7, 1), 7);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let mut original = [0u32; N];
        for i in 0..N {
            original[i] = (i as u32 * 12345 + 67) % Q;
        }

        let mut coeffs = original;
        ntt_forward(&mut coeffs);
        ntt_inverse(&mut coeffs);

        for i in 0..N {
            assert_eq!(coeffs[i], original[i], "NTT roundtrip failed at index {}", i);
        }
    }

    #[test]
    fn test_ntt_trace_size() {
        let input = [42u32; N];
        let trace = build_ntt_trace(&input, false);
        assert_eq!(trace.len(), NTT_TRACE_ROWS);
        assert_eq!(trace[0].len(), NTT_TRACE_COLS);
    }

    #[test]
    fn test_primitive_root() {
        let zeta = primitive_root();
        // Dilithium: zeta = 1753 is a primitive 2N-th root of unity (order 512)
        assert_eq!(pow_q(zeta, 2 * N as u32), 1, "zeta^(2N) != 1");
        assert_ne!(pow_q(zeta, N as u32), 1, "zeta^N == 1, not primitive 2N-th root");
    }

    #[test]
    fn test_ntt_root_of_unity() {
        let zeta = primitive_root();
        let omega = pow_q(zeta, 2);
        assert_eq!(pow_q(omega, N as u32), 1, "omega^N != 1");
        assert_ne!(pow_q(omega, (N / 2) as u32), 1, "omega^(N/2) == 1");
    }
}
