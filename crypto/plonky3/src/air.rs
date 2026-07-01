//! # DEPRECATED — Replaced by composed sub-STARKs (Phase 5)
//!
//! # STARK AIR — Algebraic Intermediate Representation
//!
//! Trace layout (per row = per attestation):
//!   Col 0: fp0  — first 24 bits of attestation hash (BabyBear)
//!   Col 1: fp1  — next 24 bits of attestation hash
//!   Col 2: verify_bit — 1 = sig verified, 0 = padding
//!   Col 3: index — row counter (0, 1, 2, ...)
//!   Col 4: acc   — running Fiat-Shamir accumulator
//!
//! Transition constraints:
//!   1. verify_bit * (verify_bit - 1) = 0
//!   2. next_index - local_index - 1 = 0
//!   3. next_acc - CHALLENGE*acc - verify_bit*(ALPHA*fp0 + BETA*fp1) = 0
//!
//! Boundary constraints (first row):
//!   4. index = 0
//!   5. verify_bit = 1
//!   6. acc = pv_init_acc

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::config::F;

pub const COL_FP0: usize = 0;
pub const COL_FP1: usize = 1;
pub const COL_VERIFY: usize = 2;
pub const COL_INDEX: usize = 3;
pub const COL_ACC: usize = 4;
pub const NUM_TRACE_COLS: usize = 5;
pub const NUM_PUBLIC_VALUES: usize = 4;

/// The STARK AIR for Dilithium3 batch verification.
pub struct DilithiumBatchVerifyAir;

impl BaseAir<F> for DilithiumBatchVerifyAir {
    fn width(&self) -> usize { NUM_TRACE_COLS }
}

impl<AB> Air<AB> for DilithiumBatchVerifyAir
where
    AB: AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("trace must have >= 1 row");
        let next = main.row_slice(1).expect("trace must have >= 2 rows");

        let local_fp0 = &local[COL_FP0];
        let local_fp1 = &local[COL_FP1];
        let local_verify = &local[COL_VERIFY];
        let local_index = &local[COL_INDEX];
        let local_acc = &local[COL_ACC];
        let _next_verify = &next[COL_VERIFY];
        let next_index = &next[COL_INDEX];
        let next_acc = &next[COL_ACC];

        // Public inputs: [init_acc, challenge, alpha, beta]
        let pv = builder.public_values();
        let pv_init_acc: AB::Expr = pv[0].into();
        let pv_challenge: AB::Expr = pv[1].into();
        let pv_alpha: AB::Expr = pv[2].into();
        let pv_beta: AB::Expr = pv[3].into();

        // Constraint 1: verify_bit is boolean
        builder.when_transition().assert_zero(
            local_verify.clone() * (local_verify.clone() - AB::Expr::ONE),
        );

        // Constraint 2: index is sequential
        builder.when_transition().assert_zero(
            next_index.clone() - local_index.clone() - AB::Expr::ONE,
        );

        // Constraint 3: accumulator chain
        let weighted_fp = pv_alpha * local_fp0.clone() + pv_beta * local_fp1.clone();
        builder.when_transition().assert_zero(
            next_acc.clone()
                - pv_challenge.clone() * local_acc.clone()
                - local_verify.clone() * weighted_fp,
        );

        // Boundary 4: first index = 0
        builder.when_first_row().assert_zero(local_index.clone());

        // Boundary 5: first verify_bit = 1
        builder.when_first_row().assert_zero(local_verify.clone() - AB::Expr::ONE);

        // Boundary 6: first acc = init_acc
        builder.when_first_row().assert_zero(local_acc.clone() - pv_init_acc);
    }
}

/// Pack bytes 0-2 of a 32-byte hash into BabyBear (24 bits LE).
pub fn pack_fp0(hash: &[u8; 32]) -> F {
    let val = (hash[0] as u32) | ((hash[1] as u32) << 8) | ((hash[2] as u32) << 16);
    F::from_u64(val as u64)
}

/// Pack bytes 3-5 of a 32-byte hash into BabyBear (24 bits LE).
pub fn pack_fp1(hash: &[u8; 32]) -> F {
    let val = (hash[3] as u32) | ((hash[4] as u32) << 8) | ((hash[5] as u32) << 16);
    F::from_u64(val as u64)
}

/// Next power of 2 >= n (minimum 2).
fn next_pow2(n: usize) -> usize {
    if n <= 1 { return 2; }
    1 << (32 - (n as u32).leading_zeros() as usize
        - (if n.is_power_of_two() { 1 } else { 0 }))
}

/// Build STARK execution trace from verified attestation hashes.
pub fn build_execution_trace(
    attestation_hashes: &[[u8; 32]],
    commitment_root: &[u8; 32],
) -> RowMajorMatrix<F> {
    let batch_size = attestation_hashes.len();
    let trace_height = next_pow2(batch_size);
    let (challenge, alpha, beta) = crate::config::derive_public_challenges(commitment_root);

    let mut acc = F::ZERO;
    let mut values = vec![F::ZERO; trace_height * NUM_TRACE_COLS];

    for row in 0..batch_size {
        let hash = &attestation_hashes[row];
        let fp0 = pack_fp0(hash);
        let fp1 = pack_fp1(hash);
        let off = row * NUM_TRACE_COLS;
        values[off + COL_FP0] = fp0;
        values[off + COL_FP1] = fp1;
        values[off + COL_VERIFY] = F::ONE;
        values[off + COL_INDEX] = F::from_u64(row as u64);
        values[off + COL_ACC] = acc;
        acc = challenge * acc + alpha * fp0 + beta * fp1;
    }

    for row in batch_size..trace_height {
        let off = row * NUM_TRACE_COLS;
        values[off + COL_VERIFY] = F::ZERO;
        values[off + COL_INDEX] = F::from_u64(row as u64);
        values[off + COL_ACC] = acc;
        acc = challenge * acc;
    }

    RowMajorMatrix::new(values, NUM_TRACE_COLS)
}

/// Build public input vector: [init_acc=0, challenge, alpha, beta].
pub fn build_public_values(commitment_root: &[u8; 32]) -> Vec<F> {
    let (challenge, alpha, beta) = crate::config::derive_public_challenges(commitment_root);
    vec![F::ZERO, challenge, alpha, beta]
}
