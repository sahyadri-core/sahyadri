//! BinaryInGoldilocksAir - Path C, C1 skeleton.
//!
//! Emulates a BinaryField128 circuit inside a Goldilocks field AIR.
//! Each BF128 element is encoded as 2 Goldilocks elements (lo/hi 64-bit).
//! All BF128 operations (add, mul, sbox) are expressed as Goldilocks
//! polynomial constraints over the 2-limb representation.
//!
//! STATUS: SKELETON. Full implementation is 1-2 weeks of circuit work.
//!
//! # Design
//!
//! BinaryField128 = GF(2^128) = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
//!
//! Encode bf_elem as (lo: Goldilocks, hi: Goldilocks) where:
//!   bf_elem = lo + hi * X^64  (as bits)
//!
//! Addition: XOR = (lo1 + lo2 - 2*AND(lo1,lo2), hi1 + hi2 - 2*AND(hi1,hi2))
//!   The AND is bitwise, not field multiplication — needs 64 bit-columns per limb.
//!
//! Multiplication: polynomial multiplication mod the irreducible, tracked in 256
//! Goldilocks cells (128 for the 128-bit result, 128 for the carries).
//!
//! Sbox x^7: 3 squarings + 1 multiply in BF128 = repeated polynomial ops.
//!
//! # Why this is research-level
//!
//! Bit-level emulation inside a prime-field AIR is not supported by any
//! published Plonky3 component. It requires a custom gadget library:
//!   - 64-bit AND, XOR, shift as Goldilocks constraints
//!   - 128-bit polynomial multiplication mod irreducible
//!   - Comparators for bit decomposition
//!
//! These are standard gadgets in prime-field proof systems (e.g., circom),
//! but Plonky3 does not ship them.
//!
//! # Public interface (to be finalized in C3)
//!
//! Public: commitment to binary trace (16 Block128 = 32 Goldilocks cells)
//! Public: statement hash (2 Goldilocks cells)
//! Witness: full binary trace as 2-limb Goldilocks encoding
//! Constraint: emulated binary AIR accepts the trace

use p3_goldilocks::Goldilocks;

/// Goldilocks-element encoding of one BF128 value.
pub type Bf128Encoded = (Goldilocks, Goldilocks);

/// Width of the emulation circuit (placeholder).
pub const WIDTH: usize = 4096;

/// Public input count: commitment (32) + statement hash (2).
pub const NUM_PUBLIC: usize = 34;

pub struct BinaryInGoldilocksAir;

// Skeleton: no constraints yet. Full impl is C1 (5-7 days).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_and_public_count() {
        assert_eq!(WIDTH, 4096);
        assert_eq!(NUM_PUBLIC, 34);
    }
}
