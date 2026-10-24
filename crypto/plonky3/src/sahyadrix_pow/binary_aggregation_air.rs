//! Binary-field 2-input aggregation AIR (Point 2, Idea 1).
//!
//! Verifies TWO binary-field proofs (π_a, π_b) in one AIR, producing one
//! output proof "π_a valid AND π_b valid". All operations are native to
//! GF(2^128), so no field emulation overhead.
//!
//! Why custom AIR instead of generic p3-recursion: Plonky3's circuit builder
//! is two-adic prime-field only. Binary tower lacks two-adic roots of unity,
//! so FriRecursionBackend rejects GF(2^128).
//!
//! Incremental build:
//!   Phase 1 (this file): struct + widths + public count, compiles, 0 constraints
//!   Phase 2: transcript replay (Poseidon2b sponge in-AIR)
//!   Phase 3: Merkle path verify
//!   Phase 4: sumcheck round verify
//!   Phase 5: WHIR query fold
//!   Phase 6: full wiring + end-to-end test

use p3_air::{Air, AirBuilder, BaseAir};
use p3_binary_field::BinaryField128;

pub const AGGREGATION_PUBLIC_INPUTS: usize = 99;
pub const AGGREGATION_WIDTH: usize = 2048;

#[derive(Clone, Copy, Default)]
pub struct BinaryAggregationAir;

impl<F> BaseAir<F> for BinaryAggregationAir {
    fn width(&self) -> usize { AGGREGATION_WIDTH }
    fn num_public_values(&self) -> usize { AGGREGATION_PUBLIC_INPUTS }
}

impl<AB: AirBuilder<F = BinaryField128>> Air<AB> for BinaryAggregationAir {
    fn eval(&self, b: &mut AB) {
        // Phase 1: no constraints. Phases 2-6 will add ~150 constraints total.
        let _ = b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_is_power_of_two() {
        assert!(AGGREGATION_WIDTH.is_power_of_two());
    }

    #[test]
    fn public_input_count() {
        assert_eq!(AGGREGATION_PUBLIC_INPUTS, 99);
    }
}
