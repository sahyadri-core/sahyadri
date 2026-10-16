//! SMT STARK sub-module.
//!
//! Proves that a (key, value) pair is present (or absent) in a Sparse
//! Merkle Tree with a given root. Uses the same STARK configuration
//! as the Dilithium batch verifier, so both sub-STARKs share field,
//! challenger, MMCS, and Poseidon2 constants.
//!
//! Layout of a state proof:
//!   - Row 0        : leaf row (hash_leaf of key and value)
//!   - Rows 1..=L   : branch rows (one per sibling in the proof)
//!   - Rows L+1..511: padding rows (identity, hash = current_hash)
//!
//! Where L is the number of siblings (up to 256).
//!
//! Public inputs:
//!   [0..4]  root       (4 Goldilocks field elements)
//!   [4..8]  key        (4 Goldilocks field elements)
//!   [8..12] value      (4 Goldilocks field elements)
//!   [12]    is_absent  (1 if the key is absent, else 0)

pub mod air;
pub mod prove;
pub mod poseidon2_batch;
pub mod poseidon2_bound;
pub mod sponge_bound;
pub mod trace;
pub mod batch;

pub use air::{
    SmtAir, COL_CURRENT_HASH, COL_DIRECTION, COL_HASH, COL_IS_ABSENT,
    COL_IS_BRANCH, COL_IS_LEAF, COL_IS_PADDING, COL_KEY, COL_SIBLING_HASH,
    COL_VALUE, HASH_LIMBS, NUM_PUBLIC_VALUES, NUM_ROWS, NUM_TRACE_COLS,
    SMT_DEPTH,
};
pub use prove::{
    prove_smt_state, verify_smt_state, SmtPublicInputs, SmtStateProof,
};
pub use trace::{
    generate_smt_trace, h256_to_limbs, limbs_to_h256, SmtTraceInput,
};
