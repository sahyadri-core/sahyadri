//! # True ZK Dilithium3 Verification via STARK
//!
//! Implements ML-DSA-65 (Dilithium3) signature verification as STARK constraints.
//! Each signature verification is proven without trusting the prover.
//!
//! ## Architecture
//!
//! | Phase | Component | Rows/Sig | Status |
//! |-------|-----------|----------|--------|
//! | 1 | Z_q arithmetic | Foundation | TODO |
//! | 2 | NTT gadget | ~6,000 | TODO |
//! | 3 | SHAKE256 gadget | ~200 | TODO |
//! | 4 | Poly multiply | ~2,000 | TODO |
//! | 5 | Norm bounds | ~1,000 | TODO |
//! | 6 | Full verify trace | ~9,200 | TODO |
//!
//! ## Trace Size for 256 sigs: ~2.4M rows
//! ## Estimated proof: ~200-400 KB
//! ## Estimated prove time: ~5-15s

pub mod params;
pub mod field_zq;
pub mod ntt_stark;
pub mod poly_mult_stark;
pub mod matrix_vec_stark;
pub mod rejection_stark;
pub mod fiat_shamir_stark;
pub mod dilithium_verify_stark;
pub mod sig_parse;
pub mod zk_verify;
pub mod witness;
pub mod composed_stark;
