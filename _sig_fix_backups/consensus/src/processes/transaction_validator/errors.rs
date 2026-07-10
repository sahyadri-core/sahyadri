//! Re-exports tx-related errors from consensus core
pub use sahyadri_consensus_core::errors::tx::*;
pub type TxResult<T> = std::result::Result<T, TxRuleError>;
