//! Error types for Sahyadri FRI-Binius.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FriBiniusError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("commitment mismatch")]
    CommitmentMismatch,

    #[error("folding round {round}: {msg}")]
    Folding { round: usize, msg: String },

    #[error("query {query} failed: {msg}")]
    Query { query: usize, msg: String },

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("proof malformed: {0}")]
    MalformedProof(String),
}
