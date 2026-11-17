use sahyadri_consensus_core::errors::{block::RuleError, coinbase::CoinbaseError};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum BuilderError {
    /// A consensus rule error
    #[error(transparent)]
    ConsensusError(#[from] RuleError),

    /// A coinbase error
    #[error(transparent)]
    CoinbaseError(#[from] CoinbaseError),

    /// Feature disabled pending a proper fix.
    #[error("block template feature disabled: {0}")]
    NotSupported(String),
}

pub type BuilderResult<T> = std::result::Result<T, BuilderError>;
