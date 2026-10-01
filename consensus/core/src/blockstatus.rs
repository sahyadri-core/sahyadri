use sahyadri_utils::mem_size::MemSizeEstimator;
use serde::{Deserialize, Serialize};

/// Block validation status in the Sahyadri account model.
///
/// The `State*` variants refer to the account-state (SMT account root)
/// commitment carried by every block header.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum BlockStatus {
    /// The block is invalid.
    StatusInvalid,

    /// The block has been fully validated and its account-state root
    /// matches the committed SMT root.
    StatusStateValid,

    /// The block is pending verification against its past account state —
    /// either it was never in the selected parent chain, or it violates
    /// finality.
    StatusStatePendingVerification,

    /// The block is not eligible to be a selected parent.
    StatusDisqualifiedFromChain,

    /// The block's transactions are not held (pruned or not yet received).
    StatusHeaderOnly,
}

impl MemSizeEstimator for BlockStatus {}

impl BlockStatus {
    pub fn has_block_header(self) -> bool {
        matches!(
            self,
            Self::StatusHeaderOnly
                | Self::StatusStateValid
                | Self::StatusStatePendingVerification
                | Self::StatusDisqualifiedFromChain
        )
    }

    pub fn is_header_only(self) -> bool {
        self == Self::StatusHeaderOnly
    }

    pub fn has_block_body(self) -> bool {
        matches!(
            self,
            Self::StatusStateValid | Self::StatusStatePendingVerification | Self::StatusDisqualifiedFromChain
        )
    }

    /// Returns true if the block's account state is either fully valid or
    /// pending verification (i.e. not invalid / not header-only).
    pub fn is_state_valid_or_pending(self) -> bool {
        matches!(self, Self::StatusStateValid | Self::StatusStatePendingVerification)
    }

    pub fn is_valid(self) -> bool {
        self != BlockStatus::StatusInvalid
    }

    pub fn is_invalid(self) -> bool {
        self == BlockStatus::StatusInvalid
    }
}
