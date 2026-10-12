//! P2P-level payload types that don't map directly to consensus-core.
//!
//! These are wire types used by the p2p layer for messages that relay
//! auxiliary data (like recursively-aggregated STARK proofs) between peers.

use sahyadri_hashes::Hash;

/// Recursively-aggregated root STARK proof for a block.
///
/// Broadcast by the node that generated it, so peers can verify and
/// store locally. Light clients query this via RPC `get_block_proof`
/// as an alternative to trusting any single RPC provider.
#[derive(Clone, Debug)]
pub struct BlockRootProof {
    /// The block this proof attests to.
    pub block_hash: Hash,
    /// Sahyadri Score at proof generation time.
    pub blue_score: u64,
    /// Number of child proofs aggregated (N in N→1).
    pub aggregated_count: u32,
    /// Serialized `RecursionOutput` (bincode).
    pub proof_bytes: Vec<u8>,
}
