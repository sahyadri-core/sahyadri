//! Binary field configuration mirrors the construction used by the Plonky3
//! workspace test utilities. The original crate is internal to that workspace
//! and is not published, so we reproduce the same types here.
//!
//! The byte hash used is Keccak-256. A Blake3 variant follows once a published
//! Blake3 hasher is available.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_field::BinaryChallenger;
use p3_challenger::HashChallenger;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

/// Digest size in bytes for the byte hash used by the Merkle tree.
pub const DIGEST_BYTES: usize = 32;

/// Byte hash used to build the Merkle tree and the challenger transcript.
pub type ByteHash = Keccak256Hash;

/// Leaf hasher: serializes a row of field elements to bytes and hashes them.
pub type FieldHash = SerializingHasher<ByteHash>;

/// Node compression: hashes the concatenation of two child digests.
pub type Compress = CompressionFunctionFromHasher<ByteHash, 2, DIGEST_BYTES>;

/// Binary Merkle commitment over matrices of tower level `L`.
pub type LevelMmcs<L> = MerkleTreeMmcs<L, u8, FieldHash, Compress, 2, DIGEST_BYTES>;

/// Merkle commitment specialized to `BinaryField128`.
pub type BinaryMmcs = LevelMmcs<BinaryField128>;

/// Fiat-Shamir transcript over tower level `L`.
pub type LevelChallenger<L> = BinaryChallenger<L, HashChallenger<u8, ByteHash, DIGEST_BYTES>>;

/// Fiat-Shamir transcript specialized to `BinaryField128`.
pub type BinaryChallenger128 = LevelChallenger<BinaryField128>;

/// Returns a fresh byte hash instance.
pub const fn byte_hash() -> ByteHash {
    Keccak256Hash
}

/// Returns a Merkle tree commitment for tower level `L` with a single-root cap.
pub fn level_mmcs<L: TowerLevel>() -> LevelMmcs<L> {
    LevelMmcs::new(FieldHash::new(byte_hash()), Compress::new(byte_hash()), 0)
}

/// Returns a Merkle tree commitment for `BinaryField128`.
pub fn mmcs() -> BinaryMmcs {
    level_mmcs::<BinaryField128>()
}

/// Returns a fresh transcript over tower level `L` with empty initial state.
pub fn level_challenger<L: TowerLevel>() -> LevelChallenger<L> {
    LevelChallenger::from_hasher(Vec::new(), byte_hash())
}

/// Returns a fresh transcript over `BinaryField128`.
pub fn challenger() -> BinaryChallenger128 {
    level_challenger::<BinaryField128>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmcs_constructs() {
        let _ = mmcs();
    }

    #[test]
    fn challenger_constructs() {
        let _ = challenger();
    }

    #[test]
    fn digest_bytes_is_32() {
        assert_eq!(DIGEST_BYTES, 32);
    }
}
