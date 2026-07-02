use crate::Result;
use crate::types::*;
use ripemd::{Digest, Ripemd160};
use sha2::Sha256;

/// Trait for public key types which can be derived using BIP32.
pub trait PublicKey: Sized {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self>;
    fn to_bytes(&self) -> PublicKeyBytes;
    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self>;

    fn fingerprint(&self) -> KeyFingerprint {
        let digest = Ripemd160::digest(Sha256::digest(self.to_bytes()));
        digest[..4].try_into().expect("digest truncated")
    }
}

/// Dilithium public key hash for BIP32 (SHA256 of full Dilithium public key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct DilithiumPkHash(pub [u8; 32]);

impl PublicKey for DilithiumPkHash {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        Ok(DilithiumPkHash(bytes))
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        self.0
    }

    fn derive_child(&self, _other: PrivateKeyBytes) -> Result<Self> {
        Err(Error::String("Dilithium does not support public key child derivation".into()))
    }
}
