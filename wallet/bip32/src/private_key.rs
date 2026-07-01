use sha2::{Sha256, Digest};
use sahyadri_dilithium::generate_keypair_from_seed;
use crate::PublicKey;
use crate::Result;
use crate::types::*;

/// Trait for private key types which can be derived using BIP32.
pub trait PrivateKey: Sized {
    type PublicKey: PublicKey;
    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self>;
    fn to_bytes(&self) -> PrivateKeyBytes;
    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self>;
    fn public_key(&self) -> Self::PublicKey;
}

/// Dilithium seed-based private key for BIP32 derivation.
#[derive(Clone)]
pub struct DilithiumSeed(pub [u8; 32]);

impl PrivateKey for DilithiumSeed {
    type PublicKey = crate::DilithiumPkHash;

    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self> {
        Ok(DilithiumSeed(*bytes))
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        self.0
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        hasher.update(&other);
        let hash = hasher.finalize();
        let mut child_seed = [0u8; 32];
        child_seed.copy_from_slice(&hash[..32]);
        Ok(DilithiumSeed(child_seed))
    }

    fn public_key(&self) -> Self::PublicKey {
        let kp = generate_keypair_from_seed(&self.0);
        let hash = Sha256::digest(kp.public_key());
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&hash[..32]);
        crate::DilithiumPkHash(pk_bytes)
    }
}
