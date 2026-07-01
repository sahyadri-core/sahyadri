use zeroize::Zeroizing;

mod private_key;
mod public_key;
mod xkey;
mod xprivate_key;
mod xpublic_key;

mod address_type;
mod attrs;
mod child_number;
mod derivation_path;
mod error;
mod mnemonic;
mod prefix;
mod result;
pub mod types;

pub mod wasm {
    //! WASM bindings for the `bip32` module.
    pub use crate::mnemonic::{Language, Mnemonic, WordCount};
}

pub use address_type::AddressType;
pub use attrs::ExtendedKeyAttrs;
pub use child_number::ChildNumber;
pub use derivation_path::DerivationPath;
pub use mnemonic::{Language, Mnemonic, WordCount};
pub use prefix::Prefix;
pub use private_key::{DilithiumSeed, PrivateKey};
pub use public_key::{DilithiumPkHash, PublicKey};
pub use types::*;
pub use xkey::ExtendedKey;
pub use xprivate_key::ExtendedPrivateKey;
pub use xpublic_key::ExtendedPublicKey;

/// Re-export DilithiumSeed as SecretKey for backward compatibility
pub use private_key::DilithiumSeed as SecretKey;

/// Extension for [`SecretKey`] (DilithiumSeed) providing string serialization.
pub trait SecretKeyExt {
    fn as_str(&self, attrs: crate::ExtendedKeyAttrs, prefix: crate::Prefix) -> Zeroizing<String>;
}

impl SecretKeyExt for DilithiumSeed {
    fn as_str(&self, attrs: crate::ExtendedKeyAttrs, prefix: crate::Prefix) -> Zeroizing<String> {
        let mut key_bytes = [0u8; KEY_SIZE];
        key_bytes.copy_from_slice(&self.to_bytes());
        let key = crate::ExtendedKey { prefix, attrs, key_bytes };
        Zeroizing::new(key.to_string())
    }
}
