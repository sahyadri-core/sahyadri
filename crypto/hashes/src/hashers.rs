// use sha3::CShake256;
use once_cell::sync::Lazy;

pub trait HasherBase {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self;
}

pub trait Hasher: HasherBase + Clone + Default {
    fn finalize(self) -> crate::Hash;
    fn reset(&mut self);
    #[inline(always)]
    fn hash<A: AsRef<[u8]>>(data: A) -> crate::Hash {
        let mut hasher = Self::default();
        hasher.update(data);
        hasher.finalize()
    }
}

// Implemented manually in pow_hashers:
//  struct PowHash => `cSHAKE256("ProofOfWorkHash")
//  struct SahyadriX => `cSHAKE256("HeavyHash")
pub use crate::pow_hashers::{PowHash, SahyadriX};
sha3_hasher! {
    struct TransactionHash => b"TransactionHash",
    struct TransactionID => b"TransactionID",
    struct TransactionSigningHash => b"TransactionSigningHash",
    struct BlockHash => b"BlockHash",
    struct ProofOfWorkHash => b"ProofOfWorkHash",
    struct MerkleBranchHash => b"MerkleBranchHash",
    struct MuHashElementHash => b"MuHashElement",
    struct MuHashFinalizeHash => b"MuHashFinalize",
    struct PersonalMessageSigningHash => b"PersonalMessageSigningHash",
}

sha256_hasher! {
    struct TransactionSigningHashECDSA => "TransactionSigningHashECDSA",
}

macro_rules! sha256_hasher {
    ($(struct $name:ident => $domain_sep:literal),+ $(,)? ) => {$(
        #[derive(Clone)]
        pub struct $name(sha2::Sha256);

        impl $name {
            #[inline]
            pub fn new() -> Self {
                use sha2::{Sha256, Digest};
                // We use Lazy in order to avoid rehashing it
                // in the future we can replace this with the correct initial state.
                static HASHER: Lazy<$name> = Lazy::new(|| {
                    // SHA256 doesn't natively support domain separation, so we hash it to make it constant size.
                    let mut tmp_state = Sha256::new();
                    tmp_state.update($domain_sep);
                    let mut out = $name(Sha256::new());
                    out.write(tmp_state.finalize());

                    out
                });
                (*HASHER).clone()
            }

            pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
                sha2::Digest::update(&mut self.0, data.as_ref());
            }

            #[inline(always)]
            pub fn finalize(self) -> crate::Hash {
                let mut out = [0u8; 32];
                out.copy_from_slice(sha2::Digest::finalize(self.0).as_slice());
                crate::Hash(out)
            }
        }
    impl_hasher!{ struct $name }
    )*};
}

macro_rules! sha3_hasher {
    ($(struct $name:ident => $domain_sep:literal),+ $(,)? ) => {$(
        #[derive(Clone)]
        pub struct $name(sha3::Sha3_256);

        impl $name {
            #[inline]
            pub fn new() -> Self {
                use sha3::{Sha3_256, Digest};
                static HASHER: Lazy<$name> = Lazy::new(|| {
                    let mut tmp_state = Sha3_256::new();
                    tmp_state.update($domain_sep);
                    let mut out = $name(Sha3_256::new());
                    out.write(tmp_state.finalize());
                    out
                });
                (*HASHER).clone()
            }

            pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
                sha3::Digest::update(&mut self.0, data.as_ref());
            }

            #[inline(always)]
            pub fn finalize(self) -> crate::Hash {
                let mut out = [0u8; 32];
                out.copy_from_slice(sha3::Digest::finalize(self.0).as_slice());
                crate::Hash(out)
            }
        }
    impl_hasher!{ struct $name }
    )*};
}

macro_rules! impl_hasher {
    (struct $name:ident) => {
        impl HasherBase for $name {
            #[inline(always)]
            fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
                self.write(data);
                self
            }
        }
        impl Hasher for $name {
            #[inline(always)]
            fn finalize(self) -> crate::Hash {
                // Call the method
                $name::finalize(self)
            }
            #[inline(always)]
            fn reset(&mut self) {
                *self = Self::new();
            }
        }
        impl Default for $name {
            #[inline(always)]
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

use {impl_hasher, sha256_hasher, sha3_hasher};

