//!
//! PublicKey (Dilithium 1952-byte public key)
//!

use crate::imports::*;
use sahyadri_consensus_core::network::NetworkType;
use sha2::{Digest, Sha256};

/// Data structure that envelopes a Dilithium PublicKey (1952 bytes).
/// @category Wallet SDK
#[derive(Clone, Debug, Serialize, Deserialize, CastFromJs)]
#[wasm_bindgen(js_name = PublicKey)]
pub struct PublicKey {
    #[wasm_bindgen(skip)]
    pub bytes: Vec<u8>,
}

#[wasm_bindgen(js_class = PublicKey)]
impl PublicKey {
    /// Create a new [`PublicKey`] from a hex-encoded Dilithium public key string.
    #[wasm_bindgen(constructor)]
    pub fn try_new(key: &str) -> Result<PublicKey> {
        let mut buf = vec![0u8; key.len() / 2];
        faster_hex::hex_decode(key.as_bytes(), &mut buf).map_err(|_| Error::custom("Invalid hex for PublicKey"))?;
        Ok(Self { bytes: buf })
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string_impl(&self) -> String {
        self.bytes.to_hex()
    }

    /// Get the [`Address`] of this PublicKey (Dilithium).
    #[wasm_bindgen(js_name = toAddress)]
    pub fn to_address_js(&self, network: &NetworkTypeT) -> Result<Address> {
        self.to_address(network.try_into()?)
    }

    /// Compute a 4-byte key fingerprint for this public key as a hex string.
    pub fn fingerprint(&self) -> Option<HexString> {
        let digest = ripemd::Ripemd160::digest(Sha256::digest(&self.bytes));
        Some(digest[..4].to_vec().to_hex().into())
    }
}

impl PublicKey {
    #[inline]
    pub fn to_address(&self, network_type: NetworkType) -> Result<Address> {
        let payload = &Sha256::digest(&self.bytes)[..20];
        let address = Address::new(network_type.into(), AddressVersion::PubKeyDilithium, payload);
        Ok(address)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_impl())
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for PublicKey {
    fn from(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "PublicKey | string")]
    pub type PublicKeyT;

    #[wasm_bindgen(extends = Array, typescript_type = "(PublicKey | string)[]")]
    pub type PublicKeyArrayT;
}

impl TryCastFromJs for PublicKey {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::resolve(value, || {
            let value = value.as_ref();
            if let Some(hex_str) = value.as_string() {
                Ok(PublicKey::try_new(hex_str.as_str())?)
            } else {
                Err(Error::custom("Invalid PublicKey"))
            }
        })
    }
}

/// XOnlyPublicKey — in Dilithium context, wraps the 20-byte address hash.
/// @category Wallet SDK
#[wasm_bindgen]
#[derive(Clone, Debug, CastFromJs)]
pub struct XOnlyPublicKey {
    #[wasm_bindgen(skip)]
    pub hash: [u8; 20],
}

#[wasm_bindgen]
impl XOnlyPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn try_new(key: &str) -> Result<XOnlyPublicKey> {
        let mut buf = vec![0u8; key.len() / 2];
        faster_hex::hex_decode(key.as_bytes(), &mut buf).map_err(|_| Error::custom("Invalid hex for XOnlyPublicKey"))?;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&buf[..20]);
        Ok(Self { hash })
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string_impl(&self) -> String {
        self.hash.to_vec().to_hex()
    }

    #[wasm_bindgen(js_name = toAddress)]
    pub fn to_address(&self, network: &NetworkTypeT) -> Result<Address> {
        let address = Address::new(network.try_into()?, AddressVersion::PubKeyDilithium, &self.hash);
        Ok(address)
    }

    #[wasm_bindgen(js_name = fromAddress)]
    pub fn from_address(address: &Address) -> Result<XOnlyPublicKey> {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&address.payload[..20]);
        Ok(Self { hash })
    }
}

impl std::fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_impl())
    }
}

impl From<[u8; 20]> for XOnlyPublicKey {
    fn from(hash: [u8; 20]) -> Self {
        Self { hash }
    }
}
