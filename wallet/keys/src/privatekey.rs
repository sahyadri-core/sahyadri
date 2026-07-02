//!
//! Private Key (Dilithium seed-based)
//!

use crate::imports::*;
use crate::keypair::Keypair;
use js_sys::{Array, Uint8Array};
use sahyadri_dilithium::generate_keypair_from_seed;
use sha2::{Digest, Sha256};

/// Data structure that envelops a Private Key (32-byte seed for Dilithium key derivation).
/// @category Wallet SDK
#[derive(Clone, Debug, CastFromJs)]
#[wasm_bindgen]
pub struct PrivateKey {
    #[wasm_bindgen(skip)]
    pub inner: [u8; 32],
}

impl PrivateKey {
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

#[wasm_bindgen]
impl PrivateKey {
    /// Create a new [`PrivateKey`] from a hex-encoded 32-byte seed string.
    #[wasm_bindgen(constructor)]
    pub fn try_new(key: &str) -> Result<PrivateKey> {
        let mut seed = [0u8; 32];
        faster_hex::hex_decode(key.as_bytes(), &mut seed).map_err(|_| Error::custom("Invalid hex for PrivateKey seed"))?;
        Ok(Self { inner: seed })
    }
}

impl PrivateKey {
    pub fn try_from_slice(data: &[u8]) -> Result<PrivateKey> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[..32]);
        Ok(Self { inner: seed })
    }
}

#[wasm_bindgen]
impl PrivateKey {
    /// Returns the [`PrivateKey`] seed encoded as a hex string.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_hex(&self) -> String {
        self.inner.to_vec().to_hex()
    }

    /// Generate a [`Keypair`] from this [`PrivateKey`] seed.
    #[wasm_bindgen(js_name = toKeypair)]
    pub fn to_keypair(&self) -> Result<Keypair, JsError> {
        Keypair::from_private_key(self)
    }

    #[wasm_bindgen(js_name = toPublicKey)]
    pub fn to_public_key(&self) -> Result<PublicKey, JsError> {
        let kp = generate_keypair_from_seed(&self.inner);
        Ok(PublicKey::from(kp.public_key().to_vec()))
    }

    /// Get the [`Address`] derived from this PrivateKey's Dilithium public key.
    #[wasm_bindgen(js_name = toAddress)]
    pub fn to_address(&self, network: &NetworkTypeT) -> Result<Address> {
        let kp = generate_keypair_from_seed(&self.inner);
        let payload = &Sha256::digest(kp.public_key())[..20];
        let address = Address::new(network.try_into()?, AddressVersion::PubKeyDilithium, payload);
        Ok(address)
    }
}

impl TryCastFromJs for PrivateKey {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::resolve(value, || {
            if let Some(hex_str) = value.as_ref().as_string() {
                Self::try_new(hex_str.as_str())
            } else if Array::is_array(value.as_ref()) {
                let array = Uint8Array::new(value.as_ref());
                Self::try_from_slice(array.to_vec().as_slice())
            } else {
                Err(Error::InvalidPrivateKey)
            }
        })
    }
}
