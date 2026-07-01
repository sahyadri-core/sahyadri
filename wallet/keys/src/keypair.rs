//!
//! [`keypair`](mod@self) module encapsulates [`Keypair`] and [`PrivateKey`].
//! The [`Keypair`] provides access to the secret and public keys (Dilithium3).
//!

use crate::imports::*;
use sahyadri_dilithium::{DilithiumKeyPair, generate_keypair, generate_keypair_from_seed};
use sha2::{Sha256, Digest};

/// Data structure that contains a Dilithium keypair.
/// @category Wallet SDK
#[derive(Clone, CastFromJs)]
#[wasm_bindgen(inspectable)]
pub struct Keypair {
    inner: DilithiumKeyPair,
}

#[wasm_bindgen]
impl Keypair {
    fn new(inner: DilithiumKeyPair) -> Self {
        Self { inner }
    }

    /// Get the [`PublicKey`] of this [`Keypair`].
    #[wasm_bindgen(getter = publicKey)]
    pub fn get_public_key(&self) -> String {
        self.inner.public_key().to_vec().to_hex()
    }

    /// Get the [`PrivateKey`] seed of this [`Keypair`].
    #[wasm_bindgen(getter = privateKey)]
    pub fn get_private_key(&self) -> String {
        self.inner.private_key()[..32].to_vec().to_hex()
    }

    /// Get the [`Address`] of this Keypair's Dilithium public key.
    #[wasm_bindgen(js_name = toAddress)]
    pub fn to_address(&self, network: &NetworkTypeT) -> Result<Address> {
        let payload = &Sha256::digest(self.inner.public_key())[..20];
        let address = Address::new(network.try_into()?, AddressVersion::PubKeyDilithium, payload);
        Ok(address)
    }

    /// Create a new random [`Keypair`].
    #[wasm_bindgen]
    pub fn random() -> Result<Keypair, JsError> {
        let kp = generate_keypair().map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Keypair::new(kp))
    }

    /// Create a new [`Keypair`] from a [`PrivateKey`] seed.
    #[wasm_bindgen(js_name = "fromPrivateKey")]
    pub fn from_private_key(secret_key: &PrivateKey) -> Result<Keypair, JsError> {
        let kp = generate_keypair_from_seed(secret_key.seed_bytes());
        Ok(Keypair::new(kp))
    }
}

impl TryCastFromJs for Keypair {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Ok(Self::try_ref_from_js_value_as_cast(value)?)
    }
}
