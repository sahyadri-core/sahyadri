//!
//! Message signing and verification functions.
//!

use sahyadri_dilithium::{sign_bytes, verify_signature_bytes, generate_keypair_from_seed, DilithiumError, SIG_SIZE};

/// A personal message (text) that can be signed.
#[derive(Clone)]
pub struct PersonalMessage<'a>(pub &'a str);

impl AsRef<[u8]> for PersonalMessage<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Clone)]
pub struct SignMessageOptions {
    /// The auxiliary randomness exists only to mitigate specific kinds of power analysis
    /// side-channel attacks. Providing it definitely improves security, but omitting it
    /// should not be considered dangerous, as most legacy signature schemes don't provide
    /// mitigations against such attacks. To read more about the relevant discussions that
    /// arose in adding this randomness please see: <https://github.com/sipa/bips/issues/195>
    pub no_aux_rand: bool,
}

/// Sign a message with the given private key
pub fn sign_message(msg: &PersonalMessage, privkey: &[u8; 32], _options: &SignMessageOptions) -> Result<Vec<u8>, DilithiumError> {
    let kp = generate_keypair_from_seed(privkey);
    let sig = sign_bytes(msg.0.as_bytes(), &kp)?;
    Ok(sig.as_bytes().to_vec())
}

/// Verifies signed message.
///
/// Verify a Dilithium3 signature against a message.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid.
pub fn verify_message(msg: &PersonalMessage, signature: &[u8], pubkey: &[u8]) -> Result<bool, String> {
    if signature.len() != SIG_SIZE {
        return Err(format!("Invalid Dilithium signature size: {} (expected {})", signature.len(), SIG_SIZE));
    }
    Ok(verify_signature_bytes(msg.0, signature, pubkey))
}
