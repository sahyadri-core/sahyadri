//! # Sahyadri Dilithium — Post-Quantum ML-DSA (FIPS 204) Module
//!
//! Post-quantum digital signatures for Sahyadri blockchain.
//! Uses ML-DSA-65 (Dilithium3, NIST Level 3) — AES-192 equivalent security.
//!
//! ## Sizes (Dilithium3)
//! - Public key:  1,952 bytes
//! - Secret key:  4,032 bytes
//! - Signature:   3,309 bytes
//!
//! ## Usage
//! ```rust,ignore
//! use sahyadri_dilithium::{generate_keypair, sign_message, verify_signature};
//!
//! let kp = generate_keypair().unwrap();
//! let sig = sign_message("did:create:csm1abc:1717000000", &kp).unwrap();
//! let valid = verify_signature("did:create:csm1abc:1717000000", &sig, kp.public_key()).unwrap();
//! assert!(valid);
//! ```

// ── Re-exports from dilithium-rs ────────────────────────────────────
pub use dilithium::{
    DilithiumMode, DilithiumError, DilithiumKeyPair, DilithiumSignature,
    MlDsaKeyPair, MlDsaSignature,
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
};

/// Sahyadri default: ML-DSA-65 (Dilithium3, NIST Level 3 ≈ AES-192)
pub const SAHYADRI_MODE: DilithiumMode = ML_DSA_65;

/// Public key size: 1,952 bytes
pub const PUBKEY_SIZE: usize = 1952;

/// Secret key size: 4,032 bytes
pub const SECKEY_SIZE: usize = 4032;

/// Signature size: 3,309 bytes
pub const SIG_SIZE: usize = 3309;

/// Seed size for deterministic key generation: 32 bytes
pub const SEED_SIZE: usize = 32;

// ── Key Generation ───────────────────────────────────────────────────

/// Generate a new Dilithium3 key pair using OS entropy.
///
/// Returns a `DilithiumKeyPair` with:
/// - Public key: 1,952 bytes
/// - Secret key: 4,032 bytes (auto-zeroized on drop)
pub fn generate_keypair() -> Result<DilithiumKeyPair, DilithiumError> {
    DilithiumKeyPair::generate(SAHYADRI_MODE)
}

/// Generate a Dilithium3 key pair deterministically from a 32-byte seed.
///
/// Use this for BIP-39 mnemonic → seed → Dilithium key derivation.
/// Same seed always produces the same key pair.
pub fn generate_keypair_from_seed(seed: &[u8; SEED_SIZE]) -> DilithiumKeyPair {
    DilithiumKeyPair::generate_deterministic(SAHYADRI_MODE, seed)
}

// ── Signing ─────────────────────────────────────────────────────────

/// Sign a message string with Dilithium3.
///
/// Uses pure ML-DSA (FIPS 204 §6.1). The message is NOT pre-hashed —
/// Dilithium uses SHAKE-256 internally.
///
/// For DID operations, typical message formats:
/// - DID_CREATE:    `"did:create:{csm_address}:{timestamp}"`
/// - DID_UPDATE:    `"did:update:{csm_address}:{timestamp}"`
/// - VC_REGISTER:   `"vc:register:{csm_address}:{vc_hash}:{timestamp}"`
pub fn sign_message(message: &str, keypair: &DilithiumKeyPair) -> Result<DilithiumSignature, DilithiumError> {
    keypair.sign(message.as_bytes(), b"")
}

/// Sign raw bytes with Dilithium3.
pub fn sign_bytes(message: &[u8], keypair: &DilithiumKeyPair) -> Result<DilithiumSignature, DilithiumError> {
    keypair.sign(message, b"")
}

// ── Verification ─────────────────────────────────────────────────────

/// Verify a Dilithium3 signature.
///
/// # Arguments
/// * `message` - The original message (same string that was signed)
/// * `signature` - The Dilithium signature
/// * `public_key` - The signer's public key bytes (1,952 bytes)
///
/// # Returns
/// * `true` if valid, `false` if invalid
pub fn verify_signature(
    message: &str,
    signature: &DilithiumSignature,
    public_key: &[u8],
) -> bool {
    DilithiumKeyPair::verify(public_key, signature, message.as_bytes(), b"", SAHYADRI_MODE)
}

/// Verify a Dilithium3 signature from raw bytes.
pub fn verify_signature_bytes(
    message: &str,
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> bool {
    let sig = DilithiumSignature::from_slice(sig_bytes);
    DilithiumKeyPair::verify(pubkey_bytes, &sig, message.as_bytes(), b"", SAHYADRI_MODE)
}

/// Auto-detect signature type and verify.
///
/// This is the main entry point for the indexer — it detects whether
/// the signature is ECDSA (64 bytes) or Dilithium (3309 bytes) and
/// dispatches to the appropriate verifier.
///
/// ECDSA verification has been replaced by Dilithium3.
/// This function only handles Dilithium path.
///
/// # Signature Length Detection
/// - 2,420 bytes → ML-DSA-44 (Dilithium2)
/// - 3,309 bytes → ML-DSA-65 (Dilithium3) ← Sahyadri default
/// - 4,627 bytes → ML-DSA-87 (Dilithium5)
pub fn is_dilithium_signature(sig_bytes: &[u8]) -> Option<DilithiumMode> {
    match sig_bytes.len() {
        2420 => Some(ML_DSA_44),
        3309 => Some(ML_DSA_65),
        4627 => Some(ML_DSA_87),
        _ => None,
    }
}

/// Verify a Dilithium signature with auto-detected mode.
pub fn verify_with_auto_mode(
    message: &str,
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Option<bool> {
    let mode = is_dilithium_signature(sig_bytes)?;
    let sig = DilithiumSignature::from_slice(sig_bytes);
    Some(DilithiumKeyPair::verify(pubkey_bytes, &sig, message.as_bytes(), b"", mode))
}

// ── Hex Helpers ──────────────────────────────────────────────────────

/// Encode public key to hex string (with mode tag prefix).
/// Format: `{02|03|05}{pubkey_hex}` — first byte = mode tag.
pub fn pubkey_to_hex(keypair: &DilithiumKeyPair) -> String {
    hex::encode(keypair.public_key_bytes())
}

/// Decode public key from hex string (with mode tag prefix).
pub fn pubkey_from_hex(hex_str: &str) -> Option<(DilithiumMode, Vec<u8>)> {
    let bytes = hex::decode(hex_str).ok()?;
    DilithiumKeyPair::from_public_key(&bytes).ok()
}

/// Encode signature to hex string.
pub fn sig_to_hex(sig: &DilithiumSignature) -> String {
    hex::encode(sig.as_bytes())
}

/// Decode signature from hex string.
pub fn sig_from_hex(hex_str: &str) -> Option<DilithiumSignature> {
    let bytes = hex::decode(hex_str).ok()?;
    if is_dilithium_signature(&bytes).is_some() {
        Some(DilithiumSignature::from_slice(&bytes))
    } else {
        None
    }
}

// ── DID Message Builders ─────────────────────────────────────────────

/// `did:create:{address}:{timestamp}`
pub fn did_create_msg(address: &str, timestamp: u64) -> String {
    format!("did:create:{}:{}", address, timestamp)
}

/// `did:update:{address}:{timestamp}`
pub fn did_update_msg(address: &str, timestamp: u64) -> String {
    format!("did:update:{}:{}", address, timestamp)
}

/// `did:rotate:{address}:{old_key_id}:{timestamp}`
pub fn did_key_rotation_msg(address: &str, old_key_id: &str, timestamp: u64) -> String {
    format!("did:rotate:{}:{}:{}", address, old_key_id, timestamp)
}

/// `did:deactivate:{address}:{timestamp}`
pub fn did_deactivate_msg(address: &str, timestamp: u64) -> String {
    format!("did:deactivate:{}:{}", address, timestamp)
}

/// `vc:register:{address}:{vc_hash}:{timestamp}`
pub fn vc_register_msg(address: &str, vc_hash: &str, timestamp: u64) -> String {
    format!("vc:register:{}:{}:{}", address, vc_hash, timestamp)
}

/// `vc:revoke:{address}:{vc_hash}:{timestamp}`
pub fn vc_revoke_msg(address: &str, vc_hash: &str, timestamp: u64) -> String {
    format!("vc:revoke:{}:{}:{}", address, vc_hash, timestamp)
}

// ── Serialization ───────────────────────────────────────────────────

/// Serialize full keypair to bytes: `[mode_tag | pk | sk]`
pub fn keypair_to_bytes(keypair: &DilithiumKeyPair) -> Vec<u8> {
    keypair.to_bytes()
}

/// Deserialize keypair from bytes
pub fn keypair_from_bytes(data: &[u8]) -> Result<DilithiumKeyPair, DilithiumError> {
    DilithiumKeyPair::from_bytes(data)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sizes() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.public_key().len(), PUBKEY_SIZE);
        assert_eq!(kp.private_key().len(), SECKEY_SIZE);
        assert_eq!(kp.mode(), SAHYADRI_MODE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_keypair().unwrap();
        let msg = "did:create:csm1sr5743abc:1717000000";

        let sig = sign_message(msg, &kp).unwrap();
        assert_eq!(sig.as_bytes().len(), SIG_SIZE);

        let valid = verify_signature(msg, &sig, kp.public_key());
        assert!(valid);
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message("did:create:csm1abc:1000", &kp).unwrap();
        let valid = verify_signature("did:create:csm1abc:1001", &sig, kp.public_key());
        assert!(!valid);
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let sig = sign_message("test", &kp1).unwrap();
        let valid = verify_signature("test", &sig, kp2.public_key());
        assert!(!valid);
    }

    #[test]
    fn test_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = generate_keypair_from_seed(&seed);
        let kp2 = generate_keypair_from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_hex_roundtrip() {
        let kp = generate_keypair().unwrap();
        let pk_hex = pubkey_to_hex(&kp);
        let (mode, pk_bytes) = pubkey_from_hex(&pk_hex).unwrap();
        assert_eq!(mode, SAHYADRI_MODE);
        assert_eq!(pk_bytes, kp.public_key());

        let sig = sign_message("test", &kp).unwrap();
        let sig_hex = sig_to_hex(&sig);
        let sig_back = sig_from_hex(&sig_hex).unwrap();
        assert_eq!(sig_back.as_bytes(), sig.as_bytes());
    }

    #[test]
    fn test_keypair_serialize_roundtrip() {
        let kp = generate_keypair().unwrap();
        let bytes = keypair_to_bytes(&kp);
        let kp2 = keypair_from_bytes(&bytes).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn test_auto_detect_sig() {
        assert_eq!(is_dilithium_signature(&vec![0u8; 3309]), Some(ML_DSA_65));
        assert_eq!(is_dilithium_signature(&vec![0u8; 2420]), Some(ML_DSA_44));
        assert_eq!(is_dilithium_signature(&vec![0u8; 4627]), Some(ML_DSA_87));
        assert_eq!(is_dilithium_signature(&vec![0u8; 64]), None); // ECDSA
    }

    #[test]
    fn test_did_message_formats() {
        assert_eq!(did_create_msg("csm1abc", 1000), "did:create:csm1abc:1000");
        assert_eq!(vc_register_msg("csm1abc", "hash123", 1000), "vc:register:csm1abc:hash123:1000");
    }
}
