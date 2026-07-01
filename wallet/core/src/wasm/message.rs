use crate::imports::*;
use sahyadri_wallet_keys::privatekey::PrivateKey;
use sahyadri_wallet_keys::publickey::PublicKey;
use sahyadri_wasm_core::types::HexString;

#[wasm_bindgen(typescript_custom_section)]
const TS_MESSAGE_TYPES: &'static str = r#"
/**
 * Interface declaration for {@link signMessage} function arguments.
 *
 * @category Message Signing
 */
export interface ISignMessage {
    message: string;
    privateKey: PrivateKey | string;
    noAuxRand?: boolean;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object, typescript_type = "ISignMessage")]
    pub type ISignMessage;
}

/// Signs a message with the given private key
/// @category Message Signing
#[wasm_bindgen(js_name = signMessage)]
pub fn js_sign_message(value: ISignMessage) -> Result<HexString, Error> {
    if let Some(object) = Object::try_from(&value) {
        let private_key = object.cast_into::<PrivateKey>("privateKey")?;
        let raw_msg = object.get_string("message")?;
        let _no_aux_rand = object.get_bool("noAuxRand").unwrap_or(false);
        let keypair = sahyadri_dilithium::generate_keypair_from_seed(&private_key.seed_bytes());
        let sig = sahyadri_dilithium::sign_bytes(raw_msg.as_bytes(), &keypair)
            .map_err(|e| Error::custom(format!("Dilithium signing failed: {e}")))?;
        Ok(faster_hex::hex_string(sig.as_bytes()).into())
    } else {
        Err(Error::custom("Failed to parse input"))
    }
}

#[wasm_bindgen(typescript_custom_section)]
const TS_VERIFY_MESSAGE_TYPES: &'static str = r#"
/**
 * Interface declaration for {@link verifyMessage} function arguments.
 *
 * @category Message Signing
 */
export interface IVerifyMessage {
    message: string;
    signature: HexString;
    publicKey: PublicKey | string;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object, typescript_type = "IVerifyMessage")]
    pub type IVerifyMessage;
}

/// Verifies with a public key the signature of the given message
/// @category Message Signing
#[wasm_bindgen(js_name = verifyMessage, skip_jsdoc)]
pub fn js_verify_message(value: IVerifyMessage) -> Result<bool, Error> {
    if let Some(object) = Object::try_from(&value) {
        let public_key = object.cast_into::<PublicKey>("publicKey")?;
        let raw_msg = object.get_string("message")?;
        let signature = object.get_string("signature")?;

        let mut signature_bytes = vec![0u8; signature.len() / 2];
        faster_hex::hex_decode(signature.as_bytes(), &mut signature_bytes).map_err(|e| Error::custom(format!("hex decode: {e}")))?;
        Ok(sahyadri_dilithium::verify_signature_bytes(&raw_msg, &signature_bytes, &public_key.bytes))
    } else {
        Err(Error::custom("Failed to parse input"))
    }
}
