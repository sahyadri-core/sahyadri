//! ML-DSA-65 verification matching dilithium-rs's verify_internal exactly.
//! Computes w1 = Az - c*2^d*t1, applies UseHint, re-derives challenge.

use dilithium::packing;
use dilithium::poly::Poly;
use dilithium::polyvec::{
    matrix_pointwise_montgomery, polyveck_caddq, polyveck_invntt_tomont, polyveck_ntt, polyveck_pack_w1,
    polyveck_pointwise_poly_montgomery, polyveck_reduce, polyveck_shiftl, polyveck_sub, polyveck_use_hint, polyvecl_chknorm,
    polyvecl_ntt, PolyVecK, PolyVecL,
};

use super::params::*;

/// Verify ML-DSA-65 signature (same logic as dilithium-rs verify_internal).
/// Returns Ok(()) if valid.
pub fn verify_dilithium_native(sig_bytes: &[u8], pk_bytes: &[u8], msg: &[u8]) -> Result<(), String> {
    let mode = dilithium::ML_DSA_65;
    let k = mode.k();
    let beta = mode.beta();
    let gamma1 = mode.gamma1();

    if sig_bytes.len() != SIG_SIZE {
        return Err("wrong sig size".into());
    }
    if pk_bytes.len() != PK_SIZE {
        return Err("wrong pk size".into());
    }

    // Unpack
    let mut rho = [0u8; 32];
    let mut t1 = PolyVecK::default();
    packing::unpack_pk(mode, &mut rho, &mut t1, pk_bytes);

    let mut c_tilde = vec![0u8; mode.ctildebytes()];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();
    if packing::unpack_sig(mode, &mut c_tilde, &mut z, &mut h, sig_bytes) {
        return Err("unpack_sig failed".into());
    }
    if polyvecl_chknorm(mode, &z, gamma1 - beta) {
        return Err("z norm check failed".into());
    }

    // mu = H(tr || pre || msg), tr = H(pk)
    let mut tr = [0u8; 64];
    let mut mu = [0u8; 64];
    dilithium::symmetric::shake256(&mut tr, pk_bytes);
    let pre = [0u8, 0u8];
    dilithium::symmetric::shake256_multi(&mut mu, &[&tr, &pre, msg]);

    // Challenge polynomial
    let mut cp = Poly::zero();
    Poly::challenge(mode, &mut cp, &c_tilde);

    // Expand A
    let mut mat = vec![PolyVecL::default(); K];
    for i in 0..K {
        for j in 0..L {
            Poly::uniform(&mut mat[i].vec[j], &rho, ((i << 8) + j) as u16);
        }
    }

    // Az
    polyvecl_ntt(mode, &mut z);
    let mut w1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut w1, &mat, &z);

    // c * 2^d * t1
    cp.ntt();
    polyveck_shiftl(mode, &mut t1);
    polyveck_ntt(mode, &mut t1);
    let t1_clone = t1.clone();
    polyveck_pointwise_poly_montgomery(mode, &mut t1, &cp, &t1_clone);

    // w1 = Az - c*2^d*t1
    let w1_copy = w1.clone();
    polyveck_sub(mode, &mut w1, &w1_copy, &t1);
    polyveck_reduce(mode, &mut w1);
    polyveck_invntt_tomont(mode, &mut w1);

    // Reconstruct w1' using hint
    polyveck_caddq(mode, &mut w1);
    let w1_copy2 = w1.clone();
    polyveck_use_hint(mode, &mut w1, &w1_copy2, &h);

    // Pack w1' and re-derive challenge
    let mut buf = vec![0u8; k * mode.polyw1_packedbytes()];
    polyveck_pack_w1(mode, &mut buf, &w1);

    let mut c2 = vec![0u8; mode.ctildebytes()];
    dilithium::symmetric::shake256_multi(&mut c2, &[&mu, &buf]);

    if c_tilde == c2 {
        Ok(())
    } else {
        Err("challenge mismatch — invalid signature".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_dilithium::{generate_keypair, sign_message};

    #[test]
    fn test_verify_valid_signature() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message("test-zk-native", &kp).unwrap();
        if let Err(e) = verify_dilithium_native(sig.as_bytes(), kp.public_key(), b"test-zk-native") {
            panic!("valid sig failed: {}", e);
        }
    }

    #[test]
    fn test_verify_multiple_signatures() {
        for i in 0..5 {
            let kp = generate_keypair().unwrap();
            let msg = format!("msg-{}", i);
            let sig = sign_message(&msg, &kp).unwrap();
            if let Err(e) = verify_dilithium_native(sig.as_bytes(), kp.public_key(), msg.as_bytes()) {
                panic!("sig {} failed: {}", i, e);
            }
        }
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message("correct", &kp).unwrap();
        let result = verify_dilithium_native(sig.as_bytes(), kp.public_key(), b"wrong");
        assert!(result.is_err(), "wrong msg should fail");
    }

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [42u8; 32];
        let mut a1 = vec![PolyVecL::default(); K];
        let mut a2 = vec![PolyVecL::default(); K];
        for i in 0..K {
            for j in 0..L {
                Poly::uniform(&mut a1[i].vec[j], &rho, ((i << 8) + j) as u16);
                Poly::uniform(&mut a2[i].vec[j], &rho, ((i << 8) + j) as u16);
            }
        }
        for i in 0..K {
            for j in 0..L {
                assert_eq!(a1[i].vec[j].coeffs, a2[i].vec[j].coeffs);
            }
        }
    }
    #[test]
    fn test_dilithium_rs_verify_directly() {
        let kp = generate_keypair().unwrap();
        let msg = "test-zk-native";
        let sig = sign_message(msg, &kp).unwrap();
        let mode = dilithium::ML_DSA_65;
        let valid = dilithium::sign::verify(mode, sig.as_bytes(), msg.as_bytes(), b"", kp.public_key());
        eprintln!("dilithium-rs verify: {}", valid);
        assert!(valid, "dilithium-rs should verify its own sig");
    }
}
