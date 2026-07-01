//! Witness capture for Dilithium3 verification.
//! Runs verify logic and captures all intermediate values for STARK trace building.

use dilithium::packing;
use dilithium::poly::Poly;
use dilithium::polyvec::{
    PolyVecK, PolyVecL,
    matrix_pointwise_montgomery,
    polyveck_pointwise_poly_montgomery,
    polyveck_sub,
    polyveck_invntt_tomont,
    polyveck_ntt,
    polyvecl_ntt,
    polyveck_reduce,
    polyveck_shiftl,
    polyveck_caddq,
    polyveck_use_hint,
    polyveck_pack_w1,
    polyvecl_chknorm,
};

use super::params::*;

fn poly_to_u32(p: &Poly) -> [u32; N] {
    let mut arr = [0u32; N];
    for i in 0..N { arr[i] = (p.coeffs[i] as i64).rem_euclid(Q as i64) as u32; }
    arr
}

fn polyvecl_to_u32(pv: &PolyVecL) -> [[u32; N]; L] {
    let mut arr = [[0u32; N]; L];
    for i in 0..L { arr[i] = poly_to_u32(&pv.vec[i]); }
    arr
}

fn polyveck_to_u32(pv: &PolyVecK) -> [[u32; N]; K] {
    let mut arr = [[0u32; N]; K];
    for i in 0..K { arr[i] = poly_to_u32(&pv.vec[i]); }
    arr
}

#[derive(Debug, Clone)]
pub struct DilithiumVerifyWitness {
    pub rho: [u8; 32],
    pub t1_shifted_coeffs: [[u32; N]; K],
    pub c_tilde_bytes: Vec<u8>,
    pub z_coeffs: [[u32; N]; L],
    pub h_coeffs: [[u32; N]; K],
    pub cp_coeffs: [u32; N],
    pub a_matrix: [[[u32; N]; L]; K],
    pub w1_packed: Vec<u8>,
    pub c2_bytes: Vec<u8>,
    pub valid: bool,
}

pub fn verify_with_witness(
    sig_bytes: &[u8],
    pk_bytes: &[u8],
    msg: &[u8],
) -> Result<DilithiumVerifyWitness, String> {
    let mode = dilithium::ML_DSA_65;
    let k = mode.k();
    let beta = mode.beta();
    let gamma1 = mode.gamma1();

    if sig_bytes.len() != SIG_SIZE { return Err("wrong sig size".into()); }
    if pk_bytes.len() != PK_SIZE { return Err("wrong pk size".into()); }

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

    let z_coeffs = polyvecl_to_u32(&z);
    let h_coeffs = polyveck_to_u32(&h);

    let mut tr = [0u8; 64];
    let mut mu = [0u8; 64];
    dilithium::symmetric::shake256(&mut tr, pk_bytes);
    let pre = [0u8, 0u8];
    dilithium::symmetric::shake256_multi(&mut mu, &[&tr, &pre, msg]);

    let mut cp = Poly::zero();
    Poly::challenge(mode, &mut cp, &c_tilde);
    let cp_coeffs = poly_to_u32(&cp);

    let mut mat = vec![PolyVecL::default(); K];
    for i in 0..K {
        for j in 0..L {
            Poly::uniform(&mut mat[i].vec[j], &rho, ((i << 8) + j) as u16);
        }
    }
    let mut a_matrix = [[[0u32; N]; L]; K];
    for i in 0..K {
        for j in 0..L {
            a_matrix[i][j] = poly_to_u32(&mat[i].vec[j]);
        }
    }

    polyvecl_ntt(mode, &mut z);
    let mut w1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut w1, &mat, &z);

    cp.ntt();
    polyveck_shiftl(mode, &mut t1);
    let t1_shifted_coeffs = polyveck_to_u32(&t1);
    polyveck_ntt(mode, &mut t1);
    let t1_clone = t1.clone();
    polyveck_pointwise_poly_montgomery(mode, &mut t1, &cp, &t1_clone);

    let w1_copy = w1.clone();
    polyveck_sub(mode, &mut w1, &w1_copy, &t1);
    polyveck_reduce(mode, &mut w1);
    polyveck_invntt_tomont(mode, &mut w1);
    polyveck_caddq(mode, &mut w1);
    let w1_copy2 = w1.clone();
    polyveck_use_hint(mode, &mut w1, &w1_copy2, &h);

    let mut buf = vec![0u8; k * mode.polyw1_packedbytes()];
    polyveck_pack_w1(mode, &mut buf, &w1);
    let w1_packed = buf.clone();
    let mut c2 = vec![0u8; mode.ctildebytes()];
    dilithium::symmetric::shake256_multi(&mut c2, &[&mu, &buf]);

    let valid = c_tilde == c2;

    Ok(DilithiumVerifyWitness {
        rho, t1_shifted_coeffs, c_tilde_bytes: c_tilde,
        z_coeffs, h_coeffs, cp_coeffs, a_matrix,
        w1_packed, c2_bytes: c2, valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_with_witness_valid() {
        use sahyadri_dilithium::{generate_keypair, sign_message};
        let kp = generate_keypair().unwrap();
        let sig = sign_message("witness-test", &kp).unwrap();
        let w = verify_with_witness(sig.as_bytes(), kp.public_key(), b"witness-test").unwrap();
        assert!(w.valid);
        assert_eq!(w.c_tilde_bytes.len(), CTILDEBYTES);
        assert_eq!(w.z_coeffs.len(), L);
        assert_eq!(w.h_coeffs.len(), K);
        assert_eq!(w.a_matrix.len(), K);
    }

    #[test]
    fn test_witness_invalid_msg() {
        use sahyadri_dilithium::{generate_keypair, sign_message};
        let kp = generate_keypair().unwrap();
        let sig = sign_message("correct", &kp).unwrap();
        let w = verify_with_witness(sig.as_bytes(), kp.public_key(), b"wrong").unwrap();
        assert!(!w.valid);
    }

    #[test]
    fn test_witness_matches_native() {
        use sahyadri_dilithium::{generate_keypair, sign_message};
        let kp = generate_keypair().unwrap();
        let sig = sign_message("match", &kp).unwrap();
        let w = verify_with_witness(sig.as_bytes(), kp.public_key(), b"match").unwrap();
        assert!(crate::dilithium_stark::zk_verify::verify_dilithium_native(
            sig.as_bytes(), kp.public_key(), b"match"
        ).is_ok());
        assert!(w.valid);
    }
}
