//! Parse raw ML-DSA-65 signature/public-key bytes into polynomial
//! components for STARK trace generation.

use dilithium::packing;
use dilithium::poly::Poly;
use dilithium::polyvec::{PolyVecK, PolyVecL};

use super::params::*;

/// Parsed Dilithium signature components.
#[derive(Debug)]
pub struct ParsedSignature {
    /// Raw challenge hash bytes (CTILDEBYTES = 48)
    pub c_tilde: Vec<u8>,
    /// Challenge polynomial c (tau=49 non-zero +/-1 coefficients), in [0, Q)
    pub c: [u32; N],
    /// Response vector z: L polynomials, coefficients in [0, Q)
    pub z: [[u32; N]; L],
    /// Hint vector h: K polynomials, coefficients 0 or 1
    pub h: [[u32; N]; K],
}

/// Parsed Dilithium public key components.
#[derive(Debug)]
pub struct ParsedPublicKey {
    /// Seed rho for matrix A expansion (32 bytes)
    pub rho: [u8; 32],
    /// Rounded public polynomial vector t1: K polynomials in [0, Q)
    pub t1: [[u32; N]; K],
}

/// Convert i32 Dilithium coefficient to u32 in [0, Q).
#[inline]
fn to_u32_q(v: i32) -> u32 {
    let q = Q as i32;
    if v < 0 { (v + q) as u32 }
    else if v >= q { (v - q) as u32 }
    else { v as u32 }
}

/// Parse an ML-DSA-65 signature from 3309 raw bytes.
pub fn parse_signature(sig_bytes: &[u8]) -> Option<ParsedSignature> {
    if sig_bytes.len() != SIG_SIZE {
        return None;
    }
    let mode = dilithium::ML_DSA_65;
    let k = mode.k();
    let l = mode.l();

    let mut c_buf = vec![0u8; mode.ctildebytes()];
    let mut z_pv = PolyVecL::default();
    let mut h_pv = PolyVecK::default();
    if packing::unpack_sig(mode, &mut c_buf, &mut z_pv, &mut h_pv, sig_bytes) {
        return None;
    }

    // Derive challenge polynomial from c_tilde
    let mut c_poly = Poly::zero();
    Poly::challenge(mode, &mut c_poly, &c_buf);
    let mut c = [0u32; N];
    for j in 0..N {
        c[j] = to_u32_q(c_poly.coeffs[j]);
    }

    let mut z = [[0u32; N]; L];
    for i in 0..l {
        for j in 0..N {
            z[i][j] = to_u32_q(z_pv.vec[i].coeffs[j]);
        }
    }

    let mut h = [[0u32; N]; K];
    for i in 0..k {
        for j in 0..N {
            h[i][j] = if h_pv.vec[i].coeffs[j] != 0 { 1u32 } else { 0u32 };
        }
    }

    Some(ParsedSignature { c_tilde: c_buf, c, z, h })
}

/// Parse an ML-DSA-65 public key from 1952 raw bytes.
pub fn parse_public_key(pk_bytes: &[u8]) -> Option<ParsedPublicKey> {
    if pk_bytes.len() != PK_SIZE {
        return None;
    }
    let mode = dilithium::ML_DSA_65;
    let k = mode.k();

    let mut rho = [0u8; 32];
    let mut t1_pv = PolyVecK::default();
    packing::unpack_pk(mode, &mut rho, &mut t1_pv, pk_bytes);

    let mut t1 = [[0u32; N]; K];
    for i in 0..k {
        for j in 0..N {
            t1[i][j] = to_u32_q(t1_pv.vec[i].coeffs[j]);
        }
    }

    Some(ParsedPublicKey { rho, t1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_dilithium::{generate_keypair, sign_message};

    #[test]
    fn test_parse_real_signature() {
        let kp = generate_keypair().unwrap();
        let msg = "sahyadri-zk-parse-test";
        let sig = sign_message(msg, &kp).unwrap();

        let parsed_sig = parse_signature(sig.as_bytes()).expect("sig parse failed");
        eprintln!("pk len = {}", kp.public_key_bytes().len());
        let parsed_pk = parse_public_key(kp.public_key()).expect("pk parse failed");

        assert_eq!(parsed_sig.c_tilde.len(), CTILDEBYTES);
        assert_eq!(parsed_sig.z.len(), L);
        assert_eq!(parsed_sig.h.len(), K);
        assert_eq!(parsed_pk.t1.len(), K);

        for poly in &parsed_sig.z {
            for &c in poly { assert!(c < Q, "z coeff {} >= Q", c); }
        }
        for poly in &parsed_sig.h {
            for &c in poly { assert!(c <= 1, "h coeff {} > 1", c); }
        }
        for poly in &parsed_pk.t1 {
            for &c in poly { assert!(c < Q, "t1 coeff {} >= Q", c); }
        }

        let mut nonzero = 0;
        for &c in &parsed_sig.c {
            assert!(c == 0 || c == 1 || c == Q - 1, "c coeff {} invalid", c);
            if c != 0 { nonzero += 1; }
        }
        assert_eq!(nonzero, 49, "challenge should have tau=49 non-zero coeffs");
    }

    #[test]
    fn test_parse_wrong_size_fails() {
        assert!(parse_signature(&[0u8; 100]).is_none());
        assert!(parse_public_key(&[0u8; 100]).is_none());
    }

    #[test]
    fn test_ctilde_matches_sig_prefix() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message("test-ctilde", &kp).unwrap();
        let parsed = parse_signature(sig.as_bytes()).unwrap();
        assert_eq!(parsed.c_tilde, &sig.as_bytes()[..CTILDEBYTES]);
    }

    #[test]
    fn test_rho_matches_pk_prefix() {
        let kp = generate_keypair().unwrap();
        let parsed = parse_public_key(kp.public_key()).unwrap();
        assert_eq!(&parsed.rho[..], &kp.public_key()[..32]);
    }
}
