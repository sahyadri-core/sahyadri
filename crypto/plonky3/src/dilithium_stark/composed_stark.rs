//! Composed STARK: proves matrix-vec, poly-mult, subtraction, norm bounds.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_air::AirBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};

use crate::config::{build_stark_config, DilithiumStarkConfig, F};
use super::params::*;
use super::witness::DilithiumVerifyWitness;
use super::matrix_vec_stark::{MatrixVecAir, build_matrix_vec_trace};
use super::poly_mult_stark::{PolyMultAir, build_poly_mult_trace};
use super::rejection_stark::{RejectionAir, build_rejection_trace};

// ── Subtraction ─────────────────────────────────────────────────────
pub const SUB_COLS: usize = 6;

pub fn build_sub_trace(az: &[[u32; N]; K], ct1: &[[u32; N]; K]) -> Vec<Vec<F>> {
    let mut rows = Vec::with_capacity(K * N);
    for k in 0..K {
        for i in 0..N {
            let (d, c) = if az[k][i] >= ct1[k][i] {
                (az[k][i] - ct1[k][i], 0u32)
            } else {
                (az[k][i] + Q - ct1[k][i], 1u32)
            };
            rows.push(vec![
                F::from_u64(k as u64), F::from_u64(i as u64),
                F::from_u64(az[k][i] as u64), F::from_u64(ct1[k][i] as u64),
                F::from_u64(d as u64), F::from_u64(c as u64),
            ]);
        }
    }
    let padded_h = rows.len().next_power_of_two();
    if padded_h > rows.len() {
        let pad = vec![F::from_u64((K-1) as u64), F::from_u64((N-1) as u64), F::ZERO, F::ZERO, F::ZERO, F::ZERO];
        rows.resize(padded_h, pad);
    }
    rows
}

pub struct SubAir;
impl<Fld> p3_air::BaseAir<Fld> for SubAir { fn width(&self) -> usize { SUB_COLS } }
impl<AB> p3_air::Air<AB> for SubAir
where AB: p3_air::AirBuilderWithPublicValues<F = F>,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let l = m.row_slice(0).unwrap();
        let n = m.row_slice(1).unwrap();
        let a = l[2].clone(); let c = l[3].clone();
        let d = l[4].clone(); let cr = l[5].clone();
        let qf: AB::Expr = F::from_u64(Q as u64).into();
        let one: AB::Expr = AB::F::ONE.into();
        b.assert_zero(cr.clone() * (cr.clone() - one.clone()));
        b.assert_zero(a - c - d.clone() + cr * qf);
        let ki = l[0].clone(); let ii = l[1].clone();
        let nki = n[0].clone(); let nii = n[1].clone();
        let mut wt = b.when_transition();
        let nm1: AB::Expr = F::from_u64((N - 1) as u64).into();
        let nlast = nm1.clone() - ii.clone();
        wt.assert_zero(nlast.clone() * (nki.clone() - ki.clone()));
        wt.assert_zero(nlast * (nii.clone() - ii.clone() - one.clone()));
        { let mut f = b.when_first_row(); f.assert_zero(l[0].clone()); f.assert_zero(l[1].clone()); }
        { let mut la = b.when_last_row();
          la.assert_zero(l[0].clone() - F::from_u64((K-1) as u64));
          la.assert_zero(l[1].clone() - F::from_u64((N-1) as u64)); }
    }
}

// ── Composed Proof ──────────────────────────────────────────────────
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DilithiumSigProof {
    pub mv_proof: Vec<u8>,
    pub pm_proofs: Vec<Vec<u8>>,
    pub sub_proof: Vec<u8>,
    pub norm_proofs: Vec<Vec<u8>>,
    pub fiat_shamir_proof: Vec<u8>,
    pub valid: bool,
}

fn to_matrix(rows: Vec<Vec<F>>, w: usize) -> RowMajorMatrix<F> {
    let h = rows.len();
    let mut v = vec![F::ZERO; h * w];
    for (i, r) in rows.iter().enumerate() {
        for (j, &val) in r.iter().enumerate() { v[i * w + j] = val; }
    }
    RowMajorMatrix::new(v, w)
}

fn ser(p: &Proof<DilithiumStarkConfig>) -> Vec<u8> {
    bincode::serialize(p).unwrap_or_default()
}
fn de(b: &[u8]) -> Result<Proof<DilithiumStarkConfig>, String> {
    bincode::deserialize(b).map_err(|e| e.to_string())
}

pub fn prove_signature(w: &DilithiumVerifyWitness) -> Result<DilithiumSigProof, String> {
    let cfg = build_stark_config();
    let pv: Vec<F> = vec![];
    // 1. Matrix-vector: A * z
    let mv_t = build_matrix_vec_trace(&w.a_matrix, &w.z_coeffs);
    let mv_p = prove(&cfg, &MatrixVecAir, to_matrix(mv_t, 9), &pv);
    // 2. Poly-mult: cp * t1[k] for each k
    let mut pm = Vec::new();
    for k in 0..K {
        let t = build_poly_mult_trace(&w.cp_coeffs, &w.t1_shifted_coeffs[k]);
        let p = prove(&cfg, &PolyMultAir, to_matrix(t, 6), &pv);
        pm.push(ser(&p));
    }
    // 3. Compute Az and c*t1 for subtraction trace
    let mut az: [[u32; N]; K] = [[0u32; N]; K];
    for k in 0..K {
        for i in 0..N {
            let mut s: u64 = 0;
            for l in 0..L {
                s = (s + w.a_matrix[k][l][i] as u64 * w.z_coeffs[l][i] as u64) % Q as u64;
            }
            az[k][i] = s as u32;
        }
    }
    let mut ct1: [[u32; N]; K] = [[0u32; N]; K];
    for k in 0..K {
        for i in 0..N {
            ct1[k][i] = (w.cp_coeffs[i] as u64 * w.t1_shifted_coeffs[k][i] as u64 % Q as u64) as u32;
        }
    }
    // 4. Subtraction: Az - c*t1 mod Q
    let sub_t = build_sub_trace(&az, &ct1);
    let sub_p = prove(&cfg, &SubAir, to_matrix(sub_t, SUB_COLS), &pv);
    // 5. Norm bounds on z (L polys) and h (K polys)
    let mut nm = Vec::new();
    for j in 0..L {
        let t = build_rejection_trace(&w.z_coeffs[j]);
        let p = prove(&cfg, &RejectionAir, to_matrix(t, 4), &pv);
        nm.push(ser(&p));
    }
    for k in 0..K {
        let t = build_rejection_trace(&w.h_coeffs[k]);
        let p = prove(&cfg, &RejectionAir, to_matrix(t, 4), &pv);
        nm.push(ser(&p));
    }
    let fs_t = super::fiat_shamir_stark::build_fiat_shamir_trace(&w.c_tilde_bytes, &w.c2_bytes);
    let fs_p = prove(&cfg, &super::fiat_shamir_stark::FiatShamirAir, to_matrix(fs_t, 2), &pv);
    Ok(DilithiumSigProof { mv_proof: ser(&mv_p), pm_proofs: pm, sub_proof: ser(&sub_p), norm_proofs: nm, fiat_shamir_proof: ser(&fs_p), valid: w.valid })
}

pub fn verify_signature(p: &DilithiumSigProof) -> Result<bool, String> {
    let cfg = build_stark_config();
    let pv: Vec<F> = vec![];
    verify(&cfg, &MatrixVecAir, &de(&p.mv_proof)?, &pv).map_err(|e| format!("{:?}", e))?;
    for (k, b) in p.pm_proofs.iter().enumerate() {
        verify(&cfg, &PolyMultAir, &de(b)?, &pv).map_err(|e| format!("pm{}: {:?}", k, e))?;
    }
    verify(&cfg, &SubAir, &de(&p.sub_proof)?, &pv).map_err(|e| format!("{:?}", e))?;
    for (j, b) in p.norm_proofs.iter().enumerate() {
        verify(&cfg, &RejectionAir, &de(b)?, &pv).map_err(|e| format!("nm{}: {:?}", j, e))?;
    verify(&cfg, &super::fiat_shamir_stark::FiatShamirAir, &de(&p.fiat_shamir_proof)?, &pv).map_err(|e| format!("fiat_shamir: {:?}", e))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_dilithium::{generate_keypair, sign_message};

    #[test]
    fn test_prove_verify_single_sig() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message("zk-prove-test", &kp).unwrap();
        let w = crate::dilithium_stark::witness::verify_with_witness(
            sig.as_bytes(),
            kp.public_key(),
            b"zk-prove-test",
        )
        .unwrap();
        let proof = prove_signature(&w).unwrap();
        assert!(verify_signature(&proof).unwrap());
    }
}
