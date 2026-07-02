//! Fiat-Shamir equality STARK: proves c_tilde == c2 byte-by-byte.
use p3_matrix::Matrix;
use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use crate::config::F;

pub const FS_COLS: usize = 2;
pub struct FiatShamirAir;
impl BaseAir<F> for FiatShamirAir { fn width(&self) -> usize { FS_COLS } }

impl<AB: p3_air::AirBuilder<F = F>> Air<AB> for FiatShamirAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("trace >= 1 row");
        builder.assert_zero(local[0].clone() - local[1].clone());
    }
}

pub fn build_fiat_shamir_trace(c_tilde: &[u8], c2: &[u8]) -> Vec<Vec<F>> {
    let len = std::cmp::max(c_tilde.len(), c2.len()).next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(len);
    for i in 0..len {
        let a = if i < c_tilde.len() { F::from_u64(c_tilde[i] as u64) } else { F::ZERO };
        let b = if i < c2.len() { F::from_u64(c2[i] as u64) } else { F::ZERO };
        trace.push(vec![a, b]);
    }
    trace
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fs_trace_shape() {
        let t = build_fiat_shamir_trace(&vec![1u8;32], &vec![1u8;32]);
        assert_eq!(t.len(), 32); assert_eq!(t[0].len(), 2);
    }
    #[test]
    fn test_fs_prove_verify() {
        use crate::config::build_stark_config;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_uni_stark::{prove, verify};
        let cfg = build_stark_config();
        let pv: Vec<F> = vec![];
        let t = build_fiat_shamir_trace(&vec![42u8;CTILDEBYTES], &vec![42u8;CTILDEBYTES]);
        let mut v = vec![F::ZERO; t.len()*2];
        for (i,r) in t.iter().enumerate() { for (j,&val) in r.iter().enumerate() { v[i*2+j]=val; } }
        let proof = prove(&cfg, &FiatShamirAir, RowMajorMatrix::new(v, 2), &pv);
        assert!(verify(&cfg, &FiatShamirAir, &proof, &pv).is_ok());
    }
}
