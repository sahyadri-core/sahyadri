// Prove and verify entry points for SMT STARK.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof};

use crate::config::{SahyadriStarkConfig, F};
use crate::smt_stark::air::{
    SmtAir, COL_FOLD, HASH_LIMBS, NUM_PUBLIC_VALUES, NUM_TRACE_COLS,
};
use crate::smt_stark::trace::{generate_smt_trace, h256_to_limbs, SmtTraceInput};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtPublicInputs {
    pub root: [F; HASH_LIMBS],
    pub key: [F; HASH_LIMBS],
    pub value: [F; HASH_LIMBS],
    pub is_absent: bool,
    pub hash_fold: [F; HASH_LIMBS],
}

impl SmtPublicInputs {
    pub fn to_vec(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.value);
        out.push(if self.is_absent { F::ONE } else { F::ZERO });
        out.extend_from_slice(&self.hash_fold);
        out
    }
}

pub struct SmtStateProof {
    pub proof: Proof<SahyadriStarkConfig>,
    pub public: SmtPublicInputs,
}

fn compute_fold_from_trace(trace: &RowMajorMatrix<F>) -> [F; HASH_LIMBS] {
    let num_rows = trace.height();
    let last_off = (num_rows - 1) * NUM_TRACE_COLS;
    let mut out = [F::ZERO; HASH_LIMBS];
    for k in 0..HASH_LIMBS {
        out[k] = trace.values[last_off + COL_FOLD + k];
    }
    out
}

pub fn prove_smt_state(
    config: &SahyadriStarkConfig,
    input: &SmtTraceInput,
) -> SmtStateProof {
    let (trace, public) = prepare_smt_input(input);
    let pv = public.to_vec();
    let air = SmtAir;
    let proof = prove(config, &air, trace, &pv).expect("SMT STARK proving failed");
    SmtStateProof { proof, public }
}

pub fn verify_smt_state(
    config: &SahyadriStarkConfig,
    proof: &SmtStateProof,
) -> Result<(), String> {
    let air = SmtAir;
    let pv = proof.public.to_vec();
    verify(config, &air, &proof.proof, &pv)
        .map_err(|e| format!("SMT STARK verification failed: {:?}", e))
}

/// Prepare trace + public inputs without proving.
/// Used by both single-proof and batch-proof paths.
pub fn prepare_smt_input(input: &SmtTraceInput) -> (RowMajorMatrix<F>, SmtPublicInputs) {
    let trace = generate_smt_trace(input);
    let root = compute_root_from_input(input);
    let hash_fold = compute_fold_from_trace(&trace);

    let public = SmtPublicInputs {
        root,
        key: h256_to_limbs(&input.key),
        value: h256_to_limbs(&input.value),
        is_absent: input.is_absent,
        hash_fold,
    };
    (trace, public)
}

fn compute_root_from_input(input: &SmtTraceInput) -> [F; HASH_LIMBS] {
    use sahyadri_smt::{hash_branch, hash_leaf};

    let mut current: [u8; 32] = if input.is_absent {
        [0u8; 32]
    } else {
        hash_leaf(&input.key, &input.value)
    };

    for sib_idx in (0..input.siblings.len()).rev() {
        let sib = input.siblings[sib_idx];
        let key_bit = (input.key[sib_idx / 8] >> (7 - (sib_idx % 8))) & 1 == 1;
        let (left, right) = if key_bit {
            (sib, current)
        } else {
            (current, sib)
        };
        current = hash_branch(&left, &right);
    }

    h256_to_limbs(&current)
}
