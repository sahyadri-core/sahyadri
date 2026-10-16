// Batch multiple SMT proofs into ONE batch-stark proof.
// Uses p3-batch-stark instead of recursion for flat scaling.

use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::{SahyadriStarkConfig, F};
use crate::smt_stark::air::SmtAir;
use crate::smt_stark::prove::prepare_smt_input;
use crate::smt_stark::trace::SmtTraceInput;

/// A batch of SMT proofs collapsed into one.
pub struct SmtBatchProof {
    pub proof: p3_batch_stark::BatchProof<SahyadriStarkConfig>,
    pub public_inputs: Vec<Vec<F>>,
    pub prover_data: ProverData<SahyadriStarkConfig>,
}

/// Prove N SMT inputs in one batch-stark proof.
pub fn prove_smt_batch(
    config: &SahyadriStarkConfig,
    inputs: &[SmtTraceInput],
) -> SmtBatchProof {
    assert!(!inputs.is_empty(), "empty batch");

    let mut traces: Vec<RowMajorMatrix<F>> = Vec::with_capacity(inputs.len());
    let mut public_inputs: Vec<Vec<F>> = Vec::with_capacity(inputs.len());

    for input in inputs {
        let (trace, public) = prepare_smt_input(input);
        traces.push(trace);
        public_inputs.push(public.to_vec());
    }

    let air = SmtAir;
    let instances: Vec<StarkInstance<'_, SahyadriStarkConfig, SmtAir>> = traces
        .iter()
        .zip(public_inputs.iter())
        .map(|(trace, pv)| StarkInstance {
            air: &air,
            trace,
            public_values: pv.clone(),
        })
        .collect();

    let prover_data = ProverData::from_instances(config, &instances)
        .expect("ProverData::from_instances failed");

    let proof = prove_batch(config, &instances, &prover_data)
        .expect("prove_batch failed");

    SmtBatchProof {
        proof,
        public_inputs,
        prover_data,
    }
}

/// Verify a batch-stark proof.
pub fn verify_smt_batch(
    config: &SahyadriStarkConfig,
    batch: &SmtBatchProof,
) -> Result<(), String> {
    let airs: Vec<SmtAir> = vec![SmtAir; batch.public_inputs.len()];
    let common = &batch.prover_data.common;

    verify_batch(
        config,
        &airs,
        &batch.proof,
        &batch.public_inputs,
        common,
    )
    .map_err(|e| format!("verify_batch: {:?}", e))
}
