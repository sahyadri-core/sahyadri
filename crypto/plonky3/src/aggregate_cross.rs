// Cross-aggregate: combine two batches of proofs with different AIRs
// into a single recursive proof.
//
// Strategy:
//   1. Aggregate each batch independently (same AIR within a batch).
//   2. Aggregate the two resulting batch proofs together.
//
// Both step 2 operations use PreparedSource::batch, which is AIR-agnostic,
// so different AIRs on each side is fine.

use p3_recursion::{build_and_prove_aggregation_layer, RecursionInput};
use p3_lookup::logup::LogUpGadget;
use p3_recursion::builtin_config::{
    goldilocks_d2_poseidon2_binary, FriConfigV1, SuiteIdV1,
};
use p3_recursion::prepared::{PreparedAggregation, PreparedInput, PreparedSource};
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{
    BatchOnly, FriRecursionBackend, Poseidon2Config, ProveNextLayerParams,
    RecursionOutput, VerifierLimits,
};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use crate::aggregate::{aggregate_batch, AggregateError, RecursionConfig};
use crate::config::{SahyadriStarkConfig, EF, F};

fn build_config() -> Result<RecursionConfig, AggregateError> {
    let limits = VerifierLimits::default();
    let descriptor = FriConfigV1::new(
        SuiteIdV1::GoldilocksD2Poseidon2BinaryFri,
        2,  // log_blowup
        0,  // log_final_poly_len
        1,  // max_log_arity
        100, // num_queries
        0,  // commit_pow_bits
        16, // query_pow_bits
        0,  // input_cap_height
        0,  // commit_cap_height
        0,  // num_random_codewords
        0,  // salt_elements
    );
    goldilocks_d2_poseidon2_binary(&descriptor, &limits)
        .map_err(|e| AggregateError::Config(format!("{e:?}")))
}

fn batch_table_public_inputs<SC>(output: &RecursionOutput<SC>) -> Vec<Vec<Val<SC>>>
where
    SC: StarkGenericConfig,
{
    vec![vec![]; output.0.proof.opened_values.instances.len()]
}

fn batch_prepared_source<'a, SC>(
    output: &'a RecursionOutput<SC>,
    table_public_inputs: &'a [Vec<Val<SC>>],
) -> PreparedSource<'static, 'a, SC, BatchOnly>
where
    SC: StarkGenericConfig,
{
    PreparedSource::batch(&output.0, &output.0.stark_common, table_public_inputs)
}

fn batch_prepared_input<'a, SC>(
    output: &'a RecursionOutput<SC>,
    table_public_inputs: &'a [Vec<Val<SC>>],
) -> PreparedInput<'a, SC>
where
    SC: StarkGenericConfig,
{
    PreparedInput::BatchStark {
        proof: &output.0,
        common_data: &output.0.stark_common,
        table_public_inputs,
    }
}

/// Aggregate two recursion outputs into one.
pub fn aggregate_two_batches(
    left: &RecursionOutput<RecursionConfig>,
    right: &RecursionOutput<RecursionConfig>,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError> {
    let config = build_config()?;
    let backend = FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let params = ProveNextLayerParams::default();

    let lt = batch_table_public_inputs(left);
    let rt = batch_table_public_inputs(right);

    let owner = PreparedAggregation::new(
        batch_prepared_source(left, &lt),
        batch_prepared_source(right, &rt),
        config,
        backend,
        params,
    )
    .map_err(|e| AggregateError::Recursion(format!("prepare: {e:?}")))?;

    let li = batch_prepared_input(left, &lt);
    let ri = batch_prepared_input(right, &rt);
    owner
        .prove(li, ri)
        .map_err(|e| AggregateError::Recursion(format!("prove: {e:?}")))
}

/// Cross-aggregate: two batches with different AIRs into one proof.
pub fn aggregate_cross<LA, RA>(
    left_proofs: Vec<Proof<SahyadriStarkConfig>>,
    left_publics: Vec<Vec<F>>,
    left_air: &LA,
    right_proofs: Vec<Proof<SahyadriStarkConfig>>,
    right_publics: Vec<Vec<F>>,
    right_air: &RA,
    threads: usize,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError>
where
    LA: RecursiveAir<F, EF, LogUpGadget> + Sync,
    RA: RecursiveAir<F, EF, LogUpGadget> + Sync,
{
    let left_batch = aggregate_batch(left_proofs, left_publics, left_air, threads)?;
    let right_batch = aggregate_batch(right_proofs, right_publics, right_air, threads)?;
    aggregate_two_batches(&left_batch, &right_batch)
}

/// Aggregate three recursion outputs into one.
pub fn aggregate_three_batches(
    a: &RecursionOutput<RecursionConfig>,
    b: &RecursionOutput<RecursionConfig>,
    c: &RecursionOutput<RecursionConfig>,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError> {
    let ab = aggregate_two_batches(a, b)?;
    aggregate_two_batches(&ab, c)
}

/// Cross-aggregate three batches with different AIRs into one proof.
pub fn aggregate_cross_three<AA, BA, CA>(
    a_proofs: Vec<Proof<SahyadriStarkConfig>>,
    a_pubs: Vec<Vec<F>>,
    a_air: &AA,
    b_proofs: Vec<Proof<SahyadriStarkConfig>>,
    b_pubs: Vec<Vec<F>>,
    b_air: &BA,
    c_proofs: Vec<Proof<SahyadriStarkConfig>>,
    c_pubs: Vec<Vec<F>>,
    c_air: &CA,
    threads: usize,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError>
where
    AA: RecursiveAir<F, EF, LogUpGadget> + Sync,
    BA: RecursiveAir<F, EF, LogUpGadget> + Sync,
    CA: RecursiveAir<F, EF, LogUpGadget> + Sync,
{
    let a_batch = aggregate_batch(a_proofs, a_pubs, a_air, threads)?;
    let b_batch = aggregate_batch(b_proofs, b_pubs, b_air, threads)?;
    let c_batch = aggregate_batch(c_proofs, c_pubs, c_air, threads)?;
    aggregate_three_batches(&a_batch, &b_batch, &c_batch)
}

use crate::smt_stark::chain_blob::ChainProofBlob;

/// Convert a ChainProofBlob into a RecursionInput::BatchStark for aggregation.
pub fn chain_blob_to_recursion_input<'a>(
    blob: &'a ChainProofBlob,
) -> RecursionInput<'a, RecursionConfig, BatchOnly> {
    use p3_circuit_prover::batch_stark_prover::NUM_PRIMITIVE_TABLES;

    let mut table_public_inputs =
        Vec::with_capacity(NUM_PRIMITIVE_TABLES + blob.proof.non_primitives.len());
    table_public_inputs.resize_with(NUM_PRIMITIVE_TABLES, Vec::new);
    table_public_inputs.extend(
        blob.proof
            .non_primitives
            .iter()
            .map(|e| e.public_values.clone()),
    );

    RecursionInput::BatchStark {
        proof: &blob.proof,
        common_data: &blob.proof.stark_common,
        table_public_inputs,
    }
}

/// Aggregate parent chain proof + current block's proof into new chain proof.
/// This is the core of E v2 — one recursion per block.
pub fn aggregate_two_chain_blobs(
    parent: &ChainProofBlob,
    current: &ChainProofBlob,
) -> Result<ChainProofBlob, AggregateError> {
    let config = build_config()?;
    let backend = FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let params = ProveNextLayerParams::default();

    let left = chain_blob_to_recursion_input(parent);
    let right = chain_blob_to_recursion_input(current);

    let combined = build_and_prove_aggregation_layer(&left, &right, &config, &backend, &params)
        .map_err(|e| AggregateError::Recursion(format!("chain aggregate: {e:?}")))?;

    Ok(ChainProofBlob {
        proof: combined.0,
        chain_depth: parent.chain_depth + 1,
        chain_commitment: current.chain_commitment,
    })
}
