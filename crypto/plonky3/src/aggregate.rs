//! Recursive STARK proof aggregation for Sahyadri.
//!
//! Uses p3-recursion's builtin `goldilocks_d2_poseidon2_binary` config
//! (MMCS W8 + challenger W8, rate=4, digest=4) — bit-for-bit identical
//! to our `DilithiumStarkConfig`.
//!
//! ### Mining-aware thread pool
//!
//! `aggregate_batch` never touches the global Rayon pool. It builds a
//! local pool sized by the caller (`threads` argument).
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_maybe_rayon::prelude::*;
use p3_recursion::builtin_config::{
    goldilocks_d2_poseidon2_binary, FriConfigV1, SuiteIdV1,
};
use p3_recursion::prepared::{PreparedAggregation, PreparedInput, PreparedSource};
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{
    build_and_prove_aggregation_layer, BatchOnly, FriRecursionBackend, Poseidon2Config,
    ProveNextLayerParams, RecursionInput, RecursionOutput, VerifierLimits,
};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use crate::config::{DilithiumStarkConfig, EF, F};

/// Builtin recursion config — matches our STARK config bit-for-bit.
pub type RecursionConfig = p3_recursion::builtin_config::GoldilocksD2Poseidon2BinaryConfig;

#[derive(Debug)]
pub enum AggregateError {
    Config(String),
    Empty,
    Recursion(String),
}

impl std::fmt::Display for AggregateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(s) => write!(f, "config: {s}"),
            Self::Empty => write!(f, "empty input"),
            Self::Recursion(s) => write!(f, "recursion: {s}"),
        }
    }
}

impl std::error::Error for AggregateError {}

// ── Helpers (copied from p3-recursion examples) ─────────────

/// Allocate the empty per-table public-input vectors expected by batch recursion.
fn batch_table_public_inputs<SC>(output: &RecursionOutput<SC>) -> Vec<Vec<Val<SC>>>
where
    SC: StarkGenericConfig,
{
    vec![vec![]; output.0.proof.opened_values.instances.len()]
}

/// Trusted source for `PreparedAggregation::new` (full authority).
fn batch_prepared_source<'a, SC>(
    output: &'a RecursionOutput<SC>,
    table_public_inputs: &'a [Vec<Val<SC>>],
) -> PreparedSource<'static, 'a, SC, BatchOnly>
where
    SC: StarkGenericConfig,
{
    PreparedSource::batch(&output.0, &output.0.stark_common, table_public_inputs)
}

/// Witness-only input for `owner.prove` (borrowed view).
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

// ── Descriptor ──────────────────────────────────────────────

fn build_descriptor() -> FriConfigV1 {
    FriConfigV1::new(
        SuiteIdV1::GoldilocksD2Poseidon2BinaryFri,
        2,   // log_blowup
        0,   // log_final_poly_len
        1,   // max_log_arity
        100, // num_queries
        0,   // commit_pow_bits
        16,  // query_pow_bits
        0,   // input_cap_height
        0,   // commit_cap_height
        0,   // num_random_codewords
        0,   // salt_elements
    )
}

fn build_config() -> Result<RecursionConfig, AggregateError> {
    let limits = VerifierLimits::default();
    goldilocks_d2_poseidon2_binary(&build_descriptor(), &limits)
        .map_err(|e| AggregateError::Config(format!("{e:?}")))
}

// ── Type-punning ────────────────────────────────────────────

fn proof_as_recursion(p: &Proof<DilithiumStarkConfig>) -> &Proof<RecursionConfig> {
    unsafe { &*(p as *const _ as *const Proof<RecursionConfig>) }
}

// ── 2-to-1 aggregation ──────────────────────────────────────

pub fn aggregate_pair<A>(
    left_proof: &Proof<DilithiumStarkConfig>,
    left_public: &[F],
    right_proof: &Proof<DilithiumStarkConfig>,
    right_public: &[F],
    air: &A,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError>
where
    A: RecursiveAir<F, EF, LogUpGadget>,
{
    let config = build_config()?;
    let backend = FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let params = ProveNextLayerParams::default();

    let left = RecursionInput::UniStark {
        proof: proof_as_recursion(left_proof),
        air,
        public_inputs: left_public.to_vec(),
        preprocessed_commit: None,
    };
    let right = RecursionInput::UniStark {
        proof: proof_as_recursion(right_proof),
        air,
        public_inputs: right_public.to_vec(),
        preprocessed_commit: None,
    };

    build_and_prove_aggregation_layer(&left, &right, &config, &backend, &params)
        .map_err(|e| AggregateError::Recursion(format!("{e:?}")))
}

// ── N-to-1 binary tree (with PreparedAggregation reuse) ─────

pub fn aggregate_batch<A>(
    proofs: Vec<Proof<DilithiumStarkConfig>>,
    publics: Vec<Vec<F>>,
    air: &A,
    threads: usize,
) -> Result<RecursionOutput<RecursionConfig>, AggregateError>
where
    A: RecursiveAir<F, EF, LogUpGadget> + Sync,
{
    // ── Validation ──────────────────────────────────────────
    if proofs.is_empty() {
        return Err(AggregateError::Empty);
    }
    if proofs.len() != publics.len() {
        return Err(AggregateError::Config(format!(
            "length mismatch: {} vs {}",
            proofs.len(),
            publics.len()
        )));
    }
    if proofs.len() < 2 || proofs.len() % 2 != 0 {
        return Err(AggregateError::Config(format!(
            "even count ≥ 2 required, got {}",
            proofs.len()
        )));
    }

    let config = build_config()?;
    let backend = FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let params = ProveNextLayerParams::default();

    // ── Mining-safe local pool ──────────────────────────────
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads.max(1))
        .thread_name(|i| format!("sahyadri-agg-{i}"))
        .build()
        .map_err(|e| AggregateError::Config(format!("rayon: {e}")))?;

    pool.install(|| {
        let n = proofs.len();

        // ── Layer 1: UniStark pairs via PreparedAggregation ────
        let pairs_l1 = n / 2;

        // First pair: build the level circuit once.
        let l1_owner = PreparedAggregation::new(
            PreparedSource::UniStark {
                air,
                proof: proof_as_recursion(&proofs[0]),
                public_inputs: &publics[0],
                preprocessed_commit: None,
            },
            PreparedSource::UniStark {
                air,
                proof: proof_as_recursion(&proofs[1]),
                public_inputs: &publics[1],
                preprocessed_commit: None,
            },
            config.clone(),
            backend.clone(),
            params.clone(),
        )
        .map_err(|e| AggregateError::Recursion(format!("layer 1 prepare: {e:?}")))?;

        // First pair via owner.
        let first_l1 = l1_owner
            .prove(
                PreparedInput::UniStark {
                    proof: proof_as_recursion(&proofs[0]),
                    public_inputs: &publics[0],
                    preprocessed_commit: None,
                },
                PreparedInput::UniStark {
                    proof: proof_as_recursion(&proofs[1]),
                    public_inputs: &publics[1],
                    preprocessed_commit: None,
                },
            )
            .map_err(|e| AggregateError::Recursion(format!("layer 1 pair 0: {e:?}")))?;

        // Remaining pairs — PARALLEL, shared circuit.
        let rest_l1: Vec<Result<RecursionOutput<RecursionConfig>, AggregateError>> =
            (1..pairs_l1)
                .into_par_iter()
                .map(|i| {
                    l1_owner
                        .prove(
                            PreparedInput::UniStark {
                                proof: proof_as_recursion(&proofs[i * 2]),
                                public_inputs: &publics[i * 2],
                                preprocessed_commit: None,
                            },
                            PreparedInput::UniStark {
                                proof: proof_as_recursion(&proofs[i * 2 + 1]),
                                public_inputs: &publics[i * 2 + 1],
                                preprocessed_commit: None,
                            },
                        )
                        .map_err(|e| {
                            AggregateError::Recursion(format!("layer 1 pair {i}: {e:?}"))
                        })
                })
                .collect();

        let mut current: Vec<RecursionOutput<RecursionConfig>> = Vec::with_capacity(pairs_l1);
        current.push(first_l1);
        current.extend(rest_l1.into_iter().collect::<Result<Vec<_>, _>>()?);

        // ── Layers 2+: PreparedAggregation (circuit reuse) ──
        let mut level: u32 = 1;
        while current.len() > 1 {
            level += 1;
            let pairs = current.len() / 2;

            // Build level owner from the FIRST pair (circuit build).
            let left0 = &current[0];
            let right0 = &current[1];
            let lt0 = batch_table_public_inputs(left0);
            let rt0 = batch_table_public_inputs(right0);

            let owner = PreparedAggregation::new(
                batch_prepared_source(left0, &lt0),
                batch_prepared_source(right0, &rt0),
                config.clone(),
                backend.clone(),
                params.clone(),
            )
            .map_err(|e| {
                AggregateError::Recursion(format!("layer {level} prepare: {e:?}"))
            })?;

            // First pair uses the owner directly.
            let li = batch_prepared_input(left0, &lt0);
            let ri = batch_prepared_input(right0, &rt0);
            let first = owner.prove(li, ri).map_err(|e| {
                AggregateError::Recursion(format!("layer {level} pair 0: {e:?}"))
            })?;

            // Remaining pairs — PARALLEL, shared circuit.
            let rest: Vec<Result<RecursionOutput<RecursionConfig>, AggregateError>> =
                (1..pairs)
                    .into_par_iter()
                    .map(|i| {
                        let left = &current[i * 2];
                        let right = &current[i * 2 + 1];
                        let lt = batch_table_public_inputs(left);
                        let rt = batch_table_public_inputs(right);
                        let li = batch_prepared_input(left, &lt);
                        let ri = batch_prepared_input(right, &rt);
                        owner.prove(li, ri).map_err(|e| {
                            AggregateError::Recursion(format!(
                                "layer {level} pair {i}: {e:?}"
                            ))
                        })
                    })
                    .collect();

            let mut next = Vec::with_capacity(pairs);
            next.push(first);
            next.extend(rest.into_iter().collect::<Result<Vec<_>, _>>()?);
            current = next;
        }

        current
            .into_iter()
            .next()
            .ok_or_else(|| AggregateError::Config("empty tree".into()))
    })
}

// ── Public-input derivation ─────────────────────────────────

pub fn derive_public_challenges(commitment_root: &[u8; 32]) -> (F, F, F) {
    let challenge = F::from_u64(u64::from_le_bytes(commitment_root[0..8].try_into().unwrap()));
    let alpha = F::from_u64(u64::from_le_bytes(commitment_root[8..16].try_into().unwrap()));
    let beta = F::from_u64(u64::from_le_bytes(commitment_root[16..24].try_into().unwrap()));
    (challenge, alpha, beta)
}

// ── Verify root proof ──────────────────────────────────────

/// Verify a root recursion proof against the builtin Goldilocks config.
///
/// Replicates the example-local `OutputTableConfigs` logic for
/// `Poseidon2Config::GOLDILOCKS_D2_W8` and calls `verify_all_tables`.
pub fn verify_root_proof(
    root: &RecursionOutput<RecursionConfig>,
) -> Result<(), AggregateError> {
    use p3_circuit_prover::BatchStarkProver;

    let config = build_config()?;
    let params = ProveNextLayerParams::default();
    let poseidon2 = Poseidon2Config::GOLDILOCKS_D2_W8;

    let mut verifier = BatchStarkProver::new(config).with_table_packing(params.table_packing);

    // Replicate `OutputTableConfigs::output_table_configs` for Poseidon2Config.
    let table_configs = if poseidon2.d() >= 2 && !poseidon2.is_arity4_shape() {
        vec![poseidon2.for_shared_challenger_table()]
    } else if poseidon2.d() >= 2 {
        vec![poseidon2.for_challenger(), poseidon2]
    } else {
        vec![poseidon2]
    };

    for table_config in table_configs {
        verifier.register_poseidon2_table::<2>(table_config);
    }
    verifier.register_recompose_table::<2>(true);

    verifier
        .verify_all_tables::<EF>(&root.0)
        .map_err(|e| AggregateError::Recursion(format!("verify_all_tables: {e:?}")))?;
    Ok(())
}

/// Verify a BatchStarkProof directly (used by ChainProofBlob).
pub fn verify_batch_stark_proof(
    proof: &p3_circuit_prover::BatchStarkProof<RecursionConfig>,
) -> Result<(), AggregateError> {
    use p3_circuit_prover::BatchStarkProver;

    let config = build_config()?;
    let params = ProveNextLayerParams::default();
    let poseidon2 = Poseidon2Config::GOLDILOCKS_D2_W8;

    let mut verifier = BatchStarkProver::new(config).with_table_packing(params.table_packing);

    let table_configs = if poseidon2.d() >= 2 && !poseidon2.is_arity4_shape() {
        vec![poseidon2.for_shared_challenger_table()]
    } else if poseidon2.d() >= 2 {
        vec![poseidon2.for_challenger(), poseidon2]
    } else {
        vec![poseidon2]
    };

    for table_config in table_configs {
        verifier.register_poseidon2_table::<2>(table_config);
    }
    verifier.register_recompose_table::<2>(true);

    verifier
        .verify_all_tables::<EF>(proof)
        .map_err(|e| AggregateError::Recursion(format!("verify_all_tables: {e:?}")))?;
    Ok(())
}
