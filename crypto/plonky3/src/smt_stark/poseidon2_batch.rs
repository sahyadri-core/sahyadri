// Standalone Poseidon2 batch STARK.
//
// Proves that a sequence of Poseidon2 W8 permutations was correctly
// evaluated. Uses the same Goldilocks round constants as the native
// Poseidon2Goldilocks<8> permutation seeded with Xoshiro256PlusPlus(1).

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::poseidon1::GOLDILOCKS_S_BOX_DEGREE;
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, RoundConstants};
use p3_uni_stark::{prove, verify, Proof};
use rand::rngs::Xoshiro256PlusPlus;
use rand::{RngExt, SeedableRng};

use crate::config::{SahyadriStarkConfig, F};

const WIDTH: usize = 8;
const SBOX_DEGREE: u64 = GOLDILOCKS_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8;

/// The Poseidon2 W8 AIR type.
pub type Poseidon2W8Air = Poseidon2Air<
    F,
    GenericPoseidon2LinearLayersGoldilocks,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Build round constants with the same rng order as
/// Poseidon2Goldilocks::new_from_rng_128, so the AIR is bit-for-bit
/// compatible with the native permutation.
///
/// Native order: external (initial then terminal) first, then internal.
/// RoundConstants::from_rng uses a different order, so we cannot use it.
pub fn build_round_constants(
) -> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);

    // Step 1: external constants (half initial, half terminal).
    // Total external rounds = 2 * HALF_FULL_ROUNDS.
    let external = ExternalLayerConstants::<F, WIDTH>::new_from_rng(
        HALF_FULL_ROUNDS * 2,
        &mut rng,
    );

    // Step 2: internal (partial) constants.
    let mut internal: Vec<F> = Vec::with_capacity(PARTIAL_ROUNDS);
    for _ in 0..PARTIAL_ROUNDS {
        internal.push(rng.random());
    }

    // Convert into AIR-friendly RoundConstants.
    RoundConstants::try_from_layers(&external, &internal)
        .expect("Poseidon2 round constants shape mismatch")
}

/// Build the Poseidon2 AIR with deterministic constants.
pub fn build_poseidon2_air() -> Poseidon2W8Air {
    Poseidon2Air::new(build_round_constants())
}

/// A Poseidon2 batch proof.
pub struct Poseidon2BatchProof {
    pub proof: Proof<SahyadriStarkConfig>,
    pub num_permutations: usize,
}

/// Prove a batch of Poseidon2 permutations.
///
/// Inputs are padded to the next power of two with zero states.
/// If the input is empty, panics.
pub fn prove_poseidon2_batch(
    config: &SahyadriStarkConfig,
    mut inputs: Vec<[F; WIDTH]>,
) -> Poseidon2BatchProof {
    assert!(!inputs.is_empty(), "inputs must not be empty");

    // Pad to next power of two (minimum 2) for FRI.
    let target_len = inputs.len().next_power_of_two().max(2);
    let dummy = [F::ZERO; WIDTH];
    while inputs.len() < target_len {
        inputs.push(dummy);
    }

    let constants = build_round_constants();
    let air: Poseidon2W8Air = Poseidon2Air::new(constants.clone());

    let trace: RowMajorMatrix<F> = generate_trace_rows::<
        F,
        GenericPoseidon2LinearLayersGoldilocks,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs.clone(), &constants, 0);

    let proof = prove(config, &air, trace, &[])
        .expect("Poseidon2 batch proving failed");

    Poseidon2BatchProof {
        proof,
        num_permutations: inputs.len(),
    }
}

/// Verify a Poseidon2 batch proof.
pub fn verify_poseidon2_batch(
    config: &SahyadriStarkConfig,
    proof: &Poseidon2BatchProof,
) -> Result<(), String> {
    let air = build_poseidon2_air();
    verify(config, &air, &proof.proof, &[])
        .map_err(|e| format!("Poseidon2 batch verification failed: {:?}", e))
}
