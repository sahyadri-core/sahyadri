// Poseidon2 single-permutation bound STARK.
//
// Proves that a specific input state, after one Poseidon2 W8 permutation,
// yields a specific output state. The AIR enforces both the permutation
// correctness (via Poseidon2Air) and the input/output binding (via
// boundary constraints on the first row).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::poseidon1::GOLDILOCKS_S_BOX_DEGREE;
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Poseidon2Goldilocks,
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air};
use p3_symmetric::Permutation;
use p3_uni_stark::{prove, verify, Proof};
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

use crate::config::{SahyadriStarkConfig, F};
use crate::smt_stark::poseidon2_batch::{build_round_constants, Poseidon2W8Air};

const WIDTH: usize = 8;
const SBOX_DEGREE: u64 = GOLDILOCKS_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8;

// Offset of the final post-state within the Poseidon2Cols layout.
//
// Column layout of Poseidon2Cols with SBOX_REGISTERS = 0:
//   inputs                : WIDTH
//   beginning_full_rounds : HALF_FULL_ROUNDS * WIDTH
//   partial_rounds        : PARTIAL_ROUNDS * 1
//   ending_full_rounds    : HALF_FULL_ROUNDS * WIDTH
const FINAL_POST_OFFSET: usize = WIDTH
    + HALF_FULL_ROUNDS * WIDTH
    + PARTIAL_ROUNDS
    + (HALF_FULL_ROUNDS - 1) * WIDTH;

/// Poseidon2 AIR with input and output exposed as public values.
pub struct Poseidon2BoundAir {
    inner: Poseidon2W8Air,
}

impl Poseidon2BoundAir {
    pub fn new() -> Self {
        let constants = build_round_constants();
        Self {
            inner: Poseidon2Air::new(constants),
        }
    }
}

impl Default for Poseidon2BoundAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<F> for Poseidon2BoundAir {
    fn width(&self) -> usize {
        <Poseidon2W8Air as BaseAir<F>>::width(&self.inner)
    }

    fn num_public_values(&self) -> usize {
        WIDTH * 2
    }
}

impl<AB> Air<AB> for Poseidon2BoundAir
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        // Enforce Poseidon2 permutation correctness on every row.
        <Poseidon2W8Air as Air<AB>>::eval(&self.inner, builder);

        // Read the current row.
        let main = builder.main();
        let local = main.current_slice();

        // Extract public values into owned expressions so the immutable
        // borrow on builder is released before calling when_first_row.
        let mut pv_exprs: Vec<AB::Expr> = Vec::with_capacity(WIDTH * 2);
        for i in 0..(WIDTH * 2) {
            pv_exprs.push(builder.public_values()[i].into());
        }

        // Bind the first row's inputs to the public input.
        for k in 0..WIDTH {
            let row_input = local[k].clone();
            let pub_input = pv_exprs[k].clone();
            builder.when_first_row().assert_eq(row_input, pub_input);
        }

        // Bind the first row's final post-state to the public output.
        for k in 0..WIDTH {
            let row_output = local[FINAL_POST_OFFSET + k].clone();
            let pub_output = pv_exprs[WIDTH + k].clone();
            builder.when_first_row().assert_eq(row_output, pub_output);
        }
    }
}

/// A bound single-permutation proof.
pub struct Poseidon2BoundProof {
    pub proof: Proof<SahyadriStarkConfig>,
    pub input: [F; WIDTH],
    pub output: [F; WIDTH],
}

/// Compute the native Poseidon2 permutation output for a given input.
fn native_permute(input: [F; WIDTH]) -> [F; WIDTH] {
    let perm: Poseidon2Goldilocks<WIDTH> = {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Poseidon2Goldilocks::<WIDTH>::new_from_rng_128(&mut rng)
    };
    let mut state = input;
    perm.permute_mut(&mut state);
    state
}

/// Prove that one Poseidon2 permutation maps input to output.
pub fn prove_single_bound(
    config: &SahyadriStarkConfig,
    input: [F; WIDTH],
) -> Poseidon2BoundProof {
    let output = native_permute(input);

    // Build padded inputs (minimum 2 rows for FRI).
    let inputs = vec![input, [F::ZERO; WIDTH]];

    let constants = build_round_constants();
    let trace: RowMajorMatrix<F> = generate_trace_rows::<
        F,
        GenericPoseidon2LinearLayersGoldilocks,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants, 0);

    let mut public: Vec<F> = Vec::with_capacity(WIDTH * 2);
    public.extend_from_slice(&input);
    public.extend_from_slice(&output);

    let air = Poseidon2BoundAir::new();
    let proof = prove(config, &air, trace, &public)
        .expect("Poseidon2 single-bound proving failed");

    Poseidon2BoundProof { proof, input, output }
}

/// Verify a bound single-permutation proof.
pub fn verify_single_bound(
    config: &SahyadriStarkConfig,
    proof: &Poseidon2BoundProof,
) -> Result<(), String> {
    let mut public: Vec<F> = Vec::with_capacity(WIDTH * 2);
    public.extend_from_slice(&proof.input);
    public.extend_from_slice(&proof.output);

    let air = Poseidon2BoundAir::new();
    verify(config, &air, &proof.proof, &public)
        .map_err(|e| format!("Poseidon2 bound verification failed: {:?}", e))
}
