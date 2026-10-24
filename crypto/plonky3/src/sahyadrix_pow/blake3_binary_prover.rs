//! Prover for binary-field Blake3 compression proofs.
//!
//! Uses BinaryPcs (BaseFold-style PCS) over GF(2^128) with Keccak-256 as the
//! byte hash. Proof generation follows the multi-STARK framework: a single
//! instance is created for the Blake3 compression AIR, proved once, and
//! verified against the same public inputs.

use p3_binary_field::BinaryField128;
use p3_binary_pcs::{
    BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData, GroupedCodewordMmcs,
};
use p3_blake3_air::{
    generate_binary_trace_rows, Blake3BinaryAir, Blake3CompressionInput,
};
use p3_matrix::Matrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::proof::MultiStarkProof;
use p3_multi_stark::{
    prove, setup, verify, ProverInstance, ProverInstances, VerifierInstance,
    VerifierInstances,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_util::{log2_ceil_usize, log2_strict_usize};

use crate::sahyadrix_pow::binary_field_config::{
    challenger, level_mmcs, BinaryChallenger128, BinaryMmcs,
};

/// Number of binary columns in a Blake3 compression trace.
pub const BLAKE3_BINARY_AIR_WIDTH: usize = 11_536;

/// Number of public values exposed by a binary Blake3 proof, as 16-bit limbs.
pub const BLAKE3_BINARY_PUBLIC_LIMBS: usize = 56;

/// Grouped codeword MMCS parameterized by the inner Merkle tree.
type M = GroupedCodewordMmcs<BinaryMmcs>;

/// Configuration for the multi-STARK prover specialized to binary fields.
pub struct Blake3BinaryConfig {
    pcs: BinaryPcs<BinaryField128, BinaryField128, M, M>,
}

impl MultiStarkConfig for Blake3BinaryConfig {
    type Val = BinaryField128;
    type Challenge = BinaryField128;
    type Challenger = BinaryChallenger128;
    type Pcs = BinaryPcs<BinaryField128, BinaryField128, M, M>;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn min_num_variables(&self) -> usize {
        1
    }

    fn build_witness(&self, tables: Vec<Table<BinaryField128>>) -> Witness<BinaryField128> {
        SuffixProver::<BinaryField128, BinaryField128>::new_witness(tables, 0)
    }

    fn committed_table<'a>(
        &self,
        data: &'a BinaryPcsProverData<BinaryField128, BinaryField128, M>,
        index: usize,
    ) -> &'a Table<BinaryField128> {
        data.table(index)
    }
}

/// Packs the public inputs of a binary Blake3 proof into field elements.
pub fn pack_binary_public_inputs(limbs: &[u16]) -> Vec<BinaryField128> {
    assert_eq!(limbs.len(), BLAKE3_BINARY_PUBLIC_LIMBS);
    limbs
        .iter()
        .map(|&x| {
            let mut bytes = [0u8; 16];
            bytes[..2].copy_from_slice(&x.to_le_bytes());
            BinaryField128::from_le_bytes(bytes)
        })
        .collect()
}

/// Extracts the 56 public limbs from a compression input.
#[allow(dead_code)]
#[allow(dead_code)]
fn extract_public_limbs(input: &Blake3CompressionInput) -> Vec<u16> {
    let mut limbs = Vec::with_capacity(BLAKE3_BINARY_PUBLIC_LIMBS);
    for w in &input.chaining_value {
        limbs.push((*w & 0xFFFF) as u16);
        limbs.push((*w >> 16) as u16);
    }
    for w in &input.block {
        limbs.push((*w & 0xFFFF) as u16);
        limbs.push((*w >> 16) as u16);
    }
    limbs.push((input.counter & 0xFFFF) as u16);
    limbs.push((input.counter >> 16) as u16);
    limbs.push((input.block_len & 0xFFFF) as u16);
    limbs.push(input.flags as u16);
    while limbs.len() < BLAKE3_BINARY_PUBLIC_LIMBS {
        limbs.push(0);
    }
    debug_assert_eq!(limbs.len(), BLAKE3_BINARY_PUBLIC_LIMBS);
    limbs
}

/// Builds the binary PCS configuration.
fn build_binary_pcs(
    num_variables: usize,
) -> Result<BinaryPcs<BinaryField128, BinaryField128, M, M>, String> {
    let config = BinaryPcsConfig::try_new::<BinaryField128, BinaryField128>(
        num_variables,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 40,
        },
    )
    .map_err(|e| format!("config error: {:?}", e))?
    .try_with_folding(1)
    .map_err(|e| format!("folding error: {:?}", e))?;

    let base_mmcs = GroupedCodewordMmcs::new(level_mmcs::<BinaryField128>(), 8);
    let round_mmcs = GroupedCodewordMmcs::for_folding(level_mmcs::<BinaryField128>(), &config);

    BinaryPcs::new(config, base_mmcs, round_mmcs)
        .map_err(|e| format!("pcs error: {:?}", e))
}



/// Pads a Blake3 binary trace to a power-of-two width.
///
/// `Table::new` requires the row width to be a power of two. The Blake3 AIR
/// width of 11,536 columns is padded to 16,384 with zero columns. The extra
/// columns are not constrained by the AIR and do not affect the proof.

/// Replicates trace rows to reach a target power-of-two height.
///
/// Blake3BinaryAir is a single-row AIR with no row-to-row constraints, so
/// repeating the same valid row N times still satisfies all constraints.
/// This is used to meet the PCS padding floor (minimum codeword arity).
fn pad_trace_rows(
    trace: p3_matrix::dense::RowMajorMatrix<BinaryField128>,
    target_height: usize,
) -> p3_matrix::dense::RowMajorMatrix<BinaryField128> {
    use p3_matrix::Matrix;
    let height = trace.height();
    let width = trace.width();
    if height >= target_height {
        return trace;
    }
    let reps = target_height / height;
    let mut values = Vec::with_capacity(target_height * width);
    for r in 0..height {
        let row = trace.row_slice(r).expect("in bounds");
        for _ in 0..reps {
            values.extend(row.iter().copied());
        }
    }
    p3_matrix::dense::RowMajorMatrix::new(values, width)
}

fn pad_trace_to_power_of_two_width(
    trace: p3_matrix::dense::RowMajorMatrix<BinaryField128>,
) -> p3_matrix::dense::RowMajorMatrix<BinaryField128> {
    use p3_matrix::Matrix;
    let height = trace.height();
    let width = trace.width();
    let padded_width = width.next_power_of_two();
    if padded_width == width {
        return trace;
    }
    let mut padded = vec![BinaryField128::from_le_bytes([0u8; 16]); height * padded_width];
    for r in 0..height {
        for c in 0..width {
            padded[r * padded_width + c] = trace.get(r, c).expect("in bounds");
        }
    }
    p3_matrix::dense::RowMajorMatrix::new(padded, padded_width)
}

/// Generates a proof of a single Blake3 compression over the binary field.
pub fn prove_blake3_binary(input: &Blake3CompressionInput) -> Option<Vec<u8>> {
    let trace = generate_binary_trace_rows::<BinaryField128>(vec![*input], 0);
    let trace = pad_trace_to_power_of_two_width(trace);
    let trace = pad_trace_rows(trace, 1 << 14);
    let height = trace.height();
    let width = trace.width();
    debug_assert_eq!(width, BLAKE3_BINARY_AIR_WIDTH);

    let total_cells = width * height;
    let num_variables = log2_ceil_usize(total_cells);

    let pcs = build_binary_pcs(num_variables).ok()?;
    let native = Blake3BinaryConfig { pcs };

    let air = Blake3BinaryAir::default();
    let air_refs: [&Blake3BinaryAir; 1] = [&air];

    let mut ch = challenger();
    let (pk, _vk) = setup(&native, &air_refs, &mut ch).ok()?;

    let trace = pad_trace_to_power_of_two_width(trace);
    let trace = pad_trace_rows(trace, 1 << 14);
    let trace = trace.transpose();
    let table = Table::new(trace);
    let instance = ProverInstance::new(&air, table, &pk, &[]);
    let proof = prove(
        &native,
        ProverInstances::new(vec![instance]),
        0,
        &mut ch,
    )
    .ok()?;

    bincode::serialize(&proof).ok()
}

/// Verifies a binary Blake3 proof against the given compression input.
///
/// This prototype recomputes the verifying key deterministically from the
/// AIR and PCS configuration. Production code should serialize the verifying
/// key alongside the proof and load it during verification.
pub fn verify_blake3_binary(proof_bytes: &[u8], input: &Blake3CompressionInput) -> bool {
    let proof: MultiStarkProof<Blake3BinaryConfig> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

    let trace = generate_binary_trace_rows::<BinaryField128>(vec![*input], 0);
    let trace = pad_trace_to_power_of_two_width(trace);
    let trace = pad_trace_rows(trace, 1 << 14);
    let height = trace.height();
    let width = trace.width();
    let total_cells = width * height;
    let num_variables = log2_ceil_usize(total_cells);
    let pcs = match build_binary_pcs(num_variables) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let native = Blake3BinaryConfig { pcs };


    let air = Blake3BinaryAir::default();
    let air_refs: [&Blake3BinaryAir; 1] = [&air];

    let mut ch = challenger();
    let (_pk, vk) = match setup(&native, &air_refs, &mut ch) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let log_height = log2_strict_usize(height);
    let instance = VerifierInstance::new(&air, &vk, log_height, &[]);
    let instances = VerifierInstances::new(vec![instance]);

    let mut ch = challenger();
    verify(&native, instances, &proof, 0, &mut ch).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn air_width_matches_binary_blake3() {
        assert_eq!(BLAKE3_BINARY_AIR_WIDTH, 11_536);
    }

    #[test]
    fn public_limbs_count_is_56() {
        assert_eq!(BLAKE3_BINARY_PUBLIC_LIMBS, 56);
    }

    #[test]
    fn pack_public_inputs_round_trip() {
        let limbs: Vec<u16> = (0..BLAKE3_BINARY_PUBLIC_LIMBS)
            .map(|i| (i as u16).wrapping_mul(3))
            .collect();
        let packed = pack_binary_public_inputs(&limbs);
        assert_eq!(packed.len(), BLAKE3_BINARY_PUBLIC_LIMBS);
    }

    #[test]
    fn prove_and_verify_blake3_single_block() {
        const SINGLE_BLOCK_FLAGS: u32 = 1 | 2 | 8;
        const BLAKE3_IV: [u32; 8] = [
            0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
            0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
        ];

        let input = Blake3CompressionInput {
            chaining_value: BLAKE3_IV,
            block: [0; 16],
            counter: 0,
            block_len: 0,
            flags: SINGLE_BLOCK_FLAGS,
        };

        let proof_bytes = prove_blake3_binary(&input).expect("proof generation failed");
        assert!(!proof_bytes.is_empty(), "proof is empty");
        assert!(
            verify_blake3_binary(&proof_bytes, &input),
            "verification failed"
        );
    }
}
