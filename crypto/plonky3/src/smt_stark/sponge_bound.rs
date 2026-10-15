// Sponge-bound STARK for a single SMT hash.
//
// An SMT hash (leaf or branch) is a PaddingFreeSponge with rate 4 and
// 3 chunks of input. It corresponds to 3 consecutive Poseidon2 W8
// permutations with chunk absorption between them.
//
// P3's PaddingFreeSponge uses OVERWRITE absorption: the rate portion
// of the state is replaced by the chunk, not added to it. This matters
// for matching the native SMT hash exactly.
//
// Public inputs: the three 4-element chunks and the 4-element output.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Poseidon2Goldilocks;
use p3_symmetric::Permutation;
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

use crate::config::{SahyadriStarkConfig, F};
use crate::smt_stark::poseidon2_bound::{
    prove_single_bound, verify_single_bound, Poseidon2BoundProof,
};

const WIDTH: usize = 8;
const RATE: usize = 4;

/// Three 4-element absorb chunks.
pub type SpongeChunks = [[F; RATE]; 3];

/// A sponge-hash proof: three Poseidon2 bound sub-proofs plus the
/// absorbed chunks and the final 4-element output.
pub struct SpongeHashProof {
    pub perm_proofs: Vec<Poseidon2BoundProof>,
    pub chunks: SpongeChunks,
    pub output: [F; RATE],
}

/// Compute the sponge hash natively.
/// Matches PaddingFreeSponge<_, 8, 4, 4> with overwrite absorption.
pub fn native_sponge_hash(chunks: &SpongeChunks) -> [F; RATE] {
    let perm: Poseidon2Goldilocks<WIDTH> = {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Poseidon2Goldilocks::<WIDTH>::new_from_rng_128(&mut rng)
    };

    let mut state = [F::ZERO; WIDTH];
    for chunk in chunks.iter() {
        for k in 0..RATE {
            state[k] = chunk[k];
        }
        perm.permute_mut(&mut state);
    }

    [state[0], state[1], state[2], state[3]]
}

/// Prove a sponge hash.
pub fn prove_sponge_hash(
    config: &SahyadriStarkConfig,
    chunks: SpongeChunks,
) -> SpongeHashProof {
    let mut state = [F::ZERO; WIDTH];
    let mut perm_proofs: Vec<Poseidon2BoundProof> = Vec::with_capacity(3);

    for chunk in chunks.iter() {
        for k in 0..RATE {
            state[k] = chunk[k];
        }
        let proof = prove_single_bound(config, state);
        state = proof.output;
        perm_proofs.push(proof);
    }

    let output = [state[0], state[1], state[2], state[3]];

    SpongeHashProof { perm_proofs, chunks, output }
}

/// Verify a sponge hash proof.
pub fn verify_sponge_hash(
    config: &SahyadriStarkConfig,
    proof: &SpongeHashProof,
) -> Result<(), String> {
    if proof.perm_proofs.len() != 3 {
        return Err(format!(
            "expected 3 perm proofs, got {}",
            proof.perm_proofs.len()
        ));
    }

    // 1. Verify each sub-proof.
    for (i, pp) in proof.perm_proofs.iter().enumerate() {
        verify_single_bound(config, pp)
            .map_err(|e| format!("perm {} verify failed: {}", i, e))?;
    }

    // 2. Check initial absorb (chunk 0 overwrites state[0..RATE]).
    {
        let p0 = &proof.perm_proofs[0];
        for k in 0..RATE {
            if p0.input[k] != proof.chunks[0][k] {
                return Err(format!("perm 0 input[{}] mismatch chunks[0]", k));
            }
        }
        for k in RATE..WIDTH {
            if p0.input[k] != F::ZERO {
                return Err(format!("perm 0 input[{}] not zero", k));
            }
        }
    }

    // 3. Check chain between perm 0 and perm 1 (overwrite semantics).
    {
        let p0_out = &proof.perm_proofs[0].output;
        let p1 = &proof.perm_proofs[1];
        for k in 0..RATE {
            if p1.input[k] != proof.chunks[1][k] {
                return Err(format!("perm 1 input[{}] chain mismatch", k));
            }
        }
        for k in RATE..WIDTH {
            if p1.input[k] != p0_out[k] {
                return Err(format!("perm 1 input[{}] passthrough mismatch", k));
            }
        }
    }

    // 4. Check chain between perm 1 and perm 2 (overwrite semantics).
    {
        let p1_out = &proof.perm_proofs[1].output;
        let p2 = &proof.perm_proofs[2];
        for k in 0..RATE {
            if p2.input[k] != proof.chunks[2][k] {
                return Err(format!("perm 2 input[{}] chain mismatch", k));
            }
        }
        for k in RATE..WIDTH {
            if p2.input[k] != p1_out[k] {
                return Err(format!("perm 2 input[{}] passthrough mismatch", k));
            }
        }
    }

    // 5. Check final output.
    {
        let p2_out = &proof.perm_proofs[2].output;
        for k in 0..RATE {
            if p2_out[k] != proof.output[k] {
                return Err(format!("final output[{}] mismatch", k));
            }
        }
    }

    Ok(())
}

/// Build the leaf-hash chunks for a given key and value.
pub fn leaf_chunks(key: &[u8; 32], value: &[u8; 32]) -> SpongeChunks {
    let domain = domain_from_str(b"SAHYADRI_SMT_LEAF_V1");
    let key_f = bytes_to_goldilocks(key);
    let value_f = bytes_to_goldilocks(value);
    [domain, key_f, value_f]
}

/// Build the branch-hash chunks for left and right child hashes.
pub fn branch_chunks(left: &[u8; 32], right: &[u8; 32]) -> SpongeChunks {
    let domain = domain_from_str(b"SAHYADRI_SMT_BRANCH_V1");
    let left_f = bytes_to_goldilocks(left);
    let right_f = bytes_to_goldilocks(right);
    [domain, left_f, right_f]
}

/// Convert bytes into 4 Goldilocks limbs, LE per 8 bytes.
fn bytes_to_goldilocks(bytes: &[u8; 32]) -> [F; 4] {
    let mut out = [F::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = F::from_u64(u64::from_le_bytes(buf));
    }
    out
}

/// Build a domain separator from an ASCII string, padded to 32 bytes.
fn domain_from_str(s: &[u8]) -> [F; 4] {
    let mut padded = [0u8; 32];
    let n = s.len().min(32);
    padded[..n].copy_from_slice(&s[..n]);
    bytes_to_goldilocks(&padded)
}
