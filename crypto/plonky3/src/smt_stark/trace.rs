// Trace generation for SMT STARK.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use sahyadri_smt::{hash_branch, hash_leaf, H256, Terminal};

use crate::config::F;
use crate::smt_stark::air::{
    ALPHA_U64, COL_CURRENT_HASH, COL_DIRECTION, COL_FOLD, COL_HASH,
    COL_IS_ABSENT, COL_IS_BRANCH, COL_IS_LEAF, COL_IS_PADDING, COL_KEY,
    COL_SIBLING_HASH, COL_VALUE, HASH_LIMBS, NUM_ROWS, NUM_TRACE_COLS,
    SMT_DEPTH,
};

pub struct SmtTraceInput {
    pub siblings: Vec<H256>,
    pub key: H256,
    pub value: H256,
    pub is_absent: bool,
}

impl SmtTraceInput {
    pub fn from_native(key: H256, proof: &sahyadri_smt::Proof) -> Self {
        match &proof.terminal {
            Terminal::Empty => Self {
                siblings: proof.siblings.clone(),
                key,
                value: [0u8; 32],
                is_absent: true,
            },
            Terminal::Leaf { value, .. } => Self {
                siblings: proof.siblings.clone(),
                key,
                value: *value,
                is_absent: false,
            },
        }
    }
}

pub fn h256_to_limbs(h: &H256) -> [F; HASH_LIMBS] {
    let mut out = [F::ZERO; HASH_LIMBS];
    for i in 0..HASH_LIMBS {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&h[i * 8..(i + 1) * 8]);
        out[i] = F::from_u64(u64::from_le_bytes(buf));
    }
    out
}

pub fn limbs_to_h256(limbs: &[F; HASH_LIMBS]) -> H256 {
    let mut out = [0u8; 32];
    for i in 0..HASH_LIMBS {
        let bytes = limbs[i].as_canonical_u64().to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

#[inline]
fn key_bit(key: &H256, i: usize) -> bool {
    (key[i / 8] >> (7 - (i % 8))) & 1 == 1
}

pub fn generate_smt_trace(input: &SmtTraceInput) -> RowMajorMatrix<F> {
    let num_siblings = input.siblings.len();
    assert!(
        num_siblings <= SMT_DEPTH,
        "siblings length {} exceeds SMT_DEPTH {}",
        num_siblings,
        SMT_DEPTH,
    );

    let mut data = vec![F::ZERO; NUM_ROWS * NUM_TRACE_COLS];

    // Row 0: leaf row
    let leaf_hash: H256 = if input.is_absent {
        [0u8; 32]
    } else {
        hash_leaf(&input.key, &input.value)
    };
    let leaf_limbs = h256_to_limbs(&leaf_hash);
    let key_limbs = h256_to_limbs(&input.key);
    let value_limbs = h256_to_limbs(&input.value);

    {
        let row = &mut data[0..NUM_TRACE_COLS];
        row[COL_IS_LEAF] = F::ONE;
        row[COL_IS_BRANCH] = F::ZERO;
        row[COL_IS_PADDING] = F::ZERO;
        row[COL_IS_ABSENT] = if input.is_absent { F::ONE } else { F::ZERO };
        row[COL_DIRECTION] = F::ZERO;

        for k in 0..HASH_LIMBS {
            row[COL_KEY + k] = key_limbs[k];
            row[COL_VALUE + k] = value_limbs[k];
            row[COL_HASH + k] = leaf_limbs[k];
        }
    }

    let mut current = leaf_limbs;

    // Rows 1..=num_siblings: branch rows
    for row_idx in 1..=num_siblings {
        let sib_idx = num_siblings - row_idx;
        let sib_h256 = input.siblings[sib_idx];
        let sib_limbs = h256_to_limbs(&sib_h256);
        let dir_bit = key_bit(&input.key, sib_idx);

        let (left, right) = if dir_bit {
            (sib_h256, limbs_to_h256(&current))
        } else {
            (limbs_to_h256(&current), sib_h256)
        };
        let new_hash = hash_branch(&left, &right);
        let new_limbs = h256_to_limbs(&new_hash);

        let off = row_idx * NUM_TRACE_COLS;
        let row = &mut data[off..off + NUM_TRACE_COLS];
        row[COL_IS_LEAF] = F::ZERO;
        row[COL_IS_BRANCH] = F::ONE;
        row[COL_IS_PADDING] = F::ZERO;
        row[COL_IS_ABSENT] = F::ZERO;
        row[COL_DIRECTION] = if dir_bit { F::ONE } else { F::ZERO };

        for k in 0..HASH_LIMBS {
            row[COL_CURRENT_HASH + k] = current[k];
            row[COL_SIBLING_HASH + k] = sib_limbs[k];
            row[COL_HASH + k] = new_limbs[k];
        }

        current = new_limbs;
    }

    // Rows num_siblings+1..NUM_ROWS: padding rows
    for row_idx in (num_siblings + 1)..NUM_ROWS {
        let off = row_idx * NUM_TRACE_COLS;
        let row = &mut data[off..off + NUM_TRACE_COLS];
        row[COL_IS_LEAF] = F::ZERO;
        row[COL_IS_BRANCH] = F::ZERO;
        row[COL_IS_PADDING] = F::ONE;
        row[COL_IS_ABSENT] = F::ZERO;
        row[COL_DIRECTION] = F::ZERO;

        for k in 0..HASH_LIMBS {
            row[COL_CURRENT_HASH + k] = current[k];
            row[COL_HASH + k] = current[k];
        }
    }

    // Compute algebraic fold of the hash column, skipping padding rows.
    let alpha = F::from_u64(ALPHA_U64);
    let mut fold = [F::ZERO; HASH_LIMBS];
    for row_idx in 0..NUM_ROWS {
        let off = row_idx * NUM_TRACE_COLS;
        let is_pad = data[off + COL_IS_PADDING] == F::ONE;
        for k in 0..HASH_LIMBS {
            let h = data[off + COL_HASH + k];
            fold[k] = if row_idx == 0 {
                h
            } else if is_pad {
                fold[k]
            } else {
                fold[k] * alpha + h
            };
            data[off + COL_FOLD + k] = fold[k];
        }
    }

    RowMajorMatrix::new(data, NUM_TRACE_COLS)
}
