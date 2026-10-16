// SMT AIR for STARK state proofs.
// Structural constraints for a 256-level sparse Merkle tree.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

use crate::config::F;

pub const HASH_LIMBS: usize = 4;
pub const SMT_DEPTH: usize = 256;
pub const NUM_ROWS: usize = 512;
pub const NUM_PUBLIC_VALUES: usize = HASH_LIMBS * 4 + 1;

/// Algebraic fold challenge constant. Must match between prover and verifier.
pub const ALPHA_U64: u64 = 0x0053_4148_5941_4452;

pub const COL_IS_LEAF: usize = 0;
pub const COL_IS_BRANCH: usize = 1;
pub const COL_IS_PADDING: usize = 2;
pub const COL_IS_ABSENT: usize = 3;
pub const COL_DIRECTION: usize = 4;

pub const COL_CURRENT_HASH: usize = 5;
pub const COL_SIBLING_HASH: usize = 9;
pub const COL_KEY: usize = 13;
pub const COL_VALUE: usize = 17;
pub const COL_HASH: usize = 21;
pub const COL_FOLD: usize = 25;

pub const NUM_TRACE_COLS: usize = 29;

#[derive(Clone, Copy, Debug)]
pub struct SmtAir;

impl BaseAir<F> for SmtAir {
    fn width(&self) -> usize {
        NUM_TRACE_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB> Air<AB> for SmtAir
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let is_leaf = local[COL_IS_LEAF].clone();
        let is_branch = local[COL_IS_BRANCH].clone();
        let is_padding = local[COL_IS_PADDING].clone();
        let is_absent = local[COL_IS_ABSENT].clone();

        // C1: booleans
        builder.assert_bool(is_leaf.clone());
        builder.assert_bool(is_branch.clone());
        builder.assert_bool(is_padding.clone());
        builder.assert_bool(is_absent.clone());
        builder.assert_bool(local[COL_DIRECTION].clone());

        // C2: exactly one of leaf/branch/padding
        builder.assert_eq(
            is_leaf.clone() + is_branch.clone() + is_padding.clone(),
            AB::Expr::ONE,
        );

        // C3: absent only on leaf
        builder.assert_zero(is_absent.clone() * is_branch.clone());
        builder.assert_zero(is_absent.clone() * is_padding.clone());

        // C4: padding is identity on hash
        for k in 0..HASH_LIMBS {
            let diff = local[COL_HASH + k].clone() - local[COL_CURRENT_HASH + k].clone();
            builder.assert_zero(is_padding.clone() * diff);
        }

        // C5: chain linkage
        for k in 0..HASH_LIMBS {
            let next_cur = next[COL_CURRENT_HASH + k].clone();
            let local_h = local[COL_HASH + k].clone();
            builder.when_transition().assert_eq(next_cur, local_h);
        }

        // Extract public values into owned expressions.
        let mut pv_exprs: Vec<AB::Expr> = Vec::with_capacity(NUM_PUBLIC_VALUES);
        for i in 0..NUM_PUBLIC_VALUES {
            pv_exprs.push(builder.public_values()[i].into());
        }

        // C6: last row hash = public root
        for k in 0..HASH_LIMBS {
            builder.when_last_row().assert_eq(
                local[COL_HASH + k].clone(),
                pv_exprs[k].clone(),
            );
        }

        // C7: first row key = public key
        for k in 0..HASH_LIMBS {
            builder.when_first_row().assert_eq(
                local[COL_KEY + k].clone(),
                pv_exprs[HASH_LIMBS + k].clone(),
            );
        }

        // C8: first row value = public value
        for k in 0..HASH_LIMBS {
            builder.when_first_row().assert_eq(
                local[COL_VALUE + k].clone(),
                pv_exprs[HASH_LIMBS * 2 + k].clone(),
            );
        }

        // C9: first row absent flag = public flag
        builder.when_first_row().assert_eq(
            is_absent.clone(),
            pv_exprs[HASH_LIMBS * 3].clone(),
        );

        // C10: first row is leaf
        builder.when_first_row().assert_eq(is_leaf.clone(), AB::Expr::ONE);
        builder.when_first_row().assert_zero(is_branch.clone());
        builder.when_first_row().assert_zero(is_padding.clone());

        // C11: Algebraic fold of the hash column.
        // fold[0] = hash[0]
        // fold[i+1] = fold[i] * alpha + hash[i+1]
        let alpha = AB::F::from_u64(ALPHA_U64);

        for k in 0..HASH_LIMBS {
            // C11a: first row
            builder.when_first_row().assert_eq(
                local[COL_FOLD + k].clone(),
                local[COL_HASH + k].clone(),
            );

            // C11b: transition — accumulate only when next row is not padding.
            let is_pad_next: AB::Expr = next[COL_IS_PADDING].clone().into();
            let active: AB::Expr = AB::Expr::ONE - is_pad_next.clone();
            let fold_next = next[COL_FOLD + k].clone();
            let fold_cur = local[COL_FOLD + k].clone();
            let hash_next = next[COL_HASH + k].clone();
            let step = fold_cur.clone() * alpha + hash_next;
            builder
                .when_transition()
                .assert_eq(fold_next, is_pad_next * fold_cur + active * step);

            // C11c: last row binds to public hash_fold
            builder.when_last_row().assert_eq(
                local[COL_FOLD + k].clone(),
                pv_exprs[HASH_LIMBS * 3 + 1 + k].clone(),
            );
        }
    }
}
