//! Binary serialization for FRI proofs.
//!
//! Length-prefixed little-endian, no serde. The same encoding is
//! decodeable by both the prover and future on-chain decoders.

use crate::bytes::{block_from_bytes, Block128Bytes};
use crate::error::FriBiniusError;
use crate::fri::{FriProof, FriQueryProof, FriRoundCommitment};
use crate::merkle::Block128;

pub fn proof_to_bytes(p: &FriProof) -> Vec<u8> {
    let est = 8
        + 20 * p.rounds.len()
        + 4
        + 16 * p.final_poly.len()
        + 4
        + p.queries.iter().map(|q| 20 + 32 * q.pairs.len() + 4 * q.paths.len()).sum::<usize>();

    let mut out = Vec::with_capacity(est);

    out.extend_from_slice(&(p.rounds.len() as u32).to_le_bytes());
    for r in &p.rounds {
        out.extend_from_slice(&r.root.blk_to_le_bytes());
        out.extend_from_slice(&(r.log_len as u32).to_le_bytes());
    }

    out.extend_from_slice(&(p.final_poly.len() as u32).to_le_bytes());
    for v in &p.final_poly {
        out.extend_from_slice(&v.blk_to_le_bytes());
    }

    out.extend_from_slice(&(p.queries.len() as u32).to_le_bytes());
    for q in &p.queries {
        out.extend_from_slice(&(q.index_0 as u64).to_le_bytes());
        out.extend_from_slice(&(q.pairs.len() as u32).to_le_bytes());
        for pair in &q.pairs {
            out.extend_from_slice(&pair[0].blk_to_le_bytes());
            out.extend_from_slice(&pair[1].blk_to_le_bytes());
        }
        out.extend_from_slice(&(q.paths.len() as u32).to_le_bytes());
        for path in &q.paths {
            out.extend_from_slice(&(path.len() as u32).to_le_bytes());
            for v in path {
                out.extend_from_slice(&v.blk_to_le_bytes());
            }
        }
    }

    out.extend_from_slice(&p.pow_nonce.to_le_bytes());
    out
}

fn take<'a>(c: &mut &'a [u8], n: usize) -> Result<&'a [u8], FriBiniusError> {
    if c.len() < n {
        return Err(FriBiniusError::MalformedProof(format!(
            "truncated: want {n}, have {}",
            c.len()
        )));
    }
    let (head, tail) = c.split_at(n);
    *c = tail;
    Ok(head)
}

pub fn proof_from_bytes(bytes: &[u8]) -> Result<FriProof, FriBiniusError> {
    let mut cur = bytes;

    let read_u32 = |c: &mut &[u8]| -> Result<u32, FriBiniusError> {
        let s = take(c, 4)?;
        Ok(u32::from_le_bytes(s.try_into().unwrap()))
    };
    let read_u64 = |c: &mut &[u8]| -> Result<u64, FriBiniusError> {
        let s = take(c, 8)?;
        Ok(u64::from_le_bytes(s.try_into().unwrap()))
    };
    let read_block = |c: &mut &[u8]| -> Result<Block128, FriBiniusError> {
        let s = take(c, 16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(block_from_bytes(a))
    };

    let nr = read_u32(&mut cur)? as usize;
    let mut rounds = Vec::with_capacity(nr);
    for _ in 0..nr {
        let root = read_block(&mut cur)?;
        let log_len = read_u32(&mut cur)? as usize;
        rounds.push(FriRoundCommitment { root, log_len });
    }

    let nf = read_u32(&mut cur)? as usize;
    let mut final_poly = Vec::with_capacity(nf);
    for _ in 0..nf {
        final_poly.push(read_block(&mut cur)?);
    }

    let nq = read_u32(&mut cur)? as usize;
    let mut queries = Vec::with_capacity(nq);
    for _ in 0..nq {
        let index_0 = read_u64(&mut cur)? as usize;
        let np = read_u32(&mut cur)? as usize;
        let mut pairs = Vec::with_capacity(np);
        for _ in 0..np {
            let a = read_block(&mut cur)?;
            let b = read_block(&mut cur)?;
            pairs.push([a, b]);
        }
        let npaths = read_u32(&mut cur)? as usize;
        let mut paths = Vec::with_capacity(npaths);
        for _ in 0..npaths {
            let plen = read_u32(&mut cur)? as usize;
            let mut path = Vec::with_capacity(plen);
            for _ in 0..plen {
                path.push(read_block(&mut cur)?);
            }
            paths.push(path);
        }
        queries.push(FriQueryProof { index_0, pairs, paths });
    }

    let pow_nonce = read_u64(&mut cur)?;

    if !cur.is_empty() {
        return Err(FriBiniusError::MalformedProof(format!(
            "{} trailing bytes",
            cur.len()
        )));
    }

    Ok(FriProof { rounds, final_poly, queries, pow_nonce })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::{FriParams, FriProver, FriVerifier};

    fn block(n: u128) -> Block128 {
        Block128::from_le_bytes(n.to_le_bytes())
    }

    fn small_params() -> FriParams {
        FriParams { log_inv_rate: 2, num_queries: 8, pow_bits: 0 }
    }

    #[test]
    fn serialize_round_trip() {
        let params = small_params();
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let evs: Vec<_> = (0..32u128).map(block).collect();
        let seed = b"ser-test";
        let proof = prover.prove(evs, seed).unwrap();
        let bytes = proof_to_bytes(&proof);
        let restored = proof_from_bytes(&bytes).unwrap();

        assert_eq!(restored.rounds.len(), proof.rounds.len());
        assert_eq!(restored.final_poly.len(), proof.final_poly.len());
        assert_eq!(restored.queries.len(), proof.queries.len());
        assert_eq!(restored.pow_nonce, proof.pow_nonce);

        let c0 = restored.rounds[0].root;
        verifier.verify(c0, &restored, seed).unwrap();
    }

    #[test]
    fn serialized_bytes_reject_tampering() {
        let params = small_params();
        let prover = FriProver::new(params.clone());
        let verifier = FriVerifier::new(params);
        let evs: Vec<_> = (0..32u128).map(block).collect();
        let seed = b"tamper-test";
        let proof = prover.prove(evs, seed).unwrap();
        let mut bytes = proof_to_bytes(&proof);
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let restored = proof_from_bytes(&bytes).unwrap();
        let c0 = proof.rounds[0].root;
        assert!(verifier.verify(c0, &restored, seed).is_err());
    }

    #[test]
    fn truncated_rejected() {
        let params = small_params();
        let prover = FriProver::new(params);
        let evs: Vec<_> = (0..16u128).map(block).collect();
        let seed = b"trunc-test";
        let proof = prover.prove(evs, seed).unwrap();
        let bytes = proof_to_bytes(&proof);
        for cut in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
            assert!(proof_from_bytes(&bytes[..cut]).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let params = small_params();
        let prover = FriProver::new(params);
        let evs: Vec<_> = (0..16u128).map(block).collect();
        let proof = prover.prove(evs, b"x").unwrap();
        let mut bytes = proof_to_bytes(&proof);
        bytes.push(0xFF);
        assert!(proof_from_bytes(&bytes).is_err());
    }
}
