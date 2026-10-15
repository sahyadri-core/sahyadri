// Debug: compare my hand-rolled sponge with P3's PaddingFreeSponge and SMT.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation};
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

type F = Goldilocks;
const WIDTH: usize = 8;
const RATE: usize = 4;

fn bytes_to_gl(bytes: &[u8; 32]) -> [F; 4] {
    let mut out = [F::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = F::from_u64(u64::from_le_bytes(buf));
    }
    out
}

fn domain_from(s: &[u8]) -> [F; 4] {
    let mut padded = [0u8; 32];
    let n = s.len().min(32);
    padded[..n].copy_from_slice(&s[..n]);
    bytes_to_gl(&padded)
}

fn make_perm() -> Poseidon2Goldilocks<WIDTH> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
    Poseidon2Goldilocks::<WIDTH>::new_from_rng_128(&mut rng)
}

#[test]
fn debug_sponge() {
    let key = [0x11u8; 32];
    let value = [0x22u8; 32];

    let domain = domain_from(b"SAHYADRI_SMT_LEAF_V1");
    let key_f = bytes_to_gl(&key);
    let value_f = bytes_to_gl(&value);

    println!();
    println!("=== INPUTS ===");
    println!("domain:   {:?}", domain);
    println!("key_f:    {:?}", key_f);
    println!("value_f:  {:?}", value_f);

    let perm = make_perm();
    let mut state = [F::ZERO; WIDTH];
    let chunks = [domain, key_f, value_f];
    for (i, chunk) in chunks.iter().enumerate() {
        for k in 0..RATE {
            state[k] = chunk[k];
        }
        perm.permute_mut(&mut state);
        println!("my sponge after perm {}: {:?}", i, &state[..4]);
    }
    println!("my sponge out: {:?}", &state[..4]);

    let perm2 = make_perm();
    let hasher: PaddingFreeSponge<Poseidon2Goldilocks<WIDTH>, WIDTH, RATE, RATE> =
        PaddingFreeSponge::new(perm2);
    let input: Vec<F> = chunks.iter().flatten().copied().collect();
    let p3_out: [F; 4] = hasher.hash_iter(input.iter().copied());
    println!("P3 sponge out: {:?}", p3_out);

    let smt_out = sahyadri_smt::hash_leaf(&key, &value);
    let smt_out_f: [F; 4] = {
        let mut arr = [F::ZERO; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&smt_out[i * 8..(i + 1) * 8]);
            arr[i] = F::from_u64(u64::from_le_bytes(buf));
        }
        arr
    };
    println!("SMT out:       {:?}", smt_out_f);

    println!();
    println!("my   == SMT ? {}", state[..4] == smt_out_f);
    println!("P3   == SMT ? {}", p3_out == smt_out_f);
    println!("my   == P3  ? {}", state[..4] == p3_out);
    println!();
}
