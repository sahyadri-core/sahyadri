#![allow(clippy::unreadable_literal)]
use crate::Hash;
use sha3::{Sha3_256, Digest};
use std::cell::RefCell;

// Audit H-03 (SZR-2026-1108 §6): Poseidon2 finalization stage, ported
// byte-for-byte from crypto/hashes/src/pow_hashers.rs. Kept as duplicate
// rather than a dependency because sahyadri-hashes transitively pulls in
// Plonky3 crates that conflict with sahyadri-miner's standalone workspace
// (wasm-bindgen version skew). Any change to consensus poseidon2_output
// MUST be mirrored here; the miner/mainnet sync will fail loudly if diverged.
use p3_symmetric::Permutation;
use p3_field::PrimeField64;
use p3_goldilocks::{default_goldilocks_poseidon2_12, Goldilocks};

const BLOCK_HASH_DOMAIN: &[u8] = b"BlockHash";

// --- 1. THE POW HASHER (The Ignition Switch) ---
#[derive(Clone, Copy)]
pub(super) struct PowHasher {
    pre_pow_hash: Hash,
    timestamp: u64,
}

impl PowHasher {
    #[inline(always)]
    pub(super) fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        Self { pre_pow_hash, timestamp }
    }

    #[inline(always)]
    pub(super) fn finalize_with_nonce(self, nonce: u64) -> Hash {
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&self.pre_pow_hash.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        
        SahyadriXer::hash_bytes(&data)
    }
}

// --- 2. THE SAHYADRIX 16MB ENGINE (ASIC-Killer) ---
/// Poseidon2 finalization — ported from crypto/hashes/src/pow_hashers.rs:52.
/// Compresses the 64-byte tail of the 16 MB memory pad plus the BLAKE3 state
/// into a 32-byte output via Poseidon2 over Goldilocks. This is the stage the
/// standalone miner was missing (consensus added it in commit 01223a4).
#[inline]
fn poseidon2_output(buffer: &[u8], state: &blake3::Hash) -> [u8; 32] {
    let mut inputs = [Goldilocks::default(); 12];

    // Last 64 bytes of 16 MB buffer -> first 8 field elements
    let tail = &buffer[buffer.len() - 64..];
    for i in 0..8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&tail[i * 8..(i + 1) * 8]);
        inputs[i] = Goldilocks::new(u64::from_le_bytes(bytes));
    }

    // BLAKE3 state (32 bytes) -> last 4 field elements
    let state_bytes = state.as_bytes();
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&state_bytes[i * 8..(i + 1) * 8]);
        inputs[8 + i] = Goldilocks::new(u64::from_le_bytes(bytes));
    }

    // Apply Poseidon2 permutation (width 12, Goldilocks)
    let perm = default_goldilocks_poseidon2_12();
    perm.permute_mut(&mut inputs);

    // Compress 12 field elements to 32 bytes via XOR-fold
    let mut out = [0u8; 32];
    for i in 0..4 {
        let lo = inputs[i].as_canonical_u64().to_le_bytes();
        let hi = inputs[i + 4].as_canonical_u64().to_le_bytes();
        for j in 0..8 {
            out[i * 8 + j] = lo[j] ^ hi[j];
        }
    }
    out
}

thread_local! {
    static MEMORY_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 16 * 1024 * 1024]);
}

#[derive(Clone, Copy)]
pub(super) struct SahyadriXer;

impl SahyadriXer {
    #[inline(always)]
    pub(super) fn hash_bytes(data: &[u8]) -> Hash {
        MEMORY_BUFFER.with(|mem| {
            let mut buffer = mem.borrow_mut();
            
            // 1. Fill 16MB buffer using Blake3
            let mut current_hash = blake3::hash(data);
            for i in 0..524288 {
                buffer[i * 32..(i + 1) * 32].copy_from_slice(current_hash.as_bytes());
                current_hash = blake3::hash(current_hash.as_bytes());
            }

            // 2. 1024 Rounds of Random Memory Access
            let mut state = blake3::hash(data);
            for _ in 0..1024 {
                let state_bytes = state.as_bytes();
                let mut index_bytes = [0u8; 4];
                index_bytes.copy_from_slice(&state_bytes[0..4]);
                let raw_index = u32::from_le_bytes(index_bytes) as usize;
                
                let address = (raw_index % 524288) * 32;
                
                let mut mix = [0u8; 64];
                mix[0..32].copy_from_slice(state_bytes);
                mix[32..64].copy_from_slice(&buffer[address..address + 32]);
                
                state = blake3::hash(&mix);
            }

            Hash::from_le_bytes(poseidon2_output(buffer.as_slice(), &state))
        })
    }

    #[inline(always)]
    pub(super) fn hash(in_hash: Hash) -> Hash {
        Self::hash_bytes(&in_hash.to_le_bytes())
    }
}

// --- 3. THE HEADER HASHER (SHA3-256 domain-separated) ---
#[derive(Clone)]
pub struct HeaderHasher(sha3::Sha3_256);

impl HeaderHasher {
    #[inline(always)]
    pub fn new() -> Self {
        let mut tmp = Sha3_256::new();
        Digest::update(&mut tmp, BLOCK_HASH_DOMAIN);
        let mut out = Self(Sha3_256::new());
        out.write(tmp.finalize());
        out
    }

    pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
        Digest::update(&mut self.0, data.as_ref());
    }

    #[inline(always)]
    pub fn finalize(self) -> Hash {
        let mut out = [0u8; 32];
        out.copy_from_slice(Digest::finalize(self.0).as_slice());
        Hash::from_le_bytes(out)
    }
}

pub trait Hasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self;
}

impl Hasher for HeaderHasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.write(data);
        self
    }
}
