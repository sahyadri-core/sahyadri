//! Sahyadri Memory Loop — 16MB ASIC-resistant PoW component.
//!
//! MUST match `consensus/pow/src/memory_loop.rs` byte-for-byte.
//! To change memory size (16MB -> 64MB etc), edit BOTH files:
//!   - consensus/pow/src/memory_loop.rs
//!   - sahyadri-miner/src/pow/memory_loop.rs
//! Then rebuild both. This is a HARD FORK.

use crate::pow::xoshiro::XoShiRo256PlusPlus;
use crate::Hash;

pub const MEMORY_SIZE: usize = 16 * 1024 * 1024;
pub const MEMORY_ROUNDS: usize = 256;

pub struct MemoryLoop {
    buffer: Box<[u8; MEMORY_SIZE]>,
}

impl MemoryLoop {
    #[inline]
    pub fn new(pre_pow_hash: &Hash) -> Self {
        let mut rng = XoShiRo256PlusPlus::new(*pre_pow_hash);
        let mut buffer = Box::new([0u8; MEMORY_SIZE]);

        for chunk in buffer.chunks_exact_mut(8) {
            let val = rng.u64();
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        Self { buffer }
    }

    #[inline]
    pub fn process(&self, input: &[u8; 32]) -> [u8; 32] {
        let mut state = *input;

        for round in 0..MEMORY_ROUNDS {
            let pos = u64::from_le_bytes(state[0..8].try_into().unwrap()) as usize % (MEMORY_SIZE - 64);

            let off = round & 31;
            for i in 0..32 {
                state[(i + off) % 32] ^= self.buffer[pos + i];
                state[(i + off) % 32] ^= self.buffer[pos + 32 + i];
            }

            let mut a = u64::from_le_bytes(state[0..8].try_into().unwrap());
            let mut b = u64::from_le_bytes(state[8..16].try_into().unwrap());
            let mut c = u64::from_le_bytes(state[16..24].try_into().unwrap());
            let mut d = u64::from_le_bytes(state[24..32].try_into().unwrap());

            a = a.wrapping_add(b).rotate_left(13);
            c = c.wrapping_add(d).rotate_left(17);
            b ^= a.rotate_left(7);
            d ^= c.rotate_left(11);

            state[0..8].copy_from_slice(&a.to_le_bytes());
            state[8..16].copy_from_slice(&b.to_le_bytes());
            state[16..24].copy_from_slice(&c.to_le_bytes());
            state[24..32].copy_from_slice(&d.to_le_bytes());
        }

        state
    }
}
