//! Sahyadri Memory Loop — 16MB ASIC-resistant PoW component
//!
//! Memory-hard sequential computation requiring 16MB random-access
//! memory per hash. Makes ASICs expensive (need 16MB on-chip SRAM).
//!
//! - 16MB buffer filled per block from pre-pow hash
//! - 256 sequential rounds per nonce (data-dependent reads)
//! - ARX mixing between rounds
//! - Read-only: deterministic across all miners

use crate::xoshiro::XoShiRo256PlusPlus;
use sahyadri_hashes::Hash;

const MEMORY_SIZE: usize = 16 * 1024 * 1024; // 16MB
const MEMORY_ROUNDS: usize = 256;

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
            // Data-dependent position from current state
            let pos = u64::from_le_bytes(state[0..8].try_into().unwrap()) as usize % (MEMORY_SIZE - 64);

            // Read 64 bytes, XOR-mix into state with cycling offset
            let off = round & 31;
            for i in 0..32 {
                state[(i + off) % 32] ^= self.buffer[pos + i];
                state[(i + off) % 32] ^= self.buffer[pos + 32 + i];
            }

            // ARX mixing (Add-Rotate-XOR) on 4 x u64
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
