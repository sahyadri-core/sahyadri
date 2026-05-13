use crate::Hash;
use std::cell::RefCell;

// 1. Data Storage Box (The Ignition Switch)
#[derive(Clone)]
pub struct PowHash {
    pre_pow_hash: Hash,
    timestamp: u64,
}

impl PowHash {
    #[inline]
    pub fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        Self { pre_pow_hash, timestamp }
    }

    #[inline]
    pub fn finalize_with_nonce(&self, nonce: u64) -> Hash {
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&self.pre_pow_hash.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());

        // Start the 16MB SahyadriX Engine!
        SahyadriX::hash(&data)
    }
}

// --- 2. THE SAHYADRIX 16MB ENGINE (Miner and Node 100% SYNCHRONIZED) ---
thread_local! {
    pub static MEMORY_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 16 * 1024 * 1024]);
}

#[derive(Clone, Copy)]
pub struct SahyadriX;

impl SahyadriX {
    #[inline(always)]
    pub fn hash(data: &[u8]) -> Hash {
        MEMORY_BUFFER.with(|mem| {
            let mut buffer = mem.borrow_mut();
            
            // 1. Fill 16MB buffer using blake3 (EXACT MINER LOGIC)
            let mut current_hash = blake3::hash(data);
            for i in 0..524288 {
                buffer[i * 32..(i + 1) * 32].copy_from_slice(current_hash.as_bytes());
                current_hash = blake3::hash(current_hash.as_bytes());
            }

            // 2. 1024 Rounds of Random Memory Access (EXACT MINER LOGIC)
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

            // Return Final Hash identically!
            Hash::from_bytes(*state.as_bytes())
        })
    }
}
