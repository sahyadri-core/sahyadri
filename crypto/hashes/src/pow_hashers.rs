use crate::Hash;
use std::cell::RefCell;

// ═══════════════════════════════════════════════════════════════
// SahyadriX — Memory-hard Proof-of-Work
//
// Hash primitive: BLAKE3 (256-bit output).
// BLAKE3 offers ~128-bit preimage resistance under Grover, matching
// SHA3-256's quantum profile, while being 3-5x faster in our 16 MB
// memory-loop workload.
//
// The 16 MB working set is per-thread (thread_local), so mining on N
// threads allocates N × 16 MB — no contention, no locks.
// ═══════════════════════════════════════════════════════════════

/// Binding of a specific block template to a nonce.
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

        // Start the 16 MB SahyadriX engine.
        SahyadriX::hash(&data)
    }
}

thread_local! {
    /// Per-thread 16 MB memory pad. Each mining thread owns its own pad.
    pub static MEMORY_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 16 * 1024 * 1024]);
}

#[derive(Clone, Copy)]
pub struct SahyadriX;

impl SahyadriX {
    /// Evaluate SahyadriX over the given input.
    ///
    /// Stage A: deterministically fill a 16 MB buffer via BLAKE3 chain.
    /// Stage B: 1024 rounds of data-dependent random-access mixing.
    /// Final: return the last 32-byte state as the PoW hash.
    #[inline(always)]
    pub fn hash(data: &[u8]) -> Hash {
        MEMORY_BUFFER.with(|mem| {
            let mut buffer = mem.borrow_mut();

            // ── Stage A: fill 16 MB buffer via BLAKE3 chain ──
            // 524288 windows × 32 bytes = 16 MB exactly.
            let mut current_hash = blake3::hash(data);
            for i in 0..524288 {
                buffer[i * 32..(i + 1) * 32].copy_from_slice(current_hash.as_bytes());
                current_hash = blake3::hash(current_hash.as_bytes());
            }

            // ── Stage B: 1024 random-access mixing rounds ──
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

            Hash::from_bytes(*state.as_bytes())
        })
    }
}
