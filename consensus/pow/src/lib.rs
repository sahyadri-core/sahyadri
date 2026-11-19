// public for benchmarks
#[doc(hidden)]
pub mod matrix;
pub mod memory_loop;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;

use crate::matrix::Matrix;
use crate::memory_loop::MemoryLoop;
use sahyadri_consensus_core::{BlockLevel, hashing, header::Header};
use sahyadri_hashes::PowHash;
use sahyadri_hashes::Hash;
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;

const POW_CACHE_MAX: usize = 10_000;

fn pow_cache() -> &'static Mutex<HashMap<(Hash, u64), (bool, Uint256)>> {
    static CACHE: OnceLock<Mutex<HashMap<(Hash, u64), (bool, Uint256)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
use sahyadri_math::Uint256;

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    header_hash: Hash,
    pub(crate) matrix: Matrix,
    pub(crate) target: Uint256,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE
    pub(crate) hasher: PowHash,
    memory_loop: MemoryLoop,
}

impl State {
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp);
        let matrix = Matrix::generate(pre_pow_hash);
        let header_hash = header.hash;

        Self { header_hash, matrix, target, hasher, memory_loop: MemoryLoop::new(&pre_pow_hash) }
    }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash = self.matrix.heavy_hash(self.memory_loop.process(&hash.as_bytes()).into());
        Uint256::from_le_bytes(hash.as_bytes())
    }

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        // Check the PoW verification cache first. Avoids recomputing the
        // 1.05M-hash PoW when the same header+nonce is seen from multiple peers.
        let cache_key = (self.header_hash, nonce);
        {
            let cache = pow_cache().lock().unwrap();
            if let Some(&result) = cache.get(&cache_key) {
                return result;
            }
        }

        let pow = self.calculate_pow(nonce);
        let result = (pow <= self.target, pow);

        // Store in cache. Clear on overflow (simple eviction).
        {
            let mut cache = pow_cache().lock().unwrap();
            if cache.len() >= POW_CACHE_MAX {
                cache.clear();
            }
            cache.insert(cache_key, result);
        }
        result
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel) -> BlockLevel {
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = State::new(header);
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
