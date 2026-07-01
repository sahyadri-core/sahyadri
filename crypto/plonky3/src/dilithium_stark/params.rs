//! Dilithium3 (ML-DSA-65) parameters per NIST FIPS 204.
//! Values match dilithium-rs v0.2.0 DilithiumMode::Dilithium3.

/// Modulus q = 2^23 - 2^13 + 1
pub const Q: u32 = 8380417;

/// Polynomial degree n = 256
pub const N: usize = 256;

/// Matrix dimension k (rows of A) — ML-DSA-65: k=6
pub const K: usize = 6;

/// Matrix dimension l (cols of A) — ML-DSA-65: l=5
pub const L: usize = 5;

/// Secret coefficient bound eta = 4
pub const ETA1: usize = 4;
pub const ETA2: usize = 4;

/// Infinity norm bound for z: gamma1 = 2^19
pub const GAMMA1: u32 = 1 << 19; // 524288

/// Low-order rounding range: gamma2 = (q-1)/32
pub const GAMMA2: u32 = (Q - 1) / 32; // 261888

/// Number of bits d for power-of-two rounding
pub const D: usize = 13;

/// Rejection bound: tau * eta = 49 * 4
pub const BETA: u32 = 196;

/// Maximum ones in hint vector
pub const OMEGA: usize = 55;

/// Challenge hash length in bytes
pub const CTILDEBYTES: usize = 48;

/// Packed size for t1 polynomial (10 bits per coefficient)
pub const POLYT1_PACKEDBYTES: usize = 320;

/// Packed size for z polynomial (20 bits per coefficient)
pub const POLYZ_PACKEDBYTES: usize = 640;

/// Public key size in bytes: 32 + K*320 = 1952
pub const PK_SIZE: usize = 1952;

/// Signature size: 48 + L*640 + OMEGA + K = 3309
pub const SIG_SIZE: usize = 3309;

/// Log2(N) = 8 (NTT stages)
pub const LOG_N: usize = 8;

/// Primitive root of unity in Z_q
pub const ROOT_OF_UNITY: u32 = 1753;
