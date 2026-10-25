//! Byte serialization for BinaryField128.
//!
//! The tower field keeps its u128 payload private, so `to_le_bytes`
//! isn't callable directly. The macro guarantees the same bit layout,
//! which makes the transmute here valid (same size, same alignment,
//! same representation as documented in p3-binary-field).

use p3_binary_field::BinaryField128;

pub trait Block128Bytes {
    fn blk_to_le_bytes(&self) -> [u8; 16];
}

impl Block128Bytes for BinaryField128 {
    #[inline]
    fn blk_to_le_bytes(&self) -> [u8; 16] {
        let v: u128 = unsafe { core::mem::transmute_copy(self) };
        v.to_le_bytes()
    }
}

#[inline]
pub fn block_from_bytes(b: [u8; 16]) -> BinaryField128 {
    BinaryField128::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for n in [0u128, 1, 0xFFFF, u128::MAX / 2] {
            let b = BinaryField128::from_le_bytes(n.to_le_bytes());
            assert_eq!(block_from_bytes(b.blk_to_le_bytes()), b);
        }
    }
}
