#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::AbstractField;
    use p3_goldilocks::Goldilocks;

    #[test]
    fn hash_lt_target_basic() {
        let hash = [0u8; 32];
        let target = [1u8; 32];
        assert!(hash_lt_target(&hash, &target));
    }

    #[test]
    fn hash_eq_target_returns_false() {
        let hash = [5u8; 32];
        let target = [5u8; 32];
        assert!(!hash_lt_target(&hash, &target));
    }

    #[test]
    fn hash_gt_target_returns_false() {
        let hash = [10u8; 32];
        let target = [5u8; 32];
        assert!(!hash_lt_target(&hash, &target));
    }

    #[test]
    fn hash_lt_target_high_byte() {
        let mut hash = [0u8; 32];
        let mut target = [0u8; 32];
        hash[31] = 1; // highest byte
        target[31] = 2;
        assert!(hash_lt_target(&hash, &target));
    }

    #[test]
    fn trace_builds_correctly() {
        let hash = [0u8; 32];
        let target = [1u8; 32];
        let trace: Vec<Goldilocks> = build_comparison_trace(&hash, &target);
        assert_eq!(trace.len(), 130);
        // Column 128 = is_less_than = true
        assert_eq!(trace[128], Goldilocks::one());
    }

    #[test]
    fn trace_bit_decomposition_correct() {
        let mut hash = [0u8; 32];
        hash[0] = 0b10110011; // 179
        let target = [0u8; 32];
        let trace: Vec<Goldilocks> = build_comparison_trace(&hash, &target);
        // Check that bits match: byte 0, bit 0 = 1, bit 1 = 1, bit 2 = 0, bit 3 = 0, ...
        assert_eq!(trace[64 + 0], Goldilocks::one());   // bit 0 = 1
        assert_eq!(trace[64 + 1], Goldilocks::one());   // bit 1 = 1
        assert_eq!(trace[64 + 2], Goldilocks::zero());  // bit 2 = 0
        assert_eq!(trace[64 + 3], Goldilocks::zero());  // bit 3 = 0
        assert_eq!(trace[64 + 4], Goldilocks::one());   // bit 4 = 1
    }
}
