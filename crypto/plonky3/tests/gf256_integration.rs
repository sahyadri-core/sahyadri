// Verify hekate-math GF(2^256) works
use hekate_math::Block256;

#[test]
fn gf256_basic() {
    let a = Block256::from(1u64);
    let b = Block256::from(2u64);
    let c = a * b;
    assert_ne!(c, Block256::from(0u64));
}
