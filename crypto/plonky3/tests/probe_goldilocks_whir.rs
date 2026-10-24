//! Probe: WhirRecursionConfig requirements.
use p3_goldilocks::Goldilocks;
use p3_recursion::backend::whir::WhirRecursionConfig;

#[derive(Clone, Debug, Default)]
pub struct GoldilocksWhirConfig;

impl WhirRecursionConfig for GoldilocksWhirConfig {
    // Empty impl: compiler errors reveal required items.
}

#[test]
fn probe_compiles() { let _ = GoldilocksWhirConfig; }
