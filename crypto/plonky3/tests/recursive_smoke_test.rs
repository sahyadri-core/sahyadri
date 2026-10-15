// Smoke test: does SmtAir automatically implement RecursiveAir?
// The blanket impl in p3-recursion::traits::air covers any Air that
// implements Air<InteractionSymbolicBuilder<F, EF>>.

use p3_lookup::logup::LogUpGadget;
use p3_recursion::traits::RecursiveAir;

use sahyadri_plonky3::config::{EF, F};
use sahyadri_plonky3::smt_stark::SmtAir;

fn assert_recursive<A: RecursiveAir<F, EF, LogUpGadget>>() {}

#[test]
fn smt_air_is_recursive_via_blanket() {
    assert_recursive::<SmtAir>();
}
