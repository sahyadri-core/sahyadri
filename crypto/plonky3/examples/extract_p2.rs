// Extract actual Poseidon2 Goldilocks constants from p3-goldilocks
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use p3_field::PrimeField64;

fn main() {
    let perm = default_goldilocks_poseidon2_12();
    
    // Test values from Plonky3 poseidon2_goldilocks_12 test vectors
    let input: [u64; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let mut state = input.map(p3_goldilocks::Goldilocks::new);
    perm.permute_mut(&mut state);
    
    println!("// Poseidon2 Goldilocks width-12 output for input [0..12]:");
    print!("pub const POSEIDON2_GOLDILOCKS_12_TEST_OUTPUT: [u64; 12] = [");
    for (i, s) in state.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("0x{:016X}", s.as_canonical_u64());
    }
    println!("];");
}
