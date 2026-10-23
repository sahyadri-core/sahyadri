//! Phase 1: Standalone Blake3 compression on BinaryField128.
//!
//! Proves that:
//! 1. Blake3BinaryAir produces correct traces over BinaryField128
//! 2. Trace satisfies all AIR constraints
//! 3. Output matches native blake3
//!
//! Foundation for Phase 2 (STARK proving on binary field).

use core::array;
use core::borrow::Borrow;

use p3_air::{BaseAir, check_constraints};
use p3_binary_field::BinaryField128;
use p3_blake3_air::{
    Blake3BinaryAir, Blake3BinaryCols, Blake3CompressionInput,
    generate_binary_trace_rows, NUM_BLAKE3_BINARY_COLS,
};
use p3_matrix::Matrix;

/// Flags of a block that is the first, last and root chunk of a hash.
const SINGLE_BLOCK_FLAGS: u32 = 1 | 2 | 8;

/// BLAKE3 IV (canonical spec, RFC draft §2.2).
///
/// These are the first 8 words of the SHA-256 IV, identical to BLAKE2s.
/// Every Blake3 implementation (Rust `blake3` crate, C, Go) uses these values.
/// They are the fixed starting state of the first compression of a chunk.
const BLAKE3_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Blake3 hash of the empty input.
const EMPTY_INPUT_HASH: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

type F = BinaryField128;

/// Build a single-block Blake3 compression input.
fn single_block_input(message: &[u8]) -> Blake3CompressionInput {
    let mut bytes = [0u8; 64];
    bytes[..message.len()].copy_from_slice(message);
    Blake3CompressionInput {
        chaining_value: BLAKE3_IV,
        block: array::from_fn(|i| {
            u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap())
        }),
        counter: 0,
        block_len: message.len() as u32,
        flags: SINGLE_BLOCK_FLAGS,
    }
}

/// Extract Blake3 output bytes from AIR trace.
///
/// `generate_binary_trace_rows` requires a power-of-2 number of inputs.
/// We pad with dummy inputs and slice outputs to the requested count.
fn trace_outputs(inputs: &[Blake3CompressionInput]) -> Vec<[u8; 32]> {
    assert!(!inputs.is_empty(), "at least one input required");

    // Pad to next power of 2
    let padded_len = inputs.len().next_power_of_two();
    let mut padded: Vec<Blake3CompressionInput> =
        Vec::with_capacity(padded_len);
    padded.extend_from_slice(inputs);
    while padded.len() < padded_len {
        padded.push(Blake3CompressionInput::default());
    }

    let air = Blake3BinaryAir::default();
    let trace = generate_binary_trace_rows::<F>(padded, 0);
    check_constraints(&air, &trace, &[]);

    // Only return the requested count (drop padding)
    (0..inputs.len())
        .map(|r| {
            let row = trace.row_slice(r).unwrap();
            let cols: &Blake3BinaryCols<F> = (*row).borrow();
            let output = cols.compression_output();
            array::from_fn(|i| output[i / 4].to_le_bytes()[i % 4])
        })
        .collect()
}

#[test]
fn binary_field_width_is_11536() {
    let air = Blake3BinaryAir::default();
    assert_eq!(
        <Blake3BinaryAir as BaseAir<F>>::width(&air),
        NUM_BLAKE3_BINARY_COLS
    );
    assert_eq!(NUM_BLAKE3_BINARY_COLS, 11_536);
}

#[test]
fn binary_empty_input_hash() {
    let input = Blake3CompressionInput {
        chaining_value: BLAKE3_IV,
        block: [0; 16],
        counter: 0,
        block_len: 0,
        flags: SINGLE_BLOCK_FLAGS,
    };
    let outputs = trace_outputs(&[input]);
    assert_eq!(outputs[0], EMPTY_INPUT_HASH);
}

#[test]
fn binary_single_block_hashes() {
    let messages: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"hello world".to_vec(),
        vec![0u8; 32],
        vec![0xFFu8; 64],
    ];
    let inputs: Vec<_> = messages.iter().map(|m| single_block_input(m)).collect();

    for (message, output) in messages.iter().zip(trace_outputs(&inputs)) {
        let expected = blake3::hash(message);
        assert_eq!(
            &output[..],
            expected.as_bytes(),
            "mismatch for message len {}",
            message.len()
        );
    }
}

#[test]
fn binary_trace_satisfies_constraints() {
    let air = Blake3BinaryAir::default();
    for height in [1usize, 2, 4] {
        let trace = air.generate_random_trace_rows::<F>(height, 0);
        assert_eq!(trace.height(), height);
        check_constraints(&air, &trace, &[]);
    }
}
