//! Public I/O handling for IVC steps.

use serde::{Deserialize, Serialize};

/// Public input/output values for one step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIO {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub step: u64,
}

/// Layout describing the sizes of public I/O.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIOLayout {
    pub input_bytes: usize,
    pub output_bytes: usize,
}

impl PublicIO {
    pub fn new(input: Vec<u8>, output: Vec<u8>, step: u64) -> Self {
        Self { input, output, step }
    }

    pub fn commit(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.step.to_le_bytes());
        h.update(&self.input);
        h.update(&self.output);
        *h.finalize().as_bytes()
    }
}

// Re-export blake3
use blake3;
