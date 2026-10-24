# sahyadri_fri_binary

Binary-field FRI-Binius PCS over GF(2^128), designed for Sahyadri's hybrid
binary-Goldilocks architecture.

## Design (clean-room from Binius, 2023)

- Base: FRI protocol adapted to binary tower fields
- Commitment: Poseidon2b Merkle over extended codewords
- Ring-switching: binary extension ↔ packed 128-bit (from Binius §4.2)
- Folding: XOR-based, additive NTT over Cantor basis

## Interfaces

- `prove_binary(air, trace) -> BinaryProof`
- `verify_binary(commitment, proof, public) -> bool`
- `verify_binary_in_goldilocks(proof) -> GoldilocksCircuit` (hybrid bridge)

## Status

In design. Implements concepts from Binius (Lurie et al., 2023) and FRI
(Ben-Sasson et al., 2018). No external code dependency.
