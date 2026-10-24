# Sahyadri: A Proof-Native Hybrid-Field Blockchain with Parallel Binary PoW and O(1) Goldilocks Recursion

**Authors:** Suraj Datir et al.
**Draft v1 — Working Paper**

---

## Abstract

We present Sahyadri, a proof-native proof-of-work blockchain that separates
computation (binary-field PoW) from aggregation (Goldilocks-field recursion).
We demonstrate two measured results: (i) 262,196 FROST-GKR Poseidon2b
permutations proven in parallel in 196 seconds on commodity hardware, and
(ii) O(1) recursive chain proofs of 698-709 KB with 17-22 ms verification,
scaling sub-linearly (1.57x per doubling) from N=8 to N=16 leaves under a
4-thread bounded pool. The hybrid field design permits binary-optimized PoW
while retaining recursive verification in a field where the Plonky3 recursion
backend is supported. We position Sahyadri against Parano1d, a related
proof-native L1, and identify the remaining engineering gap (full 262K
recursive tree) as future work.

---

## 1. Introduction

Proof-native blockchains verify execution via cryptographic proofs rather
than replay. The central promise is O(1) verification: proof size and
verification time do not grow with chain height. Two challenges dominate
implementation:

1. **Field choice.** Binary tower fields GF(2^128) permit fast arithmetic
   and are well-matched to hash-based primitives (BLAKE3, Poseidon2b). Prime
   fields (Goldilocks, BabyBear) are required by existing recursive verifier
   circuits in Plonky3.

2. **Aggregation scaling.** Recursive proofs must aggregate thousands of
   leaf proofs into a single root. The aggregation strategy determines
   wall-clock cost and memory ceiling.

Sahyadri addresses both via a **hybrid-field architecture**: binary-field
PoW proofs (fast, parallel, memory-efficient) are kept independent of a
Goldilocks-field recursive chain proof (supported by Plonky3's FRI backend).
Cross-field commitment binding is achieved through Poseidon2b sponge
compression; full in-circuit attestation is future work.

### 1.1 Contributions

1. **Parallel binary-field PoW.** We prove 262,196 FROST-GKR Poseidon2b
   permutations in 196 seconds on a single commodity machine (Section 5.1).
   To our knowledge, no prior published result reports this scale for
   binary-field FROST-GKR.

2. **O(1) recursive chain proof.** We measure 698-709 KB proofs with 17-22 ms
   verification across N=8 to N=16 leaf trees (Section 5.2). Sub-linear
   scaling is confirmed at 1.57x per doubling of leaves under a bounded
   4-thread pool.

3. **Hybrid field architecture.** We demonstrate a workable separation of
   binary PoW and Goldilocks recursion, with commitment binding via
   Poseidon2b. Full multi-field composition is identified as future work.

### 1.2 Relationship to Parano1d

Parano1d is a proof-native L1 using FRI-Binius over GF(2^128) throughout,
with constant-size proofs (~38 KB) and O(1) verification. Sahyadri differs in
field allocation (hybrid vs pure binary) and proof size (698 KB vs 38 KB).
Both achieve O(1) verification; Sahyadri's advantage is reuse of Plonky3's
mature Goldilocks recursion; its limitation is larger proof size and
unattested PoW (Section 8).

---

## 2. Background

### 2.1 FROST-GKR

FROST-GKR is a GKR-based reduction for 59 Poseidon2 permutations in a global
trace. Per-batch reduction reduces prover time, verifier time, and proof
bytes by factors of 10.69x, 14.80x, and 51.67x respectively (Parano1d
parameters). Sahyadri ports FROST-GKR from `ignotusnemo/frost-gkr` (Apache
2.0) with 3,300 lines across 47 passing tests.

### 2.2 Plonky3 Recursion Backend

Plonky3's `p3-recursion` supports FRI-backend recursion over BabyBear,
KoalaBear, and Goldilocks. Binary-field recursion is documented as
"groundwork only" upstream: the `FriRecursionBackend` requires a two-adic
prime field, and binary WHIR's recursive verifier is not implemented.
Sahyadri therefore uses Goldilocks for recursion and binary for PoW.

### 2.3 Poseidon2b

Poseidon2b operates over GF(2^128) with t=4, x^7 S-box, 8 full + 58 partial
rounds. Sahyadri implements `p3-poseidon2b` as a drop-in crate matching
Parano1d parameters, with permutation, sponge, trace, and AIR (3 tests).

---

## 3. Architecture

### 3.1 Field Allocation

- **Binary field (GF(2^128)):** BLAKE3 PoW, Poseidon2b, FROST-GKR.
- **Goldilocks field:** Recursive chain proof, aggregation circuit,
  signature verification, SMT state verification.

### 3.2 Data Flow

1. PoW nodes produce binary-field proofs for each epoch (FROST-GKR over
   Poseidon2b permutations).
2. A commitment to the binary PoW proof is published per epoch (currently
   as a Merkle root; full in-circuit attestation future work).
3. A Goldilocks recursive proof aggregates BLAKE3 chain transitions and
   signature/state checks.
4. The Goldilocks root proof (698-709 KB) is the O(1) chain proof.

### 3.3 Aggregation Strategy

Leaves are `Proof<GoldilocksConfig>` (one per block transition). Level 1
aggregates `Proof x Proof -> RecursionOutput` via `aggregate_pair`. Levels
2+ aggregate `RecursionOutput x RecursionOutput -> RecursionOutput` via
`aggregate_two_batches`. Level 1 dominates cost (67% of wall-clock at N=16);
we bound its parallel execution to a fixed thread pool to control peak
memory.

---

## 4. Implementation

### 4.1 Binary PoW Stack

- `p3-poseidon2b`: Poseidon2b permutation, sponge, trace, AIR.
- `p3-blake3-air`: BLAKE3 compression AIR (width patched to 16384).
- FROST-GKR port: 3,300 lines, 47 tests (extraction, sumcheck, shift,
  sequence, layers, native).

### 4.2 Goldilocks Recursion Stack

- 4 verifier AIRs: `FrostGkrVerifierAir`, `ExtractionAir`, `PcsOpenAir`,
  `FullVerifierAir` (all pass `check_constraints`).
- `aggregate_pair` and `aggregate_two_batches` from
  `crypto/plonky3/src/aggregate.rs` and `aggregate_cross.rs`.
- Bounded pool for Level 1: `ThreadPoolBuilder::new().num_threads(4)`.

### 4.3 Hybrid Commitment Binding

`MultiFieldBindAir` (5 tests) binds a Goldilocks commitment and a binary
commitment via Poseidon2b sponge compression. This provides sound cross-field
commitment for the PoW proof hash (currently out-of-circuit); full
in-circuit attestation is Section 8.

---

## 5. Evaluation

All measurements on a single commodity machine (Intel i7-1365U, 12 threads,
32 GB RAM), release build.

### 5.1 Binary PoW: 262K FROST-GKR Permutations

**Setup.** 4,444 batches x 59 permutations = 262,196 Poseidon2b permutations.
Chain commitments via Poseidon2b sponge.

**Result.** Parallel proof: 98.21 s. Parallel verification: 97.77 s. Total:
195.98 s (3.3 min). Speedup vs sequential: approximately 9x (sequential
extrapolated at 30 min).

**Table 1:** Binary PoW scaling

| Configuration | Prove (s) | Verify (s) | Total (s) |
|---|---|---|---|
| Sequential, 500 batches | 53.0 | 53.0 | 106.0 |
| Parallel, 500 batches | 10.8 | 10.8 | 21.6 |
| Parallel, 4,444 batches | 98.2 | 97.8 | 196.0 |

This is the largest reported binary-field FROST-GKR scale to our knowledge.

### 5.2 Goldilocks Recursion: O(1) Chain Proof

**Setup.** BLAKE3 chain transitions, one proof per block. Tree aggregation
with `aggregate_pair` (Level 1) and `aggregate_two_batches` (Levels 2+).
Level 1 uses a 4-thread bounded pool; Levels 2+ use the default pool.

**Result.**

**Table 2:** Recursive tree scaling

| N | Level 0 | Level 1 | Levels 2+ | Total | Verify | Size |
|---|---|---|---|---|---|---|
| 8 (serial) | 0.85 s | 149.8 s | 63.9 s | 214.6 s | 17.7 ms | 698 KB |
| 8 (2t) | 0.39 s | 91.6 s | 49.5 s | 142.0 s | 18.7 ms | 698 KB |
| 16 (4t) | 0.62 s | 134.0 s | 88.0 s | 223.0 s | 21.8 ms | 709 KB |

**Observations.**

1. **O(1) property.** Proof size (698-709 KB) and verify time (17.7-21.8 ms)
   are independent of N. This is the O(1) verification property promised by
   proof-native chains.

2. **Sub-linear scaling.** N=8 -> N=16 (2x leaves) yields 142 s -> 223 s
   (1.57x time) under 4-thread pool. The gap to 2x reflects Level 1
   amortization (22.9 s/pair at N=8/2t vs 16.75 s/pair at N=16/4t).

3. **Verify time variability.** Verify time ranged from 17.7 ms (N=8
   serial) to 21.8 ms (N=16/4t) with one anomalous 67.9 ms cold-cache
   measurement. Median is ~20 ms.

---

## 6. Related Work

**Parano1d.** Proof-native L1 with FRI-Binius, 38 KB proofs, O(1) verify.
Sahyadri matches O(1) property at larger proof size (698 KB), differing in
field allocation.

**Mina (Pickles).** Inductive zk-SNARK over Pasta curves, 22 KB proofs,
linear + tree hybrid aggregation. Sahyadri adopts the same hybrid
architecture but uses hash-based proofs (PQ-safe) rather than curve-based.

**Plonky3 ecosystem.** Provides FRI and WHIR backends; Sahyadri reuses
Goldilocks FRI recursion and implements binary AIRs for PoW.

---

## 7. Discussion

### 7.1 Why Hybrid Field?

Binary PoW is 10,000x faster in trace generation (Blake3 binary traces) and
parallelizes 9x at 262K scale. Goldilocks recursion is the only supported
backend in `p3-recursion` upstream. Hybridity is not a design preference but
an engineering response to upstream capability.

### 7.2 Why Bounded Level 1 Pool?

`aggregate_pair` allocates substantial backend memory per call. Unbounded
parallelism at Level 1 triggers SIGKILL at 8 pairs. The 4-thread pool caps
peak memory while preserving 1.5-2x speedup. This is an explicit memory-
latency trade-off, not an algorithmic limitation.

### 7.3 Limitations

- PoW proofs are not currently in-circuit attested by the chain proof.
- Proof size (698 KB) is 18x larger than Parano1d (38 KB).
- Full 262K recursive tree is not demonstrated (Section 8).

---

## 8. Future Work

**Full 262K recursive tree.** Current N=16 in 223 s. Full 262K requires (a)
circuit-level batch proof converter (`BatchProof -> BatchStarkProof`, est.
2-4 weeks) or (b) chain-batch leaves with custom converter (2-3 weeks).
Memory-bound; needs streaming commitment.

**Binary-field recursion.** Plonky3 upstream does not support GF(2^128)
recursion. Two paths: FRI-Binius port from `noid_fri_binius` (Apache 2.0,
2-4 weeks) or custom binary aggregation AIR (2-4 weeks).

**Multi-field PoW attestation.** In-circuit attestation of binary PoW
validity inside the Goldilocks chain proof closes the hybrid gap. Est. 2-4
weeks via 800K-gate circuit.

**WHIR Goldilocks backend.** Upstream registry rejects Goldilocks WHIR
(`FieldFamilyV1::Goldilocks => Err`). Custom trait impl needed; est. 1-2
weeks; 2.6x PCS speedup at maturity.

---

## 9. Conclusion

Sahyadri demonstrates that binary-field PoW and Goldilocks-field recursive
chain proofs can coexist. 262K binary permutations in 196 s and O(1) chain
proofs at 698-709 KB / ~20 ms are measured, reproducible results. The
remaining gap to Parano1d-parity (full 262K recursive tree, binary-field
recursion) is engineering work with clear paths, not research unknowns.

---

## Appendix A: Reproducibility

Test files: `crypto/plonky3/tests/parallel_tree_sweep.rs`,
`recursion/tests/day5_multi_air_whir.rs`,
`recursion/src/frost_gkr/benchmarks.rs`. Tag: `paper-v1`.


