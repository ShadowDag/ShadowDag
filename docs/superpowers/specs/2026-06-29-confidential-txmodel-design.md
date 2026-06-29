# Design: Confidential TX Data Model + Serialization (RingCT sub-project 2 of 4)

**Date:** 2026-06-29
**Parent:** Full RingCT. Sub-projects: (1) dual-key CLSAG ✅ → **(2) confidential
TX data model + serialization** → (3) consensus verification on the block path →
(4) wallet build + scan.
**Status:** Approved (design), pending spec review.
**Depends on:** sub-project 1 (`engine/privacy/ringct/dual_clsag.rs`:
`RingMember`, `DualCLSAGSignature`, `from_hex`/`to_hex`).

## Problem

A RingCT confidential transaction needs to carry, per input: a ring of
`(spend pubkey P_i, commitment C_i)` pairs, a per-input pseudo-output commitment
`C'`, and a dual-key CLSAG signature (which embeds key images `I`, `D`). Per
output it needs: a Pedersen commitment, a range proof, an ephemeral pubkey `R`,
and the full one-time output pubkey `P` (the address is a truncated hash and
cannot serve as a ring member). The current `TxInput`/`TxOutput` carry only a
subset (`key_image`, `ring_members` as bare pubkeys, `ring_signature`,
`commitment`, `range_proof`, `ephemeral_pubkey`). This sub-project extends the
data model and provides a typed, validated view that sub-projects 3 (consensus)
and 4 (wallet) consume. **No consensus verification or wallet construction here.**

## Goal

Extend `TxInput`/`TxOutput` with the missing RingCT fields, bind them in
`canonical_bytes`, add byte/hex serialization for the Borromean `RangeProof`, and
expose `parse_confidential_input` / `parse_confidential_output` that decode +
validate the hex fields into typed curve structures (or return `None` on any
malformed input). Ring members are carried **inline** as parallel
`ring_members` (P_i) + `ring_commitments` (C_i) arrays (decision: inline pairs,
self-contained verification; a global-offset index is a later optimization).

## Data-model changes

### `TxInput` (domain/transaction/transaction.rs) — add two fields
```rust
/// RingCT: commitment C_i for each ring member, parallel to `ring_members`
/// (same length). ring_members[i] = P_i, ring_commitments[i] = C_i. Hex
/// compressed Ristretto. None for transparent inputs.
#[serde(default)]
pub ring_commitments: Option<Vec<String>>,
/// RingCT: per-input pseudo-output commitment C' (hex compressed Ristretto).
/// None for transparent inputs.
#[serde(default)]
pub pseudo_commitment: Option<String>,
```
Existing fields keep their meaning, with one clarification documented in code:
for RingCT confidential inputs, `ring_signature` holds a **dual-key** CLSAG
(`dual_clsag::to_hex`, which embeds `I` and `D`); `key_image` repeats `I` (hex)
for fast indexing/dedup.

### `TxOutput` — add one field
```rust
/// RingCT: full one-time output public key P (hex compressed Ristretto).
/// The `address` is a truncated hash and cannot be used as a ring member;
/// this carries the full point so the output can be a decoy and be recorded
/// in the on-chain output-key index. None for transparent outputs.
#[serde(default)]
pub one_time_pubkey: Option<String>,
```

### `canonical_bytes`
Append the new fields deterministically in the existing per-input / per-output
encoding (length-prefixed, `0x01`/`0x00` presence markers, matching the existing
style): `ring_commitments` after `ring_signature` in the input section;
`one_time_pubkey` after `ephemeral_pubkey` in the output section;
`pseudo_commitment` after `ring_commitments`. Coinbase (no inputs) and
transparent TXs are unaffected (all new fields `None` → single `0x00` marker).

## RangeProof serialization

`engine/privacy/confidential/range_proof.rs::RangeProof` holds
`bit_commitments: Vec<RistrettoPoint>`, `challenges: Vec<Scalar>`,
`responses: Vec<[Scalar;2]>` (RANGE_BITS each). Add to `serialization.rs`:
```
range_proof_to_bytes(&RangeProof) -> Vec<u8>
range_proof_from_bytes(&[u8]) -> Option<RangeProof>   // rejects non-canonical / wrong-length
range_proof_to_hex / range_proof_from_hex
```
Wire format: `nbits(u32) || bit_commitments[nbits]·32 || challenges[nbits]·32 ||
responses[nbits]·64`. `from_bytes` validates exact length, canonical scalars, and
decompressable points; enforces `nbits == RANGE_BITS`.

## Typed validated views (`engine/privacy/ringct/tx_confidential.rs` — new)

```rust
pub struct ConfidentialInputView {
    pub ring: Vec<dual_clsag::RingMember>,       // (P_i, C_i)
    pub pseudo_out: RistrettoPoint,              // C'
    pub signature: dual_clsag::DualCLSAGSignature,
    pub key_image: RistrettoPoint,               // I (from the signature)
}

pub struct ConfidentialOutputView {
    pub commitment: RistrettoPoint,
    pub one_time_pubkey: RistrettoPoint,
    pub ephemeral_pubkey: RistrettoPoint,
    pub range_proof: RangeProof,
}

/// Decode + validate a confidential input. None if any field is missing,
/// lengths mismatch (ring_members.len() != ring_commitments.len() !=
/// signature.s.len()), or any point/scalar is non-canonical.
pub fn parse_confidential_input(input: &TxInput) -> Option<ConfidentialInputView>;

/// Decode + validate a confidential output. None on missing/malformed fields.
pub fn parse_confidential_output(output: &TxOutput) -> Option<ConfidentialOutputView>;
```
These are pure decoders/validators — no chain state, no crypto verification
(that is sub-project 3). They guarantee that anything returned `Some` is
structurally well-formed typed data.

## Testing

- **serde round-trip:** a TX with the new fields survives
  `bincode`/`serde_json` round-trip; transparent TX unaffected.
- **canonical_bytes binding:** setting each new field (ring_commitments,
  pseudo_commitment, one_time_pubkey) changes `canonical_bytes`; an all-`None`
  input/output is unchanged vs. pre-change for transparent TXs (coinbase hash
  stable).
- **parse happy path:** build a confidential input/output from a real dual-CLSAG
  sign (reusing sub-project 1 test helpers) → `parse_confidential_*` returns
  `Some` with points equal to the originals.
- **parse rejects:** missing field → None; `ring_members.len() !=
  ring_commitments.len()` → None; `len != signature.s.len()` → None;
  non-decompressable point → None; non-canonical scalar → None.
- **RangeProof serialization:** round-trip a real proof from
  `range_proof::prove`; truncated / wrong-nbits / non-canonical → None.

## Non-goals (later sub-projects)
- Consensus verification: dual-CLSAG verify, homomorphic balance
  `Σ C'_in = Σ C_out + fee·H`, range-proof verify, okey/ki stores, gate wiring
  (sub-project 3).
- Wallet: decoy selection, blinding/pseudo-output balancing, stealth output
  creation, scanning (sub-project 4).
- Removing the phase-1 single-key path (sub-project 3).
- Migrating bincode v1→v2 or changing the wire envelope.

## Risks
- **Consensus-format change:** new fields enter `canonical_bytes`, changing the
  txid of any TX that sets them. Transparent + coinbase TXs are unaffected (all
  `None`), so genesis and existing fixtures stay valid; confirm the full suite
  after the change. Pre-launch network ⇒ no live migration.
- Field sprawl on `TxInput`/`TxOutput`: acceptable for now (follows the existing
  Option-per-field style); a `Confidential { ... }` sub-struct is a possible
  future tidy, out of scope here.
