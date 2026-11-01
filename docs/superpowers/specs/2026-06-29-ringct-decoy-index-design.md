# Design: Confidential Output Index + Decoy Selection (RingCT sub-project 4c-i)

**Date:** 2026-06-29
**Parent:** Full RingCT → sub-project 4 (wallet) → 4c (integration). 4c is split
into **4c-i (enumerable decoy index + selection)** → 4c-ii (CLI/RPC/wallet
key-management wiring, done in a dedicated session with the app running).
**Status:** Approved (design), pending spec review.
**Depends on:** the `okey:` store + `apply_block_dag_ordered` recording
(sub-project 3), `dual_clsag::RingMember`, `verify_confidential_tx` + the 4a
builder (integration oracle).

## Problem

The builder (4a/4b) needs a ring of real on-chain confidential outputs as decoys,
but the `okey:` store (pubkey → commitment) is a prefix store with no efficient
way to sample random members. Wallets cannot build privacy rings without one.
This sub-project adds a sequential, enumerable index of confidential outputs and a
random decoy-selection function. (Wiring this into the wallet/CLI is 4c-ii.)

## Goal

Maintain a Monero-style global output index: a counter plus `N → pubkey`
entries, written atomically when a confidential output is applied. Expose
`select_decoys(count, exclude)` that returns `count` distinct real ring members
(pubkey + authentic commitment), suitable as decoys for the builder. A tx built
with these decoys passes `verify_confidential_tx`.

## Components

### 1. Indexed store on `UtxoSet` (`domain/utxo/utxo_set.rs`)
Key layout (raw store, like `okey:`/`ki:`):
- `okeyidx:count` → `u64` LE: number of confidential outputs recorded so far.
- `okeyidx:{N}` (N as ASCII decimal) → one-time pubkey hex of the Nth output.

Accessors:
```rust
pub fn confidential_output_count(&self) -> u64;       // reads okeyidx:count (0 if absent)
pub fn confidential_output_at(&self, n: u64) -> Option<String>; // pubkey hex at index n
```
Recording: in `apply_block_dag_ordered`, where confidential outputs already push
`okey:{pubkey} → commitment`, also append the index entries in the **same**
`WriteBatch`: read the current count once at the start of the block apply, then
for each confidential output push `okeyidx:{next}` = pubkey and finally write the
updated `okeyidx:count`. (Single-writer apply ⇒ no counter race.)
`output_key_commitment(pubkey)` (sub-project 3) gives each member's commitment.

### 2. Decoy selection (`engine/privacy/ringct/decoy.rs` — new)
```rust
/// Pick `count` distinct real confidential outputs as ring members, skipping any
/// pubkey in `exclude` (e.g. the real output being spent and already-chosen
/// members). Returns None if fewer than `count` eligible outputs exist.
pub fn select_decoys(
    utxo_set: &UtxoSet,
    count: usize,
    exclude: &[String],   // one-time pubkey hex to skip
) -> Option<Vec<RingMember>>;
```
Algorithm: `total = confidential_output_count()`. Repeatedly sample a random index
in `[0, total)` (OsRng), fetch the pubkey via `confidential_output_at`, skip if in
`exclude` or already chosen or its commitment is missing; collect until `count`
distinct members or give up after a bounded number of attempts
(`> total` distinct eligible impossible ⇒ return None). Each member =
`RingMember { public_key: point_from_hex(pubkey)?, commitment:
point_from_hex(output_key_commitment(pubkey)?)? }`.

> A real wallet builds a ring by calling `select_decoys(count = ring_size - 1,
> exclude = [own_output_pubkey])` and inserting its own output at a random index.
> That assembly + random-position insertion lives in 4c-ii (wallet); 4c-i delivers
> the selection primitive + index.

## Testing

- **Index round-trip:** apply a block with K confidential outputs (via the 4a
  builder + `apply_block_dag_ordered`); `confidential_output_count() == K`;
  `confidential_output_at(i)` returns each output's one-time pubkey.
- **select_decoys happy path:** with M recorded outputs, `select_decoys(n,
  exclude)` (n < M) returns n distinct members, none in `exclude`, each with the
  commitment recorded for its pubkey (`output_key_commitment`).
- **select_decoys insufficient:** `select_decoys(n, exclude)` returns None when
  eligible outputs < n (e.g. all but n−1 excluded).
- **Integration oracle:** record real outputs; `select_decoys` a ring; assemble an
  `OwnedInput` whose real member is one recorded output and whose decoys come from
  `select_decoys`; build via the 4a builder; assert `verify_confidential_tx` is
  Ok (decoys are genuine on-chain outputs, so ring-member authenticity passes).
- **Regression:** existing apply/UTXO tests still pass; counter starts at 0 and
  increments only for confidential outputs (transparent/coinbase do not bump it).

## Non-goals (4c-ii / later)
- Wallet key management, scanning whole chains into wallet state, ring assembly
  with random real-position insertion, CLI/RPC `send-confidential` /
  `receive`/`balance`, fee/decoy-count policy. (4c-ii, with the app running.)
- Decoy-selection *distribution* tuning (gamma/recent-output bias like Monero) —
  uniform sampling here; a weighted policy is a later refinement.
- Pruning/spent-output handling in the index (the index is append-only; spentness
  is tracked separately by key images).

## Risks
- **Uniform decoy distribution** is weaker than Monero's recency-weighted gamma
  pick (a known heuristic-deanonymization vector). Acceptable for 4c-i; documented
  as a follow-up. Not a consensus/soundness issue (consensus only checks members
  are real, not how they were chosen).
- Index/counter must be written in the same atomic batch as the okey/ki writes, or
  a crash could desync the count from entries — covered by writing all in the
  existing `apply_block_dag_ordered` WriteBatch.
- Append-only index grows unbounded — same as the UTXO/okey sets; pruning is a
  separate concern.
