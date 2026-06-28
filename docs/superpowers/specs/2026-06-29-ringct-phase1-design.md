# Design: Confidential Transactions (RingCT) — Phase 1: Consensus Verification Core

**Date:** 2026-06-29
**Track:** C (of 3 parallel tracks: docs / HD wallet / RingCT phase 1)
**Status:** Approved (design), pending spec review
**Scope:** Phase 1 only. Phases 2 (wallet build/scan) and 3 (UTXO/mempool
integration polish) get their own specs later.

## Problem

The privacy crypto primitives are implemented and tested — CLSAG ring signatures
(`engine/privacy/ringct/clsag.rs`), real Pedersen commitments
(`engine/privacy/confidential/pedersen.rs`), and Borromean range proofs
(`engine/privacy/confidential/range_proof.rs`) — but nothing connects them to
consensus. Today `engine/privacy/ringct/ring_validator.rs` does structural-only
checks and then **rejects all confidential transactions** behind a
`#[cfg(not(feature = "ringct_bypass"))]` gate. The bypass feature is the only way
to let a privacy TX pass, and it is compile-blocked in release builds.

Two reasons it isn't wired:
1. **Type mismatch.** `TxInput.ring_members` is `Option<Vec<String>>` (hex) and
   `TxInput.key_image` is `Option<String>`; there is no field for the CLSAG
   signature itself. `CLSAGSignature`, `RealPedersenCommitment`, and `RangeProof`
   are not serde-serializable (they hold curve types).
2. **Plaintext balance model.** Consensus balance checks compare plaintext `u64`
   amounts (`domain/transaction/tx_validator.rs` ~L337–347, L687–716). Confidential
   amounts are hidden in Pedersen commitments and must be checked homomorphically.

## Goal (Phase 1)

Make consensus **correctly verify** a fully-formed confidential transaction:
ring signatures cryptographically valid, amounts conserved homomorphically, range
proofs valid, key images unique and unseen, and ring members proven to be real
on-chain outputs. After Phase 1, a confidential TX constructed by a test harness
(real wallet construction is Phase 2) is accepted iff it is cryptographically and
economically valid; remove the blanket rejection gate.

## Threat model / what Phase 1 must prevent

| Attack | Defense in Phase 1 |
|--------|--------------------|
| Forge a ring signature | `clsag::verify(message, ring, sig)` over canonical message |
| Spend with fake/non-existent decoy keys | Ring members must exist in on-chain **output-key index**; reject otherwise |
| Inflate supply via hidden amounts | Homomorphic balance: `Σ C_in == Σ C_out + fee·H` |
| Negative / overflow output amounts | Range proof per output (value ∈ [0, 2^64)) |
| Double spend | Global **key-image store**; reject seen/duplicate key images |
| Replay across chains/reorgs | Confidential signing message binds chain id + payload_hash |

## Architecture

### 1. Serialization layer (foundation)
New module `engine/privacy/ringct/serialization.rs` (and/or per-type
`to_bytes`/`from_bytes`):

- `CLSAGSignature` ↔ bytes: `c0 (32) || len(s) (u32) || s_i (32 each) ||
  key_image (32)`.
- `RangeProof` ↔ bytes: length-prefixed `bit_commitments`, `challenges`,
  `responses[2]` (all 32-byte canonical scalars/points).
- Pedersen **commitment point** ↔ bytes: 32-byte compressed Ristretto **only**.
  The secret `value`/`blinding` of `RealPedersenCommitment` are NEVER serialized
  into a TX.
- All wrap to/from hex for the existing `String` TX fields. Every `from_bytes`
  validates canonical encoding (reject non-canonical points/scalars).

### 2. Transaction data-model additions
In `domain/transaction/transaction.rs`:

- Add `TxInput.ring_signature: Option<String>` (hex of serialized
  `CLSAGSignature`). The existing `signature` field stays Ed25519-only for
  transparent inputs. `ring_members` continues to carry the ring as hex
  compressed points (redefine its contents from arbitrary decoy strings to
  **compressed one-time pubkeys**).
- `commitment` / `range_proof` / `ephemeral_pubkey` already exist on `TxOutput`.
- Update `canonical_bytes()` to include `ring_signature` deterministically (it is
  part of TX identity but, like Ed25519 `signature`, is **excluded from the
  signing message** — see §3).

### 3. Confidential signing message (v2)
New function in `domain/transaction/tx_hash.rs`:
`confidential_signing_message_for_network(tx, network) -> [u8;32]`.

Binds (length-prefixed, deterministic order): domain tag
`b"SHADOW_TX_CONF_SIGN_V1"`, chain id, tx.timestamp, tx.fee, each output's
`address || commitment || ephemeral_pubkey`, each input's `txid || index ||
key_image || ring_members`, and `payload_hash`. **Excludes** `ring_signature`
and `signature` (circularity). Transparent TXs keep the existing v1 message.

### 4. Output-key index (decoy authenticity)
New RocksDB namespace `okey:` mapping `compressed_one_time_pubkey -> (txid,
index)` (or a membership set keyed by the pubkey). Populated when an output is
added to the UTXO set during block execution. Consensus rejects any
`ring_members` entry not present in this index.

> Phase-1 boundary: the index is **written** during block execution in Phase 1 so
> verification has data to check against; producing confidential outputs from a
> real wallet is Phase 2. Tests seed the index directly.

### 5. Key-image store (double-spend)
New RocksDB namespace `ki:` = set of spent key images. On confidential input
verification: reject if key image already in store or duplicated within the block;
insert on block commit (atomic `WriteBatch`, same transaction as UTXO updates).
This replaces the `spent` flag for confidential inputs (the input UTXO is hidden
in the ring, so we cannot mark a specific UTXO spent).

### 6. Verification wiring (the core)
Rewrite `RingValidator::validate` (`engine/privacy/ringct/ring_validator.rs`) and
the confidential branch of `tx_validator.rs`:

For a `TxType::Confidential` transaction:
1. Keep existing structural checks (key image format, ring size 4..=64, key-image
   uniqueness within TX).
2. For each input: deserialize `ring_members` → `Vec<RistrettoPoint>`,
   `ring_signature` → `CLSAGSignature`; verify every ring member exists in `okey:`;
   compute `message = confidential_signing_message_for_network(tx)`; require
   `clsag::verify(message, &ring, &sig) == true`; the input's `key_image` must
   equal `sig.key_image`.
3. Key-image checks against `ki:` store + intra-block set.
4. **Balance:** gather input commitments (from the UTXO/commitment store, see §7)
   and output commitments (from `TxOutput.commitment`); require
   `pedersen::verify_balance(inputs, outputs, fee)` i.e.
   `Σ C_in − Σ C_out − fee·H == 0`.
5. **Range proofs:** for each output, `range_proof::verify(commitment, proof) ==
   true`.
6. Remove the `#[cfg(not(feature="ringct_bypass"))]` rejection gate. The
   `ringct_bypass` feature is deleted or repurposed (decide during impl; default:
   delete, since real verification now exists).

### 7. UTXO commitment storage (minimal, Phase 1)
`domain/utxo/utxo.rs` `Utxo` gains `commitment: Option<String>` and
`one_time_pubkey: Option<String>` so a confidential input can be balance-checked
and serve as a ring member. Transparent UTXOs leave these `None`. Storage
read/write paths updated. (Full wallet-side population is Phase 2; Phase 1 wires
the read path for verification + write path during execution + tests.)

## Backward compatibility

- Transparent `Transfer` TXs are unchanged: same v1 signing message, same
  plaintext balance path, `ring_signature` = `None`.
- The confidential path is a separate branch keyed on `tx_type ==
  Confidential` / presence of commitments.
- This is a **consensus-format change** (new fields in canonical bytes, new
  stores). Since the network is pre-launch / testnet, no migration of live data is
  assumed; genesis and existing tests must be re-validated.

## Testing (Phase 1 gates)

- Unit (serialization): round-trip every type; reject non-canonical/truncated
  bytes; reject tampered scalars/points.
- Unit (message): determinism; transparent vs confidential messages differ;
  changing any bound field changes the message.
- Integration (verify happy path): construct a valid confidential TX in a test
  harness (real CLSAG sign + real commitments + real range proofs + seeded
  `okey:` index) → `RingValidator::validate == true`.
- Integration (each defense fails closed):
  - forged/tampered CLSAG → reject
  - ring member not in `okey:` index → reject
  - unbalanced commitments (inflation attempt) → reject
  - bad/negative range proof → reject
  - duplicate key image in block → reject; replay of seen key image → reject
  - wrong-message signature (replay across TXs) → reject
- Regression: existing transparent-TX tests still pass; block validation L1–L3
  remains stateless (no new DB reads moved into stateless layers — key-image /
  okey / commitment reads happen in the L4 execution/UTXO stage only).

## Open items deferred to Phase 2/3 (explicitly NOT in Phase 1)

- Wallet construction of confidential TXs (`build_confidential_transaction`),
  decoy selection policy, blinding-factor balancing, stealth output creation.
- Wallet scanning/recovery of incoming confidential outputs + amount decode.
- Mempool key-image conflict detection and eviction interplay.
- Fee privacy (fee remains public in Phase 1; balance uses public `fee·H`).

## Risks

- **Highest-risk area in the whole project.** A wiring bug = forgeable money or a
  chain split. Mitigation: every defense has an explicit fail-closed test;
  verification reads stay in the stateful L4 stage; no change to the stateless
  L1–L3 invariant.
- Canonical-bytes change invalidates previously-mined test fixtures/genesis —
  must regenerate and re-verify in the same change.
- Performance: range-proof + CLSAG verification per input is expensive; Phase 1
  prioritizes correctness, not throughput (batching is a later optimization).
