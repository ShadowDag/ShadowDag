# Design: Confidential TX Consensus Verification (RingCT sub-project 3 of 4)

**Date:** 2026-06-29
**Parent:** Full RingCT. Sub-projects: (1) dual-key CLSAG ✅ → (2) data model +
serialization ✅ → **(3) consensus verification on the block path** → (4) wallet
build + scan.
**Status:** Approved (design), pending spec review.
**Depends on:** (1) `dual_clsag`, (2) `tx_confidential` parse views + RangeProof
serialization, `pedersen::verify_balance`, `range_proof::verify`, the `ki:` /
`okey:` stores on `UtxoSet`.

> ⚠️ **HIGHEST-RISK component in the project.** This is where confidential
> transactions become consensus-valid. A flaw = money printing or a chain split.
> External cryptographic review is REQUIRED before mainnet.

## Problem

Today confidential transactions are not soundly verified by consensus (audit
R1/R2/R6): the CLSAG gate runs only in the mempool path; `validate_block_utxos`
and the live apply path `apply_block_dag_ordered` do not verify ring signatures,
do not check amounts homomorphically, do not record key images, and treat a
confidential input as a transparent spend (Ed25519 ownership + plaintext balance
on `input.txid`). With sub-projects 1+2 in place (dual-key CLSAG + data model +
parse views), this sub-project wires **sound** confidential verification into the
block validation and apply paths.

## World model (decided)

**Two separate worlds.** A confidential transaction spends only confidential
outputs and produces only confidential outputs. Authorization and double-spend
prevention are entirely via the ring signature + key image — a confidential input
does **not** reference a spendable transparent UTXO (`txid`/`index` are not used
to look up value or ownership). Transparent transactions are unchanged.
Transparent↔confidential bridging (shield/unshield) is explicitly out of scope.

## Goal

For every `tx.is_confidential()` transaction, block validation
(`UtxoValidator::validate_block_utxos`) runs a confidential gate, and block apply
(`UtxoSet::apply_block_dag_ordered`) records key images + output keys atomically.
A confidential transaction is consensus-valid iff: every ring member is a real
on-chain confidential output (P **and** C match), every input's dual-key CLSAG
verifies over the canonical message, every key image is unseen and unique, every
output's range proof verifies, and the commitments balance
`Σ C'_in == Σ C_out + fee·H`. The mempool path uses the **same** gate (no
mempool/block divergence).

## Components

### 1. Confidential signing message (extend `tx_hash.rs`)
`confidential_signing_message_for_network` currently binds outputs
(address/amount/commitment/ephemeral) + inputs (outpoint/key_image/ring_members)
+ fee + payload_hash. Extend it to also bind, per output, the `one_time_pubkey`
and (for confidential) treat `commitment` as the value commitment; and per input,
the `ring_commitments` and `pseudo_commitment`. The per-input ring `(P_i,C_i)` and
`pseudo_out` are *also* bound inside the dual-CLSAG itself; binding them here too
ties the whole transaction together so outputs/pseudo/key-images cannot be
swapped across signatures. Versioned tag stays `SHADOW_TX_CONF_SIGN_V1` →
bump to `_V2` (format changed).

### 2. `okey:` store now binds P → C (modify `UtxoSet`)
Change `record_output_key` / `output_key_exists` to a key→value store:
`okey:{one_time_pubkey_hex}` → `commitment_hex` (bytes). Add
`output_key_commitment(pk_hex) -> Option<String>` returning the recorded
commitment. Ring-member authenticity checks both the pubkey exists AND its
recorded commitment equals the ring member's `C_i`.

### 3. Confidential consensus gate (`engine/privacy/ringct/confidential_consensus.rs` — new)
```rust
/// Full confidential verification for one tx (no chain mutation). `seen_ki` is
/// the in-block key-image set (caller threads it across the block for intra-block
/// double-spend detection).
pub fn verify_confidential_tx(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    network: &NetworkMode,
    seen_ki: &mut HashSet<String>,
) -> Result<(), StorageError>;
```
Steps (fail-closed, descriptive errors):
1. `tx.outputs` non-empty; `tx.inputs` non-empty.
2. For each input: `parse_confidential_input` → view (None ⇒ reject).
   - For every ring member `(P_i, C_i)`: `utxo_set.output_key_commitment(P_i_hex)`
     must be `Some(c)` with `c == C_i_hex` (real on-chain output, authentic
     commitment).
   - `view.key_image == view.signature.key_image`; `key_image_hex` not in `ki:`
     store and not already in `seen_ki` (insert it).
   - `dual_clsag::verify(msg, &view.ring, &view.pseudo_out, &view.signature)`
     where `msg = confidential_signing_message_for_network(tx, network)`.
3. For each output: `parse_confidential_output` → view; `range_proof::verify(
   &view.commitment, &view.range_proof)` must hold.
4. **Balance:** `pedersen::verify_balance(&pseudo_outs, &output_commitments, tx.fee)`
   where `pseudo_outs[i] = view_i.pseudo_out`, `output_commitments[j] =
   out_view_j.commitment`. Must be true.
5. No transparent input/ownership/plaintext-balance checks for confidential inputs.

### 4. Wire into block validation (`utxo_validator.rs`)
In `validate_block_utxos`, after the coinbase branch and before the transparent
input loop, add:
```rust
if tx.is_confidential() {
    verify_confidential_tx(tx, utxo_set, &network, &mut seen_key_images)?;
    // confidential outputs are NOT staged into the transparent staged_outputs map
    continue;
}
```
`validate_block_utxos` gains the authoritative `NetworkMode` (audit H-net also
wants this) — thread it from `FullNode::process_block`; default mainnet only if
the caller cannot supply it. A block-level `seen_key_images: HashSet<String>`
spans all txs in the block.

### 5. Record in the live apply path (`utxo_set.rs::apply_block_dag_ordered`)
For each confidential tx in the same atomic `WriteBatch` that applies the block:
- each input's `key_image` → `ki:` (value `[1]`);
- each output's `one_time_pubkey` → `okey:` (value = `commitment_hex`), and a
  confidential UTXO record so it is spendable/decoy-eligible.
Transparent txs unchanged. (This fixes audit R2: recording was in the non-live
`apply_block_write_with_commitment`.)

### 6. Replace the phase-1 single-key path
`TxValidator::validate_confidential` (single-key, from audit remediation) is
superseded: re-point it to call `verify_confidential_tx` (or remove its callers
in favor of the new gate) so mempool and block use one code path. Remove the
single-key `RingValidator::verify_clsag` reliance for the consensus decision
(keep the file for now; deletion is a cleanup).

## Testing (adversarial, the real proof)

A test helper builds a fully-valid confidential block (reusing dual_clsag +
pedersen + range_proof), seeding `okey:` with the ring members' (P,C). Then:
- **Accept:** valid 1-in/2-out and 2-in/2-out confidential txs pass
  `verify_confidential_tx` and `validate_block_utxos`; `apply_block_dag_ordered`
  records the key images + output keys.
- **Reject, fail-closed (each its own test):**
  - unbalanced (inflate an output amount / mismatched pseudo) → balance fails;
  - bad / wrong range proof → reject;
  - ring member not in `okey:` → reject;
  - ring member P present but recorded C ≠ supplied C_i → reject;
  - key image already in `ki:` (cross-block double-spend) → reject;
  - duplicate key image within the block → reject;
  - tampered dual-CLSAG → reject;
  - message swap (move an output between two otherwise-valid txs) → reject.
- **No divergence:** the same tx is accepted/rejected identically by the mempool
  entry point and `validate_block_utxos`.
- **Determinism / statelessness:** confidential reads (`okey:`/`ki:`) happen only
  in the L4/UTXO stage (`validate_block_utxos`), never in stateless L1–L3.
- **Regression:** full transparent-tx suite still green; genesis/coinbase stable.

## Non-goals (sub-project 4 / later)
- Wallet construction of confidential txs (decoy selection, pseudo-output blinding
  balancing, stealth outputs), and scanning/recovery → sub-project 4.
- Shield/unshield bridging between transparent and confidential.
- Fee confidentiality (fee stays public; balance uses public `fee·H`).
- Deleting the legacy single-key clsag module (cleanup later).

## Risks
- **Catastrophic if wrong.** Mitigations: each defense has a dedicated
  fail-closed test; balance + range + ring-authenticity + key-image are
  independent layers; verification reads stay in the stateful stage; one code
  path for mempool + block (no divergence); external review required.
- **Consensus-format/behavior change:** confidential txs that previously were
  rejected (or treated transparently) now follow a new path. Pre-launch network ⇒
  acceptable; full suite + fresh fixtures confirm transparent path unaffected.
- **okey value format change** (set→map): the `okey:` store had no production
  writers yet (audit R2), so no migration concern.
