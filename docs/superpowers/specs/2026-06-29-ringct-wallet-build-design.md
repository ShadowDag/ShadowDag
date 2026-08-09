# Design: Confidential TX Builder (RingCT sub-project 4a of 4)

**Date:** 2026-06-29
**Parent:** Full RingCT. Sub-projects: (1) dual-key CLSAG ✅ → (2) data model ✅ →
(3) consensus verification ✅ → **(4) wallet**, itself decomposed into:
**4a builder+sign** → 4b amount-encoding + scan/recover → 4c decoy selection +
CLI/wallet integration.
**Status:** Approved (design), pending spec review.
**Depends on:** (1) `dual_clsag`, (2) data model + `tx_confidential`, (3)
`verify_confidential_tx` (used as the acceptance oracle in tests),
`pedersen`/`range_proof`, `domain::address::stealth_address`.

## Problem

Nothing constructs a confidential transaction yet — only test helpers do.
This sub-project provides the builder that, given the spender's secrets and a ring
of decoys per input, produces a `Transaction` that passes the consensus gate
`verify_confidential_tx`: balanced pseudo-output commitments, stealth outputs with
Pedersen commitments + range proofs, and a valid dual-key CLSAG per input.

## Goal

A pure builder function:
```rust
pub struct OwnedInput {
    pub spend_secret: Scalar,      // x: one-time spend key of the real output
    pub amount: u64,               // real input amount
    pub blinding: Scalar,          // r_real: blinding of the real input commitment
    pub ring: Vec<RingMember>,     // decoys + real, as (P_i, C_i)
    pub real_index: usize,         // position of the real output in `ring`
}
pub struct ConfRecipient {
    pub view_pub: RistrettoPoint,  // recipient view public key
    pub spend_pub: RistrettoPoint, // recipient spend public key
    pub amount: u64,
}
pub fn build_confidential_transaction(
    inputs: Vec<OwnedInput>,
    recipients: Vec<ConfRecipient>,
    fee: u64,
    network: &NetworkMode,
) -> Result<Transaction, CryptoError>;
```
Acceptance oracle: the returned tx satisfies
`verify_confidential_tx(&tx, &set, network, &mut seen)` when `set` has the ring
members recorded in `okey:` — i.e. **a wallet-built tx is consensus-valid**.

## Data flow

1. **Amount check:** `Σ inputs.amount == Σ recipients.amount + fee`, else
   `CryptoError`. Each input's `ring[real_index]` must open to
   `(amount, blinding)` (i.e. `C_real == amount·H + blinding·G`); else error.
2. **Outputs:** for each recipient, derive a stealth one-time address +
   ephemeral pubkey via `stealth_address::generate_full_for_network`, choose an
   output blinding `r_out`, build `C_out = amount·H + r_out·G`, and a range proof
   `range_proof::prove(amount, &r_out)`. Store hex `commitment`, `range_proof`,
   `ephemeral_pubkey`, `one_time_pubkey` on the `TxOutput` (amount field = 0).
3. **Blinding balance:** pick a random pseudo-blinding `r'_i` per input; pick
   random `r_out` for every output except the last, and set the last output's
   `r_out_last = Σ r'_i − Σ (other r_out)`. This makes `Σ C'_in == Σ C_out +
   fee·H` (the H terms already match because amounts balance). Requires ≥1 output.
4. **Inputs:** for each input, `C'_i = amount·H + r'_i·G` (pseudo-output);
   `z_i = blinding − r'_i` (so `C_real − C'_i = z_i·G`); set `ring_members`,
   `ring_commitments`, `pseudo_commitment`, and `key_image =
   dual_clsag::key_image(spend_secret, ring[real_index].public_key)`.
5. **Sign:** compute `tx.hash` placeholder (consensus uses `canonical_bytes`; the
   builder sets `tx_type=Confidential`, fee, timestamp, then computes the
   confidential message and signs). For each input,
   `dual_clsag::sign(msg, &ring, &C'_i, real_index, &spend_secret, &z_i)` →
   `ring_signature` hex. Key image set BEFORE computing the message (the message
   binds it).
6. Return the assembled `Transaction`.

## Components / files

- New: `engine/privacy/ringct/builder.rs` — `OwnedInput`, `ConfRecipient`,
  `build_confidential_transaction`, plus small private helpers.
- Modify: `lib.rs` — declare `pub mod builder;` under ringct.
- Reuses: `stealth_address` (one-time address + ephemeral), `pedersen`/generator
  H, `range_proof::prove`, `dual_clsag::{sign, key_image, to_hex}`,
  `tx_hash::confidential_signing_message_for_network`.

## Testing

- **Builds a consensus-valid tx:** construct N owned inputs (each with a real
  output + decoys), M recipients; record all ring members in a fresh `UtxoSet`
  `okey:`; build; assert `verify_confidential_tx` is `Ok`. Cover 1-in/1-out,
  2-in/2-out, and 1-in/3-out (multiple outputs exercise blinding balance).
- **Balance correctness:** the built tx's pseudo-outputs and output commitments
  satisfy `RealPedersenCommitment::verify_balance`.
- **Rejects bad construction:** `Σ in != Σ out + fee` → builder errors; an input
  whose `ring[real_index]` does not open to `(amount, blinding)` → errors.
- **Determinism of structure:** building twice yields txs that both verify (values
  differ because of random blindings/ephemerals — assert verifiability, not
  equality).
- **Tamper after build:** flipping an output commitment makes
  `verify_confidential_tx` fail (sanity that the builder isn't bypassing checks).

## Non-goals (4b/4c)
- Amount encoding so the recipient recovers the amount (`encrypted_amount` field,
  Monero-style derived blinding + masked amount) — sub-project 4b. Until then the
  recipient cannot auto-recover; the builder just produces valid outputs.
- Scanning/recovery, one-time spend-key derivation for the receiver — 4b.
- Automatic decoy selection from an enumerable chain index, wallet/CLI wiring — 4c.
- Fee privacy (fee stays public).

## Risks
- Builder bugs produce invalid txs (rejected by consensus) — caught by the
  acceptance-oracle tests; not a money risk (consensus still gates).
- Blinding-balance arithmetic is the sharp edge — covered by multi-output tests
  and the `verify_balance` assertion. Must NOT special-case the single-output path
  in a way that hides a multi-output bug.
- Secrets (`spend_secret`, blindings, `z`) are zeroized where held.
