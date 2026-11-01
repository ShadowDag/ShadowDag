# Design: Confidential Amount Encoding + Scan/Recover (RingCT sub-project 4b of 4)

**Date:** 2026-06-29
**Parent:** Full RingCT → sub-project 4 (wallet). 4a builder ✅ → **4b amount
encoding + scan/recover** → 4c decoy selection + CLI/wallet wiring.
**Status:** Approved (design), pending spec review.
**Depends on:** 4a builder, sub-projects 1-3, `stealth_address` (ECDH), `pedersen`,
`dual_clsag`, `verify_confidential_tx` (round-trip oracle).

## Problem

A confidential output produced by 4a hides its amount, but the recipient has no
way to learn the amount/blinding or derive the spend key — so received funds
cannot be detected or spent. RingCT solves this by deriving the output blinding
and an amount mask from the sender↔recipient ECDH shared secret, and publishing
the masked amount on-chain. This sub-project adds that encoding, an
`encrypted_amount` output field, and the scanning/recovery path. It also flips
4a's blinding-balance direction so output blindings can be derived (and thus
recovered).

## Goal

A sender-built confidential output carries an `encrypted_amount`; a recipient
holding the view key can scan, confirm ownership, decrypt the amount, recover the
blinding, verify the commitment opens to `(amount, blinding)`, and (with the spend
key) derive the one-time spend secret — producing an `OwnedInput` the 4a builder
can spend and consensus accepts. **Round-trip closes the loop: build → scan →
recover → spend → verify.**

## Key change vs 4a: balance direction flips to the input side

In 4a, output blindings were random and the **last output** absorbed the balance
difference. For the recipient to recover an output blinding, it must be
**derived deterministically from the shared secret** — so the sum of output
blindings is fixed. The balance (`Σ C'_in == Σ C_out + fee·H`) is therefore made
to hold by choosing the **input pseudo-output blindings** so that
`Σ r'_in == Σ derived_out_blindings`, with the **last input's pseudo-blinding
absorbing** the difference. This is the Monero model and requires ≥1 input
(already guaranteed). 4a's builder is updated accordingly.

## Components

### 1. Amount/blinding derivation (`engine/privacy/ringct/amount_encoding.rs` — new)
All derived from the ECDH shared secret `ss` (a `RistrettoPoint`) and the output
index, with domain separation:
```rust
/// Commitment blinding for an output: Hs("...commit_mask_v1" || ss || idx).
pub fn derive_blinding(ss: &RistrettoPoint, index: u32) -> Scalar;
/// 8-byte one-time pad: first 8 bytes of SHA256("...amount_v1" || ss || idx).
pub fn amount_mask(ss: &RistrettoPoint, index: u32) -> [u8; 8];
/// encrypted = amount.to_le_bytes() XOR mask.
pub fn encrypt_amount(amount: u64, mask: &[u8; 8]) -> [u8; 8];
pub fn decrypt_amount(enc: &[u8; 8], mask: &[u8; 8]) -> u64;
```
Hex helpers for the 8-byte field. `derive_blinding` uses `Scalar::from_hash`
(SHA-512); `amount_mask` uses SHA-256 truncated to 8 bytes. Both bind `ss` (its
compressed bytes) and `index` (LE u32).

### 2. Output field (`domain/transaction/transaction.rs`)
Add `TxOutput.encrypted_amount: Option<String>` (hex, 8 bytes). Bind it in
`canonical_bytes` and in `confidential_signing_message_for_network` (bump tag to
`SHADOW_TX_CONF_SIGN_V3`). Additive; transparent/coinbase set `None`.

### 3. Stealth ECDH exposure (`domain/address/stealth_address.rs`)
Expose the shared secret so sender and recipient derive identical secrets:
- A generator variant returning the `ss` point alongside the existing
  `StealthAddressResult` (e.g. `generate_full_with_secret(...) ->
  (StealthAddressResult, RistrettoPoint /* ss */)`), where `ss = r·view_pub`.
- A scan helper returning `ss` to the recipient: `recipient_shared_secret(
  ephemeral_R: &RistrettoPoint, view_priv: &Scalar) -> RistrettoPoint` (`ss =
  view_priv·R`). (The existing `scan_for_network` ownership check stays; this adds
  the ss accessor used for amount/blinding.)

### 4. Builder update (`engine/privacy/ringct/builder.rs`)
- For each recipient output: compute `ss`, `blinding = derive_blinding(ss, idx)`,
  commitment `C_out = amount·H + blinding·G`, range proof, and
  `encrypted_amount = encrypt_amount(amount, &amount_mask(ss, idx))`.
- Input pseudo-blindings: random for all but the last input; the last input's
  pseudo-blinding `= Σ derived_out_blindings − Σ(other pseudo-blindings)`.
- Everything else (rings, key images, dual-CLSAG, message) unchanged.

### 5. Scan / recover (`engine/privacy/ringct/scan.rs` — new)
```rust
pub struct RecoveredOutput {
    pub amount: u64,
    pub blinding: Scalar,            // matches the on-chain commitment
    pub one_time_pubkey: RistrettoPoint,
}
/// Returns Some(recovered) iff this output is addressed to the wallet
/// (view_priv, spend_pub) AND its commitment opens to (decrypted_amount,
/// derived_blinding). `output_index` is the output's position in its tx.
pub fn scan_confidential_output(
    output: &TxOutput, output_index: u32, view_priv: &Scalar, spend_pub: &RistrettoPoint,
) -> Option<RecoveredOutput>;
/// Derive the one-time spend secret x for a recovered output (needs spend_priv):
/// x = Hs_stealth(ss) + spend_priv  (so x·G == one_time_pubkey).
pub fn recover_spend_secret(
    output: &TxOutput, view_priv: &Scalar, spend_priv: &Scalar,
) -> Option<Scalar>;
```
Ownership = recomputed one-time address equals `output.address` (reuse stealth
`scan_for_network`) AND commitment-open check. The amount/blinding/spend-key
derivations reuse the same `ss` and the existing
`stealth_address::derive_one_time_private_key`.

## Testing

- **Encoding unit:** `encrypt`→`decrypt` round-trips for 0, 1, u64::MAX; mask
  differs per `ss`/index; `derive_blinding` deterministic + differs per ss/index.
- **Scan happy path:** build an output to a known (view, spend) keypair; scan with
  the view key → `Some` with the exact amount; the recovered blinding opens the
  commitment (`amount·H + blinding·G == C_out`).
- **Scan negatives:** an output addressed to a different recipient → `None`; a
  tampered `encrypted_amount` → recovered amount no longer opens the commitment →
  `None`.
- **Spend-key recovery:** `recover_spend_secret` yields `x` with
  `x·G == one_time_pubkey`.
- **Full round-trip (the oracle):** A builds a tx paying B (amount V); B scans,
  recovers `(amount=V, blinding, one_time_pubkey)` and `x`; assemble an
  `OwnedInput` (B's recovered output as the real member of a fresh decoy ring
  recorded in `okey:`); B builds a spend of V−fee to C; assert the spend passes
  `verify_confidential_tx`. This proves received funds are detectable AND
  spendable.
- **Builder regression:** 4a's existing build tests still pass after the
  balance-direction flip (now with derived output blindings).

## Non-goals (4c)
- Enumerable on-chain decoy index + automatic decoy selection (tests supply rings).
- Wallet state / scanning whole blocks / CLI commands.
- Subaddresses, multiple receive keys, payment IDs.

## Risks
- **Balance-flip regression:** moving absorption to the input side must keep
  `verify_balance` true; covered by 4a's multi-output tests (re-run) + the
  round-trip. Do not keep both absorption strategies — exactly one (input side).
- Amount mask is a one-time pad keyed by `ss` and index — never reuse a mask
  across outputs sharing the same `ss` (distinct `index` ensures this); documented.
- Consensus-format change (`encrypted_amount` in canonical_bytes / V3 message) —
  additive, transparent/coinbase unaffected; full suite + fixtures confirm.
- External cryptographic review still required before mainnet.
