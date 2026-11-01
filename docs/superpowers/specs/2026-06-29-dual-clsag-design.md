# Design: Dual-Key CLSAG Primitive (RingCT sub-project 1 of 4)

**Date:** 2026-06-29
**Parent:** Full RingCT (confidential amounts). Sub-projects: **(1) dual-key CLSAG
primitive** → (2) confidential TX data model + serialization → (3) consensus
verification on the block path → (4) wallet build + scan.
**Status:** Approved (design), pending spec review.

## Problem

`engine/privacy/ringct/clsag.rs` implements a **single-key** ring signature
(proves knowledge of one spend key in a ring). It does NOT bind the amount, so it
cannot support confidential amounts: a spender could form a ring mixing a small
and a large output and spend the large value while only owning the small one. Real
RingCT requires a **dual-key CLSAG** that, in one signature, proves the signer
knows (a) the spend key `p` for `P_π` AND (b) the blinding offset `z` such that the
output commitment minus the per-input pseudo-output commitment equals `z·G`. The
challenge must also bind the key image, the ring, and the commitments (audit
finding R4).

This sub-project delivers ONLY the cryptographic primitive + its tests. No
transaction data-model, consensus, or wallet wiring (those are sub-projects 2-4).

## Goal

A `dual_clsag` module exposing `sign` / `verify` / `key_image` that implements the
standard CLSAG construction over curve25519-dalek **Ristretto** (consistent with
the project's Pedersen commitments and stealth addresses, which are Ristretto).
Correctness is established by sign/verify roundtrips plus an adversarial test
battery and frozen self-generated known-answer fixtures (Monero's published KATs
are ed25519/Keccak and do not apply to a Ristretto/SHA-512 construction).

## Why Ristretto (not ed25519/Keccak, not an external crate)

- The dual-key's second dimension operates on the **same group as the Pedersen
  commitments**, which are Ristretto. An ed25519/Keccak CLSAG (to match Monero
  KATs or reuse a Monero crate) would require rewriting Pedersen + stealth — a
  large, pointless fork.
- Existing Rust CLSAG crates are ed25519-based and not drop-in for Ristretto.
- Ristretto removes cofactor/torsion handling: points are always in the
  prime-order group and equality is canonical, so the Monero `·8` / subgroup
  checks are unnecessary.

## Construction (standard CLSAG, dual-key, on Ristretto)

Ring of `n` members; member `i` has spend key `P_i` and commitment `C_i`. Signer
at index `π` knows `p` (`P_π = p·G`) and `z = r_π − r'` where `C_π − C' = z·G`
(`C'` = the per-input pseudo-output commitment; the amount term cancels because
`C'` commits to the same amount as `C_π`).

Key images: `I = p·H_p(P_π)`, `D = z·H_p(P_π)` where `H_p` is hash-to-point.

Aggregation coefficients (domain-separated SHA-512 → Scalar over the full ring +
images):
```
μ_P = H("CLSAG2_agg_P_v1" || {P_i} || {C_i} || C' || I || D)
μ_C = H("CLSAG2_agg_C_v1" || {P_i} || {C_i} || C' || I || D)
```
Per-member aggregated key `W_i = μ_P·P_i + μ_C·(C_i − C')`; aggregated image
`W_I = μ_P·I + μ_C·D`. The signer knows `w = μ_P·p + μ_C·z` with `W_π = w·G` and
`W_I = w·H_p(P_π)`.

Signing (constant-time loop of exactly `n−1` steps regardless of `π`, as the
current clsag.rs does — issue #25):
```
α random
c_{π+1} = H_c("CLSAG2_chal_v1" || msg || {ring} || C' || (α·G) || (α·H_p(P_π)))
for each i ≠ π (around the ring):
    L_i = s_i·G + c_i·W_i
    R_i = s_i·H_p(P_i) + c_i·W_I
    c_{i+1} = H_c("CLSAG2_chal_v1" || msg || {ring} || C' || L_i || R_i)
s_π = α − c_π·w
```
Output `{ c0 = c[0], s[0..n], key_image = I, d = D }`.

Verification recomputes the challenge chain from `c0` using `W_i`/`W_I`
(recomputed from the signature's `I`,`D` and the supplied ring + `C'`), and
accepts iff the final challenge equals `c0`. Empty ring and `s.len() != n` are
rejected; `I` and `D` must decompress.

The current single-key clsag is the degenerate `μ_C = 0` case; this generalizes it.

## API (`engine/privacy/ringct/dual_clsag.rs`)

```rust
pub struct RingMember {
    pub public_key: RistrettoPoint, // P_i
    pub commitment: RistrettoPoint, // C_i
}

pub struct DualCLSAGSignature {
    pub c0: Scalar,
    pub s: Vec<Scalar>,                 // one per ring member
    pub key_image: CompressedRistretto, // I
    pub d: CompressedRistretto,         // D
}

/// I = spend_secret · H_p(public_key)
pub fn key_image(spend_secret: &Scalar, public_key: &RistrettoPoint) -> RistrettoPoint;

/// commitment_secret = z = (blinding of C_π) − (blinding of pseudo_out).
pub fn sign(
    message: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint, // C'
    secret_index: usize,
    spend_secret: &Scalar,       // p
    commitment_secret: &Scalar,  // z
) -> Result<DualCLSAGSignature, CryptoError>;

pub fn verify(
    message: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint,
    sig: &DualCLSAGSignature,
) -> bool;
```

`sign` returns `CryptoError::InvalidRingIndex` if `secret_index >= ring.len()`.
Internally `α`, `w`, and the secret scalars are wrapped in `zeroize`. Byte/hex
(de)serialization of `DualCLSAGSignature` extends `serialization.rs` (already
rejects non-canonical scalars and undecompressable points) — added in this
sub-project so tests can round-trip, but consumed by sub-project 2/3.

## Security model & invariants

- Soundness rests on the standard CLSAG argument: a valid signature implies the
  signer knows `w = μ_P·p + μ_C·z`, i.e. both the spend key and the blinding
  offset — so the amount is bound (the verifier need not know `z`).
- Challenge + aggregation hashes bind: message, every `P_i` and `C_i`, the
  pseudo-output `C'`, and both key images `I`,`D` → no cross-ring reuse, no
  key-image substitution, no commitment swap.
- Constant-time signing; no secret-dependent branching/indexing.
- All inputs validated as canonical Ristretto/Scalar on the verify path.
- **External cryptographic review is REQUIRED before mainnet.** This spec is a
  faithful adaptation of a published construction, not a novel scheme, but
  money-critical crypto must be independently reviewed.

## Testing (compensating for the absence of Monero KATs)

1. **Roundtrip:** ring sizes {1, 2, 11}; for size 4 and 11, every signer index.
2. **Adversarial reject:** tampered `s[i]`, `c0`, `key_image`, `d`, or a ring
   member; wrong `message`; wrong `pseudo_out`; cross-ring (sig valid for ring A
   rejected for ring B with same message); key-image substituted from another
   key.
3. **Amount binding:** a signature produced with `commitment_secret = z` verifies
   iff `C_π − pseudo_out == z·G`; a `z'` that does not open the offset fails.
4. **Linkability:** same `(p, P)` ⇒ identical `key_image`; different keys ⇒
   different.
5. **Encoding:** `DualCLSAGSignature` byte/hex round-trips; truncated / non-canonical
   / undecompressable inputs return `None` (no panic).
6. **Property tests (proptest):** random ring size, signer index, message, blindings
   ⇒ sign then verify is always true; any single-byte mutation ⇒ verify false.
7. **Frozen KAT fixtures:** generate once from fixed seeds, commit the resulting
   signature bytes; a regression test re-derives and asserts equality so future
   refactors cannot silently change the construction.

## Non-goals (later sub-projects)

- Transaction fields, pseudo-output construction across multiple inputs, balance
  equation `Σ C'_in = Σ C_out + fee·H` (sub-projects 2/3).
- Consensus wiring, key-image store, okey index, range proofs (sub-project 3).
- Wallet decoy selection, blinding balancing, stealth outputs, scanning
  (sub-project 4).
- Replacing/removing the existing single-key `clsag.rs` (done in sub-project 3).

## Risks

- **Construction error = catastrophic (money printing).** Mitigations: faithful
  adaptation of a published scheme, the adversarial + amount-binding test battery,
  frozen KATs, and a hard requirement of external review before mainnet.
- No cross-implementation KAT (Ristretto/SHA-512 is project-specific). Mitigated
  by amount-binding + cross-ring + property tests that would catch a broken
  construction, not just a self-consistent one.
