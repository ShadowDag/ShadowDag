# ShadowDAG — External Cryptographic + Consensus Review Dossier

**Date:** 2026-07-06 · **Branch:** `feature/privacy-hdwallet-docs` · **Purpose:** single entry point for the
MANDATORY independent review that gates mainnet. This document scopes the review, lists the exact
consensus/crypto changes to audit, points to the detailed artifacts, and poses specific questions per area.

> **Honesty / limits (read first).** This dossier and all internal reviews it references are *preparation*, not a
> substitute for an independent audit. A time-boxed review **reduces** risk; it does not prove the absence of bugs.
> Nothing here is self-certified: every consensus/crypto item below is listed **because it needs an external
> cryptographer + consensus auditor**, not because it is believed safe. Findings are separated into **proven**
> (a checked reduction/test), **assumed** (relied upon, not independently verified), and **unknown/open**.
> Recommendation stands regardless of internal results: commission a **professional audit firm** and, for the
> RingCT and PoW cores, **formal verification** + KAT/property fuzzing before mainnet.

---

## 1. System under review

ShadowDAG (v1.0.0) is a **hybrid** of three lineages — audit each interface where they meet:
- **Ethereum → EVM** (`runtime/vm/`): account model, ShadowVM opcode set, gas schedule, precompiles.
- **Monero → privacy** (`engine/privacy/ringct/`, `engine/privacy/confidential/`): Pedersen commitments, range
  proofs, dual-key CLSAG ring signatures, stealth/one-time keys, shield (transparent→confidential) bootstrap.
- **Kaspa → GHOSTDAG** (`engine/dag/`, `engine/consensus/`): blockDAG ordering, blue score, tips, difficulty
  retarget; PoW is version-gated ShadowHash → UmbraHash (memory-hard, `header.version>=3`).

Threat model to assume: active MITM + chosen-ciphertext + **malicious miner/validator** (inflation, forgery,
double-spend, de-anonymization) + a future quantum adversary for long-lived secrets. A change is "secure" only
relative to this model.

---

## 2. Scope — the exact changes/areas requiring review

Ranked by risk. Each references the file(s), the commit, and the detailed artifact.

### 2.1 RingCT / confidential composition — **INFLATION + DE-ANON RISK (highest)**
The crown jewels. Detailed internal pass: `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`.
- **Primitives** (`engine/privacy/confidential/pedersen.rs`, `engine/privacy/ringct/range_proof.rs`,
  `engine/privacy/ringct/dual_clsag.rs`): generator independence (H = nothing-up-my-sleeve), homomorphic balance
  `Σ C_in = Σ C_out + fee·H`, the **hand-rolled 64-bit Borromean range proof** (internal review flags it the
  WEAKEST link — thin Fiat-Shamir; non-exploitable in isolation but replace with vetted **Bulletproofs**), dual-key
  CLSAG (`w = μ_P·p + μ_C·z`, fresh OsRng α + zeroize, identity-KI reject).
- **Shield tx** (`engine/privacy/ringct/confidential_consensus.rs::verify_shield_tx`): `C_in_i = A_i·H + r_i·G`
  from the CHAIN amount; type separation; okey freshness. Spec: `docs/superpowers/specs/2026-07-04-shield-tx-design.md`.
- **Confidential SEND end-to-end** (NEW this session): builds + PASSES the CLSAG/balance/range gate live, but the
  **block-enforcement is NOT finalized** — see §2.2. Two parallel CLSAG modules (`clsag.rs` + `dual_clsag.rs`)
  should be consolidated.

### 2.2 RingCT block-enforcement gap — **THE #1 CONSENSUS OPEN ITEM**
`TxValidator::verify_signatures_for_network` (`domain/transaction/tx_validator.rs:944` → `verify_single_input:973`)
requires a transparent Ed25519 sig on every input, so it **rejects ring-signed confidential inputs** (empty
signature/pub_key). It is called with NO `is_confidential` guard on the **mempool** (`service/mempool/core/mempool.rs:545`),
**block validation** (`engine/consensus/validation/block_validator.rs:399/409`, BEFORE the ring stage L2c:421), and
**apply** (`domain/utxo/utxo_set.rs:1195`). Consequences: confidential sends can never enter a block, and the
block-path ring check (`RingValidator::validate`, `engine/privacy/ringct/ring_validator.rs`) is **structural-only**
(the legacy forgeable `RingSignature`, `engine/privacy/ringct/ring_signature.rs` — B1-L03). **Finalizing this = a
consensus change to block validity + inflation risk.** The fix must: (a) make `verify_signatures_for_network` skip
confidential/ring inputs, (b) run the FULL CLSAG gate (`verify_confidential_tx`, not the structural `RingValidator`)
on mempool + block + apply, (c) enforce okey/key-image on apply, (d) delete the forgeable legacy `RingSignature`.
**Do not ship without this review.** (An implementation attempt is tracked separately but is explicitly
review-gated.)

### 2.3 GHOSTDAG ordering deferrals — **CONSENSUS (deferred, need reachability)**
Both change the DAG ordering for EVERY node (a hard fork of ordering); deferred because a correct fix needs a
reachability capability the codebase lacks. Detail in the audit doc §Medium (B1-M02/M03).
- **B1-M02** (`engine/dag/ghostdag/ghostdag.rs:356`): anticone approximated as `blues ∉ past`, ignoring blues in
  the block's *future* → legit-blue blocks flipped red.
- **B1-M03** (`engine/dag/ghostdag/ghostdag.rs:392`): `get_past_set` truncates at 16 384 nodes → corrupt
  anticone/merge-set on a mature chain. A naïve cap-removal reintroduces the B1-C01 unbounded-walk DoS — needs a
  Kaspa-style **reachability index** (interval labels / cached past-sets).

### 2.4 Hard-fork VM / gas schedule — **CONSENSUS (gas determinism)**
All are version-gated or immediate consensus and were flagged review-gated when landed:
- `EXP` per-exponent-byte gas + `EXP_GAS_PER_BYTE=50` (`runtime/vm/core/execution_env.rs`, commit `0b374fb`, B5-L01).
- `LOG` per-byte data gas `LOG_DATA_GAS_PER_BYTE=8` (`execution_env.rs`, commit `189b452`, B5-M01).
- `modexp` EIP-198 zero-length-modulus → empty output (`runtime/vm/precompiles/math_precompiles.rs`, `0b374fb`, B5-L02).
- `ecrecover`/`ripemd160` real precompiles + Ed25519 `verify_strict` (`189b452`, B5-M02).
Question surface: is the gas metering **deterministic + non-manipulable** across nodes/platforms, and does it match
the intended schedule (base + per-byte) exactly?

### 2.5 Consensus / difficulty + block validity — **CONSENSUS**
- Difficulty retarget full-window average (`engine/consensus/difficulty/retarget.rs::compute_average_time_integer`,
  commit `0b374fb`, B1-L01) — verify determinism + no oscillation; interaction with the DAG-rate correction and the
  `max_span` anti-timewarp clamp (a raised-but-refuted concern is documented in the audit doc's L4 review).
- Dropped the `nonce == u64::MAX` block reject (`engine/dag/security/dos_protection.rs`, `0b374fb`, B1-L02) — verify
  no sentinel elsewhere depends on it.

### 2.6 PoW — UmbraHash (memory-hard) — **CONSENSUS / mining**
`engine/mining/pow/` — memory-hard Ethash-style + mini-ProgPoW ALU. Spec:
`docs/superpowers/specs/2026-07-04-memory-hard-pow-design.md`. Verify: no algebraic/differential shortcut, cheap
asymmetric verify, version-gate correctness. (This dossier is the external review the PoW-design work said to
commission.) A prior internal review found + fixed 1 CRITICAL + 2 HIGH PoW-DoS.

### 2.7 Areas internally reviewed and believed clean — **CONFIRM, don't assume**
Nothing survived internal verification here, but treat as *assumed*, not proven: hashes, Ed25519/Schnorr/
Dilithium/Falcon, CSPRNG seeding, the RocksDB storage layer, RPC auth, the DoS-guard, genesis/emission config.
Ask the reviewer to independently confirm CSPRNG seeding and constant-time secret handling.

---

## 3. What was reviewed internally (feeds, does NOT replace this review)
- Full line-by-line audit: `docs/superpowers/audits/2026-07-05-full-codebase-line-by-line-audit.md` (38 confirmed;
  33 fixed, 5 deferred to this review).
- Shield + UmbraHash + RingCT-primitives internal adversarial review:
  `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`.
- L4 hard-fork adversarial workflow (2026-07-06): 5 independent reviewers + verify pass → 0 confirmed defects
  (documented in the audit doc's "Low-tier remediation status").
- RingCT design specs: `2026-06-29-dual-clsag-design.md`, `2026-06-29-ringct-consensus-design.md`,
  `2026-06-29-confidential-txmodel-design.md`, and the 4c-ii wallet design.

These are *inputs* for the external reviewer to check, not evidence of safety.

---

## 4. Specific questions for the reviewer

**RingCT/crypto:**
1. Is the hand-rolled Borromean range proof sound, or must it be replaced by Bulletproofs before any confidential
   value on mainnet? Is its Fiat-Shamir transcript binding enough given `L + Σ2^i·C_i == C`?
2. Is dual-key CLSAG's `w = μ_P·p + μ_C·z` construction and transcript free of the ECDSA-`k`-reuse class of bug?
   Confirm α freshness/zeroize and identity-KI rejection on every path.
3. Does `verify_shield_tx` / `verify_confidential_tx` fully prevent inflation (balance + range + okey/KI uniqueness)
   under a malicious builder?

**Consensus enforcement:**
4. §2.2 — is the proposed RingCT block-enforcement (skip transparent sig for ring inputs + full CLSAG on all three
   paths + apply-path okey/KI enforcement) sound and inflation-safe? This is the gating change.
5. §2.3 — is the reachability-index approach correct for B1-M02/M03 without reintroducing the unbounded-walk DoS?
6. §2.4/2.5 — are the gas-schedule + retarget changes deterministic across nodes and free of manipulation/oscillation?

**PoW:** 7. Any shortcut/bias in UmbraHash? Is verify cheap enough for the target block rate?

---

## 5. Recommended external tooling / engagements
Professional audit firm for the full system; **formal verification** for RingCT balance/soundness and the PoW
version gate; KAT/test vectors for every primitive (all-zero key, boundary nonces, max-length inputs);
constant-time verification (dudect/ctgrind / Trail of Bits ct tooling) for secret handling; differential/property
fuzzing (cryptofuzz) for the range proof + CLSAG; and replacing the hand-rolled range proof with a vetted
Bulletproofs implementation (dalek).

**Hard gate:** no mainnet until §2.1–2.6 are cleared by the independent review.
