All line references confirmed against source. Here is the full pre-audit report.

---

# ShadowDAG — Internal Pre-Audit Cryptographic Report (Privacy + PoW Surfaces)

**Date:** 2026-07-15 · **Branch:** `feature/privacy-hdwallet-docs` · **Author:** internal lead-cryptographer pass
**Companion to:** `docs/superpowers/audits/2026-07-06-external-review-dossier.md` and `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`

> This report **prepares** the mandatory external audit. It does **not** certify the system. It is a time-boxed adversarial pass over the RingCT/confidential, stealth-address, and UmbraHash/PoW surfaces, in which every candidate finding was re-verified refute-first against the source and, for the load-bearing items, line references were confirmed by hand (see verification note at the end). It **complements** the two prior dossiers: where they established the shield-conservation reduction, the dual-CLSAG/pedersen/range-proof primitive assessment, and the two already-fixed pre-PoW DoS vectors (`aebd91d`, `ec24c8e`) plus the latent version-gate floor (`975366f`, `UMBRA_ACTIVATION_HEIGHT`), this pass adds **net-new confirmed defects** not enumerated there and re-frames the PoW downgrade risk with proof that the legacy algorithm is actually cheap.

---

## 1. Scope, method, and honest limitations

**Surfaces covered (files read in full during the pass):**
- CLSAG + dual-key CLSAG (`engine/privacy/ringct/{clsag,dual_clsag,ring_signature,ring_validator}.rs`)
- Pedersen / range proof / amount encoding (`engine/privacy/confidential/{pedersen,range_proof}.rs`, `engine/privacy/ringct/{amount_encoding,confidential_consensus,tx_confidential,scan,serialization}.rs`)
- Key image / ring validation / decoys (`engine/privacy/ringct/{key_image,decoy}.rs` + consensus wiring)
- Stealth addresses & view/spend keys (`engine/privacy/stealth/*`, `domain/address/{stealth_address,key_derivation}.rs`)
- Shield composition (`builder.rs`, `confidential_consensus.rs`, `tx_validator.rs`, `utxo_set.rs`)
- UmbraHash PoW (`engine/mining/algorithms/{umbrahash,shadowhash,hash_mix,anti_asic}.rs`, `engine/mining/pow/pow_validator.rs`)

**Method.** Five-layer crypto-review lens (primitive → composition → implementation → key-management → threat-model), one finding at a time, each subjected to an independent refute-first verification pass. 22 candidate findings were raised; **10 confirmed as real defects**, **2 confirmed as "no-defect / sound"** positive results, **12 refuted as false positives**.

**Limitations (read before relying on anything here):**
- **Time-boxed and internal.** This reduces risk; it does not prove absence of bugs. It is **not** a substitute for the external cryptographer + consensus auditor that gates mainnet.
- **The custom primitives' soundness is *assumed*, not proven.** The hand-rolled Borromean range proof and both CLSAG variants are assumed to reduce to ECDLP-on-Ristretto in the ROM; no external reduction or machine-checked proof exists.
- **No fuzzing, no KATs, no constant-time instrumentation was run** in this pass — those are explicit external-audit asks (§5).
- **Every item is labelled proven / assumed / unknown** in §4 so the external auditor sees exactly what has and has not been established.

---

## 2. Confirmed findings (severity-ranked)

Severity uses the adversarially-adjusted rating (the raw scanner rating in parentheses where it differed).

### F-1 · HIGH (raw: critical) — Memory-hardness is optional: cheap legacy ShadowHash is co-valid at the same difficulty
**`engine/mining/algorithms/umbrahash.rs:366`** (gate at `engine/mining/pow/pow_validator.rs:48-59`; version reject at `engine/consensus/validation/block_validator.rs:254`)

- **Mechanism.** `pub const UMBRA_ACTIVATION_HEIGHT: Option<u64> = None;` makes `umbra_required_at(height)` return false at **every** height (`umbrahash.rs:370-376`), so the version floor in `PowValidator::validate` never fires. Version-1/2 headers are routed to the legacy `shadow_hash` path; only `version == 0` is rejected. Both paths compare a 256-bit hash to the **same** `target = MAX_TARGET / difficulty`, and difficulty is retargeted only to block rate. Consequently the network's effective PoW cost is the **minimum** of the two algorithms, not UmbraHash. Combined with F-2 (ShadowHash is actually cheap), a miner runs v2 ShadowHash at a fraction of honest UmbraHash cost and finds blocks at the same difficulty → cheap majority hashpower / selfish mining / double-spend, and honest memory-hard mining is economically pointless.
- **Relationship to prior work.** The 2026-07-05 dossier flagged this as latent finding #4 ("fix before the fork ships") and scaffolded the enforcement (`975366f`). This pass **confirms it is live today** on any deployment where honest miners run UmbraHash while consensus still accepts ShadowHash at the same target — i.e. the current testnet posture.
- **Fix.** Set `UMBRA_ACTIVATION_HEIGHT = Some(fork_height)` and, at/after it, **reject `version < UMBRA_POW_VERSION` at consensus** (in `validate` and the sync verifier), not merely via the `None`-gated floor. Until the two algorithms are separated they must **not** share one difficulty domain — give each PoW its own retargeted difficulty, or (preferred) retire ShadowHash entirely at the fork so exactly one cost floor exists.

### F-2 · HIGH — Legacy ShadowHash "memory-hardness" is fake (fixed access pattern, streamable, ASIC/CPU-cheap)
**`engine/mining/algorithms/shadowhash.rs:112`** (init `:102-109`, addressing `:113-119`, final hash `:130-132`; anti-ASIC layer `anti_asic.rs`)

- **Mechanism.** The 256 KB scratchpad provides no memory-latency hardness. Init computes each 32-byte chunk as `SHA256(round1 || i)` — fully independent/regenerable. The mix loop runs only `MIX_ROUNDS = 16` iterations, and both `idx` (`:113`) and `rot_idx` (`:119`) are pure functions of `round1[..]` and constants — **no read of a scratchpad value ever selects an address**, so there is no data-dependent latency chain. An ASIC/optimizer precomputes the ≤16 touched addresses, computes only those chunks, runs the tiny 16-round mix, and streams the final `SHA256`-over-256 KB while patching the ≤16 modified windows — **no 256 KB of DRAM, no random-latency stalls**. The whole thing reduces to SHA256 work, which SHA256 ASICs (the most mature hardware in existence) crush. `AntiAsic::harden_bytes` adds only a 16 KB (L1-resident) scratchpad with data-dependent *branching* (not addressing) — negligible. Contrast genuine memory-hardness in UmbraHash (`umbrahash.rs:118`, `cache_index` depends on the value just read). The file's own doc-comments ("forces memory bandwidth dependency", "ASICs cannot gain >2x", "defeat ASIC pipelining for at least 10 years") are false as implemented.
- **Fix.** Do not keep ShadowHash as a co-valid PoW. If a legacy path must remain for pre-fork blocks, hard-gate it strictly **below** the activation height and never let it be mineable at/after the fork. Remove the "memory-hard / ASIC-resistant" claims from the source. (F-1 and F-2 are the same economic vulnerability from two angles: F-1 is the availability of the cheap path, F-2 is the proof that it *is* cheap. Fix them together.)

### F-3 · MEDIUM — Pre-PoW epoch-cache amplification DoS via attacker-chosen block height
**`engine/mining/pow/pow_validator.rs:188`** (`recompute_identity_hash`; also `umba_check` cache call `:148`; unvalidated callers `service/network/relay/block_relay.rs:226`, `service/network/nodes/light_node.rs:89`)

- **Mechanism.** `recompute_identity_hash` runs on **unvalidated peer headers before the PoW/target check**. For `version >= 3` the only pre-cache guard is `if header.height > UMBRA_MAX_HEIGHT { return String::new(); }` (`:181`). With `UMBRA_MAX_HEIGHT = 1e12` and `EPOCH_BLOCKS = 3e6`, heights ≤ 1e12 span ~**333,333 distinct epochs**, all of which reach `cache_for_epoch(epoch_of(height))` (`:188`). On a miss the build closure runs `epoch_seed(epoch)` (SHA3-256 chained `epoch` times, O(epoch)) plus `mkcache` (16 MiB ≈ ~1M SHA3-512, hundreds of ms). A stream of headers whose heights fall in many *different* epochs defeats the 3-slot LRU (`MAX_EPOCH_CACHES = 3`), so every message is a cache **miss** → hundreds of ms CPU + 16 MiB allocation each, and (because `cache_for_epoch` holds a global mutex) also stalls honest validation.
- **Relationship to prior work.** This is the **residual** of dossier findings #1 (`aebd91d`, the `u64::MAX` single-call case) and #2 (`ec24c8e`, 2-epoch thrash). The `> 1e12` sentinel and the 3-slot LRU do **not** cover the many-distinct-epoch aggregate. The code's own TODO (`umbrahash.rs:341`) admits the tip-relative bound is missing.
- **Fix.** Before any `epoch_seed`/`mkcache` work on an unvalidated header, reject heights outside a tight **tip-relative** window (`tip_height + small_future_slack`); fire the absurd-height sentinel on that bound, not just 1e12. Additionally memoize `epoch_seed` incrementally and consider per-peer rate limiting of expensive-epoch header admission.

### F-4 · LOW — `clsag::verify` does not reject an identity key image (inconsistent with dual_clsag hardening)
**`engine/privacy/ringct/clsag.rs:145`**

- **Mechanism.** Single-key `verify` decompresses `sig.key_image` (`:145`) and runs ring closure but never checks `ki.is_identity()`. The sibling `dual_clsag::verify` explicitly rejects it (`dual_clsag.rs:192-194`, imports `IsIdentity` at `:21`, regression test present). Ring closure forces `I = x·H_p(P_π)`, so `I = identity` is only reachable if a ring member is itself the identity point (x=0); if an identity one-time key were ever admitted, spending it yields a constant identity key image decoupled from the spend key (degenerate linkability / self-griefing, not theft). This is the audit-known CR1 class (`2026-06-29-deep-consensus-hunt.md:229`), fixed for dual_clsag only.
- **Fix.** After decompressing `sig.key_image`, add `if ki.is_identity() { return false; }` (import `curve25519_dalek::traits::IsIdentity`), mirroring `dual_clsag.rs:192-194`.

### F-5 · LOW — Range-proof challenge hashes `usize` bit index with platform-width `to_le_bytes` (32- vs 64-bit consensus divergence)
**`engine/privacy/confidential/range_proof.rs:215`** (`bit_challenge`, declared `:212`)

- **Mechanism.** `hasher.update(bit_index.to_le_bytes());` where `bit_index: usize`. `usize::to_le_bytes()` is **platform-width** — 8 bytes on 64-bit, 4 bytes on 32-bit — so the SHA-512 preimage length (and every challenge scalar) differs by architecture, even though indices are only 0..63. `prove()` stores these challenges and `verify()` recomputes them (`:195,:201`) with an equality gate (`:203`), so a proof produced on a 64-bit node fails `verify()` on a 32-bit verifier → **cross-architecture consensus divergence / chain split on otherwise-valid confidential/shield outputs**. The sibling `amount_encoding.rs` already uses fixed-width `u32` for its index, confirming this file is the outlier. Practically unrealized (production is ~all 64-bit) hence low, but it is genuine non-determinism in consensus-critical hashing.
- **Fix.** Encode the index at fixed width: `(bit_index as u32).to_le_bytes()`. Ship as a **versioned** change since it alters proof bytes.

### F-6 · LOW — Range-proof prover is not constant-time (branches on each secret amount bit)
**`engine/privacy/confidential/range_proof.rs:90`** (secret bit at `:62`, branch spans `:90-134`)

- **Mechanism.** `let bit = (value >> i) & 1;` then `if bit == 0 { … } else { … }` is a data-dependent branch on each secret amount bit. A local co-resident / timing / EM adversary observing a wallet constructing a range proof could infer bits of the otherwise-hidden amount. Scope is the sender's own secret; `verify()` is data-oblivious over public inputs; branches are near-symmetric, so leakage is marginal. (Note: `Scalar::from(bit) * h` at `:77` is **not** a leak — dalek scalar-mult is constant-time; the only vector is the `if/else`.)
- **Fix.** If side-channel resistance is in scope for wallet signing, restructure the per-bit prover to branch-free form (compute both simulations, `conditional_select` via `Choice`), or explicitly document that range-proof generation is not hardened against local side channels.

### F-7 · LOW — Uniform decoy selection is temporally biased, enabling heuristic deanonymization
**`engine/privacy/ringct/decoy.rs:47`** (`total` at `:31`)

- **Mechanism.** `select_decoys` draws each ring member `rng.gen_range(0..total)` — uniform over the **entire** global confidential-output index — while consensus (`verify_confidential_tx`) only checks members are real on-chain outputs and never constrains ring age. Real spends skew toward recent outputs, so within a ring the newest member is disproportionately the true spend. A passive analyst applies the classic pre-gamma Monero temporal heuristic (and correlated multi-ring analysis) to guess the real input with probability well above 1/N, eroding the anonymity set even at ring size ≥ `MIN_RING_SIZE`. Probabilistic privacy degradation, not a soundness break; the module doc-comment acknowledges it as future work.
- **Fix.** Replace uniform sampling with a recency-weighted (Monero-style gamma / log-normal spend-age) distribution over the output index so decoy ages match real spend ages; document that ring anonymity is heuristic until this lands.

### F-8 · LOW — View key kept in memory unzeroized and `Debug`-printable
**`engine/privacy/stealth/view_key.rs:141`** (`#[derive(Clone, Debug)]` at `:25`, `Drop` at `:142-148`)

- **Mechanism.** `ViewKey { scalar, key_bytes, key: String }` derives `Debug`, so any `{:?}` logs the private view scalar and hex. `Drop` zeros `key_bytes` but leaves `scalar` live (zeroing `key_bytes` does not overwrite the `Scalar`'s own bytes) and does `self.key = String::new()`, which deallocates the hex buffer **without wiping it** — the view-key hex survives in freed heap. The view private key is the recipient's whole-history scanning capability: its recovery deanonymizes every past/future incoming output (it cannot spend). Exploitation needs a secondary memory disclosure (core dump/swap/heap inspection) or accidental `{:?}` logging — classic key-hygiene profile. (The code comment claiming `Scalar` can't be zeroized in safe Rust is wrong — curve25519-dalek exposes a `zeroize` feature.)
- **Fix.** Remove `Debug` (or implement a redacting one), wrap the scalar in `zeroize::Zeroizing` / call `scalar.zeroize()` in `Drop`, and zeroize the `String` bytes in place before dropping. Apply the same to `StealthKeys` (`spend_private`, no zeroization at all).

### F-9 · LOW — Degenerate ephemeral R (identity point) is accepted, letting a malicious sender publicly deanonymize a stealth output
**`domain/address/stealth_address.rs:315`** (scan DH; scanner `engine/privacy/stealth/stealth_scanner.rs:76`; decode `:148`)

- **Mechanism.** `scan()`/`scan_with_ephemeral()` compute `ss = view_private * R` with no check that `R != identity`, and `CompressedRistretto(arr).decompress()` accepts the canonical all-zero identity encoding. If a sender sets `R = identity`, then `ss = v·identity = identity` for **any** view key, so `hs = SHA256(DOMAIN_DH ‖ identity ‖ tx_hash ‖ idx)` becomes a public constant (tx_hash/idx are on-chain) and `P = hs·G + S` depends only on the recipient's **published** spend key `S`. Any third party holding the advertised `(V,S)` recomputes the exact one-time key/address and links the output — DDH unlinkability collapses for that output. Privacy-only (spending still needs `s`); requires a malicious/buggy sender. Notably the codebase already rejects the identity point in analogous paths (`dual_clsag.rs:187-192`, `tx_validator.rs:1013`) but not here.
- **Fix.** Reject `R == RistrettoPoint::identity()` in `scan` / `scan_with_ephemeral` / `scan_confidential_output` and at consensus acceptance of confidential outputs, mirroring Monero's rejection of degenerate tx public keys.

### F-10 · LOW (latent) — Divergent second apply path records confidential/shield outputs incorrectly
**`domain/utxo/utxo_set.rs:731`** (`apply_block_write_with_commitment`, defined `:553`; correct live path `apply_block_dag_ordered`, `:816`)

- **Mechanism.** `apply_block_write_with_commitment` has **no** `is_confidential()/is_shield()` branch. Its output loop materializes **every** output as a transparent `Utxo::new(addr, addr, output.amount)` — for a hidden-amount confidential output this creates a 0-value transparent UTXO and pollutes MuHash — then records `okey_key(pk) = vec![1u8]` keyed on `output.ephemeral_pubkey` (`:731-738`). The live path instead records `okey_key(one_time_pubkey) = commitment`, appends an `okeyidx` entry, and `continue`s. So the wrong key, bogus `[1u8]` value, missing `okeyidx`, missing P→C binding, and a phantom transparent UTXO all diverge. **Not live today** purely by call-graph reachability: `apply_block_write_with_commitment ← apply_block_write ← {apply_block_full (genesis only, coinbase-only, `boot.rs:130`), apply_block ← BlockProcessor::handle_reorg (no production caller; live reorg uses `recompute_virtual_chain → apply_block_dag_ordered`)}`. If `handle_reorg` were ever wired, a shield/confidential tx in a reorged block would corrupt the confidential bucket and fork nodes. (The finding's genesis cite `full_node.rs:2936` is a stale line ref — genesis apply is `boot.rs:130` — but the claim stands.)
- **Fix.** Make `apply_block_write_with_commitment` handle `is_shield()/is_confidential()` identically to `apply_block_dag_ordered` (okey[one_time_pubkey]=commitment, okeyidx, ki, tx_seen, undo), **or** delete the dead reorg path and assert this function is genesis-only so a future non-genesis shield-bearing block cannot silently take it.

### F-11 · INFO — Transparent `StealthScanner` decides ownership on a 160-bit truncated address
**`engine/privacy/stealth/stealth_scanner.rs:108`** (truncation `:105-109`, equality `:111`; same in `domain/address/stealth_address.rs:319-324`)

- **Mechanism.** `expected_addr = prefix + hex(P.compress()[..20])` and ownership is `expected_addr == candidate_address` — only 160 bits of the 32-byte one-time pubkey are bound (80-bit collision, 160-bit second-preimage — below the 128-bit target). Not exploitable for theft (forging a spendable colliding `P''` is ~2^160), and the **live confidential path** (`engine/privacy/ringct/scan.rs:45`) compares the **full** point, so it is unaffected. Same posture as 160-bit Bitcoin/Ethereum addresses; flagged as hygiene.
- **Fix.** When `output.one_time_pubkey` is present, have the transparent scanner verify the full 32-byte expected `P` against it (as `scan_confidential_output` does) rather than relying on the truncated address string.

### Positive confirmations (no-defect results worth recording)
- **Shield value-conservation composition is sound** (`engine/privacy/ringct/confidential_consensus.rs:119`, `verify_shield_tx`). Attempted refutation failed: the amount is read only from the chain (`get_utxo`), `C_in = A·H + r·G` uses the shared commit primitive, `checked_add` sums inputs, every output is range-proven (`:156`) and plaintext-zero, and `verify_balance` (`:171`) enforces `Σ C_in == Σ C_out + fee·H`. Enforced before apply on all live paths (mempool, `utxo_validator.rs:204`, peer/reorg). Soundness reduces to Pedersen binding (`log_G(H)` unknown) + range-proof soundness — **correctly deferred to external crypto review.** This corroborates the 2026-07-05 dossier's shield reduction.
- **The live confidential double-spend / amount gate is `dual_clsag::verify` on all three consensus paths** (mempool `tx_validator.rs:561-567`, block `utxo_validator.rs:191-198`, reorg/apply). Verified during refutation of F-FP-1/4/5/9 below.

---

## 3. Considered and refuted (false positives / not live) — recorded so the external auditor need not re-derive them

Each was raised, then refuted against source. They are **not** live vulnerabilities; several remain worthwhile hygiene/tech-debt.

| # | Candidate | Why refuted | Residual |
|---|-----------|-------------|----------|
| FP-1 | Legacy `ring_signature.rs` unsound (XOR "group op", SHA256 key image, structural-only `verify`) | All facts true, but **dead w.r.t. consensus**: the broken XOR ring math has no non-test caller; the live confidential gate is `dual_clsag::verify`. `RingValidator::validate` is documented structural-only. | Delete/`#[cfg(test)]`-gate (remediation task #37); remove "suitable for testnet privacy" doc. |
| FP-2 | `clsag` challenge omits message length-prefix (FS ambiguity) | Layout is `domain(18) ‖ message(var) ‖ L(32) ‖ R(32)` — **one** variable field followed by two fixed tails ⇒ injective and tail-decodable; SHA-512 MD padding also prevents differing-length collisions. No ambiguity exists. | Length-prefix is optional style consistency. |
| FP-3 | Nonce `alpha` from `OsRng` only, no RFC6979 | Sampling the nonce from the OS CSPRNG is the standard, accepted construction; the key-recovery scenario requires the CSPRNG itself to repeat output (out-of-model). `alpha`/`w` are zeroized. | Hedged/deterministic nonces are defense-in-depth. |
| FP-4 | Single-key `clsag::verify` doesn't bind amounts (inflation) | `verify_clsag` has **no consensus caller** (only its own `#[cfg(test)]`). The live gate is `dual_clsag::verify`, which binds `C_π − pseudo_out`, plus range proofs + homomorphic balance. | Consolidate the two CLSAG modules (also a dossier ask). |
| FP-5 | Range-proof FS omits the statement `C_i` | `C_i` **is** absorbed indirectly via the hashed `L` points (standard AOS/Borromean); soundness holds under DL; cut-and-paste blocked because dual_clsag signs a message covering output commitments. | Hashing `C_i` directly is Bulletproofs-style hygiene. |
| FP-6 | `verify_balance` has no standalone protection | Both consensus entry points range-verify **every** output before calling `verify_balance`; the negative-output attack is rejected first. | Weld the two checks into one API / doc-invariant. |
| FP-7 | Dead `KeyImage`/`KeyImageStore` (SHA256, evicting cache) double-spend landmine | Genuinely dead (no non-test caller). Live double-spend uses `dual_clsag::key_image` + persistent `utxo_set.key_image_seen`. | Delete the dead module. |
| FP-8 | Engine `ViewKey::from_private_key` / `StealthScanner` derivation incompatible with live wallet | Never wired to the live wallet; each build/scan pairing is internally consistent and test-covered (64/64 detection). Failure only from a hypothetical cross-wiring. | One canonical (view,spend)+hs derivation; add cross-module round-trip test. |
| FP-9 | No unshield (confidential→transparent) path — asymmetric | Simply **absent** (grep hits only docs). A one-way sink is a usability limit, not a conservation defect. | Mirror the shield gate **if** unshield is ever added; re-review then. |
| FP-10 | Custom Borromean range proof unaudited / FS omits key | Each bit is an AOS 2-ring over `{C_i, C_i−H}`; out-of-range needs `log_G(H)`; Check-1 pins bits to value. No inflation path; finder conceded "no concrete break." | **Still get it externally reviewed** / consider Bulletproofs (this is the dossier's headline ask, not a refutation of the need for review). |
| FP-11 | Power-of-two dataset item count discards FNV mixing | At each `% n` a uniform operand is XORed at the low position, so the reduced address is uniform regardless of high-bit avalanche; the "prime avoids cycles" concern targets pure-arithmetic recurrences, not hash-driven ones. `light == full` preserved. | Prime item-count is a documented deferred style choice. |
| FP-12 | PoW pre-image omits state_root/receipt_root/utxo_commitment | `merkle_root` + parents **are** bound; all acceptance paths deterministically re-execute (Bitcoin model). state/receipt roots are format-checked then re-computed; `utxo_commitment` is a local non-consensus 64-bit integrity field (always `None`, never trusted). | None — confirm re-execution stays mandatory on all admission paths. |

No item was left **UNCERTAIN** — every candidate resolved to confirmed or refuted.

---

## 4. Per-surface proven / assumed / unknown

| Surface | Proven (checked reduction/test/refutation) | Assumed (relied on, not independently verified) | Unknown / open |
|---|---|---|---|
| **CLSAG / dual-CLSAG** | dual_clsag is the sole live confidential gate on all 3 paths; identity I/D rejected in dual_clsag; single-key `verify_clsag` not consensus-wired | Unforgeability + linkability reduce to ECDLP-on-Ristretto in ROM; SHA-512 FS transcript binds ring+pseudo-out+KIs | Machine-checked soundness proof; **F-4** identity gap in single-key clsag; consolidation of the two modules |
| **Pedersen / range proof / amount** | `verify_balance` equation correct; range-verify precedes balance on every live path; C_i bound via L points; balance blocks negative outputs | Borromean per-bit soundness (hand-rolled); H is nothing-up-my-sleeve with unknown `log_G(H)` | **F-5** platform-width index (consensus divergence); **F-6** non-constant-time prover; external validation / Bulletproofs migration |
| **Key image / ring validation / decoys** | Live double-spend uses dual_clsag KI + persistent store; ring members must be authentic on-chain outputs; dead SHA256 KeyImage unreachable | Ristretto canonicity rejects torsion/small-subgroup KI variants | **F-7** decoy temporal bias (deanon heuristic) |
| **Stealth addresses & view/spend keys** | Live confidential build/scan pairing consistent + round-trip tested; engine stealth module internally consistent | DDH unlinkability given fresh CSPRNG ephemeral per output; view→spend non-derivable | **F-8** view-key hygiene; **F-9** identity-R accepted; **F-11** 160-bit truncation (info) |
| **Shield composition** | Conservation reduction sound; enforced pre-apply on all live paths; dual-bucket rollback atomic | Same primitive assumptions as above | **F-10** divergent apply path (latent); RingCT block-enforcement finalization (dossier §2.2) |
| **UmbraHash PoW** | `light == full` (tested); UmbraHash proper composes SHA3 + Ethash DAG + mini-ProgPoW; power-of-two item count harmless | Ethash bandwidth-latency memory-hardness; SHA3-for-Keccak substitution sound | **F-1** downgrade live (no cost floor); **F-2** ShadowHash fake hardness; **F-3** residual epoch-cache DoS |

---

## 5. Concrete additions to strengthen the external-review dossier

These are **net-new** asks to append to `2026-07-06-external-review-dossier.md` (§2/§4/§5); they do not duplicate its existing items.

**New questions to put to the auditor:**
1. **PoW cost floor (F-1/F-2).** Is retiring ShadowHash at the fork (single uniform floor) preferable to per-algorithm difficulty domains? What activation-height + minimum-version-by-height rule closes the downgrade with no reorg-window ambiguity? Independently confirm ShadowHash offers ~zero memory-hardness and price the ASIC/CPU advantage.
2. **Cross-architecture consensus determinism (F-5).** Audit **all** consensus-critical hash preimages for platform-width or endianness-dependent encodings (`usize`, `to_le_bytes`/`to_ne_bytes` on `usize`, pointer-width casts). Require a fixed-width-encoding invariant and a differential test across 32/64-bit targets.
3. **Degenerate-point rejection as a global invariant (F-9, F-4).** Should identity/degenerate points be rejected uniformly at every DH / key-image / ephemeral-R site (not just dual_clsag)? Enumerate every `decompress()` that feeds a secret-scalar multiply.
4. **Decoy distribution (F-7).** Validate a gamma/log-normal spend-age model and whether consensus should bound ring-member age at all (sender-chosen distribution).
5. **Pre-validation resource bounds (F-3).** Confirm a tip-relative height/epoch bound before any `epoch_seed`/`mkcache`, and review every unvalidated-header admission path (relay/sync/light) for pre-PoW amplification.

**Primitives that need KATs / test-vectors (add to §5 tooling list):**
- **UmbraHash:** published KAT vectors for `epoch_seed`, `mkcache`, `calc_dataset_item`, and full `hashimoto_light`/`hashimoto_full` at fixed (height, header, nonce); a `light == full` differential fuzzer; a KAT proving `epoch_of`/cache determinism across builds. **UmbraHash is a custom composition of vetted primitives — the highest-risk PoW tier — and warrants a dedicated consensus-cryptographer engagement, not just a code read.**
- **Range proof:** boundary vectors (v = 0, 1, 2^63, 2^64−1, 2^64), a rejection KAT for `C_i = 2H + rG`, and a **32-bit vs 64-bit reproducibility vector** (directly exercises F-5).
- **dual-CLSAG / clsag:** signing/verification KATs at ring sizes {MIN, MAX}, an identity-KI rejection vector for **both** modules (F-4), and a tamper-vector suite (mutated member/commitment/pseudo-out).
- **Stealth:** an identity-R rejection vector (F-9) and a full-32-byte-vs-160-bit ownership vector (F-11).

**Where formal verification / a professional firm is warranted:**
- **Formal verification:** shield/RingCT balance-and-range soundness reduction, and the **PoW version-gate + single-cost-floor** state machine (F-1) — model that no height admits two algorithms at one target post-activation.
- **Professional firm (hard gate before mainnet):** full RingCT primitive review incl. the hand-rolled Borromean range proof (recommend replacing with vetted dalek Bulletproofs, per both prior dossiers), constant-time verification of wallet signing (dudect/ctgrind — directly covers F-6/F-8), and the UmbraHash composition + light==full equivalence for all inputs.
- **Standing hard gate unchanged:** no mainnet until the external cryptographer + consensus auditor clear the RingCT and PoW cores; this report only sharpens the target list.

---

### Verification note (per line-by-line standard)
Line references for every **confirmed** finding were re-checked against source in this pass: `umbrahash.rs:366` (`UMBRA_ACTIVATION_HEIGHT = None`), `clsag.rs:145` vs `dual_clsag.rs:192`/`:21`, `range_proof.rs:215`/`:90`/`:62`, `decoy.rs:47`/`:31`, `view_key.rs:25`/`:142-145`, `stealth_address.rs` DH sites, `utxo_set.rs:553`/`:731-738`/`:816`, `shadowhash.rs:112-119`/`:28-33`, and `pow_validator.rs:136`/`:181`/`:188`. The refutations reproduce the adversarial-verification reasoning already recorded per finding; the confirmed items were additionally hand-checked here. This remains an internal, time-boxed pass — not a certification, and not a substitute for the mandatory external audit.