# Shield + UmbraHash — Internal Security Review & External-Review Dossier

**Date:** 2026-07-05
**Scope:** the two pieces of *new* consensus-critical code that have not had an
external audit — the **Shield** transaction path (transparent → confidential)
and the **UmbraHash + mini-ProgPoW** memory-hard proof-of-work.
**Status of the code:** experimental / pre-mainnet. RingCT sender-privacy
enforcement in blocks is explicitly documented as *not yet fully
consensus-enforced* (see `README.md`), and UmbraHash is opt-in (`--pow=umbra`,
default block version = 2 / ShadowHash).

> **This is an INTERNAL review. It does NOT replace the mandatory external
> cryptographic + consensus audit required before mainnet.** Several primitives
> below were explicitly out of scope and MUST be reviewed by a cryptographer.
> Do not treat "fixed" items as certified — treat them as ready for external
> re-verification.

---

## Method

An adversarial multi-agent review covered 10 security dimensions across both
features. Each dimension read its in-scope files in full and reported findings;
every finding was then independently re-verified against the actual code by a
second pass instructed to *refute* it. The two crown-jewel files
(`confidential_consensus.rs::verify_shield_tx` and
`pow_validator.rs::umba_check`) were additionally read in full by hand and the
top findings confirmed against that reading (not just the agents' reports).

Files in scope:
- Shield / RingCT: `engine/privacy/ringct/confidential_consensus.rs`,
  `engine/privacy/ringct/builder.rs`, `domain/transaction/transaction.rs`,
  `service/wallet/core/wallet.rs`, `domain/utxo/utxo_set.rs`,
  `domain/utxo/utxo_validator.rs`, `domain/transaction/tx_validator.rs`,
  `engine/crypto/serialization.rs`.
- UmbraHash / PoW: `engine/mining/algorithms/umbrahash.rs`,
  `engine/mining/gpu/umbrahash.cl`, `engine/mining/gpu/umbra.rs`,
  `engine/mining/pow/pow_validator.rs`, `domain/block/block_header.rs`,
  `service/network/rpc/rpc_server.rs`, `bin/miner.rs`, plus the admission paths
  `service/network/relay/block_relay.rs`, `service/network/sync/chain_verifier.rs`,
  `service/network/nodes/light_node.rs`.

---

## Findings summary

| # | Severity | Area | File | Status |
|---|----------|------|------|--------|
| 1 | 🔴 CRITICAL | PoW DoS | `umbrahash.rs` epoch_seed | **FIXED** `aebd91d` |
| 2 | 🟠 HIGH | PoW DoS | `umbrahash.rs` cache_for_epoch | **FIXED** `ec24c8e` |
| 3 | 🟠 HIGH | RingCT integrity | `confidential_consensus.rs` (okey) | **FIXED (gate)** `0b47c24` |
| 4 | 🟠 HIGH (latent) | Fork activation | `pow_validator.rs` version gate | **OPEN — pre-fork** |
| 5 | 🟡 LOW | validate/apply divergence | `utxo_validator.rs` will_spend | **OPEN — hardening** |
| 6 | 🟡 LOW | txid binding (dead code) | `tx_validator.rs` ordering | **OPEN — hygiene** |
| 7 | ⚪ INFO | dead non-injective encoder | `serialization.rs` | **OPEN — hygiene** |

Out-of-scope for this review but REQUIRED for external audit: the cryptographic
primitives themselves — `engine/privacy/confidential/pedersen.rs`
(H/G generator independence, `verify_balance`), `range_proof.rs`, and
`ringct/dual_clsag.rs`. Nothing here validated those; the balance soundness of
Shield rests entirely on H being an independent generator with no known
discrete log to G.

---

## 1. CRITICAL — unbounded `epoch_seed` → remote node hang  *(FIXED aebd91d)*

`epoch_seed(epoch)` chained SHA3-256 `epoch` times with no upper bound, and
`epoch = header.height / EPOCH_BLOCKS` where `height` is attacker-controlled in
an **unvalidated** header. A single `version >= 3` header with
`height = u64::MAX` yields `epoch ≈ 6.15e12` — trillions of SHA3-256 rounds
(hours of single-threaded hashing) — executed **before any PoW/target check** on
the peer-block, orphan (`block_relay`), sync (`chain_verifier`), and light-node
paths. One header stalls a validating node. Reachable on the *current* build
because the v3 validation path is live even though honest miners use v2.

**Fix:** consensus height ceiling `UMBRA_MAX_HEIGHT = 1e12` (~3170 years at
10 BPS). Both UmbraHash entry points reject `height > ceiling` up front —
`umba_check` returns `Err`, `recompute_identity_hash` returns the empty sentinel
(a real hashimoto result is always 64 hex chars, so the cheap anti-spoof gate
still fails closed and does no cache work). Caps `epoch_seed` to a few-ms worst
case. Test: `umbra_rejects_absurd_height_without_cache_work`.

**For external review:** confirm the ceiling value and prefer, additionally, a
*tip-relative* height bound at the network/relay layer (reject height far beyond
the current tip before any UmbraHash work).

## 2. HIGH — single-slot epoch cache thrash → pre-PoW amplification DoS  *(FIXED ec24c8e)*

`cache_for_epoch` memoized only one epoch. Alternating two epochs across a
boundary (e.g. height 0 and height `EPOCH_BLOCKS`) forced a full 16 MiB
`mkcache` (~1M SHA3-512, hundreds of ms) on every header, pre-PoW, on the orphan
and sync paths — and evicted the honest current-epoch cache each time. No
work-proof needed to trigger it.

**Fix:** replaced the single slot with a small LRU (`MAX_EPOCH_CACHES = 3`) via a
pure, unit-tested `epoch_cache_lru` helper. Current + adjacent epochs stay
resident; 2-epoch alternation no longer evicts. Combined with finding #1's
ceiling, per-header pre-PoW cost is bounded. Test:
`epoch_cache_lru_keeps_recent_and_evicts_oldest`.

**Follow-up:** build `mkcache` outside the mutex; add the tip-relative bound.

## 3. HIGH — output one-time-key (okey) freshness not enforced  *(FIXED at the gates, 0b47c24)*

Neither `verify_shield_tx` nor `verify_confidential_tx` checked that an output's
`one_time_pubkey` (okey) is fresh (`output_key_exists` was used only in tests).
A sender could reuse an existing on-chain okey; apply's bare `okey->commitment`
Put overwrites the victim's record (its output becomes uncitable as a ring
member), and a reorg rollback then unconditionally deletes the shared okey entry,
destroying the victim's still-live output and desyncing the `okeyidx` index.

**Fix:** both gates now reject an output whose `one_time_pubkey` already exists on
chain (mirroring the `key_image_seen` guard) and reject an intra-tx duplicate.
Covers the mempool, block-validate, and reorg paths. Tests
`shield_rejects_reused_output_key`, `confidential_rejects_reused_output_key`.

**Remaining (documented, not yet fixed):** intra-block *cross-tx* OTK dedup, and
an authoritative okey-freshness guard inside `apply_block_dag_ordered` — because
the live block-acceptance path is documented as not fully gating on the shared
validator yet. These should land when RingCT block-enforcement is finalized.

## 4. HIGH (latent) — UmbraHash fork gated only by version, no activation floor  *(OPEN)*

The fork is selected purely by `header.version >= UMBRA_POW_VERSION` in
`validate()`, `recompute_identity_hash`, and `validate_header`. There is no
`activation_height` / minimum-version-by-height rule anywhere (the only version
rule is `version == 0` reject). Difficulty retarget is algorithm-agnostic, so a
`version = 2` ShadowHash block is accepted at the *same target* as a v3 block
while costing orders of magnitude less. Once the fork is intended active, an
attacker mines v2 and bypasses memory-hardness indefinitely.

Not live today (the fork is not activated; both algorithms are intentionally
valid pre-fork). **Must be fixed before the fork ships.**

**Recommended fix:** introduce `UMBRA_ACTIVATION_HEIGHT` and, at/after it, reject
`version < UMBRA_POW_VERSION` in `validate_consensus_layer` and the sync
verifier. The activation height is a governance/deployment decision — it should
be chosen by the project, which is why it is left open here rather than picked
unilaterally.

## 5. LOW — shield transparent inputs not added to `will_spend`  *(OPEN, hardening)*

`validate_block_utxos` routes a Shield tx to `verify_shield_tx` then `continue`s
without inserting its transparent inputs into the block-wide `will_spend` set, so
it cannot detect the same transparent UTXO spent by a Shield tx and another tx in
the same block. Not fund loss / not a fork: the authoritative apply path uses a
shared `staged_spent` and deterministically skips the second spend, and the live
path does not gate on `validate_block_utxos`. **Fix:** insert each shield
transparent input into `will_spend` (and reject on duplicate), matching the
transparent loop.

## 6. LOW — `validate_transaction` shield/confidential early-return skips txid check  *(OPEN, dead code)*

In `TxValidator::validate_transaction`, the shield/confidential branches return
before the `tx.hash == canonical_bytes` check, so on that path the txid is not
bound to content. **Not reachable:** `validate_transaction` has no production
callers; the live mempool path (`validate_tx_for_network`) and the block path
bind the hash first. **Fix:** move the `is_shield()/is_confidential()`
early-returns to after the `verify_for_network` check.

## 7. INFO — dead `Serializer` is non-injective over RingCT/Shield fields  *(OPEN, hygiene)*

`engine/crypto/serialization.rs` `serialize_tx_input/output` omit every RingCT /
Shield field, so `Serializer::tx_hash` collides for txs differing only in a
commitment/blinding/one-time-key. Dead code: only `#[cfg(test)]` callers; the
on-chain txid uses the complete `Transaction::canonical_bytes`. **Fix:** delete
the dead `Serializer` tx/block paths or align them field-for-field with
`canonical_bytes` (prior audit item SER1).

---

## UmbraHash — the four PoW properties (internal assessment)

| Property | Assessment |
|----------|------------|
| Hard to solve | Memory-bandwidth-hard (1 GiB dataset, random dependent access) + mini-ProgPoW ALU layer. Composes vetted primitives (SHA3/Keccak + Ethash DAG structure + ProgPoW's KISS99/math/merge). |
| Cheap to verify | `hashimoto_light` regenerates only ~64 touched items from the 16 MiB cache; the ALU layer adds negligible cost. `light == full` is unit-tested. DoS vectors on the verify path found and fixed (#1, #2). |
| Progress-free | Uniform hashimoto output vs 256-bit target; standard nonce search. |
| Difficulty-tunable | Shared `difficulty_to_target_bytes` (256-bit target). **Caveat:** algorithm-agnostic target enables the downgrade in finding #4 once the fork activates. |

**ASIC posture:** memory-hardness + mini-ProgPoW push ASIC advantage from
plain-Ethash ~2× toward ~1.1×; this is a maintained *spectrum*, not immunity.
The 1 GiB dataset is far above on-chip SRAM and fits 2 GB+ cards. A custom
composition of vetted primitives is the highest-risk design tier — external
cryptographic review of the composition is essential.

---

## Required before mainnet (external audit checklist)

1. **Cryptographer review of the primitives** (out of scope here):
   `pedersen.rs` (H/G independence, `verify_balance`), `range_proof.rs`,
   `dual_clsag.rs`. Shield's inflation-resistance depends on them.
2. **Consensus review of UmbraHash composition** (Ethash DAG + mini-ProgPoW) and
   the light==full equivalence for all inputs.
3. **Fix finding #4** (fork activation floor) before scheduling the fork.
4. Finalize RingCT block-enforcement and land the remaining okey hardening (#3
   follow-ups) and #5.
5. Clean up #6/#7 dead code.
6. Re-run this adversarial review after the above.
