# M5 — Deferred Prev-State Commitment (originally: bind parent post-state into the PoW preimage)

**Status:** design approved 2026-07-16 — **but SHIPPED IN REDUCED FORM.** Read this before citing anything below.

> ⚠️ **WHAT ACTUALLY SHIPPED (as of `ad157eb`) DIFFERS FROM THIS DESIGN.**
> The implementation binds **only the GHOSTDAG selected parent's IDENTITY**. It passes canonical `None` for
> `parent.utxo_commitment`, `parent.state_root` and `parent.receipt_root`
> (`expected_prev_state_commitment` → `compute_prev_state_commitment(&sp, None, None, None)`).
>
> **Why the change:** binding those roots is unsafe today. `state_root` / `receipt_root` are populated
> post-execution, only for executed contract blocks, and are written into the stored block after it is hashed —
> so they are path-dependent. The deferred verify runs *before* the parent's roots are recomputed, so a side node
> could read different values than the miner and reject a block the miner considers valid: a consensus split.
> `utxo_commitment` is not deterministically populated either. The root slots remain in the commitment FORMAT so a
> future upgrade can bind real roots without a domain-tag change.
>
> **Therefore the core goal of this document is NOT met.** Sections below that say a block commits to "the
> already-computed post-state of its selected parent", that this-block roots become "TRANSITIVELY committed by the
> CHILD", or that the miner computes the commitment "from the SELECTED PARENT's stored roots", describe the
> DESIGN INTENT, not the shipped behaviour. A block's own post-execution state is still **not** committed by its
> child. Closing that gap requires deterministic, pre-mine-populated roots and is future work.
>
> What the shipped change *does* deliver: the header field, the versioned `ShadowDAG_Block_v2` domain, the single
> shared miner/validator derivation, the deferred verify on both accept paths, and the end-to-end wiring — i.e. the
> mechanism, ready for real roots to be plugged in later.

## Problem
`state_root` / `receipt_root` / `utxo_commitment` (and `selected_parent` / `blue_score`) live in the header but are NOT in
the PoW preimage and are NOT cross-node compared — each node recomputes its own and overwrites the header value
(`full_node.rs:1552-1553`), so they are malleable, non-committed metadata. `block.hash` = the PoW hash over
`serialize_header_raw` (version, height, timestamp, nonce, extra_nonce, difficulty, merkle_root, parents) — nothing else.

## Decision
DEFERRED (parent-state) binding, not this-block execute-before-mine. Each block commits, in its PoW preimage, to the
**already-computed post-state of its selected parent**. No dry-run execution infra; no 2× execution at 10 BPS. A block's own
post-state is committed by its child (the "1 block behind" property, standard for high-BPS DAGs).

## Mechanism
- NEW header field `prev_state_commitment: Option<String>` (64-hex SHA3-256), `#[serde(default)]`.
  `prev_state_commitment(N) = SHA3-256( DOMAIN || selected_parent || enc(parent.utxo_commitment) || enc(parent.state_root)
  || enc(parent.receipt_root) )`, where `enc(Option)` = `0x00` for None or `0x01 || utf8(hex)` for Some (canonical, no
  ambiguity), and `selected_parent` is the ghostdag-selected parent hash.
- BUMP the shared domain tag `ShadowDAG_Block_v1` → `ShadowDAG_Block_v2` and append `prev_state_commitment`
  (canonically encoded) to `serialize_header_raw`. BOTH PoW preimages use `serialize_header_raw`, so miner + FullNode + Sync
  + Light all bind it via one serializer (the "same serializer literally" requirement) + a versioned domain (no ambiguity).
- Miner: `getblocktemplate` computes `prev_state_commitment` from the SELECTED PARENT's stored roots and returns it in the
  template; the miner stamps `header.prev_state_commitment` and mines the preimage that includes it.
- Validator (on receipt): (1) recompute the EXPECTED commitment from the selected parent's stored roots and REJECT if
  `header.prev_state_commitment != expected` (this is the deferred verify); (2) the PoW check already covers it because it is
  in the preimage → a forged value also fails PoW. Both checks; either alone rejects.
- Genesis: no parent → `prev_state_commitment = GENESIS_PREV_STATE_COMMITMENT` = commitment over the empty initial state
  (a fixed constant). Genesis is re-mined (new preimage → new genesis hash) on all 3 networks.
- The existing this-block `state_root/receipt_root/utxo_commitment` stay as local post-hoc fields — now TRANSITIVELY
  committed by the CHILD's `prev_state_commitment`, so they are no longer "unbound + unverified".

## Stages (each ends green: build + clippy -D warnings + relevant tests)
1. **Foundation (pure, testable):** in umbrahash/shadowhash-adjacent code add `compute_prev_state_commitment(selected_parent,
   parent_utxo_commitment, parent_state_root, parent_receipt_root) -> String` + the `enc(Option)` helper + `GENESIS_PREV_STATE_COMMITMENT`.
   Add header field `prev_state_commitment`. Bump domain to v2 and thread the commitment through `serialize_header_raw`
   (+ `serialize_header_template`, `shadow_hash_raw_full`, `header_hash`). KATs: 1-byte change in the commitment (or any parent
   root) → different preimage bytes → different block hash; canonical `enc(Option)` (None vs Some("") distinct).
2. **Miner + template:** node computes the selected parent's commitment in the block template; miner stamps + mines it; the
   node's internal miner (engine Miner) + stratum template (or the fork-guard already disables stratum on mainnet) stay in
   parity. Update the getblocktemplate RPC shape + `bin/miner.rs` header assembly + `recompute_identity_hash`/`umbra_check`/
   `shadow_hash` to source the commitment from the header (pure(header)).
3. **Validator verify:** on block acceptance, recompute expected commitment from the selected parent's stored roots and
   reject on mismatch (network-aware where needed); keep this-block roots as local metadata.
4. **Genesis re-mine:** GENESIS_PREV_STATE_COMMITMENT constant + re-mine genesis for mainnet/testnet/regtest (new hashes) +
   bump GENESIS_VERSION note; update genesis verification + any hardcoded genesis hashes/tests.
5. **Test migration + full suite green:** update every hardcoded block-hash test to the v2 preimage; add the KATs.
6. **Adversarial re-audit (user-required):** header-hashing correctness + miner↔verifier parity + genesis + deferred-verify
   soundness (can a block commit to a wrong/again-mutated parent state? light-client story) → GO/NO-GO before commit.

## Risks
- Highest miner↔verifier parity risk of the whole audit (the user flagged it): miner and validator MUST derive the identical
  commitment + preimage. Mitigate with one serializer + a shared `compute_prev_state_commitment` + KATs + the stage-6 review.
- Genesis + all block hashes change → testnet must be wiped to deploy (GATED on explicit user auth); breaks hardcoded-hash tests.
- Reorg: the selected parent used for the commitment must be the SAME parent the validator derives (ghostdag select_parent);
  bind `selected_parent` into the commitment so the miner's choice is explicit and verified.
