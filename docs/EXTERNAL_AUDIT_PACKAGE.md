# ShadowDAG — External Cryptography & Consensus Audit Package

**Purpose:** hand this to the external cryptographer + consensus auditor. It lists (1) the code in scope, (2) the supporting documents, (3) the specific questions to answer, (4) the test-vectors/KATs to demand, and (5) where formal verification / a professional firm is warranted.

**Chain summary:** hybrid chain — EVM execution (ShadowVM) + Monero-style RingCT privacy (Ristretto/curve25519-dalek) + Kaspa-style GHOSTDAG blockDAG + a custom memory-hard PoW (UmbraHash = SHA3 + Ethash-DAG + mini-ProgPoW). Rust.

**AUDIT ANCHOR (frozen):** tag **`RC1-AUDIT-FREEZE`** → commit **`ad157eb6f19573ce2acdc587adae72b7ddd17d14`** on branch `feature/privacy-hdwallet-docs` (github.com/ShadowDag/ShadowDag). Audit THIS SHA, not the branch head. Freeze discipline is active: no cryptography/serialization/consensus change lands until this audit completes; any such change re-scopes the audit under a new tag. (The tag is annotated, not GPG-signed — verify by SHA.)

**Validation status (context, NOT certification — and self-reported):** full lib suite 2331 passed / 0 failed and clippy `-D warnings` clean; three internal adversarial review rounds on the M5 change; live verification on a fresh single-node regtest (past height 1, unclean-shutdown restart, both PoW preimages) and on a 3-node public testnet fleet (fresh chain mined 36k+ blocks, hash-verified convergence, zero `prev_state_commitment mismatch` over entire logs, follower restart + recovery under real P2P). **These are our own runs; at the time of writing there is no published CI status check on the tagged commit that you could use to corroborate them — treat them as claims, not evidence. Publishing that check is on us and is being addressed.**

**Known gaps on that same live chain (self-disclosed, see the questions):** `shield` works end-to-end, but a confidential **send** is accepted to the mempool and then never mined — question 14; H3 pre-cache bounding covers only the FullNode orphan path — question 7; the mainnet UmbraHash fork is not enforced on header-only (Light/Sync) paths — question 1; reorg-failure recovery is not fail-atomic in seven of nine blocks — question 15.

**Scope exclusion:** review only the working tree of `feature/privacy-hdwallet-docs` at the referenced commit. The repository contains stale `.claude/worktrees/*` copies that are hundreds of commits behind and are NOT the code under review — please exclude them (a grep for RingCT symbols will otherwise hit those copies).

**Freeze discipline for corrections:** documentation/wording corrections (including several made in response to your first-round feedback) land as text-only commits and do not move the code anchor. Code fixes — the H3 tip bound and check reordering, network-aware Light/Sync gating, and strict reorg recovery — are deliberately **deferred to a scheduled remediation round** and will produce a NEW code tag, which we will send you; they are not slipped in under the current anchor.

**Standing rule:** the project owner requires this external sign-off **before mainnet**; the internal pre-audit (doc #4 below) only prepares and de-risks it — it does not certify the system.

---

## 1. Code in scope (exact paths, grouped by surface)

### A. Ring signatures (CLSAG / dual-key CLSAG)
- `engine/privacy/ringct/clsag.rs`
- `engine/privacy/ringct/dual_clsag.rs`   ← the LIVE confidential gate (`dual_clsag::verify`)
- `engine/privacy/ringct/ring_signature.rs`   ← legacy, believed dead — confirm it is not a consensus gate
- `engine/privacy/ringct/ring_validator.rs`

### B. Commitments, range proof, amount encoding
- `engine/privacy/confidential/pedersen.rs`   ← generators G, H (verify unknown dlog of H wrt G)
- `engine/privacy/confidential/range_proof.rs`   ← HAND-ROLLED Borromean/AOS per-bit proof (highest-risk primitive)
- `engine/privacy/ringct/amount_encoding.rs`

### C. Key image, ring validation, confidential consensus
- `engine/privacy/ringct/key_image.rs`
- `engine/privacy/ringct/confidential_consensus.rs`   ← `verify_confidential_tx` / `verify_shield_tx`
- `engine/privacy/ringct/tx_confidential.rs`   ← `parse_confidential_output` (input/output decoders)
- `engine/privacy/ringct/decoy.rs`   ← decoy selection (uniform — see Q4)
- `engine/privacy/ringct/scan.rs`, `engine/privacy/ringct/serialization.rs`

### D. Stealth addresses & view/spend keys
- `engine/privacy/stealth/stealth_address.rs`, `view_key.rs`, `stealth_scanner.rs`
- `domain/address/stealth_address.rs`, `domain/address/key_derivation.rs`

### E. Shield transaction (transparent -> confidential composition) + block-inclusion path
- `engine/privacy/ringct/builder.rs`   ← also sets the confidential input's placeholder `txid = "0".repeat(64)` (see Q14)
- `engine/privacy/ringct/confidential_consensus.rs`
- `domain/transaction/tx_validator.rs`, `domain/utxo/utxo_set.rs`, `domain/utxo/utxo_validator.rs`
- `service/mempool/core/mempool.rs`   ← `add_transaction` (admission) and `select_transactions_for_block` (the `all_ok` outpoint-`exists()` predicate that today excludes every confidential tx from block selection — Q14)

### F. UmbraHash proof-of-work (custom composition — highest-risk PoW tier)
- `engine/mining/algorithms/umbrahash.rs`   ← core (epoch_seed, mkcache, dataset, hashimoto_light/full) + the network-aware activation schedule (`MAINNET_UMBRA_ACTIVATION_HEIGHT = Some(1)`, i.e. mainnet retires ShadowHash from height 1; testnet/regtest unscheduled) and the per-epoch build lock (H3)
- `engine/mining/algorithms/hash_mix.rs`, `anti_asic.rs`, `shadowhash.rs` (legacy algorithm + the ONE shared header-preimage serializer — see section H)
- `engine/mining/pow/pow_validator.rs`   ← version-gated dispatch + `validate_for_network` activation floor + tip-relative pre-cache bound (H3)
- `engine/mining/gpu/umbrahash.cl`, `engine/mining/gpu/umbra.rs` (GPU kernels — must match CPU byte-for-byte; the GPU nonce patch relies on `HEADER_NONCE_OFFSET`)
- Note: the built-in ShadowHash-only Stratum pool is force-disabled on ALL networks at the frozen SHA (`daemon/mod.rs`) — it is not a live mining surface; confirm it cannot be re-enabled into a rejectable-block producer.

### G. Consensus / fork-choice adjacency (context for the above)
- `service/network/nodes/full_node.rs` (`recompute_virtual_chain`, apply paths; M3 atomic acceptance via leaf-gated `ghostdag.remove_block` + `drop_offending_block_if_leaf`)
- `engine/consensus/validation/block_validator.rs`, `engine/consensus/reorg/`

### H. M5 deferred state commitment (NEW consensus + serialization surface at this freeze)
Every block header carries `prev_state_commitment` = SHA3-256 over a domain-separated encoding (`"ShadowDAG_PrevState_v1"`) of the block's GHOSTDAG selected parent; the value is inside BOTH PoW preimages (header domain tag bumped `ShadowDAG_Block_v1` → `_v2`) and is consensus-enforced for every height>0 block. It binds ONLY the deterministic selected-parent identity — the parent's `utxo_commitment`/`state_root`/`receipt_root` slots are encoded as canonical `None` (reserved for a future deterministic-roots fork).

> **Naming caveat — do not over-read "state commitment".** Despite the name, this does **NOT** make the parent's post-execution state a consensus commitment. `state_root` / `receipt_root` are still computed post-execution and written into the already-hashed stored block, so they remain outside the PoW hash and are path-dependent; binding them pre-execution would diverge across nodes. A block's own post-execution state is therefore still **not** committed by its child. What shipped is the mechanism (header field, versioned domain, one shared miner/validator derivation, deferred verify on both accept paths) with reserved slots for real roots later. Earlier revisions of this package and some in-repo comments overstated this; they have been corrected.
- `engine/mining/algorithms/shadowhash.rs`   ← `serialize_header_raw` (the single core preimage serializer, domain v2), `enc_opt_root` (canonical Option encoding: `0x00` vs `0x01||len||bytes`), `compute_prev_state_commitment`, `genesis_prev_state_commitment`, `HEADER_NONCE_OFFSET` invariant
- `domain/block/block_header.rs`   ← the header field (`#[serde(default)]`)
- `service/network/nodes/full_node.rs`   ← `expected_prev_state_commitment` (the ONE shared miner/validator derivation over `select_parent(parents)`), `publish_mining_template` / `republish_mining_template` (template publication: startup, per-accept, post-genesis, post-recovery), and the deferred-verify in BOTH accept paths (`process_block_inner` AND the orphan-reconnect `process_block_without_orphans`)
- `service/network/rpc/rpc_server.rs`   ← `getblocktemplate` serves it (process-default fallback when `RpcState.mining_state` is None); `cmd_submitblock` re-applies the submitted value before re-hash/validate
- `bin/miner.rs`   ← stamps the template value at every hash site (ShadowHash, UmbraHash, GPU) + transmits it on submit
- `config/genesis/genesis.rs`   ← genesis re-mined for the v2 preimage (new mainnet/testnet/regtest nonce+hash constants; mainnet build panics on any mismatch)

---

## 2. Supporting documents to send with the code
- `docs/AUDIT_SCOPE.md`
- `docs/superpowers/audits/2026-07-06-external-review-dossier.md`  (prior dossier)
- `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`  (shield + PoW internal review + 2 fixed DoS bugs)
- `docs/superpowers/audits/2026-07-15-internal-crypto-preaudit.md`  (12 confirmed findings, per-surface proven/assumed/unknown, and the source of most questions below)
- `docs/superpowers/audits/2026-07-15-final-reaudit.md`  (re-audit of the pre-audit fixes)
- `docs/superpowers/specs/2026-07-16-m5-deferred-state-commitment-design.md`  (**M5 design** — the deferred state commitment now in scope as section H)

---

## 3. Questions to put to the auditor

**PoW / mining economics**
1. **Single cost floor — IMPLEMENTED ON THE AUTHORITATIVE PATH ONLY; header-only paths do NOT enforce it (was F-1/F-2).** H2 landed `umbra_activation_height(Mainnet) = Some(1)` (`umbrahash.rs`), enforced by `umbra_required_at_for` + `PowValidator::validate_for_network`, so mainnet retires ShadowHash from height 1 (genesis is the only ShadowHash block); testnet/regtest are unscheduled.
    **We explicitly RETRACT any claim of Full/Sync/Light parity.** The network-agnostic `UMBRA_ACTIVATION_HEIGHT` is still `None` (and pinned there by a test), so the blind `umbra_required_at` returns false at EVERY height. `LightNode` and `ChainVerifier` validate via `recompute_identity_hash`, which gates on that blind rule and has no `NetworkMode` — so after mainnet height 1 those header-only paths may accept a downgraded v2 ShadowHash header that `validate_for_network` rejects. This is an open, disclosed divergence (see also question 7); our planned fix is to thread `NetworkMode` into the header-only validators.
    **Questions:** (a) does the version-by-height gate close the downgrade on the authoritative path with no reorg-window ambiguity (no height where both algorithms are co-valid at one target)? (b) is genesis-only ShadowHash acceptable? (c) what is the correct security posture for header-only paths that cannot see consensus state — must they enforce the fork, or be declared non-authoritative and unusable for security decisions? (d) confirm the underlying claim that ShadowHash provides ~zero memory-hardness (access pattern not value-dependent → streamable → reduces to SHA256).
2. **UmbraHash composition.** It composes SHA3-256/512 + the Ethash/Dagger-Hashimoto DAG + a mini-ProgPoW ALU layer. Confirm the memory-hardness reduces to the Ethash bandwidth-latency assumption, that `hashimoto_light == hashimoto_full` for **all** inputs (not just sampled), and that the CPU and GPU (OpenCL) paths are byte-identical.

**Privacy / RingCT**
3. **Range proof.** The Borromean per-bit range proof is hand-rolled. **Recommend replacing it with a vetted implementation (dalek Bulletproofs)?** Independently review its soundness (no negative/overflow amount can pass → no inflation) if it is kept.
4. **Degenerate-point rejection (F-9/F-4).** Should identity/degenerate points be rejected **uniformly** at every DH / key-image / ephemeral-R site? Please enumerate every `decompress()` that feeds a secret-scalar multiply and confirm each rejects the identity/torsion cases.
5. **Decoy distribution (F-7).** Decoys are drawn uniformly over the whole output index → temporal bias (newest ring member is disproportionately the real spend). Validate a gamma/log-normal spend-age model; **should consensus bound ring-member age at all?**

**Consensus determinism / DoS**
6. **Cross-architecture determinism (F-5).** Audit **all** consensus-critical hash preimages for platform-width or endianness-dependent encodings (`usize`, `to_le_bytes`/`to_ne_bytes` on `usize`, pointer-width casts). Require a fixed-width-encoding invariant + a 32-bit vs 64-bit differential test. (One instance fixed in `range_proof.rs`; ask them to find the rest.)
7. **Pre-validation resource bounds — PARTIAL, and we know it is exploitable (was F-3).** H3 landed a per-epoch build lock and a **tip-relative** bound, but ONLY on the FullNode orphan path. We disclose the gap rather than ask you to find it:
    - `PowValidator::recompute_identity_hash` takes only `&BlockHeader` — **no tip context**. Its sole height guard is the absolute `UMBRA_MAX_HEIGHT = 1e12`, after which it calls `cache_for_epoch(epoch_of(height))` on an **unvalidated attacker-chosen height** — up to epoch ~333,333, i.e. a 333k-iteration `epoch_seed` chain plus a 16 MiB `mkcache`.
    - **Three callers invoke it BEFORE the cheap checks**: `LightNode::validate_header_basic` (PoW recompute precedes the genesis/height checks — and the fn is `static`, so it structurally cannot consult a tip), `ChainVerifier`'s per-header loop (PoW precedes parent/height continuity), and `BlockRelay::add_to_orphan_pool`.
    - `MAX_EPOCH_CACHES = 3`, so alternating 4+ distinct far epochs evicts on every header and forces a fresh `mkcache` each time. The in-code comment justifying the small lock bound explicitly assumes the tip-relative orphan bound — an assumption that holds only for the FullNode path.
    **Questions:** (a) confirm the amplification factor and whether an absolute ceiling can ever be sufficient without tip context; (b) what is the correct admission ordering — should *any* PoW/epoch work precede parent/height/genesis validation on header-only paths? (c) review our planned fix: a tip-bounded variant plus reordering all three callers.

**Shield composition**
8. **Value conservation.** Confirm the transparent→confidential shield binds the public input amount `A` to the commitment `C = A·H + r·G` with no mint path, and that the dual-bucket (transparent supply / confidential supply) accounting conserves total supply across apply **and** reorg/rollback.

**M5 deferred state commitment (NEW at this freeze — section H)**
9. **Header-domain migration.** `serialize_header_raw` bumped its domain tag `ShadowDAG_Block_v1` → `_v2` (same 18-byte length, `HEADER_NONCE_OFFSET` unchanged) and appends `prev_state_commitment` via `enc_opt_root` after the sorted parents. Confirm: (a) no v1/v2 cross-domain preimage collision; (b) `enc_opt_root` is injective/canonical (`None` vs `Some("")` vs length-prefix games); (c) the appended field cannot create preimage ambiguity with any adjacent variable-length field; (d) the GPU nonce-patch offset remains sound.
10. **Commitment semantics & non-degradation.** At this freeze the commitment binds only `select_parent(parents)` — data already derivable from the PoW-bound parent list. Confirm this adds binding without weakening anything (no PoW-strength downgrade, no new grinding surface via the reserved all-`None` root slots), and state what invariants a future fork MUST satisfy before real roots are bound into the reserved slots (deterministic, populated pre-mine, reorg-independent).
11. **Enforcement completeness.** The deferred-verify runs in `process_block_inner` AND `process_block_without_orphans`. Adversarially confirm there is NO height>0 acceptance path (sync, relay, compact-block reconstruction, recovery/replay, RPC submit) that admits a block bypassing it, and that miner-side template publication (`publish_mining_template` on startup / per-accept / post-genesis / post-recovery) can never serve a (parents, commitment) pair the verifier rejects — three liveness-halt wirings of exactly this class were found and fixed internally (daemon null-fallback; fresh-genesis publish; restart stale-seed); hunt for a fourth.
12. **Genesis re-mine.** The v2 preimage required re-mining genesis (new mainnet/testnet/regtest nonce+hash constants; mainnet build hard-panics on mismatch). Confirm the constants reproduce from the committed code and that `genesis_prev_state_commitment()` (empty selected-parent) is unambiguous vs any real parent hash.

**Confidential-spend block INCLUSION gap (live-confirmed 2026-07-18 — the confidential send is NOT minable today)**
14. **Confidential txs are accepted to the mempool but never SELECTED into a block.** Live on testnet at the frozen SHA: `shield` works end-to-end (14 confidential outputs mined), and an A→B confidential send **builds and is accepted to the mempool** (ring size 11, amount hidden) — but it is **never mined**, so the recipient never receives it. It is not rejected: zero block-level rejections in the logs; the tx simply stays `status: mempool` forever. Root cause, confirmed in code: `Mempool::select_transactions_for_block` (`service/mempool/core/mempool.rs`, the `all_ok` check) requires **every** input's `utxo_key(txid, index)` to satisfy `utxo_set.exists(key)`, while a confidential input carries `txid = "0".repeat(64)` (`engine/privacy/ringct/builder.rs` — "outpoint is meaningless for confidential inputs"), so `exists()` is false and the tx is silently excluded from selection.
    **PRECISION (an earlier revision of this document got this wrong):** block-level RingCT verification **already exists and runs**. On the live accept path `full_node.rs::recompute_virtual_chain` calls `verify_block_confidential_txs` → `confidential_consensus::verify_confidential_tx` (on-chain ring-member authenticity, ring-size bounds, advertised-vs-signature key-image binding, canonical key-image encoding, cross-block and intra-block key-image uniqueness, dual-CLSAG, per-output range proofs, plaintext-amount-zero, OTK freshness, homomorphic balance) **before** `apply_block_dag_ordered`. So the gap is **block production/inclusion**, not verification. Note for your map: the gate is NOT in `BlockValidator` — `block_validator.rs` runs only the deprecated structural `RingValidator::validate`, which does no cryptography.
    **Questions:** (a) What is the correct selection-time validity predicate for a ring input — presumably "every ring member's output key is in the confidential output index AND the key image is unspent" instead of an outpoint `exists()` check? (b) Given that the crypto gate already runs at accept time, is enabling selection sufficient, or must the structural `BlockValidator` path also carry the full gate (defence in depth / different entry points)? Confirm no inflation path once confidential spends actually flow through apply, incl. key-image handling across reorg/rollback. (c) Specify the **activation/fork discipline** so old and new nodes cannot split when confidential spends become minable. (d) Review the DoS surface of admitting to the mempool transactions that can never be mined (they occupy mempool space indefinitely — should selection-ineligible txs be rejected at admission instead?).
    *Status: deliberately NOT fixed — a consensus change on the confidential path, reserved for this review.*

**Reorg-failure recovery is not fail-atomic (self-disclosed, open)**
15. **Seven of nine failure-recovery blocks in `FullNode::recompute_virtual_chain` use a best-effort pattern that can leave state neither old nor new.** Only two blocks use the strict pattern (a `restore_failed` flag → `FATAL_reorg_restore_failed_halting` → `std::process::exit(1)`). The other seven discard results — `let _ = utxo_set.rollback_block_undo(...)`, `let _ = utxo_set.apply_block_dag_ordered(...)` for the **old-chain restore** — log a contract-restore failure without acting on it, and then simply `return Err`, with no halt. One of them also lacks an `else` arm when the old block is missing/pruned, so restoration is silently skipped. A failed restore therefore continues execution with an indeterminate UTXO/contract state.
    **Questions:** (a) Confirm the correct discipline: must ANY failed restore during reorg recovery be a hard stop (halt / require reindex) rather than an `Err` return? (b) Is a partially-restored UTXO set detectable at next startup, or does it corrupt silently? (c) Review our planned fix: one shared helper — checked `rollback_new_chain` plus `restore_old_chain_or_halt` — applied to all nine blocks, with no discarded results in consensus recovery.
    *Status: fix scheduled before the next freeze tag; disclosed here because it affects how you interpret any reorg-related finding.*

**Consensus atomicity (M3)**
13. **Atomic acceptance.** `recompute_virtual_chain` failure now rolls back the just-inserted block only when it is a childless leaf (`drop_offending_block_if_leaf`, leaf-gated `ghostdag.remove_block`). Confirm acceptance is all-or-nothing under every failure interleaving (no phantom GHOSTDAG tip with a deleted body, no half-deleted mid-chain block).

---

## 4. Test-vectors / KATs to demand (deliverables from the auditor or to build before mainnet)
- **UmbraHash:** published KAT vectors for `epoch_seed`, `mkcache`, `calc_dataset_item`, and full `hashimoto_light`/`hashimoto_full` at fixed (height, header, nonce); a `light == full` differential fuzzer; a build-determinism KAT.
- **Range proof:** boundary vectors (v = 0, 1, 2^63, 2^64−1, 2^64), a rejection KAT for an out-of-range commitment, and a **32-bit vs 64-bit reproducibility vector**.
- **dual-CLSAG / clsag:** sign/verify KATs at min & max ring size; identity-key-image rejection vector for **both** modules; a tamper suite (mutated ring member / commitment / pseudo-out).
- **Stealth:** an identity-R rejection vector; a full-32-byte (not 160-bit-truncated) ownership vector.
- **M5 commitment:** published vectors for `compute_prev_state_commitment` (empty selected-parent = the genesis constant; a known 64-hex parent; `None` vs `Some("")` root-slot discrimination); a v1-vs-v2 domain-separation vector (same fields, different digests); a header-preimage vector proving a 1-byte `prev_state_commitment` change flips both PoW preimages (the in-repo KAT `prev_state_commitment_binds_to_block_hash` is the starting point); genesis nonce/hash reproduction for all three networks.

## 5. Where formal verification / a professional firm is warranted
- **Professional audit firm (hard gate before mainnet):** full RingCT primitive review incl. the hand-rolled Borromean range proof; constant-time verification of wallet signing (dudect/ctgrind); the UmbraHash composition + light==full equivalence.
- **Formal verification:** the shield/RingCT balance-and-range soundness reduction, and the PoW version-gate / single-cost-floor state machine (prove no height admits two algorithms at one target post-activation).
- **Tooling to run:** KAT/Wycheproof-style vectors, differential/property fuzzing (cryptofuzz-style), constant-time analysis on the binary, and a 32/64-bit differential build test.

---

*Prepared from the internal adversarial pre-audit (2026-07-15); updated 2026-07-18 for the RC1-AUDIT-FREEZE anchor (`ad157eb`) — H2/H3/M3 landed, M5 added as section H with questions 9–13. Contains no secrets; defensive review of the owner's own authorized chain.*
