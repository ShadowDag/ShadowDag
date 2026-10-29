I've re-verified all NEW findings against the real code on HEAD. Key correction: the two orphan-pool/relay findings are **test-only dead code** (grep confirms `receive_block`/`add_to_orphan_pool` have no live callers — only tests at block_relay.rs:720–829), so their live severity is latent, not medium. Everything else confirmed. Here is the final report.

---

# ShadowDAG — Final Re-Audit Report (branch HEAD 7e84ce0)

## 1. Verdict on the Fixes

**All listed fixes HOLD. No fix was marked BYPASSABLE or REGRESSED by any domain, and independent re-derivation confirms none is bypassable.**

| Fix | Domain(s) | Status | Re-verified anchor |
|---|---|---|---|
| **P0-A + C1** — `TxInput.key_image` bound to the CLSAG-embedded image + canonical lowercase hex; apply records the canonical KI | RingCT, Shield | HOLDS | confidential_consensus.rs:262–302; utxo_set.rs:924–934 |
| **P0-D** — `dual_clsag::from_bytes` bounds ring count before arithmetic (checked_mul/add) | RingCT | HOLDS | dual_clsag.rs:237–245 |
| **F-4** — dual-CLSAG rejects identity key image / D | RingCT | HOLDS | dual_clsag.rs:193–195 |
| **F-9** — `parse_confidential_output` rejects identity ephemeral R | RingCT, Shield | HOLDS | tx_confidential.rs:73–75 |
| **F-10** — `apply_block_write_with_commitment` refuses confidential/shield | RingCT, Shield | HOLDS | utxo_set.rs:568–575 |
| **Shield conservation** — public input amount bound to `C_in=A·H+r·G` from UTXO set, output amount 0, per-output range proof, ΣC_in=ΣC_out+fee·H, fee≤Σin | Shield | HOLDS | confidential_consensus.rs:98–177 |
| **Shield apply/rollback** — symmetric dual-bucket, whole-tx skip on bad input, atomic batch | Shield | HOLDS | utxo_set.rs:974–1078, 1482–1617 |
| **F-5** — range proof u32 fixed-width bit index, 64-bit range, bound to one commitment | Shield | HOLDS | range_proof.rs:169–219 |
| **C2** — strictly-ascending canonical parent order; hashed set == stored order | GHOSTDAG, Retarget, Sync | HOLDS | block_validator.rs:911; shadowhash.rs:211–218 |
| **C3** — retarget uses `ghostdag.get_blue_score`, never wire `header.blue_score` | Retarget, Sync | HOLDS | full_node.rs:1041 |
| **C4** — ancestry-pure expected difficulty; miner-stamped == validator-expected anchor | Retarget, Sync | HOLDS | full_node.rs:580–608, 1788–1790 |
| **C5** — Umbra activation floor in `recompute_identity_hash` | PoW, Sync | HOLDS (code correct; **inert** — see P0-B) | pow_validator.rs:182–186 |
| **Umbra absolute-height ceiling** (pre-cache DoS floor) | PoW | HOLDS | pow_validator.rs:136–141, 193–195 |

No apply/sync/relay/light path was found that records a key image, applies a confidential/shield tx, or computes difficulty while bypassing the corresponding gate.

## 2. NEW Findings (is_new=true) — re-verified against HEAD

| # | Finding | File:line | Verdict |
|---|---|---|---|
| 1 | Legacy `clsag_sig_from_bytes` lacks the P0-D ring-count bound (`need = 36 + count*32 + 32`, `Vec::with_capacity(count)`, no cap) | serialization.rs:36 | **CONFIRMED, but LATENT** — only caller `RingValidator::verify_clsag` is unwired; live ring gate is dual-CLSAG. Real defect, not consensus-reachable. |
| 2 | Local prune depth leaks into the consensus difficulty window (retarget walk `break`s on pruned body) | full_node.rs:1005 (+ maybe_prune:375) | **CONFIRMED.** `SHADOWDAG_PRUNE_KEEP_DEPTH` (default 2000) accepts any value ≥1; SHORT_WINDOW=144. keep_depth<144 truncates the window → different `next_diff` → strict-`!=` split. Genuine medium; default config safe, no `keep_depth ≥ SHORT_WINDOW` guard. |
| 3 | Consensus `MAX_PARENTS=80` exceeds header-sync wire cap `MAX_PARENTS_PER_HEADER=64` | messages/mod.rs:145 | **CONFIRMED.** MAX_DAG_PARENTS=MAX_PARENTS=80 (dos_protection.rs:22); block_validator accepts ≤80; Headers deserialize rejects >64. A 65–80-parent block accepted by full-relay cannot cross header-sync → IBD stall / propagation asymmetry. Genuine medium. |
| 4 | `getblocktemplate`/`submitblock` read `next_difficulty` and `dag_tips` as two separate cells (torn snapshot) | rpc_server.rs:1892 | **CONFIRMED, liveness-only.** Cannot split (expected-difficulty is a pure function of the block's parents); wastes a mining round. Low. |
| 5 | Orphan-pool admission skips the target check for `difficulty==0` headers | block_relay.rs:236 | **CONFIRMED as written, but DEAD CODE.** Grep: `add_to_orphan_pool`/`receive_block` have **no live callers** (tests only, 720–829). Live P2P Block dispatch goes through PENDING_BLOCKS→`process_block`. The finding's claim of live "relay/sync/SPV" reachability is **not substantiated** — downgraded to latent. |
| 6 | `umbra_check` returns `Ok(h.hash)` for `difficulty==0` v≥3 headers without recomputation | pow_validator.rs:142 | **CONFIRMED as written, low.** Only reachable at height 0 (guarded at :127); real acceptance anchors genesis to a known constant. Fail-open asymmetry vs ShadowHash path; hardening only. |

No NEW finding is a false positive; two (#5, #6) and #1 are latent/dead-path and are demoted accordingly.

## 3. Final Remaining-Issues List (deduped, ranked)

### 🔴 HIGH — mainnet blockers (economic / inflation / halt)

| # | Title | Sev | File:line | Mechanism | Class |
|---|---|---|---|---|---|
| H1 | **Shield/RingCT no-inflation soundness rests on an unaudited hand-rolled Borromean range proof** | High | engine/privacy/confidential/range_proof.rs:150 (parse serialization.rs:99) | If Borromean/AOS soundness or Fiat-Shamir binding is flawed, a commitment can encode an out-of-range/`mod-l` value and still pass verify; combined with ΣC_in=ΣC_out+fee·H this mints hidden value. Balance eq. bounds nothing without the range proof. | **Inflation** (assurance — external crypto review) |
| H2 | **P0-B: UMBRA_ACTIVATION_HEIGHT=None — ShadowHash stays co-valid; one shared difficulty domain; memory-hard floor inert** | High | engine/mining/algorithms/umbrahash.rs:366 | `umbra_required_at()` always false → C5 floor never fires; v<3 blocks mine at the same target; ShadowHash + UmbraHash share one EMA/LWMA meaningful for neither. | **Consensus/economic** (hard-fork/governance) |
| H3 | **P0-C: no tip-relative pre-cache bound + mkcache serialized under one process-wide Mutex** | High | engine/mining/algorithms/umbrahash.rs:415 | Only bound is absolute UMBRA_MAX_HEIGHT (1e12 → epochs ~333k). Unvalidated v≥3 headers with >3 distinct high epochs each force a fresh ~16 MiB mkcache + long epoch_seed under the global mutex → amplification DoS stalling validation. | **Halt/DoS** (live once Umbra headers accepted) |

### 🟠 MEDIUM — consensus/network hardening (fix before mainnet)

| # | Title | Sev | File:line | Mechanism | Class |
|---|---|---|---|---|---|
| M1 | Prune depth leaks into the consensus difficulty window | Med | full_node.rs:1005 | Operator `keep_depth < SHORT_WINDOW(144)` prunes a body inside the retarget window → walk stops early → different `next_diff` → permanent split. No guard. **[NEW]** | **Consensus split** (misconfig) |
| M2 | Consensus MAX_PARENTS=80 > header-sync cap 64 | Med | messages/mod.rs:145 | A 65–80-parent block accepted by full-relay fails Headers deserialization → header-syncing/late-joining nodes strand. **[NEW]** | **Propagation asymmetry / IBD stall** |
| M3 | Non-atomic GhostDag/L4 acceptance — block persists in GhostDag after a later stage fails | Med | full_node.rs:751 | `ghostdag.add_block` commits before `recompute_virtual_chain`; on reorg-depth or L4-reject the block is not evicted (no per-block removal), stays a tip while its body may be deleted. | **State corruption / divergence** |
| M4 | Non-fail-atomic reorg recovery — log-and-continue on old-chain restore failure | Med | full_node.rs:1371 | Mid-reorg failure re-applies the old chain with errors only logged; a failed restore leaves UTXO+contract state partially reverted, node continues from inconsistent committed state. | **State corruption / halt** |
| M5 | UmbraHash PoW preimage omits state_root/receipt_root/utxo_commitment/selected_parent | Med | umbrahash.rs:435 | One valid PoW solution is malleable across different state/UTXO commitments; work does not bind execution state. | **PoW malleability** |
| M6 | SPV light node enforces no DAA / heaviest-work / checkpoint | Med | light_node.rs:118 (also :97) | `add_header` checks only self-declared difficulty + continuity; a from-genesis difficulty-1 header chain is followed and yields "valid" merkle proofs a full node rejects. | **SPV client trust** (not full-node consensus) |

### 🟡 LOW — privacy / assurance / latent (brief)

- **Ring-member uniqueness not deduped** in the confidential gate — confidential_consensus.rs:239 (anonymity-set shrink; no double-spend).
- **Non-canonical hex → uncitable/unspendable outputs** — utxo_set.rs:940 / serialization.rs:63 (value-loss/consistency; KI itself now forced canonical, no inflation).
- **dual-CLSAG D=identity (z=0) edge** — dual_clsag.rs:193 (completeness corner; soundness-safe, external crypto review).
- **Decoy selection uniform, not age-weighted** — decoy.rs:1 (privacy; no consensus impact).
- **Torn getblocktemplate/submitblock snapshot** — rpc_server.rs:1892 (liveness only, cannot split). **[NEW]**
- **Legacy `clsag_sig_from_bytes` no ring-count bound** — serialization.rs:36 (latent; only caller unwired — bound it or delete the dead single-key CLSAG module). **[NEW]**
- **Orphan-pool `difficulty==0` admission bypass** — block_relay.rs:236 (real but **test-only/dead** path today; fix or delete when wiring relay live). **[NEW]**
- **`umbra_check` `difficulty==0` genesis fail-open** — pow_validator.rs:142 (height-0 only, anchored to constant). **[NEW]**
- **BlockRelay relays connected blocks before full PoW/consensus validation** — block_relay.rs:205 (latent dead-code; live gossip re-broadcasts only after acceptance).

## 4. Bottom Line

The branch is materially closer to mainnet-ready: **every previously-identified consensus fix (C2–C5, P0-A/C1, P0-D, F-4/5/9/10, and the full shield transparent→confidential value-conservation path) HOLDS with no bypass or regression**, and the re-audit surfaced **no new live consensus-split, double-spend, or inflation defect** — the four new consensus/network items (M1, M2, and the latent lows) are a misconfiguration guard, a wire-constant mismatch, and dead-path hardening, all fixable with small, local changes. The critical path to mainnet is therefore **not** more consensus rewrites but four gated items, in order: (1) **external cryptographic review of the hand-rolled Borromean range proof + dual-CLSAG** (H1/H3-adjacent) — the sole remaining unaudited inflation-soundness dependency and a hard gate; (2) **set `UMBRA_ACTIVATION_HEIGHT` and enforce a single memory-hard cost floor** (H2, a coordinated hard fork); (3) **bound the Umbra epoch cache tip-relative + add a per-epoch build lock** (H3 DoS); and (4) two trivial guards plus atomic acceptance — `keep_depth ≥ SHORT_WINDOW` (M1), align the header parent cap to the consensus cap (M2), and make GhostDag/reorg acceptance all-or-nothing (M3/M4). Until the crypto review clears H1 and P0-B activation is scheduled, the confidential/shield feature and the PoW hard fork should remain testnet-gated.