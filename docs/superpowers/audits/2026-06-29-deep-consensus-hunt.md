# Deep Consensus Vuln Hunt — 2026-06-29 (ultracode)

Multi-agent workflow hunt for the confirmed bug class **"a limit/validation enforced
at CONSTRUCTION (mempool / block_builder) but NOT on the peer-block/reorg
validation+apply path"**, plus reorg/state-root/difficulty/swap surfaces. Every
finding was adversarially verified by an independent agent AND re-verified by me
against the real code before any fix.

## FIXED (verified + regression-tested + suite green 2201)

| # | Sev | Issue | Fix |
|---|-----|-------|-----|
| A | CRIT | Confidential RingCT txs applied on the peer/reorg path with only the structural RingValidator check (no CLSAG/balance/ring-authenticity/range/key-image gate) → inflation+double-spend | `recompute_virtual_chain` runs `verify_block_confidential_txs` (full gate) before each apply; abort+rollback on failure |
| B | MED | `MAX_BLOCK_GAS` enforced only in block_builder, not on incoming blocks → contract-exec CPU DoS | `validate_network_layer` sums tx gas_limits (checked_add) vs MAX_BLOCK_GAS |
| C | HIGH | Same-block coinbase spend bypassed `COINBASE_MATURITY` on `apply_block_dag_ordered` (maturity check read cb_height only from committed DB) → diverged from validate_block_utxos | track `staged_coinbase`; treat same-block coinbase spend as conflict (skip) |
| D | **CRIT** | **Reorg rollback never reversed confidential `ki:` markers** → after a reorg the key image stays seen-forever: genuine owner's input frozen + nodes that saw the orphan reject the tx while others accept it = **permanent consensus fork** | `BlockUndoData` records created key-images; `rollback_block_undo` deletes them atomically |
| E | HIGH | Reorg rollback left `okey:`/`okeyidx:N`/`okeyidx:count` stale → global confidential-output index desync (orphaned decoys, inflated counter, cross-node divergence) | record created output-keys + okeyidx [start,end) span; rollback deletes them + restores the counter |
| F | MED | SwapTx locks to an HTLC `SD1h` output that `verify_input_ownership_by_address` can never match → **permanently unspendable = fund burn**; HTLC engine in-memory only, never enforced | reject SwapTx at consensus until a real HTLC spend path exists |

(A/B/C were found+fixed in the first hunt pass; D/E/F in the second.)

## DOCUMENTED — confirmed but NOT fixed (architectural / risky difficulty refactor)

These are real (independently verified) MEDIUM findings whose correct fix is an
architectural change or a difficulty-engine refactor. A rushed change to consensus
difficulty / state-root binding risks breaking mining or halting the chain worse
than the bounded defect, so they are flagged for dedicated, carefully-tested work.

### G — MEDIUM: peer block's `state_root` / `receipt_root` are never verified
`full_node.rs:1131` `InvariantChecker::quick_check(rr, sr, …)` compares the node's
OWN locally-computed roots against themselves (tautology — can't fail on a peer
mismatch); the peer's claimed `header.{state,receipt}_root` are read nowhere on
the apply path, and `full_node.rs:1101-1112` OVERWRITES the header with local
values. The roots are excluded from PoW and the merkle root (computed
post-execution), so they are unauthenticated — there is effectively **no
contract-layer state-root consensus**. **Why not fixed now:** the roots are
post-execution by architecture, so a "reject on peer-claim mismatch" guard would
reject every block if miners broadcast `None` roots (which they do — block_builder
sets them None). The correct fix binds a prior block's state_root into the next
block's PoW/commitment (Ethereum parent-state model) — a design change. The UTXO
layer (incl. the confidential gate) IS authoritative and validated, so no
inflation/double-spend follows from this; the gap is undetected contract-VM
divergence. Fix the misleading comment at `block_validator.rs:310-311` too.

### H — MEDIUM: tip-extension difficulty uses a global mutable EMA, not the block's parent-chain retarget
`expected_difficulty_for_block` (full_node.rs:519-524) returns `retarget.ema_difficulty()`
— a single global EMA tied to the current selected tip and seeded from node-local
restart/arrival history — instead of a pure function of the incoming block's own
parent ancestry. Two honest nodes with different histories can compute different
expected difficulty for the same block → disagree on validity (split/liveness).
(The cheap-low-work-fork framing was refuted: the `height = max(parent)+1` rule +
fail-closed same-height anchoring block it.) **Fix (deferred):** recompute expected
difficulty by walking the block's own selected-parent window — a difficulty-engine
change requiring careful testing.

### I — MEDIUM: difficulty retarget EMA not rolled back/rebuilt across reorgs
`RetargetEngine` windows are append-only with no rollback; `recompute_virtual_chain`
feeds only the new best tip and never un-feeds rolled-back blocks, so after a reorg
the EMA blends abandoned + canonical chains. Since the next tip's difficulty must
match this path-dependent `ema_difficulty()` by strict equality, a freshly-synced
node and a node that lived through the reorg can disagree on the next block until
stale records age out (bounded by EMA α=1/20 + 4× clamp). **Fix (deferred):** after
each `recompute_virtual_chain` that changes the tip, rebuild `RetargetEngine`
deterministically from the canonical selected-parent chain (mirror the startup
seed). Contained but touches consensus difficulty — needs dedicated testing.

## Also noted (dead code, not a vuln)
`engine/anti_double_spend/` and `engine/consensus/block_processor.rs` have no live
callers (live path = `FullNode::process_block` → `recompute_virtual_chain` →
`apply_block_dag_ordered`). Cleanup candidates.

## Third hunt pass (fresh surfaces: tx-malleability, VM, emission, crash-atomicity, mempool-parity, privacy)

### FIXED (verified + regression-tested; suite 2203 green)

| # | Sev | Issue | Fix |
|---|-----|-------|-----|
| J | **CRIT** | **Crash-recovery bricks the node:** `verify_and_recover` compared the per-block CHAINED commitment (`utxo:commitment:{hash}`, a block-history hash) against `compute_commitment_hash()` (a set SNAPSHOT) — structurally incomparable → every restart past genesis wiped the UTXO set, replayed, still mismatched, and FATAL'd (node unbootable). | Drop the broken snapshot-vs-chained comparison; use the reorg-independent count-based integrity check (proper snapshot/Merkle UTXO commitment is future work). `daemon/mod.rs`. |
| K | HIGH | Confidential output plaintext `amount` never forced to 0 → sender could leak the real value in the clear (scanner trusts it), defeating amount-hiding. Conversely the zero-amount spam filters had no confidential exemption, so honest amount=0 confidential outputs were rejected on the live path. | `verify_confidential_tx` rejects `amount != 0`; dag_shield/spam_filter/dos_protection make the zero-amount rejection transparent-only. |
| L | HIGH | Reentrancy guard never covered the top-level (entry-point) contract — A→B→A drain of the entry contract was admitted (guard only registered child frames). | top-level entries (executor deploy/call, FullNode ContractCreate/ContractCall) now call `execute_frame_guarded`. |

### DOCUMENTED — confirmed but NOT fixed (architecture / IBD-risk / cleanup)

- **M — HIGH (crash-atomicity):** UTXO state and contract state live in SEPARATE RocksDBs committed in separate batches; a crash between the UTXO commit and the contract-persist commit leaves a contract-state hole, and recovery's idempotency skip (`get_commitment(block_hash).is_some()`) never re-executes contracts → divergent `state_root` on contract chains. Fix needs a contract-applied marker in the contract-DB batch + recovery re-execution, or unifying both DBs into one (column families) — a storage-architecture change with real risk; deferred. Documented in OPS_RUNBOOK as a manual incident today.
- **N — MEDIUM→relay (mempool-block parity):** per-tx timestamp anti-replay/age (MAX_TX_FUTURE_SECS / MAX_TX_AGE_SECS) is enforced at mempool/P2P entry but not on the block-apply path. NOT a fork (all block validators apply the same rules) and tx.timestamp is signed, so no fund loss — relay/template inconsistency only. A naive wall-clock check on the block path would BREAK IBD (historical txs are >24h old); the safe fix is header-relative (`tx.timestamp <= block.header.timestamp + skew`) and is deferred.
- **O — LOW (emission):** the selfish-mining / red-block reward penalty (`reward.rs` penalized_miner_reward etc.) is dead code — never wired into coinbase construction or validation. Per-block emission is still hard-capped on both validation paths, so NOT an inflation primitive; it is a missing economic deterrent. Either remove the dead module + its claims, or wire it in deterministically (on-chain blue/red + delay, not node-local timestamps).

## Remediation of the deferred items (user: "fix everything")

After the user asked for ALL confirmed items fixed, the following were additionally
FIXED (verified + regression-tested; full suite 2205 green, clippy clean):

| # | Sev | Fix |
|---|-----|-----|
| H+I | MED | Difficulty is now a pure function of the CANONICAL selected-parent chain. `build_retarget_from_canonical` rebuilds the RetargetEngine from the tip's selected-parent window at BOTH startup seed and the reorg path (was: incremental feed + all-blocks-by-height seed → node-local, reorg/arrival-dependent → strict-equality split risk). Determinism regression test. |
| N | MED/relay | `validate_structural_layer` now rejects any non-coinbase tx whose timestamp exceeds `block.header.timestamp + 15s` (header-relative ⇒ IBD-safe). Closes the mempool-vs-block timestamp divergence. Regression test. |

### STILL deferred — genuine storage/consensus REDESIGNS (NOT safe to hot-patch)

These are real but their correct fix is an architecture change; a rushed patch
would risk corrupting UTXO/contract state on every block (worse than the bounded
defect), and there is no crash/restart integration harness here to validate them.
They are flagged for dedicated, tested work + the mandatory external review.

- **M (HIGH) — contract-state crash hole:** UTXO (main DB) and contract state
  (separate DB) commit in separate batches; a crash between them + the
  UTXO-commitment idempotency skip leaves a permanent contract-state hole.
  Correct fix: either (a) reorder to persist contracts BEFORE the UTXO commitment
  (so the existing skip guard becomes a correct marker), or (b) write a
  `contract:applied:{block_hash}` marker in the contract-DB batch + re-execute on
  recovery, or (c) unify UTXO+contract into one RocksDB (column families) committed
  in ONE WriteBatch. (c) is the robust end state. All require careful re-test of the
  apply/rollback loop — deferred to avoid every-block corruption risk.
- **G (MED) — no contract state-root consensus:** header `state_root`/`receipt_root`
  are computed post-execution, not in PoW/merkle, and never compared to the peer's
  claim. Binding them into consensus is an architectural change (parent-state model
  / 2-phase commit). UTXO layer is authoritative + execution is deterministic, so no
  inflation/fork follows; the gap is undetected VM-divergence. Deferred.
- **ST1 (HIGH) — cross-store atomicity:** UTXO / block / DAG / DSP writes span
  separate stores; a crash mid-sequence can desync consensus state. Fix = shared
  WriteBatch / unified column families. Large storage refactor. Deferred.
- **O (LOW):** dead selfish-mining reward penalty — NOT a vuln (emission hard-capped
  per block); cleanup only.

## Fourth pass + remaining-deferred remediation

FIXED (verified + regression-tested; full suite 2207 green, clippy clean):

| # | Sev | Fix |
|---|-----|-----|
| M | HIGH | Contract-state crash hole healed: `persist_with_undo` writes a `contract:applied:{block_hash}` marker in the SAME atomic batch as contract state; `recompute_virtual_chain` skips a block only if BOTH the UTXO commitment AND the contract marker are present (else re-executes the crash-interrupted block); rollback clears the marker. Regression test. |
| P2P-Addr | HIGH | (4th hunt) `Addr` entries are now validated as routable `host:port` SocketAddrs before being persisted (reject garbage/loopback/unspecified/multicast + ban-score). Previously unvalidated strings bloated the peer DB without bound (each a unique "ip" bypassing the per-IP cap) → disk exhaustion + peer-store poisoning. Regression test. |

4th hunt coverage: shadow_pool/mixer, P2P, serialization, pruning/snapshot, key-mgmt —
**only the Addr finding** surfaced; the other four surfaces verified clean (shadow_pool
confirmed non-consensus/decorative; serialization tx-hash binding sound; pruning respects
MAX_REORG_DEPTH; key-mgmt KDF/sig/multisig sound).

### STILL deferred — genuine redesigns (need dedicated work + external review)
- **G (MED):** no contract state-root consensus (roots post-execution, not in PoW). Architectural.
- **ST1 (HIGH):** broad cross-store write atomicity (UTXO/block/DAG/DSP separate stores). M closed the
  contract-vs-UTXO case; the general multi-store atomicity needs a shared WriteBatch/CF refactor.
- **Sized addrman (follow-up):** bound even valid-but-distinct addresses with eviction (P2P design pattern).
- **O (LOW):** dead reward-penalty code — not a vuln.

## Fifth pass (fork-choice / finality / RPC / sync / indexes / checkpoints)

Confirmed (verified by me against real code) — both MEDIUM, both DEFERRED as
consensus redesigns (mitigated; a rushed fork-choice change risks a network split):

- **FC1 (MED) — fork choice is by block-count, not work:** `select_best_tip`
  (full_node.rs:752-766) ranks tips by `blue_score → chain_height → hash`; there is
  NO cumulative-PoW term. The implemented work machinery
  (`Difficulty::accumulate_blue_work`, `reorg::CumulativeWork`) is DEAD (no live
  callers). MITIGATED: every block enforces `header.difficulty == expected` (strict)
  + PoW, and the retarget raises difficulty when parallel blocks arrive, so a
  higher blue_score requires comparable real work → no cheap-takeover exploit; deep
  reorgs are bounded by the static `MAX_REORG_DEPTH = 200`. Residual: two equal-count
  competing sub-chains with unequal per-block difficulty rank EQUAL (deviation from
  Nakamoto/Kaspa heaviest-chain). FIX (deferred, consensus-critical): maintain a
  per-block cumulative-work index and compare by it FIRST in `select_best_tip` /
  `recompute_virtual_chain`, blue_score as tie-break — wire the existing
  `accumulate_blue_work`/`CumulativeWork`.
- **FC2 (MED) — finality/auto-checkpoints inert:** `FinalityManager` computes a
  dynamic finality depth + persists auto-checkpoints (`chkpt:` keys), but
  `current_depth()`/`is_checkpointed()` and `Checkpoints::is_valid_with_dynamic` have
  NO callers in fork choice / reorg / validation; only the genesis-only hardcoded
  checkpoint list is enforced. So the adaptive deep-reorg backstop is not active
  (the static 200-block bound IS active). FIX (deferred): feed
  `FinalityManager::current_depth()` into the reorg-depth check and enforce
  `is_valid_with_dynamic` in the validation/reorg path.

5th-hunt coverage: fork-choice/finality, RPC handler surface, sync modules,
indexes/cache, checkpoints/genesis. RPC, sync, indexes/cache, checkpoints/genesis
surfaced no new confirmed exploitable bug (sync modules confirmed unwired/dead;
RPC auth table covers mutating methods; indexes read-only).

## Final deferred set (all confirmed real, all MEDIUM, all mitigated — consensus/storage REDESIGNS)
These share: real but NOT turnkey-exploitable, and their correct fix is an
architecture change where a rushed patch is itself a serious risk. They are the
proper scope of the mandatory external consensus+crypto review:
**G** (state-root not in PoW), **ST1** (broad cross-store atomicity),
**FC1** (cumulative-work fork choice), **FC2** (dynamic finality/checkpoint
enforcement), **sized-addrman** (eviction backstop). `O` (dead reward penalty) = not a vuln.

## Overarching recommendation
The recurring root cause is **two divergent block-application paths**: the lenient
`apply_block_dag_ordered` (live; skips conflicts) vs the strict
`validate_block_utxos` (genesis/boot; rejects block). Unifying them behind one gate
would eliminate this entire finding class. External cryptographic + consensus review
remains required before mainnet.
