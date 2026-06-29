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

## Overarching recommendation
The recurring root cause is **two divergent block-application paths**: the lenient
`apply_block_dag_ordered` (live; skips conflicts) vs the strict
`validate_block_utxos` (genesis/boot; rejects block). Unifying them behind one gate
would eliminate this entire finding class. External cryptographic + consensus review
remains required before mainnet.
