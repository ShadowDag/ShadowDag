# ShadowDAG — Mainnet Readiness

Honest status of the codebase for a public **mainnet with real economic value**.
Last updated: 2026-07 (consensus/privacy/sync hardening pass).

## TL;DR

- **Testnet / internal / demo:** READY for a level, always-online set of nodes.
  Builds, ~2266 tests pass, binaries run, the 3-seed testnet converges and stays
  converged; a fee-bearing wallet tx mines and confirms.
- **Mainnet with real money:** NOT YET. Blockers, in order: (1) **fresh/far-behind
  node convergence** on a tall chain (design spec written, partly implemented —
  see below); (2) the consensus/storage redesigns (A1/G state-root-in-PoW, A3
  fee-attribution, ST1); (3) an independent external crypto + consensus audit;
  (4) weeks of public **multi-miner** testnet. None can be self-certified.

## 2026-07 session — consensus / privacy / sync hardening (all pushed, tests green)

Fixed + regression-tested this pass (correctness verified: all synced nodes agree
on the chain, no fork):

- **Coinbase fee accounting** — the mempool never evicted mined txs, so templates
  re-claimed fees execution would drop → every coinbase invalid → followers
  rejected the chain (froze the testnet at height 1659). Fixed (evict on accept +
  `is_tx_seen` template filter + idempotent recompute).
- **Selected-parent walks** — blocks stored with `selected_parent=None` truncated
  every fork-choice/recovery walk; now resolved to the GHOSTDAG max-blue parent.
- **Recovery replayed ALL blocks** (incl. red/side coinbases = inflation past the
  cap); now replays only the selected chain, tie-stable with the live tip.
- **Gas-limit DoS** — a `None`-gas contract tx counted as 0 in the block-gas cap
  but executed at 10M; unified via `effective_gas_limit`.
- **GHOSTDAG selected parent, ring size 5→11, anti-eclipse /16 subnet caps, WAL
  fsync at the commit boundary.**
- **Adversarial re-review** of the above caught + fixed a HIGH recovery tie-flip
  and a MEDIUM mempool over-eviction it had introduced.
- **DISPROVEN a claimed inflation gap (A2):** the live path mints only the selected
  chain (strictly-increasing heights), so per-height issuance ≤ the schedule — no
  per-block over-issuance. (The real vector was the recovery replay, now fixed.)

**Remaining #1 convergence blocker — a fresh/far-behind node cannot join a TALL
chain.** Root-caused live and partly fixed (W1 in-order batch processing, W2
orphan-resolution capped to the reorg window, W3 512-block backfill cap, W4
defer ancestry-difficulty for orphans). Live result: still stalls because forward
header-sync delivers 0 Headers under load — the remaining hard core. Full design
+ remaining work in
[`docs/superpowers/specs/2026-07-03-sync-protocol-convergence-redesign.md`](superpowers/specs/2026-07-03-sync-protocol-convergence-redesign.md).
**Needs a 2-node regtest harness to iterate in seconds + focused header-sync
tracing — not more live redeploy cycles.**

**GEN1 — genesis metadata contradiction (launch-time fix):** `GENESIS_MESSAGE`
says `2026-01-01` but `GENESIS_TIMESTAMP` = `1_735_689_600` (2025-01-01);
testnet has the same mismatch. Genesis is re-mined once at launch with the FINAL
date (any change re-derives the nonce + hash), so align the message/timestamp and
re-mine `MAINNET/TESTNET_GENESIS_NONCE` + `_HASH` then (`mine_genesis` +
`pow_genesis_tests`). Doing it now against a placeholder date is throwaway.

## What was done (security hardening)

- **22+ vulnerabilities fixed** across consensus/DAG, RingCT privacy, mempool,
  P2P, VM/smart-contracts, crash-recovery, and the wallet — 3 of them CRITICAL
  (peer-path confidential gate, reorg key-image/output rollback, crash-recovery
  brick). Every fix has a regression test.
- **FC1 — heaviest-cumulative-work fork choice:** implemented. Tips are ranked by
  total proof-of-work (not blue-block count), with the recovery path using the
  same rule. Prevents a higher-block-count / lower-work chain from displacing the
  honest heaviest chain.
- **Full test suite:** ~2218 unit + integration/e2e/proptest/security tests, 0
  ignored, all passing. Doctests pass. `clippy --all-targets -D warnings` clean.
  All 9 binaries run. `--features desktop` compiles.
- **CI fixed:** the integration-test job referenced a non-existent target and had
  been failing every run; now runs the suite correctly.

## Verified sound (no change needed)

- **Finality (FC2 core):** deep reorgs are rejected pre-write on both the new-chain
  length and the old-chain rollback depth (`MAX_REORG_DEPTH = 200`). With FC1 this
  is a coherent "heaviest chain within a 200-block finality window" rule.
- **State-root determinism:** account + storage maps are `BTreeMap` (sorted), so
  the state root is deterministic across nodes.
- **VM execution determinism:** no wall-clock / RNG / float / hash-map-order
  dependence on the execution path.

## DEFERRED — required before mainnet (need dedicated work + external review)

These are architectural changes to the highest-risk layers. A rushed or
unreviewed change here can split the network or corrupt state — for real money,
the cure must not be worse than the (currently mitigated) disease.

- **G — bind contract state-root into consensus.** Contract `state_root` is
  computed but emitted as `None` and never validated, so a node bug causing
  contract-state divergence would not be caught (UTXO state IS validated;
  execution is deterministic, so this is defense-in-depth). Fixing it changes
  block hashing + the mining flow (fill the root post-execution, validate it on
  the peer path). **Mitigation today:** deterministic execution + authoritative
  UTXO layer.
- **ST1 — cross-store write atomicity.** UTXO / block / DAG / contract stores
  commit in separate RocksDB batches; a crash between them can leave them
  inconsistent. Fixing it needs a unified DB (column families) or a shared
  WriteBatch. **Mitigation today:** block store is written first as the source of
  truth and the others are rebuilt on recovery; the contract↔UTXO case is already
  closed atomically.

## Known incomplete / disabled features (not bugs — by design)

- **Multisig threshold-signature aggregation** (`aggregate_signatures`) is a
  disabled stub; m-of-n collection works, aggregation (MuSig2/FROST) does not.
- **SDK** speaks JSON-RPC over plain HTTP only; **HTTPS is not supported** (rejects
  `https://` explicitly).
- **gRPC** server returns "not yet implemented" for unregistered methods
  (JSON-RPC is the primary interface).
- **Post-quantum (pq-dilithium)** feature is disabled pending a maintained backend.
- The legacy `runtime/vm/core/vm.rs` engine is superseded by `execution_env.rs`
  (the live consensus VM); its CALL/CREATE family are intentional stubs.

## Hard requirements before mainnet (cannot be skipped)

1. **Independent external audit** — crypto (CLSAG / Pedersen / range-proof
   *soundness*, which was NOT verified here) + consensus (fork choice, finality,
   the FC1 change, G, ST1). This is non-negotiable for real funds.
2. **Public testnet for weeks** — multiple real nodes, real mining, real load,
   real adversaries. Synthetic single-process tests do not substitute.
3. **Resolve G and ST1** above, within the scope of (1).
4. **Economic review** of emission, fees, and initial distribution.
