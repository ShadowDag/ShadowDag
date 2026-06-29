# ShadowDAG — Mainnet Readiness

Honest status of the codebase for a public **mainnet with real economic value**.
Last updated by the security-hardening pass (2026-06).

## TL;DR

- **Testnet / internal / demo:** READY. Builds, all tests pass, binaries run.
- **Mainnet with real money:** NOT YET. Requires (1) the two deferred consensus/
  storage redesigns below, (2) an independent external crypto + consensus audit,
  and (3) weeks of public testnet. None of these can be self-certified.

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
