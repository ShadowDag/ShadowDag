# Sync-Protocol Convergence Redesign — Design Spec

> **Status:** design-first. NOT yet implemented. This spec captures the live-diagnosed
> root causes of the remaining convergence blocker and the prioritized redesign.
> Consensus-adjacent — implement with an external reviewer in the loop.

**Goal:** a fresh or far-behind node can reliably join a chain of non-trivial height
(IBD genesis→tip) and stay converged, even under the gossip load of a tall chain.

---

## 1. Problem statement (reproduced live, 2026-07-03)

On the 3-seed docker testnet, once the chain grew tall (~10 000 blocks), a **fresh** node
(`seed3`, wiped) and a **far-behind** node (`seed2`, ~1 400 behind after its own restart
downtime) could **not** catch up. `seed1` (miner) kept advancing; the followers stalled.

**Correctness was never in question:** all synced nodes agreed on the identical block hash
at every common height (e.g. `00008d7a…` at 7738) — no fork, no consensus split. The nine
consensus/privacy/hardening commits this session are correctness-clean. This is purely a
**liveness / sync-throughput** failure.

## 2. Confirmed root causes (each observed in live logs)

1. **Difficulty divergence on out-of-order blocks (the hard blocker).**
   A behind node receives, via gossip, blocks far ahead of its tip. It computes the
   *expected* difficulty from **its own (un-synced) ancestry** and rejects them:
   `difficulty mismatch: claimed 4096 expected 3892`. Difficulty is only correct if blocks
   are validated **in order** (genesis→tip), because each block's target depends on the
   preceding window. A node that cannot IBD in order can therefore validate *nothing* it
   receives out of order.

2. **Header-sync is emitted but does not reliably pull.**
   The daemon sends `GetHeaders{from_hash=best, count=512}` every 6 s
   (`daemon/mod.rs:517`). But the follower's **outbound link to the miner is intermittent**
   (`seed3` shows only 2 successful `outbound_connected addr=144.172…` in its whole history),
   and when a response does arrive the `Headers → GetBlock → Block` apply is **drowned by the
   gossip flood** (thousands of `block_rejected_transient` per minute). Ordered backfill never
   makes sustained progress.

3. **Gossip flood scales with chain height.**
   Peers re-broadcast blocks a behind node cannot use (near-tip orphans:
   `orphan: parent … not found`; or the difficulty-mismatch blocks above). The flood grows
   with chain height, so the taller the chain, the harder it is to join — the event loop
   spends its budget validating-and-rejecting instead of doing ordered sync.
   *Partially mitigated already:* `is_far_future_gossip` (commit 4a08835) cheaply drops gossip
   more than `FINALITY_DEPTH*4` above the tip — but the flood here is *within-window* orphans
   and difficulty failures, a different mode this gate does not catch.

4. **Bootstrap DNS noise (cosmetic, not the blocker).**
   The testnet DNS seeds (`seedN-testnet.shadowdag.network`) are unprovisioned, so the
   reconnect loop spams `Name or service not known`. The IP bootstrap entries DO work
   (`seed3` reaches `144.172` / `172.86` by IP), so this is noise, not the cause — but it
   should be cleaned up (provision DNS or stop retrying dead names so fast).

## 3. Design principles

- **IBD is in-order or nothing.** A node below a peer's tip must fetch and apply blocks
  strictly genesis→tip so difficulty (and every ancestry-dependent check) validates. Never
  attempt to validate a gossiped block whose selected-parent chain to our tip is incomplete.
- **Sync is prioritized over gossip.** While a node is materially behind (tip < peer_best −
  K), it should *suspend* processing unsolicited gossip and spend its budget on the ordered
  `GetHeaders → GetBlock` pipeline. Gossip resumes once caught up.
- **Serve the requested range, don't re-gossip the world.** A peer answering `GetHeaders`
  should return a contiguous forward range from the requester's locator; nodes should not
  blindly re-broadcast their whole chain.
- **One durable sync peer.** Pick a best-height peer as the sync source and keep that
  connection stable for the duration of IBD (don't let slow-peer/lag heuristics tear it down
  mid-backfill; trusted seeds are already whitelisted — extend that to the active sync peer).

## 4. Prioritized work items (each bounded, with an acceptance test)

- **W1 — Block-locator `GetHeaders`.** Send a locator (tip + exponentially-spaced ancestors)
  so the server finds the common ancestor and returns a contiguous forward range. *Accept:*
  a node N blocks behind converges to the tip in ≈ceil(N/batch) round-trips, no genesis
  re-dump.
- **W2 — Behind-node gossip suspension.** While `best_height + K < observed_peer_best`, drop
  *all* unsolicited block gossip cheaply (extend the `is_far_future_gossip` idea to "any block
  not part of the in-flight ordered range"). *Accept:* a far-behind node's event loop shows
  ~0 `block_rejected_transient` and steadily rising height.
- **W3 — Stable sync peer + raise the 64-block `GetBlock` cap.** Keep the chosen sync peer's
  connection exempt from slow-peer teardown during IBD; raise/parameterize the per-`Headers`
  request cap (`p2p.rs`, currently 64) so backfill isn't throttled. *Accept:* sustained
  backfill throughput ≫ current; the sync link survives a full IBD.
- **W4 — Defer ancestry-dependent difficulty for orphans (the hard blocker).**
  *Confirmed mechanism (full_node.rs):* `process_block_inner` runs Phase 1
  (`validate_block_full_with_difficulty`, line ~591) BEFORE the Phase 2 parent-existence /
  orphan check (line ~608). For a block far ahead of our tip (`height > best + 1`),
  `expected_difficulty_for_block` (line 538-543) returns OUR TIP's EMA difficulty — wrong,
  because the block's real target is fixed by ITS OWN un-synced ancestry. So a valid future
  block is hard-rejected `difficulty mismatch: claimed X expected Y` and NEVER reaches the
  orphan buffer. A behind node therefore cannot ingest anything ahead of it, and IBD stalls.
  *Fix (consensus-critical refactor — external review):* split validation into
  (i) SELF-CONSISTENT checks that need only the block (format, PoW-vs-claimed-difficulty,
  merkle, signatures) — always run, reject junk; and (ii) ANCESTRY-DEPENDENT difficulty
  (claimed vs expected-from-parent-window) — run ONLY once the block's parents are present.
  A block with missing parents passes (i), is buffered as an orphan (bounded pool, PoW
  already checked so no junk-flood), and (ii) is validated when it is re-processed after its
  parents arrive in order (before it is ever applied). Difficulty is thus ALWAYS validated
  pre-apply — just deferred for not-yet-connectable blocks. *Accept:* zero `difficulty
  mismatch` rejections during a healthy IBD; a fresh node ingests the miner's chain in order.
  *Do NOT* simply reorder Phase 1/Phase 2 wholesale (breaks the stateless-Phase-1 invariant
  and could buffer non-PoW junk) — split the checks as above.
- **W5 — Bootstrap hygiene.** Provision the DNS seeds (or de-prioritize unresolved names and
  back off their retry) so logs aren't flooded and dial effort goes to reachable peers.
  *Accept:* no `Name or service not known` spam; fresh node connects within seconds.

## 5. Already landed this session (foundation, keep)

- Rate-limit / whitelist / self-connect / orphan-gate / header-sibling-serve /
  orphan-parent-broadcast (convergence layers 1–5) — a level chain converges and stays
  converged.
- `is_far_future_gossip` cheap far-future drop (4a08835) — the W2 seed.
- Recovery replays only the selected chain (bd58912) + GHOSTDAG selected-parent (44a677e) +
  tie-stable recovery (5404639) — recovery reproduces the live chain exactly.

## 6. Non-goals / out of scope

- No consensus-rule change (difficulty *formula*, PoW, emission) — this is transport/sync.
- Not the A1 (state-root-in-PoW) or A3 (fee-attribution past-cone) items — those are separate
  external-review-tier consensus changes.

## 7. Test strategy

- **Local 2-node regtest with a forced gap:** mine N blocks on node A, start node B fresh,
  assert B reaches A's tip with zero difficulty-mismatch rejections and bounded round-trips.
  (Regtest iterates in seconds vs the ~6-min server redeploy.)
- **Property test** the block-locator: for any (behind_height, tip_height), the locator +
  server walk yields a contiguous range covering the gap.
- **Live acceptance:** on the 3-seed testnet, wipe a follower and confirm it IBDs to the
  miner's tip and then tracks it, under the miner's full gossip load.
