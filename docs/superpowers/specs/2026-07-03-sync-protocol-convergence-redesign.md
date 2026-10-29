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

1. **Difficulty divergence (THE hard blocker — ROOT-CAUSED, CONFIRMED, and FIXED 2026-07-04).**
   With W1–W4 landed, header-sync now works end-to-end (traced live: a fresh node SENDS
   `GetHeaders` from its tip, the peer SERVES 512 headers, the node RECEIVES 512). But the
   next block was still rejected `difficulty mismatch: claimed 4096 expected 3892`, so IBD
   never advanced past the tip. The divergence was inside
   `FullNode::build_retarget_from_canonical` — both the miner (recompute_virtual_chain, which
   rebuilds `self.retarget` on every accept) and tip-extension validation
   (`expected_difficulty_for_block`, via `self.retarget.ema_difficulty()`) go through it, so a
   syncing node computing a different value for the same tip rejected the miner's next block
   forever.

   **Confirmed cause: `dag_width = block_store.blocks_at_height(h)`.** That fed the retarget's
   per-block `dag_block_count` from the LOCAL store's count of blocks at each height — which
   differs between a full miner (holds all red/side siblings) and a syncing follower (holds
   only the selected chain). Via the DAG-rate path (retarget.rs:199, active when
   `dag_blocks_in_window > n`) that changed the computed difficulty. A first unit test with
   *on-target* (1 s) spacing wrongly suggested width-independence — but that regime floors the
   correction (`blended_time` is already 1, so dividing by the ratio and `.max(1)` is a
   no-op). Re-running with *off-target* (3 s) spacing and width 3-vs-1 produced **242 vs 11**
   from the identical selected chain — a 22× divergence — proving the mechanism. The live
   `4096 vs 3892` is the mild real-world version (small real width gap).

   **Fix (LANDED): key the DAG-rate weight on `b.header.parents.len()`.** The parents list is
   committed in the header and covered by PoW (see `BlockHeader::resolved_selected_parent`),
   so it is IDENTICAL on every node regardless of which siblings it holds, yet still scales
   with merge width (a block merging W tips contributes W) — preserving the DAG-rate
   correction while making it deterministic across sync states. No GHOSTDAG threading needed
   (the earlier `ghostdag.get_blue_score` idea is unnecessary — and `header.blue_score` is 0
   for mined blocks anyway). Guard test:
   `retarget_is_independent_of_dag_width_the_node_happens_to_hold` (full_node.rs) builds two
   stores with the identical selected chain but different siblings and asserts equal
   difficulty; it FAILED pre-fix (242 vs 11) and PASSES post-fix. Full suite: 2267 pass.
   **CONSENSUS-FORMULA CHANGE:** difficulty *values* change vs the old formula, so this is a
   hard fork — requires a genesis re-mine / testnet wipe on deploy, and merits external
   review of the economic behavior (single-miner linear chain → parents.len()≈1 → pure chain
   retarget; wide DAG → correction scales with merge width). No live chain not already being
   reset is broken by it (docker testnet is wiped; frozen mainnet is being relaunched).
   **Verify live:** wipe a follower and confirm it IBDs a tall single-miner chain to the tip
   with zero `difficulty mismatch`.

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
