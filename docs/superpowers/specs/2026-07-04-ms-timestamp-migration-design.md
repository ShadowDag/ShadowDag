> **Status:** design-first, workflow-generated (7-agent exhaustive map of 207 timestamp touchpoints, 119 high-risk), then lead-synthesized. NOT yet implemented. Consensus-critical hard fork — implement in one activation with an external reviewer in the loop. Enables ~10 BPS.
>
> **GHOSTDAG blocker (spec 6.1) RESOLVED 2026-07-04:** ghostdag core (ghostdag.rs/ordering.rs/blue_set.rs/red_set.rs) read for time arithmetic — the only as_nanos() is in #[cfg(test)]; DagBlock.timestamp (ghostdag.rs:52) is a stored passthrough never used in blue-set/ordering dt math. GHOSTDAG needs NO change; timestamp becomes ms automatically. Safe.

# ShadowDAG — Block+Tx Timestamp Migration: SECONDS → MILLISECONDS

**Spec version:** 1.0 · **Author:** consensus engineering · **Enables:** ~10 blocks/sec selected-chain throughput · **Nature:** hard fork (PoW/coinbase preimage commits to the raw timestamp integer)

## 0. Corrections to the input maps (verified against code)

Before the design, four facts I confirmed by reading the tree — they change the scope:

1. **`retarget.rs:14 MAX_DAG_TIMESTAMP_DRIFT = 5` is DEAD.** Grep shows zero references. The difficulty-map rated it `high`; it is `none`. **Delete it**, do not convert.
2. **Two enforced future-gates the block-validator map declared out of scope actually exist and fire on the block path:**
   - `engine/dag/security/flood_protection.rs:17,42` — own `MAX_FUTURE_SECS=120`, own `.as_secs()` at L34, called from `dag_shield.rs:122`.
   - `engine/dag/core/dag_manager.rs:107,165-166` — own `MAX_FUTURE_TIMESTAMP=120`, own `.as_secs()` at L165.
   Both are block-ts-vs-wall-clock future gates → **both must migrate**. Adding these, there are **six** independent block-future gates, not four.
3. **`block_validator.rs:52` comment already reads "At 10 BPS with 100ms target"** — the code author already anticipated the target below.
4. **`adjust_difficulty` (retarget.rs:309) divides `current*TARGET/actual_time` in u128** — integer-safe today; the ms change keeps it integer-safe only if `TARGET_BLOCK_TIME` stays ≥ the smallest `actual_time` (see §1.5).

Commit **a3cea0d** (read in full) is the smoking gun: it documents the exact failure this migration fixes — at 1s granularity, R4's `ts ≥ parent+1` drifts the tip ahead of wall-clock when mining >1 bps, and the block dies on the 120s future gate (~442 blocks in ~300s, drifted ~140s, then stalled). The commit is a **miner-side throttle only**; it must be relaxed/rescaled post-migration or it re-caps throughput.

---

## 1. CANONICAL DECISIONS

### 1.1 Unit
`BlockHeader.timestamp` and `Transaction.timestamp` are **unix epoch milliseconds**, `u64`. No width change (u64 ms overflows ≈ year 292 million). Both migrate **atomically at the same activation** (they are compared to each other at `block_validator.rs:320` and are each hashed into their own preimage).

### 1.2 TARGET_BLOCK_TIME
For **10 BPS**: **`TARGET_BLOCK_TIME_MS = 100`** (1000 ms / 10 bps). This is the single shared difficulty target that all three engines must equal. `bps_engine.rs:for_bps` already computes `block_interval_ms = 1000/bps = 100` — key every engine off `ConsensusParams` derived from BPS, not a literal.

- Introduce `ConsensusParams::TARGET_BLOCK_TIME_MS = 1000 / BLOCKS_PER_SECOND`, `BLOCKS_PER_SECOND = 10`.
- `pow_difficulty.rs` already uses `TARGET_BLOCK_TIME_MS = 1000`; **change its value to 100** so all three converge.

### 1.3 MAX_FUTURE window
Keep the real-time window at **120 s → `MAX_FUTURE_MS = 120_000`**. 120 s of clock-skew tolerance is unrelated to block spacing; do **not** shrink it. All **six** future-gate constants become `120_000` and all six wall-clock reads become `.as_millis() as u64` (§2).

### 1.4 R4 monotonic (`ts > parent`) under ms — sub-ms ties
R4 stays **strict `>`** (block_validator.rs:599). In ms it enforces **≥ 1 ms progress**, so the max selected-chain rate becomes **1000 blocks/sec** — comfortably above 10 BPS. Sub-ms ties: at 10 BPS honest spacing is ~100 ms, so `parent+1ms` collisions are effectively impossible on the selected chain. The template floor `min_timestamp = max_parent_ts + 1` (rpc_server.rs:1909, daemon/mod.rs:1075) is the mechanism — the `+1` is now +1 **ms**, which is the whole unlock. **Do not widen the `+1`**; strict monotonicity is what anti-timewarp R4 relies on. Parallel DAG blocks at the same height are siblings (not ancestors of each other) so they are **not** subject to R4 against one another — they may share a ms.

### 1.5 MTP / median-time-past scaling
`median_time_past` (block_validator.rs:656) and `MEDIAN_TIME_SPAN=11` are **unit-agnostic** (sort + index) — no code change; output is ms automatically once ancestors are ms. **Value note (non-fork, recommended):** at 100 ms spacing an 11-block MTP spans ~1.1 s of real time (was ~11 s). This is fine for monotonicity but weak as a drift anchor. **Recommendation:** raise `MEDIAN_TIME_SPAN` to preserve real-time coverage (e.g. 99 or 111 blocks ≈ 10–11 s). This is a **consensus value change** and must ship in the same activation. Do **not** adopt `TimestampHelper::median` (timestamp.rs:54) — it averages the two middle values for even input and would diverge from `sorted[len/2]`.

### 1.6 LWMA / retarget dt — integer safety
The retarget ratio is `new = current * TARGET / actual_time` in u128 (retarget.rs:309). Under ms:
- Numerator `TARGET_BLOCK_TIME_SECS → TARGET_BLOCK_TIME_MS = 100`. `actual_time` (blended dt) is now in ms (~100). Units cancel → ratio unchanged in magnitude. **Integer-safe**: `current (≤ u64::MAX/2) * 100` fits u128 with huge headroom; division by `actual_time.max(1)` never divides by zero.
- `compute_lwma` (retarget.rs:335): `dt = t2-t1 else 1`. The `1` floor is now **1 ms**. At 100 ms target, real dts are ~100, so the floor rarely binds — good. Upper clamp `MAX_BLOCK_SPACING = TARGET*10` must be ms (`100*10 = 1000 ms`); leaving it at `10` would clamp every real 100 ms dt down to 10 ms and collapse the average. **Redefine `MAX_BLOCK_SPACING` off the ms target.**
- `expected_blue = time_span * expected_bps` (retarget.rs:236): `expected_bps` is per-**second** integer (=10). `time_span` becomes ms. Must become **`time_span_ms * expected_bps / 1000`** or `expected_blue` inflates 1000× and the blue-stabilizer silently dies identically on all nodes. Verified `expected_bps` is integer, so `/1000` is exact.
- **Same-timestamp heuristic** (`count_same_timestamp_pairs`, retarget.rs:181): a 1-s-resolution hack to detect sub-second mining. Under ms it never fires on honest traffic and mis-fires on rare identical ms. **Remove it** (delete the call and the function), or redefine as "dt below a ms threshold." Removal is cleanest and is a consensus change → same activation.
- Cliff (retarget.rs:264-267): `TARGET_BLOCK_TIME_SECS` → ms in both the threshold and the divisor, else cliff always triggers.

### 1.7 Miner throttle (commit a3cea0d) interaction
`bin/miner.rs:210` `TS_DRIFT_BUDGET_SECS=30` and its sleep math (L211-217) are **miner-local liveness, not consensus**. Post-migration, R4 forces only +1 **ms**/block, so at 10 BPS honest spacing (100 ms) the tip tracks wall-clock and drift no longer accrues — the throttle should essentially never trigger. Still, re-express it in ms to avoid 1000× mis-scaling: `TS_DRIFT_BUDGET_MS = 30_000`, `wait_ms = (min_timestamp - now_ms - TS_DRIFT_BUDGET_MS).min(15_000)`, `sleep(Duration::from_millis(wait_ms.max(1)))`. Also lower **`MIN_SUBMIT_INTERVAL_MS=700`** (miner.rs:602) — it caps *this* miner at ~1.4 blocks/sec, which throttles 10 BPS. Set to ~50–90 ms (tuning, not consensus).

---

## 2. EXHAUSTIVE CHANGE LIST (ordered so the tree never half-migrates)

The compiler will **not** catch a seconds-value flowing into an ms comparison (both are `u64`). Order matters: land the shared constant and the header semantics first behind a version gate, then flip every producer and consumer in one activation. Recommended sequencing = **A (params) → B (validators/gates) → C (retarget) → D (stamping) → E (tx) → F (genesis) → G (RPC/SDK/docs)**, all merged and activated together (single flag-day / fresh genesis; see §4).

### A. Consensus params (do first — single source of truth)
- **`config/.../consensus params` (ConsensusParams / block_validator.rs:34,54,60):**
  - `MAX_FUTURE_SECS 120 → MAX_FUTURE_MS 120_000`
  - `MAX_TIMESTAMP_JUMP_SECS 30 → MAX_TIMESTAMP_JUMP_MS 30_000` (keeps 30 s window)
  - `MAX_DAG_DENSE_TIMESTAMP_JUMP_SECS 10 → *_MS 10_000`
  - `MEDIAN_TIME_SPAN 11 → 99` (see §1.5) — optional but recommended
  - `MAX_PAST_BLOCK_SECS 600` — dead in live path; convert to `600_000` only to keep tests meaningful.
  - Add `TARGET_BLOCK_TIME_MS = 100`, `BLOCKS_PER_SECOND = 10`, `MAX_FUTURE_MS` re-exported so the 6 gates share ONE constant.

### B. All SIX block-future gates + ancestry rules (block-ts vs wall-clock, and vs ancestry)
1. **`engine/consensus/validation/block_validator.rs`**: L557 `.as_secs()→.as_millis() as u64`; L565 uses `MAX_FUTURE_MS`; L614/L629 use the ms jump consts; L320 tx-vs-block uses `MAX_TX_FUTURE_MS=15_000`. R3/R4 (L585/599) unchanged (unit-agnostic, now ms). Update test helpers L1285-1354 + L1649/1663/1677/1689/1738/1810/1833 to ms.
2. **`domain/block/block_rules.rs`**: L16 `120→120_000`; L39 `.as_secs()→.as_millis()`; L43 unchanged shape.
3. **`engine/dag/security/dos_protection.rs`**: L38 `120→120_000`; L109 `.as_secs()→.as_millis()`; L114/116 unchanged shape.
4. **`engine/dag/security/dag_shield.rs`**: L174 & L229 `.as_secs()→.as_millis()`; L178 uses `MAX_FUTURE_MS`; L233 literal `120→120_000`; L237 literal `86_400→86_400_000`. Tests L461/584/673 to ms.
5. **`engine/dag/security/flood_protection.rs`** *(map-missed)*: L17 `120→120_000`; L34 `.as_secs()→.as_millis()`; L42 unchanged shape; tests L138/151 to ms.
6. **`engine/dag/core/dag_manager.rs`** *(map-missed)*: L107 `120→120_000`; L165 `.as_secs()→.as_millis()`; L166 unchanged shape.
- **`domain/types/timestamp.rs`**: already ms — route the above wall-clock reads through `TimestampHelper::now()` (L25) for consistency; **deprecate `now_secs()` (L34)** so no consensus caller can accidentally read seconds. `MAX_FUTURE_DRIFT_MS`, `is_valid`, `median`(don't adopt) unchanged.

### C. Difficulty / retarget (seconds engines → ms; pow engine already ms)
- **`engine/consensus/difficulty/retarget.rs`**: L7 `TARGET_BLOCK_TIME_SECS 1 → TARGET_BLOCK_TIME_MS 100`; **delete L14 `MAX_DAG_TIMESTAMP_DRIFT`** (dead); L32 `MAX_BLOCK_SPACING = TARGET_BLOCK_TIME_MS * 10 (=1000)`; L236 `expected_blue = time_span * expected_bps / 1000`; **remove same-ts heuristic L181/292**; L264-265 cliff → ms target; L309/L461 numerator → ms target; L323/335/342/350/360/371/376 defaults/floors/clamps → ms target. All ratios stay u128-integer-safe.
- **`engine/consensus/difficulty/difficulty_adjustment.rs`**: L26 `TARGET_BLOCK_TIME_SECS → ms`; L37/79 init from ms; L124/128/173/177/190/196 span/expected/clamps → ms. `RETARGET_INTERVAL`(L18)/`RETARGET_BLOCK_INTERVAL`(L23) are block-count — **no change**. Legacy `adjust_difficulty` L216 → ms if any caller; else delete.
- **`engine/mining/pow/pow_difficulty.rs`**: change `TARGET_BLOCK_TIME_MS 1000 → 100` (L46). Everything else already ms — **no other change** (it is the reference model; R1-R4 at L353-384 already `*1000`/ms).
- **`engine/dag/core/bps_engine.rs`**: no consensus change (local production throttle in wall-seconds; `block_interval_ms` already correct). Only update stale "10 BPS" comments.

### D. Stamping sites (three producers — must flip together)
- **`bin/miner.rs`**: L194 `.as_secs()→.as_millis() as u64` (`now_ms`); L210 `TS_DRIFT_BUDGET_SECS→_MS 30_000`; L211/212 ms math; L217 `from_millis`; L220 `now_ms.max(min_timestamp)`; L602 `MIN_SUBMIT_INTERVAL_MS` lower (tuning). L240/269/334/405/561/750/793 carry the `timestamp` var unchanged (now ms).
- **`engine/mining/miner/miner_controller.rs`**: L99 `.as_secs()→.as_millis() as u64` (covers coinbase+header via block_template.rs:132/191).
- **`daemon/mod.rs`**: **L1073 `.as_secs()→.as_millis() as u64`** (the one self-contained logic edit here); L1075 `now.max(max_parent_ts+1)` — `+1` now +1 ms; L1065/1089/1100 passthrough.
- **`engine/mining/stratum/stratum_server.rs`**: `BlockTemplate.timestamp` (L365) originates upstream (node getblocktemplate) → becomes ms automatically. L384/412 hex-encode, L1105/1146/1178/1202 hash/submit — passthrough. Update Stratum protocol doc: ts is ms. Pool stats (now_secs L1316, connected_at/last_share/uptime, VARDIFF/TTL) stay seconds — **no change**.

### E. Transaction timestamps (atomic with block — they are compared and each hashed)
- **`domain/transaction/tx_validator.rs`**: L29 `MAX_TX_AGE_SECS → MAX_TX_AGE_MS 86_400_000`; L38 `MAX_TX_FUTURE_SECS → MAX_TX_FUTURE_MS 15_000`; L1020 `.as_secs()→.as_millis() as u64`; L1025/1034 compare ms (relabel/÷1000 the error strings — cosmetic).
- **`domain/transaction/tx_builder.rs`**: L87 `.as_secs()→.as_millis() as u64`; L123/156 reuse same var (txid+signing preimage must be byte-identical); L226/238/290 passthrough (coinbase ts = block ts).
- **`service/mempool/core/mempool.rs`**: L927/1279/2201/2263 `.as_secs()→.as_millis()`; compare against ms bounds; L2295 legacy fallback now ms (matches). Local pool policy (`low` risk) but must be internally consistent or saturating_sub over/underflows.
- **`config/consensus/mempool_config.rs`**: L122 `MAX_MEMPOOL_TX_AGE_SECS → _MS (72*3600*1000)`; L131 `MAX_ORPHAN_AGE_SECS → _MS (3_600_000)`.
- **SDKs (tx-ts only; NO SDK encodes block ts):** `sdk-python/shadowdag_sdk.py:216,253`, `wasm-sdk/src/lib.rs:266,338`, `runtime/wasm/sdk.rs:190`, and node anchor `domain/transaction/tx_hash.rs:62` — no byte-layout change (u64 LE width-invariant), but every SDK must emit **ms** in lockstep with `tx_validator` or SDK txs sign correctly yet get range-rejected. **`fee *1000` (mempool L398/652/1812) is a fee-resolution factor — DO NOT touch.**

### F. Genesis (hard-fork root; re-mine required)
- **`config/genesis/genesis.rs`**: L43 `GENESIS_TIMESTAMP 1_735_689_600 → 1_735_689_600_000`; L94 testnet `→ *_000`; L105 regtest `0` (invariant). Because ts feeds the PoW preimage (L282/324) and coinbase preimage (L181/212), **re-mine and update** `MAINNET_GENESIS_NONCE` (L62), `MAINNET_GENESIS_HASH` (L63), `MAINNET_MERKLE_ROOT` (L65), `MAINNET_COINBASE_HASH` (L67), and the testnet pair (L70/71) — else `build_block` panics at startup (L343). All nodes ship identical constants. (Alternative "leave genesis as the one pre-migration block + ms from height 1" is possible but forces a mixed-unit R4/MTP normalization at height 1 — **rejected** as higher-risk; see §3.)

### G. RPC / docs (read-only echo + parse)
- **`service/network/rpc/rpc_server.rs`**: emissions getblock 1483 / getblockheader 2341 / getblocksbyheight 2372 / getchain 4130 — **no code change**, now emit ms. getblocktemplate 1903/1909/1924 passthrough (`+1` = +1 ms). submitblock parse 1991 / build 2168 passthrough (bounds enforced in B). Rate-limit as_secs 165/1018 stay seconds. **Add a `*_ms` note or dual field in the RPC schema** so explorers/wallets don't silently misread ms as seconds.

---

## 3. DIVERGENCE-RISK REGISTER (every `high` touchpoint + mitigation)

**Fork mechanism class 1 — ts hashed into PoW/merkle (a unit mismatch changes the block hash every node recomputes):**
| Site | Mitigation |
|---|---|
| `block_rules.rs:50`, `miner.rs:334`, `stratum 1105/1146/1202`, `genesis 282/324/591` (PoW preimage) | Single activation + genesis re-mine (§4). Header **version bump** so a validator interprets each block's ts in its correct era; pre-fork blocks never re-hashed under ms. |
| `miner.rs:240`, `genesis 181` (coinbase→merkle) | Coinbase ts = block ts, migrated by the same producer edit; merkle recompute deterministic per era. |
| `tx_builder 87/123`, `tx_hash.rs:62`, SDKs (tx txid+signature) | tx-ts migrates atomically with block-ts; all SDKs flip together. u64 width-invariant so only the *value* unit matters. |

**Fork mechanism class 2 — ancestry-relative anti-timewarp (all nodes evaluate on identical data; any unit inconsistency = one node accepts what another rejects):**
| Rule | Site | Mitigation |
|---|---|---|
| R3 MTP | block_validator 584/585 | unit-agnostic; ms because ancestors are ms. No mixed-era ancestors (fresh genesis, §4). |
| R4 `ts>parent` | 598/599 | strict `>` unchanged; enables ≥1 ms progress = the unlock. |
| R5/R6 jumps | 613/628 | consts → ms (`30_000`/`10_000`); else collapse to 30 ms/10 ms and reject all real blocks. |
| Retarget difficulty (strict-equality check) | retarget.rs whole file, difficulty_adjustment.rs, feed at full_node.rs:971 | Difficulty is a pure function of ms timestamps; every ms-scaled const converted in ONE release. `validate_difficulty` is `claimed==expected` — any un-migrated second-scaled clamp → every node computes the *same wrong* value and rejects the other convention → split between s-nodes and ms-nodes. Mitigation: no partial rollout — flag-day/fresh chain, all three difficulty engines share `TARGET_BLOCK_TIME_MS=100`. |

**Explicitly called out — block ts vs wall-clock (6 gates):** block_validator 557/565, block_rules 39/43, dos_protection 109/116, dag_shield 174/178, **flood_protection 34/42**, **dag_manager 165/166**. Each pairs a `.as_secs()` read with a `120` const. Mitigation: convert the read AND the const **together, per gate**, all to the shared `MAX_FUTURE_MS`. A half-migrated gate makes every ms block look ~1000× future → universal rejection / sync partition (not a state fork, but a network-wide stall — exactly the a3cea0d death, permanently).

**Explicitly called out — tx ts vs block ts:** block_validator.rs:320 (`tx.timestamp > block.header.timestamp + MAX_TX_FUTURE_MS`) and dag_shield 233/237. Mitigation: tx-ts and block-ts share one activation; both ms.

**Explicitly called out — stored ts:** DagBlock copies (full_node 658/759/2822, daemon 1262), BlockTimeRecord (full_node 971), VM BlockContext (full_node 1852), getblocktemplate max_parent (rpc 1903, daemon 1065). All passthrough → ms once headers are ms. **VM `block.timestamp` opcode is consensus-visible via state_root** — decide ONE policy network-wide: expose raw ms **or** ÷1000 for EVM seconds-convention. Recommendation: expose ms and document it; contracts on this chain are new so no legacy seconds-assumption exists. Whatever is chosen is applied identically on every node (agreement preserved regardless).

**GHOSTDAG caveat (open, must confirm):** DagBlock.timestamp flows into `ghostdag.add_block`. Confirm GHOSTDAG does no seconds-assuming time-difference arithmetic on it (it should use blue-score/topology, not ms deltas). Flagged in §6.

---

## 4. BACKWARD-COMPAT / DEPLOY

- **Hard fork, non-negotiable.** ts is committed into PoW + coinbase + merkle + txid + signature preimages. Same wall instant hashes differently as s vs ms. There is no soft path.
- **Difficulty + validation values change** → old blocks are invalid under new rules and vice-versa. No block can be valid under both conventions.
- **Genesis re-mine REQUIRED** (§2.F): new `GENESIS_TIMESTAMP=1_735_689_600_000` ⇒ new genesis PoW ⇒ re-mine nonce/hash/merkle/coinbase for mainnet and testnet, or nodes panic at startup.
- **Full testnet wipe REQUIRED.** The docker testnet must be reset from the re-mined genesis; no migration of existing s-era blocks (they'd need per-block ×1000 rewrite of a hashed field, which changes every hash — pointless). Wipe + relaunch.
- **Frozen mainnet (systemd 9332, stuck at height 1281 ~2 months, seed3 corrupt — per memory):** this migration is a **clean-slate relaunch opportunity**. The frozen mainnet cannot be upgraded in place (it would fork from block 1282 anyway, and it's already dead). Treat the ms migration as the **mainnet-2 genesis**: re-mine, redeploy all seeds from the fixed genesis, retire the corrupt seed3. Coordinate the flag-day so all seeds start on the ms genesis simultaneously — a single node stamping seconds forks itself off instantly.
- **Header version bump** (`GENESIS_VERSION` / `header.version`) so tooling and any future migration can distinguish s-era (v1) from ms-era (v2) blocks. Even with a fresh chain this future-proofs the next fork.

---

## 5. TEST PLAN

**Unit (deterministic, must be identical cross-node):**
1. **Retarget determinism under ms:** feed a fixed ms `BlockTimeRecord` sequence through `retarget.rs` and `difficulty_adjustment.rs`; assert the emitted difficulty is bit-identical across runs and equals an independently hand-computed value with `TARGET_BLOCK_TIME_MS=100`. Property test: random monotonic ms sequences → difficulty stays in `[MIN,MAX]`, u128 math never overflows/div-by-zero.
2. **`pow_difficulty` vs `retarget` convergence:** same ms input to both engines → assert equal target (they now share `TARGET_BLOCK_TIME_MS=100`).
3. **R1 future (ms):** ts = now_ms + 120_000 accepts; + 120_001 rejects — for **all six gates** (block_validator, block_rules, dos_protection, dag_shield, flood_protection, dag_manager). Assert no gate rejects a valid ms block as "future."
4. **R4 monotonic (ms):** parent ts P, child P+1 accepts (≥1 ms), child P rejects. Sibling blocks at same height sharing a ms both valid.
5. **R5/R6 jumps (ms):** jump 30_000 ms accepts, 30_001 rejects (R5); dense (≥3 parents) 10_000 accepts, 10_001 rejects (R6).
6. **MTP (ms):** with `MEDIAN_TIME_SPAN=99`, assert `median_time_past` picks `sorted[len/2]` in ms and R3 rejects `ts ≤ mtp`.
7. **tx-vs-block (ms):** coinbase ts == header ts (ms) passes L320; a seconds-valued tx in an ms block is rejected as ancient (proves atomicity requirement).
8. **Genesis:** `build_block` mainnet arm does **not** panic with the re-mined ms constants; `verify_genesis_detailed` equality holds; regtest (ts=0) unaffected.
9. **Miner throttle (ms):** with min_timestamp = now_ms (no drift), throttle never sleeps; sleep math uses `from_millis`.
10. **Mempool/orphan expiry (ms):** a tx aged 86_400_000 ms boundary evicts correctly; no saturating_sub under/overflow.

**Live acceptance (the real gate):**
- Fresh testnet from re-mined ms genesis, ≥3 nodes.
- **Sustain > 1 block/sec for ≥ 30 min** (target ~10 BPS) with **zero** future-timestamp rejections and **zero** difficulty mismatches (the a3cea0d failure must not recur: previously stalled at ~442 blocks/~140 s drift).
- Assert selected-chain tip timestamp tracks wall-clock within `MAX_FUTURE_MS` indefinitely (no monotonic drift).
- Cross-node **equal-difficulty**: every node reports identical difficulty at each height (dump + diff).
- Stratum path: external worker mines an ms template, share validates, block accepted (no accepted-share/rejected-block split).
- Reorg/DAG-density test: force ≥3-parent blocks, confirm R6 and GHOSTDAG ordering stable at 10 BPS.

---

## 6. OPEN QUESTIONS / EXTERNAL-REVIEW ITEMS

1. **GHOSTDAG time arithmetic (blocking):** does `ghostdag.add_block` / blue-set selection do any `dt` math on `DagBlock.timestamp` that assumes seconds? Maps did not read the GHOSTDAG core. **Must be read in full before mainnet.**
2. **`MEDIAN_TIME_SPAN` value:** keep 11 (≈1.1 s MTP window at 100 ms) or raise to ~99 (≈10 s)? A too-short MTP weakens the monotonic anchor and eases minor timestamp games. Reviewer to confirm the security/latency tradeoff; either way it's a consensus value fixed at activation.
3. **VM `block.timestamp` policy:** expose raw ms or ÷1000 seconds-convention? Consensus-visible via state_root; both are fork-safe if uniform. Decide before contracts ship.
4. **R5/R6 window sizing:** ×1000 preserves 30 s/10 s real windows but at 10 BPS that's 300/100 blocks of allowed jump. Reviewer to decide whether to tighten (e.g. 5 s / 2 s) for stricter anti-timewarp now that granularity is fine.
5. **`same-ts heuristic` removal:** confirm no other caller depends on `count_same_timestamp_pairs` before deletion (grep: only retarget.rs).
6. **`MAX_DAG_TIMESTAMP_DRIFT` deletion:** confirm nothing imports it via re-export before removing (grep shows single declaration, zero uses — safe, but re-verify on the review branch).
7. **`MIN_SUBMIT_INTERVAL_MS` / RPC write rate-limit:** lowering to ~50 ms to allow 10 BPS may collide with the node's RPC rate limiter — confirm the submitblock path can accept ≥10 writes/sec/miner.
8. **tx-ts scope decision (record explicitly):** this spec migrates tx-ts to ms *with* block-ts (required by the L320 tx-vs-block compare and dag_shield 233/237). The alternative "block-ts ms, tx-ts stays seconds" is **rejected** because those two direct comparisons would mix units. Reviewer to ratify the atomic tx+block migration.

**Files verified in this session (read directly, not from maps):** `block_validator.rs` (30-69, 550-649), `retarget.rs` (1-40, 225-370), `flood_protection.rs` (1-55), `dag_manager.rs` (95-134, 165-171), `genesis.rs` (40-69), plus grep of all `MAX_FUTURE*` and `FloodProtection`/`MAX_DAG_TIMESTAMP_DRIFT` references and commit **a3cea0d** in full. Net corrections to the maps: `MAX_DAG_TIMESTAMP_DRIFT` is dead (delete, not convert); `flood_protection.rs` and `dag_manager.rs` are two additional enforced future-gates that must migrate (total six).
