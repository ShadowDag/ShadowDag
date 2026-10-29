# ShadowDAG — Full Line-by-Line Codebase Audit (findings only, no fixes)

**Started:** 2026-07-05
**Scope:** every production `.rs` file — 293 files / 130,440 lines across engine, service,
domain, config, runtime, infrastructure, bin, daemon. Each file is read IN FULL by an
auditor agent; every candidate finding is adversarially re-verified against the real code.
**Mandate:** produce a COMPLETE list of bugs, vulnerabilities, and correctness/security
issues. Do NOT fix anything — document only.

> This is an INTERNAL audit and does not replace a professional external audit. "No finding
> in a file" means the reviewers surfaced nothing that survived verification, not a proof of
> correctness. Findings are ranked by attacker/impact: Critical (key/value/consensus break),
> High (forgery/DoS/auth bypass), Medium (conditional/degradation), Low/Info (hygiene).

## Coverage tracker

| Batch | Units | Status |
|-------|-------|--------|
| engine-consensus-dag | 8 | **done** (2026-07-05) |
| engine-privacy | 3 | **done** (2026-07-05) |
| engine-mining | 3 | **done** (2026-07-05) |
| engine-other | 3 | **done** (2026-07-05) |
| runtime-vm | 10 | **done** (2026-07-05) |
| service-network | 11 | **done** (2026-07-05) |
| service-mempool | 2 | **done** (2026-07-05) |
| service-wallet | 2 | **done** (2026-07-05) |
| service-other | 1 | **done** (2026-07-05) |
| core-domain | 5 | **done** (2026-07-05) |
| core-config | 2 | **done** (2026-07-05) |
| core-infrastructure | 2 | **done** (2026-07-05) |
| core-bin | 3 | **done** (2026-07-05) |
| core-daemon | 1 | **done** (2026-07-05) |

---

## Confirmed findings

### Batch 1 — engine-consensus-dag + engine-privacy (65 files)

_11 CONFIRMED + 4 latent (unreachable/self-healing) out of 28 raised. Every finding below was
re-read line-by-line against the live source by the lead auditor (not just the sub-agent) before
listing. Severity is post-verification._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B1-C01 | **Critical** | engine/dag/core/dag_manager.rs:227 | consensus / liveness | Unbounded ancestor walk + never-pruned DAG topology → false "cycle" rejects every block once ancestry > 50k = permanent chain halt |
| B1-H01 | High | engine/dag/core/dag_manager.rs:396 | dos | `would_create_cycle` rebuilds a fresh BFS per parent → O(parents × 50 000) RocksDB scans per block |
| B1-H02 | High | engine/dag/security/dos_protection.rs:200 · spam_filter.rs:77 | logic-error | Shield tx outputs (amount=0 by design) not exempt from the zero-output rule → Shield can never be mined |
| B1-H03 | High | engine/dag/sync/dag_sync.rs:180 | concurrency | Iterating a `DashSet` while `remove()`-ing from it inside the loop → shard self-deadlock (ingestion freeze) |
| B1-M01 | Medium | engine/consensus/state/mod.rs:95 | consensus | Post-recovery consistency issues only `warn`, node still boots — violates the module's own "treat as fatal" contract |
| B1-M02 | Medium | engine/dag/ghostdag/ghostdag.rs:356 | consensus | Anticone approximated as `blues ∉ past`, ignoring blues in the block's *future* → legit-blue blocks flipped to red |
| B1-M03 | Medium | engine/dag/ghostdag/ghostdag.rs:392 | consensus | `get_past_set` truncates at 16 384 nodes → corrupt anticone/merge-set classification on any mature chain |
| B1-M04 | Medium | engine/dag/security/spam_filter.rs:82 | validation-gap | Two identical `(address, amount)` outputs rejected as spam (a valid tx shape); dos_protection *allows* them → validators disagree |
| B1-L01 | Low | engine/consensus/difficulty/retarget.rs:344 | logic-error | Long-window avg divides median-to-oldest span by full `n-1` interval count → ~2× underestimate → ~15% difficulty bias |
| B1-L02 | Low | engine/dag/security/dos_protection.rs:106 | validation-gap | `nonce == u64::MAX` rejected as a "sentinel" (valid PoW at that nonce dropped); inconsistent with flood_protection |
| B1-L03 | Low/Info | engine/privacy/ringct/ring_signature.rs:207 | crypto | Legacy `RingSignature` closes the ring with no secret → forgeable, no anonymity. DEPRECATED, test-only, **not** on the consensus path (CLSAG is) |

#### B1-C01 (Critical) — false-cycle chain halt via unbounded ancestor walk
`engine/dag/core/dag_manager.rs:227` — `if self.would_create_cycle(hash, p).unwrap_or(true) { reject("cycle detected") }`.
`would_create_cycle` (lines 396-433) BFS-walks the **parent ancestry** of each parent `p` and returns
`Err` the moment it has walked `MAX_ANCESTOR_WALK = 50_000` nodes (line 24, 406-410); `.unwrap_or(true)`
coerces that `Err` into "assume cycle" and rejects the block. The walk `target` is the new block's own
hash, which is not inserted until line 259 (*after* this check), so `current == target` never matches and
the BFS always traverses the full ancestor set. DAG topology (`parent:`/`child:`/`exists:` keys) is written
at insert (264-265) and deleted **only** by `remove_block_topology` (290+, rollback of a childless tip) —
there is no height/finality-based pruning of edges anywhere (block-body pruning in `block_store` does not
touch DagManager topology). So the reachable ancestry of any live tip grows monotonically with height.
**Failure:** once a tip's ancestor closure exceeds 50 000 blocks (≈ total chain height; at 10 BPS ≈ 83 min
of history, longer on the slower testnet), `would_create_cycle` returns `Err` for every parent and **every
new non-genesis block is rejected as a false cycle on all nodes** — an unrecoverable network-wide liveness
halt, not merely a fork. (The live testnet has not yet crossed 50k, which is why it hasn't manifested.)

**✅ FIXED (commit 4f9a182).** The cycle check was proven to be dead *and* harmful logic: at line 227 the
block is already guaranteed new (line 147-149 rejects it as `DuplicateBlock` if it exists), every parent is
guaranteed to exist (line 222), and none equals the block (line 214 self-parent check) — so the new block is
reachable from no block in the DAG and can never close a cycle. `would_create_cycle` could therefore never
legitimately return `Ok(true)`; it only returned `Ok(false)` or the walk-limit `Err` that `.unwrap_or(true)`
turned into a false rejection. Fix: removed the `would_create_cycle` call, the function, and the now-unused
`MAX_ANCESTOR_WALK` constant — which resolves **both B1-C01 (halt) and B1-H01 (the O(parents×50k) DoS)** since
they share this root. Added a `deep_chain_keeps_accepting_new_blocks` regression test
(tests/suite/consensus_tests.rs). Verified green: build + clippy `-D warnings` (default and gpu-opencl) + tests.
This matches the correct rule already documented for the sibling `block_graph.rs::has_cycle` ("a cycle exists
iff the block is reachable from one of its parents"). NOTE: DAG topology is still never height/finality-pruned
(the growth driver), which remains a separate memory-footprint consideration but no longer causes a halt.

#### B1-H01 (High) — O(parents × 50k) redundant cycle-walk per block
Same function as B1-C01. The caller loop (211-242) invokes `would_create_cycle` once per parent, and the
function allocates a **fresh** `visited`/`queue`/`cache` each call (397-399) with no sharing across the up
to `MAX_DAG_PARENTS = 80` parents of one block. `get_parents` (354) is a RocksDB prefix scan. Worst case
80 × 50 000 = 4 000 000 backend visits to validate a single block, on the sequential acceptance path. On
the P2P path this is gated behind valid PoW, but it still multiplies per-block validation cost up to 80×
and accelerates the approach to the B1-C01 halt.

#### B1-H02 (High) — Shield transactions are unminable (zero-output rule)
`engine/dag/security/dos_protection.rs:196` binds `let is_conf = tx.is_confidential();` and line 200
rejects `output.amount == 0 && !is_conf` as "Zero output". `is_confidential()` is true only for
`TxType::Confidential`, **not** `TxType::Shield`; Shield outputs legitimately carry `amount = 0` (value in
the commitment). The identical bug sits in `spam_filter.rs:71/77`. Both run on the block-acceptance path via
`DagShield::validate_block_for_network` (spam_filter is step 5 / dag_shield.rs:129 → `moderate`; dos is
step 6 / :136 → `severe`), invoked from `block_validator.rs:263`. The sibling site `dag_shield.rs:241` *was*
correctly fixed to `is_confidential() || is_shield()`, proving the exemption was known — these two structural
validators were missed. **Failure:** any block containing a valid Shield tx is rejected chain-wide; Shield is
functionally dead on-chain despite being an advertised feature. (Explains why "Shield live-testnet verify"
was still pending — it would have failed here.)

**✅ FIXED (commit 88b64d9).** Changed both `is_conf` bindings from `tx.is_confidential()` to
`tx.is_confidential() || tx.is_shield()` (dos_protection.rs:197, spam_filter.rs:71), mirroring the
already-correct `dag_shield.rs:244` gate. Verified there is no third live site: all other
`is_confidential`/`is_shield` sites are correctly paired, and `engine/tx_validation/mod.rs`'s own zero-amount
reject is in a `TxValidationPipeline` that has no production caller (dead module). Added two regression tests
(tests/suite/dos_tests.rs): a Shield tx with amount=0 outputs now passes both validators, with a differential
assertion that a *transparent* zero-amount output is still rejected with "Zero output". Green: build + clippy
`-D warnings` (both feature sets) + tests. NOTE: the duplicate-`(address, amount)`-output check (B1-M04) is
separate and still present, but shield outputs use unique one-time addresses so it does not block them.

**⚠️ B1-H02 was INCOMPLETE — a third blocking site found by live testnet E2E (commit 40eaa3e).** After the
dos_protection/spam_filter fix, a live shield tx was accepted to the mempool but every mined block carrying it
was rejected with `tx N structural validation failed`. Root cause: the block path validates each tx via
`TxValidator::validate_structure_for_network` → `sum_outputs` (tx_validator.rs:1135), whose
`if output.amount < DUST_LIMIT { return None }` dust floor also rejects shield/confidential outputs (amount=0).
The original audit grep matched the `amount == 0 && !is_conf` pattern (dos/spam) but MISSED this `< DUST_LIMIT`
variant. Fixed by exempting `is_confidential() || is_shield()` from the dust floor (keeping MAX + overflow), with
a `validate_structure_for_network` regression test (the block-path validator my earlier unit tests didn't
cover). **Lesson: unit tests over individual validators are insufficient for a feature that must pass the whole
block-acceptance pipeline — the live E2E on a clean converged testnet is what surfaced the gap.** After 40eaa3e,
shield is minable end-to-end (see live-verify note in [[testnet-live-state]]).

#### B1-H03 (High) — DashSet iterate-while-remove self-deadlock
`engine/dag/sync/dag_sync.rs:179-186`: `for entry in self.seen_cache.iter() { self.seen_cache.remove(entry.key()); … }`
on `Arc<DashSet<[u8;32]>>`. dashmap's `iter()` holds a **read** guard on the current shard while the yielded
entry is live; `remove()` of a key hashing to that same shard needs a **write** guard on it → the thread
blocks on a lock it already holds. **Failure:** the trim path fires when `seen_cache.len() > CACHE_LIMIT
(50 000)` and the counter hits a 1000-multiple (reachable under sustained block ingestion, since entries are
only ever added, never removed elsewhere); the ingestion thread deadlocks and the sync/ingestion subsystem
freezes. (Deadlock certainty is dashmap-version-dependent; at minimum this is a documented footgun and an
incorrect trim. Fix pattern: `retain`, or collect keys then remove.)

**✅ FIXED (commit 9e7a15c).** Replaced the iterate-then-remove loop with `DashSet::retain` (dashmap's
deadlock-free conditional-removal API — one safe pass, no allocation, evicts the first `CACHE_TRIM` entries).
Extracted into a `trim_seen_cache(cache, max_evict)` helper so it is unit-testable without building a full
`DagSync` (which needs trait-object mocks + RocksDB). A codebase-wide sweep confirmed this was the **only**
iterate-DashSet/DashMap-while-remove site (ghostdag's cache eviction already collects keys first). Regression
test `trim_seen_cache_evicts_bounded_count_without_deadlock` asserts bounded eviction on the real code path
(a revert to iterate-then-remove would hang it). Green: build + clippy `-D warnings` (both feature sets) + tests.
(Note: a *direct* deadlock test is impractical — it would hang on regression rather than fail cleanly — so the
test verifies eviction correctness on the fixed path instead.)

#### B1-M01 (Medium) — partial-recovery consistency downgraded to a warning
`engine/consensus/state/mod.rs:95-99`: after `recover_from_db`, `verify_consistency()` issues (missing tip
in `block_data`, missing `selected_parent` refs, `best_blue_score`/`best_height` ≠ tip's actual values) are
emitted as `slog_warn` and the function returns `Ok(s)`. The doc comment (74-81) explicitly states a node
with partially-recovered consensus state "is dangerous, so callers should treat this as fatal." **Failure:**
on a partially-written/corrupt DB the node boots with a tip absent from `block_data`; `selected_chain_path`
then yields a bogus single-element path, corrupting fork-choice/finality traversal instead of refusing to
start. Not directly attacker-triggerable (requires prior corruption).

#### B1-M02 (Medium) — GHOSTDAG anticone ignores future contamination
`engine/dag/ghostdag/ghostdag.rs:356`: `size = blue_set.iter().filter(|b| !past.contains(*b)).count()`.
The true anticone of `h` w.r.t. the blues is `{b ∈ blues : b ∉ past(h) ∧ b ∉ future(h)}`; this counts any
blue not in `past(h)`, including **descendants** of `h`. `classify_merge_set` (276-302) iterates the merge
set in parent-ward BFS order (descendants-first) with no ancestors-first topological sort, so a descendant
`D` of `h` can be classified blue and inserted into `current_blues` before `h` is processed, then inflate
`h`'s anticone count past `K` and flip a legitimately-blue `h` to red — changing `blue_score`/selected-parent
vs canonical GHOSTDAG. Deterministic (all nodes compute the same wrong result → no inter-node split), but a
real deviation an attacker can steer via DAG shape.

#### B1-M03 (Medium) — truncated past-set corrupts classification on mature chains
`engine/dag/ghostdag/ghostdag.rs:392-394`: `get_past_set` `break`s at `visited.len() >= limit`
(`MAX_ANTICONE_WALK = 16_384`), returning only the nearest ~16k ancestors. With `K = 180` the DAG is wide
and `reconstruct_full_blue_set` accumulates blues over up to 10 000 selected-parent hops, so the blue set
contains genuine deep-ancestor blues outside the 16k window; they satisfy `!past.contains(b)` and are
miscounted as anticone (B1-M02 amplified), inflating counts past `K` and stalling blue-score growth. The
same truncation in `compute_merge_set` (240) lets already-ordered historical blocks be re-added/reclassified.
Deterministic; erodes the GHOSTDAG K-cluster security argument once the chain exceeds ~16k blocks (~27 min
at 10 BPS).

#### B1-M04 (Medium) — valid duplicate outputs rejected as spam
`engine/dag/security/spam_filter.rs:82-85`: keys `seen_outputs` on `(&output.address, output.amount)` and
returns `false` on the first collision → whole block rejected via `DagShield` step 5. Paying the same address
two equal amounts (or change equal to the payment) is a legitimate, common UTXO shape and is forbidden by no
other validator — indeed `dos_protection.rs:208-210` explicitly documents that duplicate `(address, amount)`
pairs ARE valid and does not check them. The two structural validators therefore **disagree**, and any block
carrying such a tx is censored chain-wide.

#### B1-L01 (Low) — long-window average ~2× underestimate
`engine/consensus/difficulty/retarget.rs:341-355`: `median = times[n/2]`, `span = median − oldest` (covers
~half the window's intervals) is divided by `denom = n − 1` (the full-span interval count) → result ≈ `dt/2`.
`long_avg` feeds only the 30% term of `blended_time` (line 170: `(lwma·7 + long_avg·3)/10`), so difficulty
runs ~15% high and selected-chain blocks slightly slow. Deterministic integer math over the same window on
every node — no split, no attacker leverage, no fund impact. Pure calibration error.

#### B1-L02 (Low) — valid `nonce == u64::MAX` rejected
`engine/dag/security/dos_protection.rs:106`: `if block.header.nonce == MAX_NONCE { fail }` with
`MAX_NONCE = u64::MAX`. A relayed/Stratum block whose valid PoW nonce equals `u64::MAX` (submittable as
`ffffffffffffffff`) is dropped as a severe DoS violation, and `flood_protection.rs` treats the same value as
valid (`MAX_VALID_NONCE = u64::MAX`) — the two guards disagree. Impact ~2⁻⁶⁴ per template; harmless in
practice but a real cross-guard inconsistency.

#### B1-L03 (Low/Info) — legacy ring signature is forgeable (deprecated, unreachable)
`engine/privacy/ringct/ring_signature.rs:226-234`: the ring is closed with
`r[s] = alpha ⊕ scalar_mul(c[s], H(pk[s]))`, using only a random `alpha`, the public chain value `c[s]`, and
the public `H(pk[s])`; the private key enters **nowhere** in the ring-closure discrete-log relation (only in
`key_image = SHA256(domain‖priv)`). Any party can therefore reproduce a verifying signature for an arbitrary
key image over an arbitrary ring → no unforgeability, no anonymity, no linkability. **Mitigated:** the file
is `#[deprecated]`, `sign_with_key`/`verify_signature` are referenced only by their own tests, and the live
confidential/consensus path uses CLSAG via `verify_confidential_tx` (utxo_validator.rs:192) — verified by
grep. Listed as a latent crypto hazard for any future caller of the legacy API.

#### Latent (real defect, no reachable impact today) — tracked, not fixed
- **block_processor.rs:54** (info) — `find_fork_point` off-by-one misses a common ancestor at exactly
  `max_depth`, but `BlockProcessor::{find_fork_point,handle_reorg}` are **dead code** (only their own tests
  call them); production reorg uses `full_node::recompute_virtual_chain`. Latent, zero reachable impact.
- **consensus/state/mod.rs:238** (low) — `recover_from_db` trusts the persisted `cs:chain` tip verbatim and
  never re-derives the max-blue-score tip from `block_data`; a non-atomic `persist_block_data`/`persist_chain_state`
  pair (137/149) can leave a stale tip after a crash. **Self-healing**: the next accepted higher-score block
  advances the tip. Narrow crash race, converges — no persistent split.
- **dag_state.rs:255** (info) — `store_block_metadata` writes the color key but (unlike `mark_blue`/`mark_red`)
  never deletes the opposite-color key → both markers could coexist. `store_block_metadata`/`is_blue`/`is_red`
  are **dead code** (no callers). Latent.
- **shadow_pool.rs:490** (low) — `recover_from_db` rebuilds persisted txs with `timestamp = 0`, so the next
  `process()` force-expires them straight to `ready`, bypassing the `MIN_ANON_SET` anonymity guarantee. But
  `new_with_db` (the only path that enables persistence) is **never called** in production (`ShadowNode`/
  `ShadowPoolManager` use `ShadowPool::new()` with `db = None`), so nothing is ever persisted or recovered.
  Latent until persistence is wired.

---

### Batch 2 — engine-mining + engine-other (48 files)

_3 CONFIRMED + 0 latent out of 5 raised. Each re-read line-by-line against the live source before listing._

**Notable clean result:** the cryptographic primitive units — `engine/crypto/hash/*`
(blake3, keccak, muhash, sha3, shadowhash), `engine/crypto/keys/*`, `engine/crypto/random/*`
(csprng, entropy), and `engine/crypto/signatures/*` (ed25519, schnorr, dilithium, falcon) — were read in
full and produced **no finding that survived verification**. (Per the disclaimer, this is "nothing
surfaced", not a proof of correctness; the mandatory external cryptographic review still applies before
mainnet, especially for the post-quantum Dilithium/Falcon paths and the ShadowHash/UmbraHash PoW.)

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B2-M01 | Medium | engine/mining/stratum/stratum_server.rs:652 | dos | The global `workers` **write** lock is held across the heavy ShadowHash in `validate_share`/`meets_network_difficulty`/`share_block_hash` → one worker's submit flood stalls the whole pool |
| B2-L01 | Low | engine/mining/miner/block_template.rs:91 | concurrency | Tips read in two separate lock snapshots (`select_parents` then `get_tips`) → a concurrent tip eviction collapses the computed block height → wasted PoW on a rejected template |
| B2-L02 | Low | engine/mining/stratum/stratum_server.rs:1100 | consensus (forward-compat) | Stratum always hashes with ShadowHash regardless of `template.version`, so at the UmbraHash (v3) fork every pool-found block is rejected by the node's version-gated validator |

#### B2-M01 (Medium) — stratum share validation serializes the whole pool under a write lock
`handle_submit` takes `let mut workers = self.workers.write()` (line 652); line 653 binds `worker` as a
`&mut` borrow of that map, and that borrow is live through lines 713/719/724/762 (`accept_share`, vardiff,
`reject_share`). So the exclusive guard is held across `validate_share` (681), and on the block-found branch
across `meets_network_difficulty` (728) and `share_block_hash` (738) — each a full `shadow_hash_raw_full`
(256 KB scratchpad fill + memory-hard mixing + 256-round anti-ASIC + SHA3). The server is thread-per-
connection, and every worker path (other submits, vardiff `set_difficulty`, disconnect cleanup) contends on
the same single `RwLock`. **Failure:** one authorized worker spamming `mining.submit` with distinct nonces
(distinct nonces skip the pre-hash duplicate check at 667-673, forcing the hash) serializes all workers
behind one lock while a CPU-heavy hash runs per submission, stalling pool service and pinning a core.
**Bounded by:** submit requires a matching worker name (653) and peer_addr (656), and the listener binds
`127.0.0.1` by default (only widened via `SHADOWDAG_STRATUM_BIND`). No consensus/fund impact — degraded pool
service only. Fix pattern: compute the hash outside the `workers` write lock.

#### B2-L01 (Low) — block-template height TOCTOU across two tip snapshots
`build_from_dag` calls `select_dag_parents` (86) which locks+unlocks `TipManager`, then re-reads tips via
`get_tips()` (91) in a *separate* snapshot. The "Read tips ONCE to avoid TOCTOU" comment (88-90) only covers
consistency among the height/score maps built from that second snapshot — not the gap after parent selection.
If a concurrent block insertion (`on_new_block`) evicts a chosen parent `P` between the two reads,
`tip_map_height.get(P)` is `None`, the height loop (102-110) silently skips it, and `max_parent_height`
collapses (to a stale lower value, or 0 → height 1 if all chosen parents were evicted). **Failure:** the
miner builds and mines a template whose height violates the `max(parent_heights)+1` rule; `Miner::validate_parents`
doesn't check height, so the wasted PoW is only caught when peers (and its own `block_validator.rs:962-971`,
which recomputes height from the real DAG) reject the block. Narrow window, self-healing next template, no
consensus split — pure wasted-work/liveness.

#### B2-L02 (Low) — stratum PoW not version-gated (UmbraHash fork will reject all pool blocks)
`validate_share` (1100), `meets_network_difficulty` (1141), and `share_block_hash` (1196) unconditionally
call `shadowhash::shadow_hash_raw_full(template.version, …)` — `version` is only a hash *input*, never an
algorithm switch. But `PowValidator::validate` (pow_validator.rs:48-64) hard-rejects sub-v3 blocks once
`umbra_required_at(height)` and routes `version >= 3` to `umbra_check` (UmbraHash `hashimoto_light`), a
different hash. **Failure (latent):** when templates bump to v3 at the planned hard fork, the pool accepts
shares under ShadowHash that aren't valid UmbraHash and submits blocks the node recomputes under UmbraHash
and rejects → all pool-found blocks lost. Not triggerable today: `UMBRA_ACTIVATION_HEIGHT = None` and both
the daemon RPC template and `block_template.rs` hardcode `version: 2`. The standalone `bin/miner.rs` already
gates on `umbra_mode`, so only the pool path was left unported — must be fixed as part of enabling the fork.

---

### Batch 3 — core-domain (42 files)

_1 CONFIRMED + 0 latent out of 14 raised (13 refuted on verification). Re-read line-by-line before listing.
The core data layer — `transaction.rs`, `tx_validator.rs`, `utxo_set.rs`, `utxo_validator.rs`, `merkle_*`,
`amount.rs` (overflow), `address/*` — was otherwise solid; the single surviving finding is a remote panic._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B3-H01 | High | domain/utxo/utxo_set.rs:44 | panic / dos | `utxo_key`'s error string slices the txid at byte 24 without a char-boundary check → a crafted non-ASCII txid panics the tx-validation thread (remote DoS via the mempool path) |

#### B3-H01 (High) — remote panic on a crafted txid in `utxo_key`
`domain/utxo/utxo_set.rs:40-47`: `utxo_key` calls `UtxoKey::try_new(...).ok_or_else(|| StorageError::Other(format!(…, &tx_hash[..tx_hash.len().min(24)])))`.
The `ok_or_else` closure is evaluated **eagerly** on every malformed (`None`) txid, and `&tx_hash[..24]`
panics when byte 24 is not a UTF-8 char boundary. `.min(24)` bounds the *length* but not the boundary, so a
txid of e.g. 22 ASCII bytes + a 4-byte emoji (bytes 22-25) makes index 24 land mid-codepoint → panic. The
function's own doc comment (37-38) claims it "Returns `Err` on malformed hashes instead of panicking — safe
for untrusted network input", which is **false** — the `format!` panics before any `Err` is produced.
**Reachability (verified precisely — the panic is inside `utxo_key`, so `.ok()`/`match` wrappers do NOT
prevent it; it fires before any `Err` is returned):** `TxInput.txid` is an unvalidated `String` and
`DagShield::pre_validate_tx` never checks each `input.txid`. The relay admission `Mempool::add_transaction`
runs the signature gate (`verify_signatures_for_network`, mempool.rs:537) **before** any `utxo_key` call, so
the poison tx must be **attacker-signed** — trivial: the attacker sets `input.owner` to their own pubkey and
signs the signing message (which serializes the raw txid bytes, so no panic there). Such a tx is admitted
(no UTXO-existence or txid-format gate at relay). The panic then fires when a `utxo_key`-bearing consumer
processes the admitted tx: the **block builder** `select_transactions_for_block` (mempool.rs:1139/1150/1159)
— which crashes the miner's block-production thread, and because the tx persists in the mempool, keeps
crashing it (mining DoS); the **RBF path** inside `add_transaction` (mempool.rs:614) for a conflicting tx;
and the **authenticated** `sendrawtransaction` RPC → `add_transaction_validated` → `validate_tx_for_network`
(mempool.rs:1458 → tx_validator.rs:288). Incoming *block* validation is guarded (`dag_shield.rs:399` rejects
non-64-hex txids), so this is a mempool/relay/mining-side crash, not a consensus split/inflation/fund-loss.
Near-zero-cost remote DoS on block production → **High**. (Correction vs. the initial auditor note: the tx
must be validly self-signed, and the crash lands on the block-builder/consumer, not "instantly on receipt".)

**✅ FIXED (commit 0057a92).** Replaced the panicking byte slice `&tx_hash[..tx_hash.len().min(24)]` with a
char-boundary-safe preview `tx_hash.chars().take(24).collect::<String>()`, which never panics. A codebase-wide
sweep for the same byte-slice-panic class confirmed this is the **only** reachable production instance: the
twin `&tx_hash[..24]` in `utxo_key.rs:61` is `#[cfg(test)]` (the strict test-only constructor that panics on
bad data by design); `block_validator.rs:297` slices `tx.hash` but is guarded — `DagShield`/`SpamFilter`
(block_validator.rs:263) rejects any duplicate-hash block via the identical `HashSet` dedup *before* that line
is reached; and every `hex::encode(&hash[..20])`-style slice is on `[u8; 32]` byte arrays (byte indexing is
always boundary-safe). Regression test `utxo_key_rejects_non_ascii_txid_without_panic` (22 ASCII bytes + a
4-byte emoji straddling byte 24) asserts `Err`, not panic. Green: build + clippy `-D warnings` (both feature
sets) + tests.

---

### Batch 4 — service-network (48 files, incl. the 5656-line RPC server, 3347-line full_node, 2787-line p2p)

_11 CONFIRMED + 3 latent out of 34 raised. Each re-read line-by-line before listing; the tx-relay finding
(B4-M03) was traced end-to-end through the mempool accept path to confirm no `verify_for_network` gate._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B4-M01 | Medium | service/network/p2p/peer_manager.rs:291 | concurrency | `add_peer_record` reads the per-IP conn count outside the write lock (TOCTOU) → concurrent adds from one IP exceed `MAX_PEERS_PER_IP` and corrupt the counter |
| B4-M02 | Medium | service/network/propagation/dandelion.rs:261 | privacy | Stem next-hop re-randomized **per transaction** instead of fixed per-epoch → breaks the Dandelion++ anti-deanonymization guarantee (the per-epoch `stem_peer_map` is dead) |
| B4-M03 | Medium | service/network/relay/tx_relay.rs:90 | dos / censorship | Relay+mempool dedup keyed on the **unverified** `tx.hash`; the mempool accept path checks signatures but not `hash==content`, so an attacker can pre-seed a victim's hash and censor their tx |
| B4-L01 | Low | service/network/nodes/full_node.rs:2660 | dos | `peer_block_timestamps` never evicts empty per-peer entries → unbounded map growth across rotated `peer_id`s |
| B4-L02 | Low | service/network/nodes/full_node.rs:2698 | dos | Multi-parent orphan resolved via one parent leaves its hash dangling under the other parents in `orphan_by_parent` (slow leak) |
| B4-L03 | Low | service/network/nodes/light_node.rs:107 | logic-error | SPV future-timestamp gate compares a **ms** header timestamp to a **secs** wall clock → rejects every real header (SPV sync broken); module not wired into the running node |
| B4-L04 | Low | service/network/p2p/peer_manager.rs:338 | concurrency | `remove_peer` checks existence outside the write lock, then unconditionally decrements `meta:peer_count` → concurrent double-remove undercounts the store |
| B4-L05 | Low | service/network/rpc/rpc_server.rs:4179 | integer-overflow | `getblockrange` computes `from + 10 / from + 100` unchecked on attacker `from` (release wraps to empty range; debug panics) |
| B4-L06 | Low | service/network/rpc/rpc_server.rs:3924 | integer-overflow | `getdagslice` loops `from_height .. from_height + count` unchecked (sibling `getblocks` uses `saturating_add`; this one doesn't) |
| B4-L07 | Low | service/network/sync/chain_verifier.rs:196 | logic-error | Header future-check mixes **ms** timestamp with **secs** clock → rejects all real chains; `ChainVerifier` has no production caller (dead) |
| B4-L08 | Low | service/network/sync/chain_verifier.rs:247 | logic-error | Inter-header gap is a **ms** delta compared to a **secs** constant (`MAX_HEADER_TIME_GAP_SECS=120`) → misjudges normal spacing; dead code |

#### B4-M01 (Medium) — per-IP connection cap is racy (TOCTOU)
`add_peer_record` reads `conn_count_for_ip(ip)` at line 291 (which locks, reads, and **releases** the DB
lock), checks `count >= MAX_PEERS_PER_IP` at 292, then re-acquires the lock at 301 for the write batch. The
`already_exists`/`stored` checks *are* inside the write lock (302-309), but the per-IP `count` is not, so two
concurrent adds of *distinct new* addresses on the same IP both read the same stale count and both write
`count+1` — a lost update that (a) lets one IP exceed `MAX_PEERS_PER_IP=3` and (b) leaves `conn:IP`
undercounted (it can even drift to 0 while records remain, since `remove_peer` also decrements it). Weakens a
defense-in-depth per-IP anti-DoS/eclipse limit; not a consensus/fund invariant → Medium. (`add_peer_record`'s
own `stored` counter is race-free because it's read+written under one lock — `remove_peer` is the mirror bug,
B4-L04.)

#### B4-M02 (Medium) — Dandelion++ stem successor re-randomized per-tx (anonymity loss)
`select_stem_peer_from` (dandelion.rs:256-263) picks `peers[next_rng() % peers.len()]` with a **fresh** OsRng
draw per call, so every stem transaction goes to an independently-random next hop. Dandelion++ (Fanti et al.
2018) requires a **stable per-epoch** stem successor so an adversary can't use graph-learning/intersection to
localize the source; the code even declares a per-epoch `stem_peer_map` (field 74) but it is only cleared on
epoch rotation and **never read or written for routing** (dead). The relay is live (used by `mempool_manager`
and `p2p.rs:936`), so a victim's stem edges fan across all peers within an epoch — exactly the deanonymization
Dandelion++ exists to prevent. Weakens (not fully removes) source-hiding in a **privacy coin's core relay** →
Medium.

#### B4-M03 (Medium) — transaction censorship via unverified `tx.hash` dedup
`tx_relay.rs` keys relay dedup on `relay:tx:{tx.hash}` (50, 90) taken from the raw deserialized tx, and the
mempool keys its dup gate on `tx:{tx.hash}` — but the **relay/mempool accept path never verifies that
`tx.hash` commits to the content**. `Mempool::add_transaction` runs `verify_signatures_for_network`
(mempool.rs:537) — which signs over a message that *includes* `tx.hash` as a field — but **not**
`TxHash::verify_for_network` (the `hash_for_network(tx)==tx.hash` check). So an attacker spending their own
UTXOs can sign a tx that carries a *victim's* predictable future hash `H`; it is accepted, writes `tx:{H}` and
`relay:tx:{H}`, and the genuine victim tx `H` is then dropped as a duplicate/already-relayed at both gates —
targeted censorship/griefing for one relay fee. **Bounded:** block-inclusion *does* enforce the hash
(`validate_structure_for_network` → `verify_for_network`, tx_validator.rs:367, on the block path), so the
poison tx can never be mined → no fund loss/inflation, mempool-layer censorship only → Medium.

#### B4-L01…L08 (Low) — leaks, races, unchecked arithmetic, and a ms/secs cluster
- **B4-L01 / full_node.rs:2660** — `is_peer_rate_limited` prunes each peer's inner timestamp `Vec` but never
  removes the emptied outer key; `peer_id` is attacker-mintable (self-signed Ed25519 identity), so the map
  grows one ~100-byte entry per identity forever (no disconnect/sweep cleanup). Contrast `orphan_count_by_peer`
  which *does* remove-at-zero. Slow unbounded growth (~1M identities ≈ 100 MB).
- **B4-L02 / full_node.rs:2698** — `add_orphan` registers a multi-parent orphan under every parent; resolving
  via one parent (`by_parent.remove(current_parent)` + `orphan_pool.remove`) leaves its hash dangling under the
  other parents. `evict_expired_orphans` can't reclaim them (gated on `pool.get(hash)`, already gone).
  Self-healing when siblings later arrive; permanent only for never-arriving parents.
- **B4-L04 / peer_manager.rs:338** — `remove_peer` checks `peer_exists` under a transient lock, then re-locks
  and does an unconditional `meta:peer_count = stored.saturating_sub(1)`; two concurrent removes of the same
  addr both pass the check and both decrement while one record is deleted → the persisted count drifts *below*
  ground truth, weakening the `MAX_STORED_PEERS` cap (can only over-admit, never wrongly reject).
- **B4-L05 / rpc_server.rs:4179** and **B4-L06 / rpc_server.rs:3924** — `getblockrange` (`from+10`/`from+100`)
  and `getdagslice` (`from_height+count`) do unchecked `u64` adds on attacker-controlled, unauthenticated
  read-only params. Production (release, no overflow-checks) wraps to a degenerate empty range → benign; debug
  builds panic the connection thread. The sibling `getblocks` guards the identical pattern with
  `saturating_add` — these two were missed.
- **ms/secs cluster (B4-L03 / light_node.rs:107, B4-L07 / chain_verifier.rs:196, B4-L08 / chain_verifier.rs:247)**
  — three future/gap timestamp checks in the SPV light-node and the standalone chain-verifier still compare
  **millisecond** header timestamps against **second**-scale clocks/constants (leftovers the ms-timestamp
  migration missed). Each would fully break header sync if driven with real headers, but **both modules are
  currently unwired in the running full node** (the live path validates in ms via `block_validator`), so the
  harm is confined to any external SPV consumer. If either is ever wired into production sync, these escalate
  to High (self-inflicted sync failure / chain rejection).

#### Latent (real defect, no reachable impact today) — tracked, not fixed
- **peer_manager.rs:82** (info) — `PeerRecord::is_active` does `now - last_seen` unchecked; a backward local
  clock step underflows. In release it wraps to `~u64::MAX` → `< PEER_HEALTH_TIMEOUT_SECS` is false → the peer
  is treated *inactive* (transient, self-healing exclusion), not "active" as first summarized; not
  attacker-influenced. Info.
- **reputation/mod.rs:206** (low) — `effective_score`'s anti-eclipse "age bonus" is derived from message
  counters (`total_ok + total_sent`) not wall-clock uptime, so a Sybil can fabricate it by sending cheap
  traffic. But the whole `ReputationManager` API (`effective_score`/`weakest_peer`/`should_admit_over_weakest`)
  has **no production caller** — peer admission uses the separate `peer_manager` reputation subsystem. Would be
  a genuine Medium anti-eclipse weakness the moment it is wired in.
- **rpc_server.rs:4021** (info) — `estimatetxfee` multiplies attacker-controlled input/output counts unchecked
  (`inputs*150 + outputs*50 + 50`); pure calculation, no state effect (release wraps to a nonsense estimate,
  debug panics the one request). Info.

---

### Batch 5 — runtime-vm (ShadowVM, 43 files incl. the 6120-line execution_env)

_5 CONFIRMED + 1 latent out of 15 raised. A key severity correction was made after tracing the live vs. dead
VM: the production path is `ExecutionEnvironment::execute_frame` (execution_env.rs), not the legacy `vm.rs`._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B5-M01 | Medium | runtime/vm/core/execution_env.rs:3357 | dos / gas | `LOG1-4` charge memory-expansion but **no per-byte log-data gas** → ~4470× undercharge lets a contract force every validator to materialize/store huge log payloads within the block gas budget |
| B5-M02 | Medium | runtime/vm/precompiles/crypto_precompiles.rs:102 | crypto | `ed25519_verify` precompile (0x08) uses non-strict `verify()` → signature malleability; contracts relying on signature uniqueness/replay-protection can be defeated |
| B5-L01 | Low | runtime/vm/core/execution_env.rs:1546 | gas | `EXP` charges only flat opcode gas (no per-exponent-byte cost) → ~32× ALU undercharge vs. EVM `10 + 50·byte_len(exp)` |
| B5-L02 | Low | runtime/vm/precompiles/math_precompiles.rs:85 | logic-error | `modexp` with `mod_len == 0` returns a 1-byte output (`.max(1)`) instead of empty, violating its own contract and EIP-198 |
| B5-L03 (latent) | Low | runtime/vm/core/vm.rs:1136 | panic | `MLOAD`/`MSTORE` truncate the U256 offset with `as_usize()` then `offset+32` wraps → out-of-order slice panic — but this is the **legacy `vm.rs` engine with no production callers** (dead) |

#### B5-M01 (Medium) — LOG opcodes undercharge data bytes (resource-exhaustion amplification)
In the live VM's dispatch loop (execution_env.rs:1350-1359) the **only** per-opcode gas is the flat
`op.gas_cost()` at line 1352. The `LOG1-4` arm additionally charges just `charge_and_expand_memory(…, end)`
for the data window (3357) and then copies `memory[offset..end].to_vec()` into an unbounded `logs` Vec (3363-3365).
There is **no 8-gas-per-byte log-data charge** (EVM's `375 + 375·topics + 8·bytes`; the per-topic 375 *is*
present, folded into the base cost at opcodes.rs). Once memory is warm, `charge_and_expand_memory` returns
immediately (zero incremental gas), so a loop of `LOG4 offset=0 length=1_048_576` costs only the flat 1875
base each iteration while allocating+storing a 1 MB payload — a ~4470× undercharge that every validating node
re-executes and stores. Notably the `*COPY` opcodes already got a dedicated `charge_copy_words` guard
(execution_env.rs:1042, comment: "a CPU/bandwidth DoS replayed by every validating node") — the same guard was
never applied to LOG. Bounded by the block gas budget but amplified — Medium.

#### B5-M02 (Medium) — ed25519 precompile permits malleable signatures
`ed25519_verify` (crypto_precompiles.rs:102) calls `vk.verify(message, &sig)` — the permissive, cofactored
ed25519-dalek 2 equation that tolerates non-canonical `S` and torsion points — with no manual canonicality
check. It is registered live at address **0x08** (precompile_registry.rs:158-164). The project already treats
ed25519 malleability as security-relevant everywhere else: `tx_validator.rs` deliberately pairs
`s_is_canonical(...)` with `verify_strict(...)` and comments "prevents signature malleability… the same tx
could have multiple valid signature encodings". A contract using precompile 0x08 for signature-based
authorization/replay-protection can be attacked: given one valid signature an attacker produces a second
distinct one that also returns `0x01`. Deterministic, so **not** a consensus fork — a contract-level crypto
weakness → Medium. (Same lax `verify()` also at runtime/wasm/sdk.rs:173.)

#### B5-L01 / B5-L02 (Low) — EXP gas + modexp output length
- **EXP (execution_env.rs:1546-1551)** does `base.wrapping_pow(exp)` (a real 256-bit square-and-multiply,
  ~256 iterations for a full exponent) but is billed only the flat `EXP=50` base gas — no per-exponent-byte
  surcharge. ~32× undercharge vs. EVM; bounded constant factor, microseconds per op → Low gas-fairness nit.
- **modexp (math_precompiles.rs:84-85)** returns `vec![0u8; mod_len.max(1)]` for `mod_len == 0` — one byte
  where the module's own contract and EIP-198 require empty output (the neighboring `modulus==0` branch at 90
  correctly returns exact `mod_len`). Deterministic (no fork); only a contract depending on EIP-198-exact
  return length is affected → Low.

#### B5-L01-latent — `vm.rs` MLOAD/MSTORE offset-truncation panic (DEAD legacy engine)
`vm.rs` MLOAD (1130-1159) and MSTORE (1161-1187) take the offset via `as_usize()` (low 64 bits only, ignoring
the safe `U256::to_mem_offset()` reject-on-overflow helper) then compute `offset + 32`; for an offset near
`u64::MAX` this wraps (release) into a range `start > end`, panicking on the slice — or panics on the add
itself (debug). **However `vm.rs` is explicitly the legacy engine**: its own header (543-574) states "LEGACY
ENGINE — NOT THE PRODUCTION EXECUTION PATH… `cargo grep ShadowVm` returns no callers; `execute_bytecode` is
only invoked from `vm::tests`", and it stubs out CALL/CREATE entirely. The production path
(`ExecutionEnvironment::execute_frame`) guards the analogous offsets with `checked_add` + `MAX_MEMORY_SIZE`
bounds (see the latent note below), so **no reachable panic in the live VM**. Recorded as latent/Low, correcting
the auditor's Medium (which assumed the code was on the block-validation path).

#### Latent (real defect, no reachable impact today) — tracked, not fixed
- **execution_env.rs:1967** (info) — `RETURN`/`REVERT`/`CALL`/`*COPY`/`LOG`/`CREATE` in the **live** VM take
  memory offsets via `as_u64() as usize` (low-64 truncation) instead of the file's own `to_mem_offset()` (which
  `MLOAD`/`MSTORE`/`CALLDATALOAD` do use). But every one of these sites routes the truncated offset through
  `read_memory_zero_padded` / `checked_add` + `MAX_MEMORY_SIZE` bounds before any slice, so the result is a
  bounded in-range window — no OOB, no panic, fully deterministic (no fork). An EVM-conformance/internal-
  consistency nit (all sites should use `to_mem_offset()`), not a reachable defect. Info.

---

### Batch 6 — mempool + wallet + service-other + storage (33 files)

_6 CONFIRMED + 1 latent out of 33 raised. Each re-read line-by-line before listing. Clean units: the RocksDB
storage layer (`core-infrastructure-0`, 14 files), `service/rpc/auth`, `service/security/dos_protection`, and
`service/events/*` surfaced nothing that survived verification._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B6-M01 | Medium | service/mempool/core/mempool_manager.rs:143 | logic-error | `on_new_block` cascade-removes a confirmed parent's still-in-mempool children, which just became spendable → CPFP children silently dropped, must be rebroadcast |
| B6-M02 | Medium | service/mempool/core/mempool.rs:856 | dos | `remove_single_tx` does full O(n) scans of the entire `fee:` and `rdep:` index on **every** removal → cascade eviction is O(n²), a CPU-DoS under mempool congestion |
| B6-M03 | Medium | service/wallet/keys/multisig.rs:211 | logic-error | Multisig `is_expired` compares a **ms** elapsed time to a **secs** constant (`SIG_TIMEOUT_SECS=3600`) → pending multisig expires in 3.6 s instead of 1 h, breaking signature collection |
| B6-L01 | Low | service/wallet/core/wallet.rs:198 | validation-gap | `restore_from_mnemonic` does no BIP39 checksum/wordlist/count check → a typo derives a different valid-looking seed and silently restores an empty wallet |
| B6-L02 | Low | service/wallet/core/wallet.rs:785 | integer-overflow | `InsufficientFunds { need: amount + fee }` is unchecked (the guard above uses `saturating_add`) → debug panic / release wrap in the local CLI on `amount=u64::MAX` |
| B6-L03 | Low | infrastructure/storage/rocksdb/utxo/utxo_store.rs:50 | data-loss | `add_utxo` writes the UTXO and its `addr:` index as **two non-atomic puts** (every sibling path uses a `WriteBatch`) → a power-loss torn write leaves a spendable-but-unindexed UTXO, under-counting `get_balance` until rescan |

#### B6-M01 (Medium) — confirming a parent evicts its still-valid children (CPFP breakage)
`on_new_block` (mempool_manager.rs:139-147) calls `tx_pool.remove_with_dependents(txid)` for each confirmed
txid; `remove_with_dependents` (tx_pool.rs:76-85) collects `get_dependents(txid)` (the live `rdep:` edges) and
recursively removes every dependent. When a block confirms parent `P` but **not** its mempool child `C` (a
routine case — late arrival, size-limited template, or a peer that mined without `C`), `C`'s input (`P`'s
output) is now a *confirmed* UTXO, so `C` just became valid and mineable — yet it is hard-deleted from the
mempool with no re-injection. This is exactly the child-pays-for-parent case (a child added to bump a low-fee
parent), evicted the instant the parent confirms; the user must rebroadcast. Deterministic across nodes (no
fork), no fund loss → Medium liveness/relay degradation.

#### B6-M02 (Medium) — O(n²) mempool eviction under congestion
`remove_single_tx` (mempool.rs:835-922) deletes a tx's `fee:` entry by scanning **all** `fee:` keys and
matching by value (`prefix_iterator(PFX_FEE).filter(|(_,v)| v==txid)`, 856-863) and its `rdep:` entries by
scanning **all** `rdep:` keys and matching the suffix (881-892) — both full O(n) walks. They are avoidable:
the `fee:` key is deterministically reconstructible from the already-loaded tx (same formula at 398/653) and
the `rdep`-as-child edges are exactly `rdep:{input.txid}:{input.index}:{txid}` — indeed the neighboring `dep:`
scan (868-876) *does* use a txid-keyed prefix seek. `remove_transaction` cascades the full dependent closure,
and `evict_to_fit` removes up to `EVICTION_BATCH_SIZE=256` per round on the pool-full `add_transaction` hot
path, so removing k txs from an n≈100 000 pool is O(k·n) (~5×10⁷ key iterations/round) — an attacker sustains
it by keeping the pool full with a long low-fee dependency chain. Throughput degradation, not a hard halt →
Medium.

#### B6-M03 (Medium) — multisig signature window is 3.6 seconds, not 1 hour (ms/secs)
`PendingMultisig::is_expired` (multisig.rs:211) is `now_ms().saturating_sub(self.created_at) > SIG_TIMEOUT_SECS`.
Both `now_ms()` and `created_at` are epoch **milliseconds**, but `SIG_TIMEOUT_SECS = 3_600` is **seconds**, so
the entry expires after 3600 ms = 3.6 s. `MultisigManager::sign` rejects with "Pending multisig has expired"
and `cleanup` evicts it, so in a 2-of-3 the second signer arriving even 5 s later is refused and the pending
state is silently dropped — multisig collection is unusable for any realistic human/network latency (tests miss
it because they add all partials in the same instant). Wallet-side, no consensus/fund impact → Medium
functional break. (Another leftover of the ms-timestamp migration — cf. B4-L03/L07/L08.)

#### B6-L01 / B6-L02 / B6-L03 (Low)
- **wallet.rs:198** — `restore_from_mnemonic` guards only empty/blank words then calls `mnemonic_to_seed_simple`
  (PBKDF2 over the joined words) with no BIP39 checksum, wordlist-membership, or word-count check (the CLI
  caller doesn't even enforce 12 words). A single mistyped word yields a different seed → a fresh empty wallet
  returned as `Ok`. No fund loss (the correct phrase still recovers the real seed deterministically), local UX
  hazard only → Low.
- **wallet.rs:785** — the `InsufficientFunds { need: amount + fee }` error value is built with unchecked `+`
  while the guard at 783 uses `saturating_add` and the balance sum at 781 uses `checked_add`. `amount=u64::MAX,
  fee=1` overflows: debug panic / release wrong number, in the operator's own CLI on self-supplied input (no
  remote/RPC vector). The two sibling sites (520, 968) are correct → Low.
- **utxo_store.rs:50** — `add_utxo` does `put(key,data)` then `put(addr_key,key)` as two separate writes (all
  sibling paths — `spend_utxo`, `apply_transaction`, `write_batch` — use an atomic `WriteBatch`; `unspend_utxo`
  reorg-restore calls straight into this). A plain process crash is safe (shared WAL replays both atomically);
  only an OS/power-loss torn write between the puts leaves a spendable-but-unindexed UTXO, under-counting
  `get_balance` until a rescan. Under-count only (never over-count/inflation), recoverable → Low.

#### Latent (real defect, no reachable impact today) — tracked, not fixed
- **wallet.rs:962** (info) — `select_utxos` accumulates `total += u.amount` unchecked (debug panic / release
  wrap) while the sibling `update_utxos` uses `checked_add(...).unwrap_or(u64::MAX)`. Reaching it needs one
  account's unspent UTXOs to sum past `u64::MAX` (~decades of total emission concentrated+unspent) and the loop
  breaks at `total >= amount` first, so no honest-state failure — latent robustness gap. Info.

---

### Batch 7 — config + bin + daemon (18 files)

_2 CONFIRMED + 2 latent out of 10 raised. Each re-read line-by-line before listing. Clean units: `config/genesis`,
`config/checkpoints` (see latent), `config/consensus/{consensus_params,emission_schedule,mempool_config}`,
`config/network/*`, `bin/{node,miner,mine_genesis,loadtest,rotate_rpc_password}`, and `daemon/mod.rs` surfaced
nothing that survived verification — the consensus parameters, genesis, emission schedule, and the daemon wiring
are solid. Both confirmed findings are low-severity local CLI footguns._

| ID | Severity | File:line | Category | One-line |
|----|----------|-----------|----------|----------|
| B7-L01 | Low | config/node/node_config.rs:305 | validation-gap | An unrecognized `--network` value **fails open to Mainnet** (with only a stderr warning) instead of aborting → a CLI typo can boot a node on mainnet |
| B7-L02 | Low | bin/wallet.rs:522 | logic-error | `cmd_restore` hardcodes the network default to `"mainnet"` (ignoring `SHADOWDAG_NETWORK`), reintroducing the exact env-mismatch `cmd_new` was fixed to avoid → restored wallet saved under the wrong network, "not found" by later commands |

#### B7-L01 / B7-L02 (Low) — CLI network-selection footguns
- **node_config.rs:305** — `network = val.parse().unwrap_or_else(|_| { eprintln!("WARNING…"); NetworkMode::Mainnet })`.
  `FromStr` accepts only mainnet/testnet/regtest (± aliases), so a typo (`--network tetsnet`) silently selects
  Mainnet — mainnet magic/ports/data-dir/peers. Operator CLI input only (not attacker-reachable), no-flag default
  is already Mainnet, warning emitted → Low fail-open validation gap (should abort on unknown network).
- **bin/wallet.rs:522** — `let network = args.get(2)…unwrap_or("mainnet")`. `cmd_new` was explicitly fixed to
  `unwrap_or(&env_network)` with a comment about this very bug; `cmd_restore` reintroduces the hardcoded default
  (and only *warns* on env mismatch at 525-530). With `SHADOWDAG_NETWORK=testnet`, `restore` with no positional
  arg persists a mainnet (SD1) wallet under the mainnet dir while balance/send derive testnet (ST1) → "wallet not
  found" footgun. Keys are recoverable (same mnemonic), no fund loss → Low.

#### Latent (real defect, no reachable impact today) — tracked, not fixed
- **config/checkpoints.rs:104** (low) — the dynamic auto-checkpoint loader guards
  `if key.len() < prefix.len()+8 || !key.starts_with(prefix) { break; }` — using `break` (not `continue`) on a
  short-but-still-prefixed key would abort the whole scan and drop all higher-keyed checkpoints (the sibling
  loader in `finality.rs:165-171` correctly splits the conditions). But the only writer (`finality.rs:367`)
  always emits exactly 14-byte keys (RocksDB never surfaces a truncated key), and `is_valid_with_dynamic` has
  **no caller** in the validation/reorg/fork-choice path — active deep-reorg protection is the static 200-block
  finality bound. Latent robustness/consistency bug, no reachable impact.
- **bin/wallet.rs:725** (info) — `let fee = args.get(4).and_then(safe_sdag_to_sats).unwrap_or(1)` parses an
  explicit fee arg as **whole SDAG** (×1e8) while the absent-arg default is **1 satoshi** — a default/explicit
  unit inconsistency. Not the "silent 100M× drain" first claimed: the `amount` arg on the same command is also
  SDAG (so a user reads "1" as 1 SDAG consistently), and the effective fee is printed (`Fee: … sats (… SDAG)`)
  before any broadcast. Minor unit-consistency nit → Info.

---

## Executive summary — complete findings list (all 7 batches, severity-ranked)

**Coverage:** all 293 production `.rs` files / 130,440 lines across 56 units / 14 subsystem groups were read
in full by auditor agents; every candidate was adversarially re-verified, and every **confirmed** finding below
was additionally re-read line-by-line against the live source by the lead auditor. **139 candidates raised →
38 confirmed + 12 latent** (the rest refuted on verification). No fixes were applied — this is a findings-only
audit. It is INTERNAL and does not replace the mandatory external cryptographic + consensus review before mainnet.

**Confirmed by severity: 1 Critical · 4 High · 13 Medium · 20 Low. Plus 12 latent (info / unreachable / dead code).**

### 🔴 Critical (1)
| ID | File:line | Status | Issue |
|----|-----------|--------|-------|
| B1-C01 | engine/dag/core/dag_manager.rs:227 | ✅ **FIXED** 4f9a182 | Unbounded ancestor-walk (50k cap) + never-pruned DAG topology → false "cycle" rejects every block once a tip's ancestry exceeds 50 000 = **permanent network-wide chain halt** |

### 🟠 High (4)
| ID | File:line | Status | Issue |
|----|-----------|--------|-------|
| B1-H01 | engine/dag/core/dag_manager.rs:396 | ✅ **FIXED** 4f9a182 | O(parents × 50k) redundant cycle-walk per block validation (shares B1-C01's root — fixed by the same commit) |
| B1-H02 | dos_protection.rs:200 · spam_filter.rs:77 | ✅ **FIXED** 88b64d9 | Shield tx outputs (amount=0) not exempt from zero-output rule → **Shield unminable** chain-wide |
| B1-H03 | engine/dag/sync/dag_sync.rs:180 | ✅ **FIXED** 9e7a15c | Iterate-DashSet-while-removing → shard self-deadlock freezes block ingestion |
| B3-H01 | domain/utxo/utxo_set.rs:44 | ✅ **FIXED** 0057a92 | `utxo_key` slices a txid at byte 24 without a char-boundary check → crafted txid panics the block builder (remote mining DoS) |

### 🟡 Medium (13) — **11 FIXED, 2 deferred to external consensus review**
| ID | Status | File:line | Issue |
|----|--------|-----------|-------|
| B1-M01 | ✅ bcb24f0 | consensus/state/mod.rs:95 | Partial-recovery consistency issues only warned, node boots anyway (violates own "fatal" contract) |
| B1-M02 | ⏸ **DEFERRED** | dag/ghostdag/ghostdag.rs:356 | Anticone ignores future-contamination → legit-blue blocks flipped red (GHOSTDAG deviation) |
| B1-M03 | ⏸ **DEFERRED** | dag/ghostdag/ghostdag.rs:392 | `get_past_set` truncated at 16 384 → corrupt classification on mature chains |
| B1-M04 | ✅ bcb24f0 | dag/security/spam_filter.rs:82 | Valid duplicate `(address, amount)` outputs rejected as spam (validators disagree) |
| B2-M01 | ✅ 5fd443e | mining/stratum/stratum_server.rs:652 | Heavy ShadowHash under the global `workers` write lock → one worker stalls the pool |
| B4-M01 | ✅ 576a466 | p2p/peer_manager.rs:291 | Per-IP connection cap TOCTOU → exceed `MAX_PEERS_PER_IP` + corrupt counter |
| B4-M02 | ✅ 5fd443e | propagation/dandelion.rs:261 | Stem hop re-randomized per-tx (not per-epoch) → breaks Dandelion++ source-hiding (privacy) |
| B4-M03 | ✅ 576a466 | relay/tx_relay.rs:90 | Dedup on unverified `tx.hash` (mempool checks sigs, not hash-binds-content) → targeted tx censorship |
| B5-M01 | ✅ 189b452 (HF) | vm/core/execution_env.rs:3357 | LOG opcodes lack per-byte gas (~4470× undercharge) → log/memory resource-exhaustion |
| B5-M02 | ✅ 189b452 (HF) | vm/precompiles/crypto_precompiles.rs:102 | ed25519 precompile (0x08) uses non-strict `verify()` → signature malleability |
| B6-M01 | ✅ a05efec | mempool/core/mempool_manager.rs:143 | Confirming a parent evicts its still-valid CPFP children |
| B6-M02 | ✅ a05efec | mempool/core/mempool.rs:856 | O(n) `fee:`/`rdep:` scans per removal → O(n²) eviction CPU-DoS under congestion |
| B6-M03 | ✅ a05efec | wallet/keys/multisig.rs:211 | ms/secs mismatch → multisig signature window is 3.6 s, not 1 h |

**Fix notes.** 11 mediums fixed each with a regression test + green build/clippy(-D, both feature sets)/tests,
committed + pushed to `feature/privacy-hdwallet-docs`. B5-M01/M02 change deterministic gas/precompile behaviour
(**hard fork** — flagged `(HF)`), so they must go through the mandatory external consensus review before mainnet.
The fixes are **committed but NOT yet redeployed** to the testnet (which still runs 40eaa3e = the 5 highs + shield);
several are consensus/gas changes needing a coordinated (fresh-chain) deploy.

#### B1-M02 / B1-M03 (GHOSTDAG) — ⏸ DEFERRED to external consensus review (fix designed, not landed)
Both are deterministic GHOSTDAG-classification defects — all honest nodes compute the SAME (wrong) result, so no
inter-node split, but a real deviation from canonical GHOSTDAG that fixing changes the DAG ordering for **every**
node (a hard fork of consensus ordering). They are **coupled**: a correct fix needs a *reachability* capability the
codebase lacks.
- **B1-M02** (anticone future-contamination): classify the merge set **ancestors-first** (topological order) or
  exclude `future(h)` from the anticone count — both require "is `b` reachable from `h`", i.e. reachability.
- **B1-M03** (past-set truncation at 16 384): a naïve cap-removal reintroduces the **unbounded ancestor-walk DoS**
  that B1-C01 just fixed; the correct fix is a **reachability index** (Kaspa-style interval labels / cached
  past-sets) so past-set queries are complete AND bounded.
Per the standing rule (mandatory external cryptographic **+ consensus** review; do NOT self-certify consensus
changes), a rushed unreviewed GHOSTDAG rewrite risks a worse ordering bug or a chain split. Documented here with
the fix design and deferred — the **#1 consensus item** for the external review, alongside the RingCT/crypto
primitives and the B5 hard-fork items.

### 🟢 Low (20) & Info/latent (12)
Gas-metering nits (EXP, modexp), a **ms/secs unit cluster** in unwired SPV/chain-verifier/retarget/light-node
code (B1-L01, B4-L03/L07/L08 — would be High if ever wired into live sync), unchecked RPC/CLI arithmetic that
wraps harmlessly in release, two peer-store TOCTOU counter drifts, two slow memory leaks, a non-atomic UTXO
index write, mnemonic checksum absence, and CLI network-selection footguns. Full detail per-batch above; latent
items (dead code / self-healing / unreachable) are listed under each batch's "Latent" subsection.

#### Low-tier remediation status (2026-07-06)
**17 / 20 fixed, tested (2314 lib tests green), and pushed; 3 deferred to the external review.**

| Commit | Lows fixed |
|--------|-----------|
| `ec72c15` (L1) | B4-L01, B4-L02, B4-L04, B4-L05, B4-L06 — peer-map leak, multi-parent orphan leak, `remove_peer` counter TOCTOU, `getblockrange`/`getdagslice` unchecked arithmetic |
| `99ec795` (L2) | B6-L01, B6-L02, B7-L01, B7-L02 — mnemonic word-count guard, `need = amount+fee` saturating, `--network` unknown aborts, `cmd_restore` honours `SHADOWDAG_NETWORK` |
| `2127ddd` (L3a) | B4-L03, B4-L07, B4-L08, B6-L03 — ms/secs unit cluster (light_node SPV, chain_verifier ×2) + atomic `add_utxo` WriteBatch |
| `0b374fb` (L4 · **hard-fork; review-gated**) | B1-L01 retarget full-span average, B1-L02 drop MAX_NONCE reject, B5-L01 EXP per-exponent-byte gas, B5-L02 modexp EIP-198 empty output |

**Deferred (3):**
- **B1-L03** — legacy `RingSignature` is forgeable but DEPRECATED / test-only / off the consensus path (CLSAG is live). Slated for deletion in a future dead-code cleanup, not a live-path fix.
- **B2-L01** — block-template height TOCTOU across two tip snapshots. Correct fix needs a single-snapshot `select_dag_parents`+`get_tips` refactor (self-inflicted wasted PoW only, no consensus impact); deferred to avoid an under-scoped mining-path change.
- **B2-L02** — Stratum always hashes with ShadowHash regardless of `template.version`; at the UmbraHash (v3) fork every pool block would be rejected. Forward-compat only (`UMBRA_ACTIVATION_HEIGHT` is still `None`); fix = wire the umbra-version cache into the stratum path, bundled with the B5 hard-fork's external review.

**L4 independent review (2026-07-06):** a 5-agent adversarial workflow (one reviewer per change + a consensus-determinism cross-lens, each re-reading the committed source, then an adversarial verify pass) returned **0 confirmed defects**. One raised concern — that after B1-L01 the pre-existing `max_span` anti-timewarp clamp (retarget.rs:350) saturates the 30%-weight `long_avg` term at ~TARGET for any sustained `dt > TARGET` — was **refuted**: the 70%-weight LWMA term (per-interval clamp at 10×TARGET) still tracks slowdown, the `decreases_when_blocks_too_slow` test confirms difficulty still falls, and the clamp is a deliberate manipulation bound. Same calibration class as B1-L01 itself (deterministic, no split, no attacker leverage). The four L4 changes remain **hard-fork / consensus** items requiring the mandatory external review before mainnet activation.

### Cross-cutting themes
1. **ms/secs unit mismatches** (5 sites: retarget.rs, light_node.rs, chain_verifier.rs ×2, multisig.rs) — a
   recurring leftover of the completed millisecond-timestamp migration. Live-path ones are calibration-only;
   the SPV/chain-verifier ones are latent because those modules are unwired, but each **breaks sync if wired**.
2. **Unbounded/never-pruned structures** (DAG topology → B1-C01/H01, `peer_block_timestamps`, `orphan_by_parent`,
   `seen_cache` trim) — growth without eviction is the single most common serious class here, and the critical
   B1-C01 halt is its worst instance.
3. **`tx.hash` not bound to content on the relay/mempool path** (B4-M03) while the block path enforces it —
   an asymmetry enabling mempool-layer censorship.
4. **Two VMs** — the live `execution_env.rs` is bounds-guarded; the dead legacy `vm.rs` is not (its MLOAD panic
   is latent only because it has no callers).
5. **Clean areas** (nothing survived verification): the crypto primitives (hashes, Ed25519/Schnorr/Dilithium/
   Falcon, CSPRNG), the RocksDB storage layer, RPC auth, the DoS-guard, and the genesis/consensus-param/emission
   config. These still require the external cryptographic review before mainnet.
