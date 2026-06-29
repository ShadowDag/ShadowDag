# Full Codebase Security/Correctness Audit — 2026-06-29

Exhaustive line-by-line audit of all production code (~125k LOC, excl tests/target)
via 8 parallel auditors, each reading its assigned files IN FULL. Findings below;
each FIX item is verified against the real code before fixing.

Coverage (all read in full by the assigned auditor):
- Consensus + DAG (engine/consensus/*, engine/dag/*) — 43 files
- ShadowVM (runtime/vm/*, runtime/wasm, runtime/node_runtime)
- Privacy/RingCT (engine/privacy/ringct/*, confidential/*, stealth, address)
- Mempool + domain (service/mempool/*, domain/transaction|utxo|block|address)
- P2P networking (service/network/p2p|propagation|sync|relay|dos_guard|reputation|...)
- RPC/Auth/Web UIs (rpc/*, service/rpc/auth, explorer, wallet_ui, contract_ide, full_node)
- Storage/Mining/Bins/Config (infrastructure/storage/*, engine/mining/*, bin/*, config/*)
- shadow_pool + engine/crypto + leftovers

Legend: **[FIX]** = fixing this session · **[DOC]** = documented for follow-up (larger
refactor / needs product decision / lower blast radius).

## RESOLUTION (this session)

All 18 **[FIX]** items below were verified against the real code and fixed, each
with a regression test where meaningful, committed per-cluster. Final gate:
`cargo clippy --all-targets -- -D warnings` clean, full lib suite **2181 passed,
0 failed** (net of 3 deleted dead fake-crypto modules + added KAT/regression tests).

| ID | Fix summary |
|----|-------------|
| A1 | min-DAG-parents now a pure fn of height+constant (env reads removed) |
| A2 | blue-set sorted before truncation (deterministic) |
| A3 | blue_score/chain_height use saturating_add |
| A4 | coinbase split uses u128 intermediate |
| V1/V2/V3 | added `U256::add_mod`/`mul_mod` (carry/full-width correct); EXP uses `wrapping_pow`; KAT tests |
| P1 | char-safe peer-identity truncation |
| P2 | DagShield requires hash bytes be ascii-hex |
| M1 | fee-rate scaled to milli-sat/byte |
| R1 | confidential txs return from the confidential gate (no transparent fall-through); regression test |
| S1 | pool payout u128 + clamp pct≤100 + saturating_sub |
| S2 | coinbase reward u128; char-safe parent-hash slice |
| K1 | derive_children range uses saturating_add |
| MX1 | `/debug` served to loopback peers only |
| RPC1 | global state lock dropped before VM simulation (deploy/call/estimate_gas) |
| XC1 | deleted dead insecure crypto (bulletproofs/pedersen_commitment/confidential_tx) |
| DAN1 | dandelion clock math uses saturating_sub |

### Second remediation pass (security DOC items)

After the 18 above, additional documented security items were verified and fixed:

| ID | Fix summary |
|----|-------------|
| NET1 | live inbound-connection-per-IP cap enforced in accept_loop (anti-eclipse); regression test |
| MEM1 | cheap fee/quota checks moved before signature verification; `remove_transaction` cascade made iterative (no stack-overflow DoS); 1500-deep-chain regression test |
| RBF1 | RBF replacement must cover REAL transitive dependent fees (`dependent_fees`), not a MIN_FEE_BUMP lower bound; regression test |
| bincode | allocation-bounded wire deserialization on P2PMessage/Tx/Block (anti-OOM); wire-compat round-trip test |
| MUH | RE-CLASSIFIED: **not a live issue** — the live UTXO commitment uses SHA-256 (`compute_commitment_hash`); `muhash.rs` is dead code (only its own tests reference it). No fix needed. |

Final gate after both passes: clippy `--all-targets -D warnings` clean, full lib
suite **2185 passed, 0 failed**.

### Still open — honestly NOT fixed (need larger refactor / product decision)
- **ST1** cross-store write atomicity (DSP/confirmed-tx/UTXO, add_utxo, ban_peer):
  needs a storage refactor to a shared WriteBatch / column families. Existing
  per-stage rollback mitigates partial-failure on the block path; full atomicity
  is a multi-file change deferred intentionally.
- **GEN1** genesis date/difficulty: needs a re-mine + product decision.
- **misc (loopback-only, LOW):** explorer JS XSS (HTML-escape chain fields),
  gRPC no-auth (loopback bind + write handlers are stubs), address-prefix
  substring classification. Low blast radius; deferred.

The **[DOC]** items above remain open for follow-up. Verified-correct
confirmations are unchanged.

## CRITICAL / HIGH — consensus, money, live panics

| ID | Sev | Where | Issue | Status |
|----|-----|-------|-------|--------|
| A1 | CRIT | engine/dag/security/selfish_mining_guard.rs | min-DAG-parents consensus rule read from env vars (`SHADOWDAG_MIN_DAG_PARENTS`/`NETWORK`) → nodes disagree → chain split | **[FIX]** |
| A2 | HIGH | engine/dag/ghostdag/blue_set.rs | blue-set truncation iterates a `HashSet` (non-deterministic order) → different nodes keep different subsets → coloring/score divergence | **[FIX]** |
| A3 | HIGH | engine/dag/ghostdag/ghostdag.rs:154,156 | blue_score / chain_height use unchecked `+` (overflow panic/wrap on corrupt stored score) | **[FIX]** |
| A4 | HIGH | engine/consensus/validation/block_validator.rs:986 | coinbase split `expected_reward * MINER_REWARD_PCT` unchecked multiply | **[FIX]** |
| V1 | MED | runtime/vm/core/execution_env.rs:1544 | MULMOD truncates product to low 256 bits → wrong result | **[FIX]** |
| V2 | MED | runtime/vm/core/execution_env.rs:1528 | ADDMOD drops carry → wrong when a+b ≥ 2^256 | **[FIX]** |
| V3 | MED | runtime/vm/core/execution_env.rs:1519 | EXP caps exponent at 255 + low-u64 only → wrong | **[FIX]** |
| P1 | MED | service/network/p2p/p2p.rs:1644 | byte-slice `&id[..16]` on attacker user_agent → panic mid-UTF-8, kills peer thread, leaks PEER_LAST_OUTBOUND | **[FIX]** |
| P2 | MED | engine/dag/security/dag_shield.rs | block/tx hash length-checked but NOT hex-validated → enables byte-slice panics | **[FIX]** |
| M1 | CRIT(func) | service/mempool/core/mempool.rs:607 | fee-rate index uses integer division (`fee/size`) → collapses to 0 for normal txs → eviction/template ordering broken | **[FIX]** |
| R1 | MED | domain/transaction/tx_validator.rs:473,740 | confidential tx runs `validate_confidential` then FALLS THROUGH into transparent UTXO loop → confidential txs rejected at mempool (divergence from block path) [our RingCT bug] | **[FIX]** |
| S1 | HIGH | engine/mining/stratum/stratum_server.rs:1189,1226 | pool payout `reward*pct/100` then `reward-fee` in u64 → overflow/underflow | **[FIX]** |
| S2 | MED | engine/mining/miner/miner.rs:61,129,167 | reward-split u64 overflow; height-0 `height-1` panic; address byte-slice panic | **[FIX]** |
| K1 | LOW | domain/address/key_derivation.rs:94 | `start + count` overflow panic | **[FIX]** |
| MX1| MED | telemetry/metrics/prometheus.rs:218 | `/debug` dumps internal state with no auth; dangerous if bound non-loopback | **[FIX]** |
| RPC1| HIGH | service/network/rpc/rpc_server.rs:4289+ | global state lock held across VM simulation → one authed client freezes all RPC | **[FIX]** |
| XC1| HIGH | engine/privacy/ringct/ring_signature.rs, confidential/bulletproofs.rs, pedersen_commitment.rs, single-key clsag in ring_validator | insecure legacy/fake crypto still compiled + reachable (not the live gate, but latent forgery surface) | **[FIX: quarantine]** |
| DAN1| LOW | service/network/propagation/dandelion.rs:183,195,267 | wall-clock `now - x` without saturating_sub → debug panic / wrap | **[FIX]** |

## Documented for follow-up (not fixed this session)

| ID | Sev | Where | Issue | Why DOC |
|----|-----|-------|-------|---------|
| C2 | MED | domain/utxo/utxo_set.rs apply_block_write_with_commitment | confidential okey recorded with wrong key (ephemeral) + value vs the live dag-ordered path | verify if path is live; if dead, remove — needs call-site check |
| MUH| MED | engine/crypto/hash/muhash.rs | UTXO commitment uses 64-bit prime field (forgeable) | verify consensus usage; real-field reimpl is large |
| ST1| HIGH | cross-store atomicity (DSP/confirmed-tx/UTXO, add_utxo, ban_peer two puts) | non-atomic multi-store writes; replay doesn't rebuild DSP | needs storage refactor (shared DB/CF) |
| NET1| HIGH | reputation/connection_manager/rate_limiter/sync/relay/propagation | large security modules NOT wired into live node; PeerDiversity/per-IP caps not enforced on accept → eclipse risk; sync modules skip PoW if wired | wiring is a feature effort |
| MEM1| HIGH | mempool.rs | per-sender limit keyed on free-form `owner` (bypass); sig-verify before cheap checks; `remove_transaction` unbounded recursion + full-keyspace scans | needs careful mempool rework + tests |
| RBF1| HIGH | mempool/core/rbf.rs | dependent-fee accounting uses MIN_FEE_BUMP lower bound → replacement can lower total fees | needs real descendant-fee plumbing |
| SER1| MED | engine/crypto/serialization.rs | Serializer::tx_hash omits one_time_pubkey/encrypted_amount | verify consumers; align or delete |
| FIN1| MED | engine/consensus/finality.rs | f64 in finality-depth (gates reorg) | integer rewrite; clamped so low blast |
| GEN1| MED | config/genesis/genesis.rs | genesis message/timestamp date mismatch; stored genesis not re-verified on recovery; low genesis difficulty | needs re-mine + product decision |
| reorg| MED | block_processor.rs | reorg mutates state before new chain proven appliable | needs staged-apply refactor |
| misc| LOW | address classification substring match; explorer JS XSS (loopback); gRPC no-auth (loopback, stubs); CREATE2 gas; modexp gas; bincode inner-length limit; shadow_pool onion decorative | various — documented |

## Verified CORRECT (high-value confirmations, not bugs)
- RingCT active gate: dual-CLSAG binds msg+ring+commitments+key-images; homomorphic
  balance enforced; range proofs sound; double-spend via ki store; ring authenticity
  binds P AND C. No money-printing/double-spend in the live confidential path.
- VM consensus path: no reachable node-halting panic; all memory opcodes use
  checked_add + MAX_MEMORY_SIZE; U256 div/mod-by-zero safe; gas metering checked;
  BTreeMap determinism; depth limit + reentrancy guard correct.
- RPC auth: PBKDF2-210k, const-time password compare, lockout, token revocation,
  body/header caps before alloc, LOCAL_NOAUTH inert; coinbase post-execution
  over-mint check present; submitblock can't set tip directly.
- Wire reader bounds size before alloc + checksum before deserialize; DoS guard
  bans ip + ip:port; nonce anti-replay ring; is_banned fails closed.
- Reward/emission u128 + saturating + compile-time asserts; snapshot apply atomic.
