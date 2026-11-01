# Adversarial Audit — New Code (RingCT 4c-ii + session security work)

Line-by-line adversarial audit of the code ADDED this session (not covered by the
earlier full-codebase audit). 3 parallel auditors read the new files IN FULL
(crypto core; wallet confidential layer; CLI/RPC); every finding below was then
**re-verified by me against the actual code** before fixing.

## Fixed

| ID | Sev | Where | Issue | Fix |
|----|-----|-------|-------|-----|
| A-CRIT | **CRITICAL** | service/network/nodes/full_node.rs (recompute_virtual_chain) | Confidential txs were applied on the live peer-block/reorg path with ONLY the structural RingValidator check — `verify_confidential_tx` ran only on mempool+genesis, and `apply_block_dag_ordered` records confidential state WITHOUT validating. A peer block with forged CLSAG / unbalanced commitments / fabricated ring / missing range proof / reused key image → **inflation + double-spend** on every node. | Run the full confidential gate (`verify_block_confidential_txs` → `verify_confidential_tx`, block-wide seen-key-image set) before each `apply_block_dag_ordered`, against state with earlier new-chain blocks applied; abort+rollback+drop-offending-block on failure. Regression test. |
| B-F1 | HIGH (privacy) | service/wallet/core/wallet.rs build_confidential_send | Real ring member always appended last (`real_index = len-1`) → the last on-chain ring member is always the real spend → full deanonymization of every confidential input. | Insert real member at a uniformly random position (OsRng). |
| C-F1 | MED (DoS) | bin/wallet.rs scan loop | Loop bound from attacker-controllable `getblockcount`; `start += 500` could overflow (debug panic / release infinite loop); hostile node height = wallet DoS. | Cap height at 100M; `checked_add`. |
| C-F2 | LOW/MED (OOM) | bin/wallet.rs scan | Whole chain buffered in `Vec<Block>` before scanning → OOM from hostile node. | Stream per page (scan + drop). |
| C-F3 | LOW | bin/wallet.rs cmd_send | `to_vec(&tx).unwrap_or_default()` printed empty raw hex on serialize error while claiming success. | Explicit error + return. |

## Documented (not fixed — low/no impact or prover-side)

| ID | Sev | Where | Why not fixed |
|----|-----|-------|---------------|
| B-F2 | LOW | wallet.rs network_mode() | `parse().unwrap_or(Mainnet)` is fragile but INTERNALLY CONSISTENT (address gen + parse + mode all key off the same network string), so no cross-net spend / fund loss. Erroring on unknown network could break wallets with odd strings; left as-is. |
| B-F3 | LOW | wallet.rs ConfidentialUtxo serde(default) | bincode is non-self-describing, so `#[serde(default)]` does NOT rescue a pre-field wallet blob (it errors instead of defaulting). Harmless on this fresh chain (no pre-field blobs exist); would need explicit blob versioning before any persisted-wallet upgrade. |
| A-LOW | LOW | range_proof.rs:90 prove() | `if bit == 0 {…} else {…}` is a non-constant-time branch on a secret bit — a prover-side timing side-channel, not network-reachable and not consensus. Harden before mainnet (match dual_clsag's constant-step style). |
| A-INFO | INFO | scan.rs recover_spend_secret | Does not re-assert `x·G == one_time_pubkey`; caller runs `scan_confidential_output` first. Only uses the caller's own keys; a wrong key yields an unspendable input, not a vuln. |
| C-F4 | LOW | bin/wallet.rs cli_rpc_call | Only honors Content-Length (no chunked transfer). Fail-safe: a differently-framed response → None → DB fallback. Node uses Connection: close + length, so latent. |

## Verified CORRECT (high-value confirmations, against the real code)
- Homomorphic balance (Σ pseudo-in == Σ out + fee·H), range proofs enforced per output,
  key-image uniqueness (on-chain store + block-wide set), ring authenticity (both P and C
  looked up in the okey index), CLSAG message binding (V3 domain-sep, binds outputs/inputs/
  key-images/commitments), amount-encoding domain separation, scan↔builder derivation match
  (context-free), parse/serialization panic-safety.
- Wallet: confidential key derivation deterministic+stable+canonical; SD1p address
  length/checksum/network handling; build_confidential_send UTXO selection / change / no
  in-tx double-spend / 0-change; scan dedup; mark-spent key-image identical to builder/consensus.
- getblockfull: state lock dropped before serialization (no DoS), no panic, public/read-only.
- CLI address routing (is_confidential_addr ↔ validate_address "1p") consistent; amount parsing
  integer-only with checked arithmetic; all address/hex/JSON paths guarded (no panics).

Final gate after fixes: clippy `--all-targets -D warnings` clean; full lib suite
**2198 passed, 0 failed**.
