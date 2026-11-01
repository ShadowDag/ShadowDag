# Shield Transaction (transparent → confidential) — Design Spec

> **Status:** design-first, adversarially validated (3-agent map + 3-agent inflation/double-spend/deanon
> attack). NOT yet implemented. **CONSENSUS-CRITICAL, INFLATION-RISK.** An error in the balance rule or the
> apply/rollback path mints unlimited supply. **MUST have external cryptographic + consensus review before
> mainnet**, and must be testnet-verified first.

**Goal:** let TRANSPARENT funds enter the confidential (RingCT) pool, so the confidential feature can be
bootstrapped. Today `build_confidential_send` is strictly confidential→confidential (needs pre-existing
confidential UTXOs + on-chain decoys); on a transparent-coinbase chain the first confidential UTXO can never be
created (empirically: `send <SD1p> → "insufficient confidential funds"`). A **shield** tx (transparent inputs →
confidential outputs) is the missing entry point.

---

## 1. Cryptographic rule (the crux — get this exactly right)

**ShadowDAG convention (REVERSED vs Monero — verified in `engine/privacy/confidential/pedersen.rs:52`):**
`C = value·H + blinding·G`, i.e. **amount on H, blinding on G**. `verify_balance` puts the public fee on H:
`fee_commitment = fee·H` (`pedersen.rs:110`), checking `Σ inputs == Σ outputs + fee·H`.

**Shield input pseudo-commitment (per transparent input i):**

    C_in_i = A_i·H + r_i·G          — amount A_i on H, blinding r_i on G

- `A_i` = the input UTXO's amount, **read from the UTXO set** (`utxo_set.get_utxo(txid,index).amount`),
  **NEVER from the transaction**. This is the ONLY anchor to real value; the Ed25519 signature authenticates
  outpoint ownership, not amount.
- `r_i` = a blinding scalar, **the only input-side value the tx may carry**. It cannot move value once `A_i` is
  chain-fixed; it exists only to let the prover balance the output blindings.
- Build `C_in_i` via the SAME `RealPedersenCommitment::commit(A_i, r_i)` primitive the rest of the system uses —
  never hand-roll the point (guards against the swapped-generator inflation, Attack V1).

**Balance (reuse the existing check unchanged):**

    Σ (A_i·H + r_i·G)  ==  Σ C_out  +  fee·H

Matching generators: H terms ⇒ `Σ A_i = Σ a_j + fee` (amount balance, forced because A_i are public/chain-fixed);
G terms ⇒ `Σ r_i = Σ r_j` (blinding balance, prover-controlled). Outputs keep the existing rules: plaintext
`amount == 0`, per-output range proof `a_j ∈ [0, 2^64)`.

**Fee:** `fee` MUST be placed on H, MUST equal `tx.fee` (the exact value the coinbase claims), and the verifier
MUST assert `fee ≤ Σ A_i` from the UTXO-set amounts.

---

## 2. Data model

- **New `TxType::Shield`** (enum `domain/transaction/transaction.rs:12-29`) with a **new canonical discriminant
  byte 0x09** (`transaction.rs:241-251`). A distinct type is mandatory — `canonical_bytes` must commit to it, and
  it is the dispatch key. Add `Transaction::is_shield()` (`== TxType::Shield`).
- **Shield input** = a transparent outpoint (`txid,index,owner,signature,pub_key` as normal) PLUS the blinding
  `r_i`. `TxInput` has no scalar-blinding field today; carry `r_i` in the existing `pseudo_commitment: Option<String>`
  field (repurposed for shield inputs to hold the hex blinding scalar) OR add a dedicated `shield_blinding:
  Option<String>`. Decision: **add `shield_blinding: Option<String>`** — reusing `pseudo_commitment` (a
  confidential-input commitment point) for a scalar invites parser confusion. `#[serde(default)]`, in
  `canonical_bytes`.
- **Shield output** = a normal CONFIDENTIAL output (`commitment`, `range_proof`, `one_time_pubkey`,
  `ephemeral_pubkey`, `encrypted_amount`, `amount == 0`) — identical to a `Confidential` tx output.

---

## 3. Routing — ALL FIVE `is_confidential()` sites must gain a consistent shield arm

A shield lives in BOTH worlds (transparent inputs, confidential outputs). The five INDEPENDENT dispatch
predicates must each route shield the same way — a single site that classifies it into only one world silently
skips the other world's check/mutation (fork or inflation, deanon Attack 3):

1. Mempool A — `domain/transaction/tx_validator.rs:479` (validate_tx_for_network)
2. Mempool B — `domain/transaction/tx_validator.rs:602` (validate_transaction)
3. Block gate — `engine/consensus/validation/utxo_validator.rs:191`
4. Reorg gate — `service/network/nodes/full_node.rs:2898`
5. Apply — `domain/utxo/utxo_set.rs:895`

Add `is_shield()` handling at every one, each calling the SAME `verify_shield_tx` / shield-apply. An integration
test must assert a shield block validates+applies identically via the block path AND the reorg path.

---

## 4. Consensus verify — new `verify_shield_tx` (own path, do NOT merge with ring inputs)

For a `TxType::Shield` tx:
1. Inputs non-empty, outputs non-empty.
2. **For each input:** look up the UTXO; require it EXISTS, is UNSPENT, `owner` matches, Ed25519 signature valid
   (transparent ownership), and coinbase-MATURE. Reconstruct `C_in_i = utxo.amount·H + r_i·G` from the CHAIN
   amount + the tx `shield_blinding` r_i. **No key image, no ring, no CLSAG** (transparent inputs are public
   spends). Reject duplicate outpoints within the tx (anti self/double count).
3. **For each output:** `amount == 0`, parse confidential view, range proof verifies. (Same as confidential.)
4. **Balance:** `verify_balance(&[C_in_i…], &[C_out…], tx.fee)` (the existing fn) — pass the RECONSTRUCTED input
   commitments. Assert `tx.fee ≤ Σ utxo.amount`.
5. Shield inputs and confidential ring inputs MUST NOT share one tx / one balance vector (inflation Attack V3):
   a `Shield` tx has ONLY transparent inputs; a `Confidential` tx has ONLY ring inputs. Enforce: a Shield input
   must not carry ring fields; a Confidential input must not carry `shield_blinding`.

---

## 5. Apply — new shield apply path (the current confidential branch `continue`s WITHOUT spending)

`apply_block_dag_ordered` (`utxo_set.rs:895-933`) currently, for `is_confidential()`, records okey/okeyidx and
`continue`s — it NEVER marks inputs spent. A shield reusing that branch = infinite re-shield + cross-world
double-spend (double-spend Attacks 1/2/5, all CATASTROPHIC). The shield apply path MUST, in ONE atomic batch:
- **Spend each transparent input** through the transparent namespace: check `!utxo.spent`, insert into
  `staged_spent` (so a later tx in the same block can't re-spend it), mark `spent=true`, delete addr index,
  push to `undo.spent_utxos`.
- **Record each confidential output** to `okey:{one_time_pubkey}` → commitment and append `okeyidx:`,
  push to `undo.created_output_keys` + set `undo.conf_index_*`.
- **Dual-bucket undo:** rollback must restore the transparent inputs (`spent_utxos`) AND delete the confidential
  outputs (`created_output_keys`/`okeyidx`). The `amount==0` corruption guard in `rollback_block_undo`
  (`utxo_set.rs:1338`) must not fire — the transparent-input restore carries a real amount, so bucket by ROLE
  (input=transparent, output=confidential), which it already is.
- **Reconcile the two apply paths' okey recording** (double-spend Attack 4): `apply_block_dag_ordered` records
  okey from `one_time_pubkey`→commitment; `apply_block_write_with_commitment` (genesis) keys off
  `ephemeral_pubkey`→`[1u8]`. A shield output must be recorded IDENTICALLY on both, or `output_key_commitment`
  returns different values per node (ring-validity fork). Fix + test both paths.
- MuHash: a shield SPENDS transparent (remove_by_key) and its confidential outputs are NOT transparent UTXOs
  (not in export_all), so the accumulator gets the removes but no adds — consistent with the transparent-set
  definition.

---

## 6. Wallet — `build_shield` + CLI

New `Wallet::build_shield(recipient_SD1p, amount, fee, utxo_set)`: select transparent UTXOs (like the normal
transparent send), derive stealth confidential output(s) to the recipient's SD1p (view/spend pub), commit
`C_out = a·H + r_out·G` with range proofs, choose per-input blindings r_i so `Σ r_i = Σ r_out`, set change as a
second confidential output to self (or a transparent change output — decide: transparent change keeps it
simple). Route from CLI `send`: if recipient is SD1p AND the wallet has NO confidential UTXOs (or a new `shield`
subcommand), build a shield instead of a confidential send.

---

## 7. Test plan — one test per attack vector (all must fail closed)

Consensus unit tests (each an attempted mint that MUST be rejected):
1. Swapped generators (`A_i·G + r_i·H`) → balance fails.
2. Input commitment implying amount ≠ chain UTXO amount → rejected (A_i read from set).
3. Shield + ring input in one tx → rejected (type separation).
4. Duplicate/self-spent outpoint within a shield → rejected.
5. `fee` on G, or `fee ≠ tx.fee`, or `fee > Σ A_i` → rejected.
6. Output `amount != 0`, or missing/invalid range proof → rejected (existing gate, re-assert for shield).
7. Multi-output wrap-around (Σ a_j > u64) with honest A_i → rejected by the `Σ A_i` public cap + range proofs.

Apply/rollback tests:
8. Shield input is marked spent (not re-shieldable); same outpoint can't also be spent by a transparent tx
   (same block AND next block).
9. Rollback of a shield restores the transparent input AND deletes the confidential outputs/okeyidx; no
   `amount==0` corruption abort.
10. Same shield block applied via block path vs reorg path → identical okey/okeyidx/ki/spent state.

Round-trip + live:
11. Wallet builds a shield; node accepts; recipient scans + recovers the confidential output; recipient then
    does a confidential→confidential send (bootstrapping now works end-to-end).
12. Live testnet: shield a coinbase, confirm the confidential pool now has ≥ CONF_RING_SIZE outputs so a
    subsequent confidential send finds decoys.

---

## 8. Deploy / review

CONSENSUS change (new valid tx shape + discriminant) → genesis re-mine + testnet wipe on activation, keyed by
`TxType`. **External cryptographic + consensus review is MANDATORY before mainnet** — the balance rule and the
mixed apply/rollback are inflation-catastrophic if wrong. Ship to testnet first, verify tests 1–12, then hand the
spec + implementation to the reviewer. Do NOT self-certify.

## 9. Non-goals

- Unshield (confidential → transparent) — a separate feature; shield alone bootstraps the pool.
- Changing the confidential→confidential path (works; unit-tested).
- 256-bit MuHash / consensus UTXO commitment (separate).
