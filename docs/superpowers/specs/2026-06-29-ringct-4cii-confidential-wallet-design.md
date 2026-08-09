# RingCT Sub-Project 4c-ii — Confidential Wallet Send/Receive

**Date:** 2026-06-29
**Status:** Implemented (wallet/CLI wiring). Live-node manual verification + external
crypto review pending. RPC `getconfidentialaddress` deferred (node has no user-wallet
handle; the CLI `stealth` command exposes the address and `sendrawtransaction` accepts
confidential txs). Plan: `docs/superpowers/plans/2026-06-29-ringct-4cii-confidential-wallet.md`.
**Depends on:** RingCT 4a/4b/4c-i (crypto core complete: `build_confidential_transaction`,
`scan_confidential_output`, `recover_spend_secret`, `select_decoys`, dual-CLSAG,
`verify_confidential_tx`, `okeyidx:` global output index).

## Goal

Let a user **receive** and **send** confidential (RingCT) value through the wallet,
CLI, and RPC. The cryptographic core and the consensus/mempool/RPC acceptance path
already exist and are tested; this sub-project wires the **wallet layer** on top of
them. Full end-to-end confirmation needs a running node (follow-up acceptance); this
ships with automated wiring tests that prove the whole path short of block production.

## What already exists (reused, NOT rebuilt)

- **`domain/address/invisible_wallet.rs::InvisibleWallet`** — deterministic view/spend
  keys from a 32-byte master key (`from_master_key`), `view_public()`, `spend_public()`,
  `view_key_hex()`, `is_mine(ephemeral, addr)`, and `derive_spend_key_for(ephemeral)`
  (recovers the one-time spend scalar). This IS our confidential key manager.
- **`engine/privacy/ringct/`** — `build_confidential_transaction(inputs, recipients, fee, network)`,
  `scan_confidential_output(output, idx, view_secret, spend_public) -> RecoveredOutput{amount,blinding,one_time_pubkey}`,
  `recover_spend_secret(output, view_secret, spend_secret)`, `select_decoys(utxo_set, count, exclude)`.
- **RPC `sendrawtransaction`** already accepts + validates `TxType::Confidential`.
- **Mempool / consensus** already validate confidential txs (`verify_confidential_tx`).

### Critical consistency rule
The builder derives the one-time key with a **context-free** hash scalar
(`generate_full_for_network_with_secret` → `hs = H(ss,"",0)`), and
`scan_confidential_output` uses the same context-free derivation. The receive path
MUST use `ringct::scan_confidential_output` (NOT `StealthScanner`/`InvisibleWallet::is_mine`,
which use a tx-context hash) so detection + amount recovery match what the builder produced.
Spend-secret recovery uses `recover_spend_secret` / `InvisibleWallet::derive_spend_key_for`.

## Gaps to build

### 1. Publishable confidential receive address — `domain/address/invisible_wallet.rs`
`InvisibleWallet` exposes the two public points but has no single shareable string.
Add:
- `pub fn confidential_address(&self) -> String` → `"<prefix>1p" + hex(view_pub‖spend_pub)(64B) + hex(checksum)(4B)`,
  where `prefix` ∈ {SD,ST,SR} by network and `checksum = SHA256(view_pub‖spend_pub)[..4]`.
- `pub fn parse_confidential_address(addr, network) -> Result<(RistrettoPoint /*view*/, RistrettoPoint /*spend*/)>`
  — validates prefix, length (4 + 128 + 8 = 140 chars), checksum, and on-curve points.
- Round-trip + tamper tests.

(`SD1s…` stays the one-time *output* address; `SD1p…` is the reusable *payment* address.)

### 2. Wallet ↔ confidential keys — `service/wallet/core/wallet.rs`
- Add `confidential: Option<InvisibleWallet>` to `Wallet`, populated on unlock by
  deriving a stable 32-byte master key from the decrypted wallet seed (domain-separated,
  e.g. `SHA256("ShadowDAG_conf_master_v1" ‖ seed)[..32]`) and passing it to
  `InvisibleWallet::from_master_key`. Same seed → same confidential keys (recoverable
  from the mnemonic). The exact derivation tag is fixed in code and never changes once shipped.
- `pub fn confidential_receive_address(&self) -> Option<String>` → delegates to
  `InvisibleWallet::confidential_address()`.

### 3. Confidential UTXO tracking — `service/wallet/core/wallet.rs` + `storage/wallet_db.rs`
- `struct ConfidentialUtxo { txid, index, amount, blinding: Scalar, one_time_pubkey: String, ephemeral_pubkey: String, spent: bool }`.
- Persisted in wallet_db (new key prefix, e.g. `cutxo:`), encrypted at rest like other wallet state.
- The raw one-time **spend secret is NOT stored** — recovered on demand at spend time
  via `recover_spend_secret` from the stored `ephemeral_pubkey` + the wallet's view/spend scalars.
- `confidential_balance()` sums unspent `ConfidentialUtxo.amount`.

### 4. Receive / scan path — `service/wallet/core/wallet.rs`
- `pub fn scan_confidential(&mut self, tx: &Transaction) -> Vec<ConfidentialUtxo>`:
  for each output call `scan_confidential_output(out, idx, view_secret, spend_public)`;
  on match, record a `ConfidentialUtxo` (skip already-known / spent key images).
- `pub fn scan_blocks(&mut self, blocks: &[Block])`: iterate, accumulate, persist.
- Marks a `ConfidentialUtxo` spent when a later scanned/own tx uses its key image.

### 5. Send path — `service/wallet/core/wallet.rs`
- `pub fn build_confidential_send(&self, recipient_addr: &str, amount: u64, fee: u64, utxo_set: &UtxoSet) -> Result<Transaction>`:
  1. `parse_confidential_address(recipient_addr)` → (view_pub, spend_pub).
  2. Select own unspent `ConfidentialUtxo`s covering `amount + fee` (largest-first).
  3. Per selected input: `ring = select_decoys(utxo_set, RING_SIZE-1, [own_otk])`,
     append the real `RingMember{ public_key: own_otk, commitment }`, set `real_index`,
     recover `spend_secret` via `recover_spend_secret`, read `blinding`/`amount` from the stored UTXO.
  4. Recipients = `[ConfRecipient{view_pub, spend_pub, amount}]` + **change to self**
     (`ConfRecipient` built from the wallet's own view/spend publics, `change = inputs − amount − fee`)
     when change > 0.
  5. `build_confidential_transaction(inputs, recipients, fee, &network)` → `Transaction`.
- Ring size = existing consensus/mempool constant (min 4); reuse, don't redefine.
- Returns the tx for the caller to broadcast (CLI prints raw / submits via RPC).

### 6. CLI — `bin/wallet.rs`
- Implement the stubbed `cmd_stealth` → print `confidential_receive_address()` (the `…1p` address to share).
- `cmd_send`: if the recipient address has the `…1p` (confidential payment) prefix,
  route to `build_confidential_send`; otherwise the existing transparent `build_tx`.
  Print the raw tx (and submit via RPC `sendrawtransaction` if `--broadcast`).
- `cmd_scan`: open the node block/UTXO DB read-only, run `scan_blocks`, persist found
  `ConfidentialUtxo`s, and print confidential balance + spendable count.

### 7. RPC — `service/network/rpc/rpc_server.rs`
- Submission already works (`sendrawtransaction` accepts confidential txs).
- Add only a small read-only helper `getconfidentialaddress` (returns the node-wallet's
  `…1p` address) if a wallet context is available; otherwise no RPC change. No new
  validation logic — the consensus gate is unchanged.

## Data flow

```
RECEIVE:  node blocks ──scan_blocks──▶ scan_confidential_output(view_secret,spend_pub)
          ──match──▶ ConfidentialUtxo{amount,blinding,otk,ephemeral} ──persist (cutxo:)
                                                              └─▶ confidential_balance()

SEND:     recipient …1p addr ─parse─▶ (view_pub,spend_pub)
          own ConfidentialUtxos ─select─▶ inputs (ring=select_decoys+real,
                                          spend_secret=recover_spend_secret)
          recipients=[target]+[change→self] ─build_confidential_transaction─▶ Tx
          ─▶ RPC sendrawtransaction ─▶ mempool verify_confidential_tx ─▶ P2P broadcast
```

## Error handling
- Address parse failures (bad prefix/length/checksum/off-curve) → typed error, no panic.
- Insufficient confidential funds → explicit error (amount+fee > spendable).
- `select_decoys` returns `None` (too few on-chain confidential outputs) → error telling
  the user the anonymity set is too small yet.
- All scalar/point decode paths return `Result`/`Option`, never `unwrap` on wallet data.

## Testing (automated, no live node)
1. **Address round-trip** — encode→parse yields the same points; tampered checksum/prefix/length rejected.
2. **Deterministic keys** — same seed → same `confidential_address()`; different seeds differ.
3. **Full wallet round-trip** (the acceptance oracle):
   - Seed a `UtxoSet` with N confidential decoy outputs (recording their `okeyidx:` indices).
   - Wallets A and B each derive confidential keys; B exposes its `…1p` address.
   - A owns a confidential UTXO (its one-time output recorded on-chain); A calls
     `build_confidential_send(B_addr, amount, fee, utxo_set)` with change back to A.
   - Assert `verify_confidential_tx` accepts the tx.
   - B `scan_confidential(tx)` recovers the correct `amount` + a `ConfidentialUtxo`.
   - Record the new outputs on-chain, then B `build_confidential_send` spending that UTXO
     → `verify_confidential_tx` accepts (proves recovered blinding + spend secret are usable).
4. **Change correctness** — `inputs == target + change + fee`; change is scannable by the sender.
5. **CLI arg parsing** — confidential send routing by `…1p` prefix; `cmd_stealth` prints a parseable address.

## Out of scope (follow-up)
- Live-node manual verification (send between two running wallets) — final acceptance.
- Monero-style gamma decoy weighting (current uniform selection is consensus-valid).
- Wallet auto-rescan daemon / wallet birthday optimization.
- External cryptographic review (still required before mainnet).

## YAGNI / decisions
- **One** reusable payment address per wallet (no sub-address rotation here) — keeps the
  receive path simple; rotation is a later refinement.
- Change always returns to the wallet's own confidential address (rescannable + spendable).
- No new consensus/mempool/RPC validation — reuse the existing gate verbatim.
