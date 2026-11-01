# RingCT 4c-ii — Confidential Wallet Send/Receive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire confidential (RingCT) send/receive into the wallet, CLI, and RPC on top of the already-complete crypto core.

**Architecture:** Reuse `InvisibleWallet` (deterministic view/spend keys, scan, spend-secret recovery) and the `ringct` core (`build_confidential_transaction`, `scan_confidential_output`, `recover_spend_secret`, `select_decoys`). Add a publishable `SD1p` dual-key address, derive an `InvisibleWallet` from the wallet seed, track `ConfidentialUtxo`s, and expose send/scan via wallet methods + CLI.

**Tech Stack:** Rust, curve25519-dalek (Ristretto), RocksDB, existing wallet/CLI/RPC.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-4cii-confidential-wallet-design.md`

**Per-task green gate (run at the end of every task):**
```
cargo build --all-targets 2>&1 | grep -E "^error" ; \
cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^error|^warning" ; \
cargo test --lib <relevant_module>
```
All comments in English. Commit at the end of each task.

---

## Verified APIs (use these exact signatures)

- `InvisibleWallet::from_master_key(master_key: [u8;32], network: &str) -> Result<Self, CryptoError>`;
  `.view_public() -> RistrettoPoint`, `.spend_public() -> RistrettoPoint`,
  `.view_scalar`/`.spend_scalar` are **private** — add accessors as needed (Task 2).
  `.derive_spend_key_for(&RistrettoPoint) -> Result<Scalar, CryptoError>`.
- `ringct::scan::scan_confidential_output(output: &TxOutput, output_index: u32, view_priv: &Scalar, spend_pub: &RistrettoPoint) -> Option<RecoveredOutput>`
  where `RecoveredOutput { amount: u64, blinding: Scalar, one_time_pubkey: RistrettoPoint }`.
- `ringct::scan::recover_spend_secret(output, view_priv: &Scalar, spend_priv: &Scalar) -> Option<Scalar>`.
- `ringct::builder::build_confidential_transaction(inputs: Vec<OwnedInput>, recipients: Vec<ConfRecipient>, fee: u64, network: &NetworkMode) -> Result<Transaction, CryptoError>`.
  `OwnedInput { spend_secret: Scalar, amount: u64, blinding: Scalar, ring: Vec<RingMember>, real_index: usize }`,
  `ConfRecipient { view_pub: RistrettoPoint, spend_pub: RistrettoPoint, amount: u64 }`,
  `RingMember { public_key: RistrettoPoint, commitment: RistrettoPoint }`.
- `ringct::decoy::select_decoys(utxo_set: &UtxoSet, count: usize, exclude: &[String]) -> Option<Vec<RingMember>>`.
- `ringct::serialization::point_from_hex(&str) -> Option<RistrettoPoint>`.
- `Wallet` (`service/wallet/core/wallet.rs`): private `session_key: Option<Vec<u8>>` (seed), `network: String`; `unlock(...)` sets `session_key`.
- `UtxoSet::output_key_commitment(&pk_hex) -> Option<String>` (commitment hex for a one-time pubkey).

---

## Task 1: `SD1p` confidential payment address (encode/parse)

**Files:**
- Modify: `domain/address/invisible_wallet.rs`
- Test: same file `#[cfg(test)] mod tests`

- [ ] **Step 1: Write failing tests** (append to the tests module)

```rust
#[test]
fn confidential_address_round_trips() {
    let w = InvisibleWallet::from_master_key([7u8; 32], "mainnet").unwrap();
    let addr = w.confidential_address();
    assert!(addr.starts_with("SD1p"));
    let (v, s) = InvisibleWallet::parse_confidential_address(&addr, "mainnet").unwrap();
    assert_eq!(v, w.view_public());
    assert_eq!(s, w.spend_public());
}

#[test]
fn confidential_address_rejects_tampered_checksum() {
    let w = InvisibleWallet::from_master_key([7u8; 32], "mainnet").unwrap();
    let mut addr = w.confidential_address();
    addr.pop();
    addr.push(if addr.ends_with('0') { '1' } else { '0' });
    assert!(InvisibleWallet::parse_confidential_address(&addr, "mainnet").is_err());
}

#[test]
fn confidential_address_rejects_wrong_network_prefix() {
    let w = InvisibleWallet::from_master_key([7u8; 32], "mainnet").unwrap();
    let addr = w.confidential_address();
    assert!(InvisibleWallet::parse_confidential_address(&addr, "testnet").is_err());
}
```

- [ ] **Step 2: Run, verify FAIL** — `cargo test --lib invisible_wallet` → fails (methods missing).

- [ ] **Step 3: Implement** (add to `impl InvisibleWallet`, and ensure `use sha2::{Digest, Sha256};` and `CompressedRistretto` are imported)

```rust
/// Network prefix for the reusable confidential payment address (`<p>1p`).
fn conf_prefix(network: &str) -> &'static str {
    match network {
        "testnet" => "ST1p",
        "regtest" => "SR1p",
        _ => "SD1p",
    }
}

/// Reusable confidential payment address: prefix + hex(view_pub‖spend_pub) + hex(checksum[..4]).
/// Senders parse this to obtain (view_pub, spend_pub) for stealth output generation.
pub fn confidential_address(&self) -> String {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(self.view_public.compress().as_bytes());
    body.extend_from_slice(self.spend_public.compress().as_bytes());
    let checksum = &Sha256::digest(&body)[..4];
    format!(
        "{}{}{}",
        Self::conf_prefix(&self.network),
        hex::encode(&body),
        hex::encode(checksum)
    )
}

/// Parse a confidential payment address for `network` into (view_pub, spend_pub).
pub fn parse_confidential_address(
    addr: &str,
    network: &str,
) -> Result<(RistrettoPoint, RistrettoPoint), CryptoError> {
    let prefix = Self::conf_prefix(network);
    let rest = addr
        .strip_prefix(prefix)
        .ok_or_else(|| CryptoError::InvalidKey("bad confidential address prefix".into()))?;
    // 64 body bytes = 128 hex + 4 checksum bytes = 8 hex.
    if rest.len() != 136 {
        return Err(CryptoError::InvalidKey("bad confidential address length".into()));
    }
    let raw = hex::decode(rest).map_err(|_| CryptoError::InvalidKey("non-hex address".into()))?;
    let (body, checksum) = raw.split_at(64);
    if &Sha256::digest(body)[..4] != checksum {
        return Err(CryptoError::InvalidKey("confidential address checksum mismatch".into()));
    }
    let decode = |b: &[u8]| -> Result<RistrettoPoint, CryptoError> {
        let arr: [u8; 32] = b.try_into().map_err(|_| CryptoError::InvalidKey("bad point len".into()))?;
        CompressedRistretto(arr)
            .decompress()
            .ok_or_else(|| CryptoError::InvalidKey("point not on curve".into()))
    };
    Ok((decode(&body[..32])?, decode(&body[32..])?))
}
```

- [ ] **Step 4: Run, verify PASS** — `cargo test --lib invisible_wallet`.
- [ ] **Step 5: Green gate + commit**

```bash
git add domain/address/invisible_wallet.rs
git commit -m "feat(privacy): SD1p reusable confidential payment address (encode/parse)"
```

---

## Task 2: Derive the wallet's confidential keys from its seed

**Files:**
- Modify: `domain/address/invisible_wallet.rs` (add `view_scalar()`/`spend_scalar()` accessors — needed by scan/build)
- Modify: `service/wallet/core/wallet.rs`
- Test: `service/wallet/core/wallet.rs` tests

- [ ] **Step 1: Add scalar accessors to InvisibleWallet** (the fields are private; scan/build need them)

```rust
/// View secret scalar (needed for scanning confidential outputs).
pub fn view_scalar(&self) -> Scalar { self.view_scalar }
/// Spend secret scalar (needed to recover one-time spend keys).
pub fn spend_scalar(&self) -> Scalar { self.spend_scalar }
```

- [ ] **Step 2: Write failing test** (in `wallet.rs` tests)

```rust
#[test]
fn confidential_address_is_deterministic_from_seed() {
    let mut w1 = Wallet::new("mainnet");
    w1.restore_from_seed(vec![9u8; 32]).unwrap();
    let mut w2 = Wallet::new("mainnet");
    w2.restore_from_seed(vec![9u8; 32]).unwrap();
    let a1 = w1.confidential_receive_address().unwrap();
    let a2 = w2.confidential_receive_address().unwrap();
    assert_eq!(a1, a2, "same seed must yield same confidential address");
    assert!(a1.starts_with("SD1p"));

    let mut w3 = Wallet::new("mainnet");
    w3.restore_from_seed(vec![1u8; 32]).unwrap();
    assert_ne!(a1, w3.confidential_receive_address().unwrap());
}
```

- [ ] **Step 3: Run, verify FAIL** — `cargo test --lib wallet::core::wallet`.

- [ ] **Step 4: Implement** in `wallet.rs`. Add a helper that derives a stable 32-byte master key from the seed, and a method building the `InvisibleWallet` on demand (avoids storing a second copy; the seed is already in `session_key`).

```rust
// at top of file
use sha2::{Digest, Sha256};
use crate::domain::address::invisible_wallet::InvisibleWallet;

impl Wallet {
    /// Stable 32-byte confidential master key derived from the unlocked seed.
    /// Domain-separated tag is FIXED forever (changing it loses funds).
    fn confidential_master_key(&self) -> Option<[u8; 32]> {
        let seed = self.session_key.as_ref()?;
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_conf_master_v1");
        h.update(seed);
        let out = h.finalize();
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&out);
        Some(mk)
    }

    /// Build the confidential (view/spend) key wallet from the seed. None if locked.
    pub fn confidential_keys(&self) -> Option<InvisibleWallet> {
        let mk = self.confidential_master_key()?;
        InvisibleWallet::from_master_key(mk, &self.network).ok()
    }

    /// Reusable confidential receive address (SD1p…). None if locked.
    pub fn confidential_receive_address(&self) -> Option<String> {
        Some(self.confidential_keys()?.confidential_address())
    }
}
```

- [ ] **Step 5: Run, verify PASS**; **green gate + commit**

```bash
git add domain/address/invisible_wallet.rs service/wallet/core/wallet.rs
git commit -m "feat(wallet): derive confidential view/spend keys from seed; expose SD1p address"
```

---

## Task 3: `ConfidentialUtxo` type + wallet state

**Files:**
- Modify: `service/wallet/core/wallet.rs` (add type + in-memory tracking)
- Test: `wallet.rs` tests

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn confidential_balance_sums_unspent() {
    let mut w = Wallet::new("mainnet");
    w.restore_from_seed(vec![5u8; 32]).unwrap();
    assert_eq!(w.confidential_balance(), 0);
    w.add_confidential_utxo(ConfidentialUtxo {
        txid: "a".into(), index: 0, amount: 100,
        blinding_hex: "00".repeat(32), one_time_pubkey: "11".repeat(32),
        ephemeral_pubkey: "22".repeat(32), spent: false,
    });
    w.add_confidential_utxo(ConfidentialUtxo {
        txid: "b".into(), index: 0, amount: 50,
        blinding_hex: "00".repeat(32), one_time_pubkey: "33".repeat(32),
        ephemeral_pubkey: "44".repeat(32), spent: true,
    });
    assert_eq!(w.confidential_balance(), 100); // spent excluded
}
```

- [ ] **Step 2: Run, verify FAIL.**

- [ ] **Step 3: Implement.** Store `blinding` as hex (Scalar serialized) so the struct stays plain-serializable for persistence in Task 3b.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ConfidentialUtxo {
    pub txid: String,
    pub index: u32,
    pub amount: u64,
    pub blinding_hex: String,        // hex(Scalar.to_bytes())
    pub one_time_pubkey: String,     // hex(compressed point) — the real ring member
    pub ephemeral_pubkey: String,    // hex(R) — to recover spend secret at spend time
    pub spent: bool,
}

// add field to `struct Wallet`:
//   confidential_utxos: Vec<ConfidentialUtxo>,
// initialize to Vec::new() in every Wallet constructor.

impl Wallet {
    pub fn add_confidential_utxo(&mut self, u: ConfidentialUtxo) {
        if !self.confidential_utxos.iter().any(|e| e.one_time_pubkey == u.one_time_pubkey) {
            self.confidential_utxos.push(u);
        }
    }
    pub fn confidential_balance(&self) -> u64 {
        self.confidential_utxos.iter().filter(|u| !u.spent).map(|u| u.amount).sum()
    }
    pub fn confidential_utxos(&self) -> &[ConfidentialUtxo] { &self.confidential_utxos }
}
```

- [ ] **Step 4: Run, verify PASS; green gate + commit**

```bash
git add service/wallet/core/wallet.rs
git commit -m "feat(wallet): ConfidentialUtxo type + confidential balance tracking"
```

---

## Task 3b: Persist confidential UTXOs in wallet_db

**Files:**
- Modify: `service/wallet/storage/wallet_db.rs`
- Test: `wallet_db.rs` tests

- [ ] **Step 1:** Read `wallet_db.rs` fully to follow its existing save/load pattern (RocksDB key prefixes + (de)serialization helper). Mirror it.
- [ ] **Step 2: Write failing test** that saves a `Vec<ConfidentialUtxo>` under prefix `cutxo:` and loads it back equal (use the file's existing temp-DB helper).
- [ ] **Step 3: Implement** `save_confidential_utxos(&self, wallet_id, &[ConfidentialUtxo])` and `load_confidential_utxos(&self, wallet_id) -> Vec<ConfidentialUtxo>` using bincode + the existing DB handle, key `format!("cutxo:{wallet_id}")`.
- [ ] **Step 4: Wire** `Wallet` save/load (wherever transparent UTXOs persist) to also persist `confidential_utxos`.
- [ ] **Step 5: Run, verify PASS; green gate + commit**

```bash
git add service/wallet/storage/wallet_db.rs service/wallet/core/wallet.rs
git commit -m "feat(wallet): persist confidential UTXOs in wallet_db (cutxo:)"
```

---

## Task 4: Receive path — `scan_confidential` / `scan_blocks`

**Files:**
- Modify: `service/wallet/core/wallet.rs`
- Test: `wallet.rs` tests

- [ ] **Step 1: Write failing test** (build a real confidential tx to self, then scan it)

```rust
#[test]
fn scan_confidential_recovers_self_output() {
    use crate::engine::privacy::ringct::builder::{build_confidential_transaction, ConfRecipient, OwnedInput};
    use crate::config::node::node_config::NetworkMode;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
    use rand::rngs::OsRng;

    let mut w = Wallet::new("mainnet");
    w.restore_from_seed(vec![3u8; 32]).unwrap();
    let ck = w.confidential_keys().unwrap();

    // Build a confidential tx whose single output is addressed to THIS wallet.
    // Provide a self-spend input via a freshly seeded UtxoSet ring.
    let set = UtxoSet::new_empty();
    let h = crate::engine::privacy::confidential::pedersen::generator_h();
    // Seed 4 decoys.
    for _ in 0..4 {
        let pk = Scalar::random(&mut OsRng) * G;
        let c = Scalar::from(7u64) * h + Scalar::random(&mut OsRng) * G;
        set.record_confidential_output_indexed(
            &hex::encode(pk.compress().as_bytes()),
            &hex::encode(c.compress().as_bytes()),
        ).unwrap();
    }
    // Real input owned by an ephemeral spender.
    let spend = Scalar::random(&mut OsRng);
    let bl = Scalar::random(&mut OsRng);
    let real_pk = spend * G;
    let real_c = Scalar::from(100u64) * h + bl * G;
    set.record_confidential_output_indexed(
        &hex::encode(real_pk.compress().as_bytes()),
        &hex::encode(real_c.compress().as_bytes()),
    ).unwrap();
    let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(
        &set, 4, &[hex::encode(real_pk.compress().as_bytes())]).unwrap();
    ring.push(crate::engine::privacy::ringct::dual_clsag::RingMember { public_key: real_pk, commitment: real_c });
    let real_index = ring.len() - 1;

    let tx = build_confidential_transaction(
        vec![OwnedInput { spend_secret: spend, amount: 100, blinding: bl, ring, real_index }],
        vec![ConfRecipient { view_pub: ck.view_public(), spend_pub: ck.spend_public(), amount: 100 }],
        0, &NetworkMode::Mainnet,
    ).unwrap();

    let found = w.scan_confidential(&tx);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].amount, 100);
    assert_eq!(w.confidential_balance(), 100);
}
```

- [ ] **Step 2: Run, verify FAIL.**

- [ ] **Step 3: Implement** in `wallet.rs`

```rust
use crate::engine::privacy::ringct::scan::scan_confidential_output;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::block::block::Block;

impl Wallet {
    /// Scan a tx for outputs owned by this wallet; record + return new ConfidentialUtxos.
    pub fn scan_confidential(&mut self, tx: &Transaction) -> Vec<ConfidentialUtxo> {
        let ck = match self.confidential_keys() { Some(c) => c, None => return Vec::new() };
        let (vs, sp) = (ck.view_scalar(), ck.spend_public());
        let mut found = Vec::new();
        for (idx, out) in tx.outputs.iter().enumerate() {
            if let Some(rec) = scan_confidential_output(out, idx as u32, &vs, &sp) {
                let u = ConfidentialUtxo {
                    txid: tx.hash.clone(),
                    index: idx as u32,
                    amount: rec.amount,
                    blinding_hex: hex::encode(rec.blinding.to_bytes()),
                    one_time_pubkey: hex::encode(rec.one_time_pubkey.compress().as_bytes()),
                    ephemeral_pubkey: out.ephemeral_pubkey.clone().unwrap_or_default(),
                    spent: false,
                };
                let before = self.confidential_utxos.len();
                self.add_confidential_utxo(u.clone());
                if self.confidential_utxos.len() > before { found.push(u); }
            }
        }
        found
    }

    /// Scan many blocks (e.g. from the node DB) and accumulate owned outputs.
    pub fn scan_blocks(&mut self, blocks: &[Block]) -> usize {
        let mut n = 0;
        for b in blocks {
            for tx in &b.body.transactions {
                n += self.scan_confidential(tx).len();
            }
        }
        n
    }
}
```

- [ ] **Step 4: Run, verify PASS; green gate + commit**

```bash
git add service/wallet/core/wallet.rs
git commit -m "feat(wallet): scan_confidential / scan_blocks receive path"
```

---

## Task 5: Send path — `build_confidential_send` (+ acceptance oracle)

**Files:**
- Modify: `service/wallet/core/wallet.rs`
- Test: `wallet.rs` tests (the full round-trip)

- [ ] **Step 1: Write the failing acceptance test** — A→B send, verify accepts, B scans, B respends.

```rust
#[test]
fn full_confidential_roundtrip_a_to_b_then_b_spends() {
    use crate::config::node::node_config::NetworkMode;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    let net = NetworkMode::Mainnet;
    let h = crate::engine::privacy::confidential::pedersen::generator_h();
    let set = UtxoSet::new_empty();
    let seed_decoys = |set: &UtxoSet, n: usize| {
        for _ in 0..n {
            let pk = Scalar::random(&mut OsRng) * G;
            let c = Scalar::from(9u64) * h + Scalar::random(&mut OsRng) * G;
            set.record_confidential_output_indexed(
                &hex::encode(pk.compress().as_bytes()),
                &hex::encode(c.compress().as_bytes())).unwrap();
        }
    };
    seed_decoys(&set, 8);

    // Wallet A owns a confidential UTXO of 100 (recorded on-chain).
    let mut a = Wallet::new("mainnet"); a.restore_from_seed(vec![10u8;32]).unwrap();
    let ack = a.confidential_keys().unwrap();
    let mut b = Wallet::new("mainnet"); b.restore_from_seed(vec![20u8;32]).unwrap();

    // Seed A's own output by building a tx to A and scanning it (reuses Task 4 path).
    let spend = Scalar::random(&mut OsRng); let bl = Scalar::random(&mut OsRng);
    let real_pk = spend*G; let real_c = Scalar::from(100u64)*h + bl*G;
    set.record_confidential_output_indexed(
        &hex::encode(real_pk.compress().as_bytes()), &hex::encode(real_c.compress().as_bytes())).unwrap();
    let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(&set, 4, &[hex::encode(real_pk.compress().as_bytes())]).unwrap();
    ring.push(crate::engine::privacy::ringct::dual_clsag::RingMember{public_key:real_pk,commitment:real_c});
    let ri = ring.len()-1;
    let seed_tx = crate::engine::privacy::ringct::builder::build_confidential_transaction(
        vec![crate::engine::privacy::ringct::builder::OwnedInput{spend_secret:spend,amount:100,blinding:bl,ring,real_index:ri}],
        vec![crate::engine::privacy::ringct::builder::ConfRecipient{view_pub:ack.view_public(),spend_pub:ack.spend_public(),amount:100}],
        0,&net).unwrap();
    // record A's new output on-chain so it can be a ring member later, then scan into A.
    for out in &seed_tx.outputs {
        set.record_confidential_output_indexed(
            out.one_time_pubkey.as_ref().unwrap(), out.commitment.as_ref().unwrap()).unwrap();
    }
    assert_eq!(a.scan_confidential(&seed_tx).len(), 1);

    // A sends 60 to B (change 40 back to A, fee 0).
    let tx = a.build_confidential_send(&b.confidential_receive_address().unwrap(), 60, 0, &set).unwrap();
    let mut seen = HashSet::new();
    assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok(), "A→B tx must be consensus-valid");

    // B scans and finds 60.
    assert_eq!(b.scan_confidential(&tx).iter().map(|u| u.amount).sum::<u64>(), 60);

    // Record tx outputs on-chain; B spends its 60 to A.
    for out in &tx.outputs {
        set.record_confidential_output_indexed(out.one_time_pubkey.as_ref().unwrap(), out.commitment.as_ref().unwrap()).unwrap();
    }
    let tx2 = b.build_confidential_send(&a.confidential_receive_address().unwrap(), 60, 0, &set).unwrap();
    let mut seen2 = HashSet::new();
    assert!(verify_confidential_tx(&tx2, &set, &net, &mut seen2).is_ok(), "B respend must be consensus-valid");
}
```

- [ ] **Step 2: Run, verify FAIL.**

- [ ] **Step 3: Implement** `build_confidential_send`. Convert `self.network: String` to `NetworkMode` via the existing helper (check `config/node/node_config.rs` for `NetworkMode::from_str`/`for_name`; use it). Mark selected UTXOs spent.

```rust
use crate::engine::privacy::ringct::builder::{build_confidential_transaction, ConfRecipient, OwnedInput};
use crate::engine::privacy::ringct::decoy::select_decoys;
use crate::engine::privacy::ringct::dual_clsag::RingMember;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use crate::domain::utxo::utxo_set::UtxoSet;
use curve25519_dalek::scalar::Scalar;

const CONF_RING_SIZE: usize = 5; // 1 real + 4 decoys (min ring per ring_validator)

impl Wallet {
    pub fn build_confidential_send(
        &self,
        recipient_addr: &str,
        amount: u64,
        fee: u64,
        utxo_set: &UtxoSet,
    ) -> Result<Transaction, WalletError> {
        let ck = self.confidential_keys().ok_or(WalletError::Locked)?;
        let net = self.network_mode();
        let (view_pub, spend_pub) =
            InvisibleWallet::parse_confidential_address(recipient_addr, &self.network)
                .map_err(|e| WalletError::Other(format!("bad recipient address: {e}")))?;

        // Select unspent confidential UTXOs, largest-first, to cover amount+fee.
        let need = amount.checked_add(fee).ok_or_else(|| WalletError::Other("amount+fee overflow".into()))?;
        let mut chosen: Vec<&ConfidentialUtxo> = self.confidential_utxos.iter().filter(|u| !u.spent).collect();
        chosen.sort_by(|a, b| b.amount.cmp(&a.amount));
        let mut inputs_total = 0u64;
        let mut picked: Vec<&ConfidentialUtxo> = Vec::new();
        for u in chosen { if inputs_total >= need { break; } inputs_total += u.amount; picked.push(u); }
        if inputs_total < need { return Err(WalletError::Other("insufficient confidential funds".into())); }

        // Build OwnedInputs (ring + recovered spend secret + blinding).
        let mut owned = Vec::with_capacity(picked.len());
        for u in &picked {
            let real_pk = point_from_hex(&u.one_time_pubkey).ok_or_else(|| WalletError::Other("bad otk".into()))?;
            let real_c = utxo_set.output_key_commitment(&u.one_time_pubkey)
                .and_then(|c| point_from_hex(&c))
                .ok_or_else(|| WalletError::Other("real output not on-chain yet".into()))?;
            let mut ring = select_decoys(utxo_set, CONF_RING_SIZE - 1, &[u.one_time_pubkey.clone()])
                .ok_or_else(|| WalletError::Other("not enough decoys yet".into()))?;
            ring.push(RingMember { public_key: real_pk, commitment: real_c });
            let real_index = ring.len() - 1;
            // Recover the one-time spend secret directly from the stored ephemeral
            // pubkey (avoids fabricating a TxOutput; mirrors recover_spend_secret).
            let eph = point_from_hex(&u.ephemeral_pubkey)
                .ok_or_else(|| WalletError::Other("bad ephemeral pubkey".into()))?;
            let spend_secret = ck.derive_spend_key_for(&eph)
                .map_err(|e| WalletError::Other(format!("spend-secret recovery failed: {e}")))?;
            let blinding = scalar_from_hex(&u.blinding_hex).ok_or_else(|| WalletError::Other("bad blinding".into()))?;
            owned.push(OwnedInput { spend_secret, amount: u.amount, blinding, ring, real_index });
        }

        // Recipients: target + change-to-self.
        let mut recipients = vec![ConfRecipient { view_pub, spend_pub, amount }];
        let change = inputs_total - need;
        if change > 0 {
            recipients.push(ConfRecipient { view_pub: ck.view_public(), spend_pub: ck.spend_public(), amount: change });
        }

        build_confidential_transaction(owned, recipients, fee, &net)
            .map_err(|e| WalletError::Other(format!("build confidential tx failed: {e}")))
    }
}

fn scalar_from_hex(s: &str) -> Option<Scalar> {
    let b = hex::decode(s).ok()?;
    let arr: [u8; 32] = b.try_into().ok()?;
    Option::from(Scalar::from_canonical_bytes(arr))
}
```

Also add a `network_mode()` helper on `Wallet` that maps `self.network` (`"mainnet"`/`"testnet"`/`"regtest"`) to `NetworkMode` using the existing constructor in `config/node/node_config.rs` (read it; do not invent). Add `WalletError::Locked` / `WalletError::Other(String)` variants if missing.

- [ ] **Step 4: Run, verify PASS** — `cargo test --lib wallet::core::wallet::full_confidential_roundtrip`.
- [ ] **Step 5: Green gate + commit**

```bash
git add service/wallet/core/wallet.rs
git commit -m "feat(wallet): build_confidential_send with change-to-self (+ full round-trip test)"
```

---

## Task 6: CLI wiring — receive address, send routing, scan

**Files:**
- Modify: `bin/wallet.rs`
- Test: `bin/wallet.rs` tests (arg-routing helpers) — keep logic in testable functions.

- [ ] **Step 1:** Read `bin/wallet.rs` `cmd_stealth`, `cmd_send`, `validate_address`, and the wallet load/unlock helper in full.
- [ ] **Step 2: Implement `cmd_stealth`** to unlock the wallet and print `wallet.confidential_receive_address()` (the `SD1p…` address to share for receiving), with a short explanation line.
- [ ] **Step 3: Route `cmd_send`**: after parsing `<to> <amount> [fee]`, if `to` starts with the confidential prefix for the network (`SD1p`/`ST1p`/`SR1p`), open the node UTXO set read-only and call `wallet.build_confidential_send(to, amount, fee, &utxo_set)`; otherwise the existing transparent `build_tx`. Print the resulting tx as JSON/raw hex for `sendrawtransaction` (match how transparent send currently prints).
- [ ] **Step 4: Add `cmd_scan`**: load+unlock wallet, open node blocks read-only, run `wallet.scan_blocks(&blocks)`, persist, and print confidential balance + spendable count. Register `"scan"` in `CLI_COMMANDS` and the dispatch match.
- [ ] **Step 5: Add a small unit test** for the prefix-routing predicate, e.g. `fn is_confidential_addr(addr, network) -> bool`, asserting `SD1p…` → true and a standard `SD…`/stealth `SD1s…` → false.
- [ ] **Step 6: Green gate + commit**

```bash
git add bin/wallet.rs
git commit -m "feat(cli): confidential receive address, send routing by 1p prefix, scan command"
```

---

## Task 7: Minimal RPC — `getconfidentialaddress` (read-only, optional)

**Files:**
- Modify: `service/network/rpc/rpc_server.rs`
- Test: `rpc_server.rs` tests if a wallet/state fixture exists; otherwise skip the unit test and rely on manual.

- [ ] **Step 1:** Read how RPC accesses any wallet/state context. If the RPC server has **no** wallet handle, DO NOT fabricate one — record in the plan notes that `getconfidentialaddress` is deferred to the CLI (which already exposes it) and submission already works via `sendrawtransaction`. Skip to Step 4.
- [ ] **Step 2 (only if a wallet handle exists):** Add a `getconfidentialaddress` method returning `{ "address": "<SD1p…>" }` from the node wallet's `confidential_receive_address()`; register it in the dispatch table; it requires no auth (read-only, no secrets — the address is public).
- [ ] **Step 3:** Add a handler test asserting a well-formed `SD1p…` string is returned.
- [ ] **Step 4: Green gate + commit**

```bash
git add service/network/rpc/rpc_server.rs
git commit -m "feat(rpc): expose getconfidentialaddress (or document deferral)"
```

---

## Task 8: Final integration gate + docs/memory

- [ ] **Step 1:** `cargo build --all-targets` clean; `cargo clippy --all-targets -- -D warnings` clean; `cargo test --lib` full suite green.
- [ ] **Step 2:** Update `docs/superpowers/specs/.../...-design.md` status to "Implemented (wiring); live-node manual verification pending".
- [ ] **Step 3:** Update the project memory (`shadowdag-project.md`) to mark 4c-ii wiring done + note live-node manual verification + external crypto review still pending.
- [ ] **Step 4:** Commit, then push the branch.

```bash
git add -A && git commit -m "docs: mark RingCT 4c-ii wiring complete; note pending manual + crypto review"
git push origin feature/privacy-hdwallet-docs
```

---

## Notes / risks for the implementer
- **Derivation consistency:** confidential outputs MUST be scanned with `ringct::scan_confidential_output` (context-free hs), matching the builder. Do NOT use `StealthScanner`/`is_mine` (tx-context hs) for confidential outputs.
- **Real input must be on-chain:** `build_confidential_send` looks up the real commitment via `utxo_set.output_key_commitment(otk)`; a freshly-received output is only spendable once recorded in the node's confidential index (mirrors how the round-trip test records outputs before spending).
- **Change is rescannable:** change goes to the wallet's own `confidential_address()`, so a later `scan_confidential` re-detects it.
- **No secret persisted:** the one-time spend secret is recovered on demand from the stored `ephemeral_pubkey`; only `blinding_hex` (needed for the Pedersen opening) is stored.
- **NetworkMode mapping:** reuse the existing constructor in `config/node/node_config.rs`; do not hard-code magic.
