# Design: HD Wallet (BIP39 + SLIP-0010)

**Date:** 2026-06-29
**Track:** B (of 3 parallel tracks: docs / HD wallet / RingCT phase 1)
**Status:** Approved (design), pending spec review

## Problem

`service/wallet/keys/hd_wallet.rs` is a 30-line stub: it only wraps `KeyManager`
to encrypt/decrypt a single key. There is no deterministic hierarchical key
derivation, no recovery phrase, and no standard derivation path. A user cannot
back up one seed and recover all addresses.

## Goal

A real HD wallet: one BIP39 mnemonic backs up the entire wallet; child Ed25519
keypairs are derived deterministically via SLIP-0010; each derived key produces a
ShadowDAG address using the existing address-derivation logic.

## Why SLIP-0010 (not plain BIP32)

The chain signs with **Ed25519** (`ed25519-dalek`). BIP32's standard derivation
is defined for secp256k1; applying it to Ed25519 is non-standard and incompatible
with other wallets. **SLIP-0010** is the established standard for Ed25519 HD
derivation. Consequence: Ed25519 SLIP-0010 supports **hardened derivation only**
(no public-parent → public-child), which is fine for a wallet that holds the seed.

## Architecture

### Module layout
Rewrite `service/wallet/keys/hd_wallet.rs`. Keep `KeyManager` as the at-rest
encryption layer (AES-256-GCM + PBKDF2-600k already implemented and audited).

```
HDWallet
  ├─ mnemonic: secret (zeroized)        // BIP39, 12 or 24 words
  ├─ seed: [u8;64] (zeroized)           // BIP39 seed (PBKDF2-HMAC-SHA512)
  └─ derive(account, index) -> DerivedKey
DerivedKey
  ├─ signing_key: ed25519 SigningKey    // zeroized
  ├─ public_key_hex
  └─ address (network-prefixed)
```

### Derivation path
`m / 44' / COIN' / account' / 0' / index'`  (all hardened, per SLIP-0010 Ed25519)

- `COIN'` = **9333'** provisional (mirrors the mainnet P2P port; no registered
  SLIP-0044 id for ShadowDAG). Documented as provisional in code + spec.
- `account'` and `index'` chosen by caller; default account 0.

### Key generation steps
1. `generate_mnemonic(words: 12|24)` → BIP39 mnemonic (uses `bip39` crate
   wordlist + entropy from `OsRng`).
2. `mnemonic.to_seed(passphrase)` → 64-byte seed.
3. SLIP-0010 master: `I = HMAC-SHA512(key=b"ed25519 seed", data=seed)`;
   `k = I[0..32]`, `chain_code = I[32..64]`.
4. For each hardened path element: `I = HMAC-SHA512(key=chain_code,
   data=0x00 || k || ser32(index | 0x80000000))`; update `k`, `chain_code`.
5. Final `k` is the Ed25519 secret scalar seed → `SigningKey::from_bytes(k)`.
6. Address via existing logic (`SHA256("ShadowDAG_Addr_v1" || pubkey)[..20]` with
   network prefix) — reuse, do not duplicate.

### Persistence
- Store the **mnemonic** (or its entropy) encrypted via `KeyManager`
  (`store_key_encrypted` / `get_key_decrypted`) under a reserved key id
  (e.g. `hdwallet:mnemonic`). Child keys are derived on demand, never stored.
- `restore_from_mnemonic(phrase, password)` re-encrypts and stores.

## Dependencies

- New: `bip39` crate (maintained; provides wordlist + checksum + seed).
- Existing: `hmac`, `sha2`, `ed25519-dalek`, `zeroize`, `rand` — already in
  `Cargo.toml`.

## Interfaces (public API)

```rust
impl HDWallet {
    fn generate(words: MnemonicWords, password: &str, km: KeyManager) -> Result<Self>;
    fn restore_from_mnemonic(phrase: &str, password: &str, km: KeyManager) -> Result<Self>;
    fn load(password: &str, km: KeyManager) -> Result<Self>;       // decrypt stored mnemonic
    fn derive(&self, account: u32, index: u32) -> Result<DerivedKey>;
    fn mnemonic_phrase(&self) -> &str;  // for one-time display/backup
}
```

## Testing

- **SLIP-0010 official Ed25519 test vectors** (known seed → known keys at known
  paths) — the primary correctness gate.
- BIP39: known mnemonic + passphrase → known 64-byte seed vector.
- Round-trip: generate → derive(0,0) → address starts with correct network prefix;
  same mnemonic re-derives identical keys.
- Persistence: store encrypted → load with right password recovers; wrong password
  fails cleanly (reuses `KeyManager` auth-fail path).
- Zeroization: secrets dropped without lingering copies (best-effort, via `zeroize`).

## Non-Goals

- No secp256k1 / BIP32 compatibility.
- No public-only (watch-only) derivation in this pass.
- No GUI/CLI wiring in this spec (separate follow-up); this delivers the library
  + tests. CLI/GUI hookup can be a thin later change.

## Risks

- **Provisional coin type 9333'** may change if a real SLIP-0044 id is later
  registered — documented; only affects derivation namespace, not security.
- `bip39` crate API/version pinning — pin a specific version in `Cargo.toml`.
