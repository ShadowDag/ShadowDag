// ═══════════════════════════════════════════════════════════════════════════
//  ShadowDAG WASM/JS SDK — portable wallet primitives
//
//  Re-implements the chain's EXACT address-derivation chain so addresses,
//  mnemonics, and keys generated here match `shadowdag-wallet` byte-for-byte:
//
//    1. mnemonic -> seed : PBKDF2-HMAC-SHA256(words, "ShadowDAG"+pass, 2048, 64B)
//    2. seed -> key      : HMAC-SHA256(seed, "ShadowDAG/44'/999'/{a}'/{c}/{i}")[..32]
//                          -> Ed25519 SigningKey
//    3. pubkey -> address: prefix + hex(SHA256("ShadowDAG_Addr_v1" || pubkey)[..20])
//
//  Verified against pinned reference vectors from the main crate
//  (service/wallet/core/wallet.rs::tests::wasm_sdk_reference_vectors).
//
//  Build for the web/Node:  wasm-pack build --target web   (or --target nodejs)
// ═══════════════════════════════════════════════════════════════════════════

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use wasm_bindgen::prelude::*;

const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwxyz";
const VOWELS: &[u8] = b"aeiou";

// ── Pure (portable) core ────────────────────────────────────────────────────

fn network_prefix(network: &str) -> &'static str {
    match network {
        "mainnet" => "SD1",
        "testnet" => "ST1",
        "regtest" => "SR1",
        // Fail-safe: unknown labels default to mainnet (matches the node).
        _ => "SD1",
    }
}

/// address = prefix + hex(SHA256("ShadowDAG_Addr_v1" || pubkey)[..20])
fn addr_from_pubkey(pubkey: &[u8], network: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Addr_v1");
    h.update(pubkey);
    let hash = h.finalize();
    format!("{}{}", network_prefix(network), hex::encode(&hash[..20]))
}

/// Deterministic 2048-word list (matches wallet.rs::generate_bip39_wordlist).
fn wordlist() -> Vec<String> {
    let mut words: Vec<String> = Vec::with_capacity(2048);
    let mut seen = std::collections::HashSet::with_capacity(2048);
    for i in 0u32..8192 {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_BIP39_WordGen_v1");
        h.update(i.to_le_bytes());
        let hash = h.finalize();
        let word_len = 3 + (hash[0] % 5) as usize;
        let mut word = String::with_capacity(word_len);
        for j in 0..word_len {
            let byte = hash[(j + 1) % 32];
            if j % 2 == 0 {
                word.push(CONSONANTS[(byte as usize) % CONSONANTS.len()] as char);
            } else {
                word.push(VOWELS[(byte as usize) % VOWELS.len()] as char);
            }
        }
        if word.len() >= 3 && seen.insert(word.clone()) {
            words.push(word);
            if words.len() >= 2048 {
                break;
            }
        }
    }
    words
}

/// entropy -> 12 mnemonic words (matches wallet.rs::entropy_to_mnemonic_simple).
/// NOTE: uses SHA3-256 on the entropy (not SHA-256).
fn entropy_to_mnemonic(entropy: &[u8]) -> Vec<String> {
    let wl = wordlist();
    let hash = Sha3_256::digest(entropy);
    let mut bits: Vec<u8> = Vec::with_capacity(256);
    for byte in hash.iter() {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }
    (0..12)
        .map(|i| {
            let start = i * 11;
            let mut idx: usize = 0;
            for b in 0..11 {
                if start + b < bits.len() {
                    idx = (idx << 1) | (bits[start + b] as usize);
                }
            }
            wl[idx % 2048].clone()
        })
        .collect()
}

/// words -> 64-byte seed (matches wallet.rs::mnemonic_to_seed_simple).
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    let salt = format!("ShadowDAG{}", passphrase);
    let mut seed = vec![0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

/// seed -> Ed25519 signing key (matches wallet.rs::derive_key).
fn derive_signing_key(seed: &[u8], account: u32, index: u32, change: bool) -> SigningKey {
    type HmacSha256 = Hmac<Sha256>;
    let path = format!(
        "ShadowDAG/44'/999'/{}'/{}/{}",
        account,
        if change { 1 } else { 0 },
        index
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(path.as_bytes());
    let res = mac.finalize().into_bytes();
    let key: [u8; 32] = res[..32].try_into().expect("HMAC-SHA256 output is 32 bytes");
    SigningKey::from_bytes(&key)
}

/// Standard-address validity (matches the core of address.rs::is_valid):
/// prefix in {SD1, ST1, SR1}, optional subtype byte (s/k/h), then 40 hex chars.
fn is_valid_address(addr: &str) -> bool {
    let has_prefix =
        addr.starts_with("SD1") || addr.starts_with("ST1") || addr.starts_with("SR1");
    if !has_prefix || addr.len() <= 3 {
        return false;
    }
    let subtype = addr.as_bytes()[3];
    let prefix_len = match subtype {
        b's' | b'k' | b'h' => 4,
        _ => 3,
    };
    if addr.len() != prefix_len + 40 {
        return false;
    }
    addr[prefix_len..].bytes().all(|c| c.is_ascii_hexdigit())
}

// ── wasm-bindgen (JS-facing) API ────────────────────────────────────────────

/// Derive the standard address for a raw Ed25519 public key (hex, 32 bytes).
#[wasm_bindgen]
pub fn address_from_public_key(public_key_hex: &str, network: &str) -> Result<String, JsValue> {
    let pk = hex::decode(public_key_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(addr_from_pubkey(&pk, network))
}

/// Restore the primary (account 0, external, index 0) address from a mnemonic.
#[wasm_bindgen]
pub fn address_from_mnemonic(mnemonic: &str, passphrase: &str, network: &str) -> String {
    let seed = mnemonic_to_seed(mnemonic, passphrase);
    let sk = derive_signing_key(&seed, 0, 0, false);
    addr_from_pubkey(&sk.verifying_key().to_bytes(), network)
}

/// Derive a specific address (account / index / change) from a 64-byte seed (hex).
#[wasm_bindgen]
pub fn address_from_seed(
    seed_hex: &str,
    account: u32,
    index: u32,
    change: bool,
    network: &str,
) -> Result<String, JsValue> {
    let seed = hex::decode(seed_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk = derive_signing_key(&seed, account, index, change);
    Ok(addr_from_pubkey(&sk.verifying_key().to_bytes(), network))
}

/// Convert a mnemonic to its 64-byte seed (hex).
#[wasm_bindgen]
pub fn mnemonic_to_seed_hex(mnemonic: &str, passphrase: &str) -> String {
    hex::encode(mnemonic_to_seed(mnemonic, passphrase))
}

/// Generate a fresh 12-word mnemonic from 256 bits of system entropy.
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsValue> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(entropy_to_mnemonic(&entropy).join(" "))
}

/// Create a brand-new wallet: returns `mnemonic\naddress` (newline-separated).
/// (JS callers split on '\n'; a richer struct can be added later.)
#[wasm_bindgen]
pub fn new_wallet(network: &str) -> Result<String, JsValue> {
    let mnemonic = generate_mnemonic()?;
    let address = address_from_mnemonic(&mnemonic, "", network);
    Ok(format!("{}\n{}", mnemonic, address))
}

/// Validate a ShadowDAG standard address.
#[wasm_bindgen]
pub fn validate_address(address: &str) -> bool {
    is_valid_address(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors captured from the main crate
    // (wallet.rs::tests::wasm_sdk_reference_vectors). If these ever diverge, the
    // SDK no longer matches the chain — a hard error, not a warning.
    const V1_PUBKEY_ONES_ADDR: &str = "SD1723695fe652da72b39aa12f17e6a81c7379ba05b";
    const V2_SEED_TWOS_PUBKEY: &str =
        "384d0633d25725798cb3fa2b349dff39d1ff2d623e8a5d79fcd632e91740c2c1";
    const V2_SEED_TWOS_ADDR: &str = "SD1f28fa3d42b184f0ce7e84809e89efde6637bd597";
    const V3_MNEMONIC: &str =
        "lumecad gova gureri debedi rida kapa buliham gel pozesu zireke wozaga tit";
    const V3_SEED_HEX: &str = "ef8510cce605655da029f274d9920e69ac342a9b4ce492b138b847bc7d2ca5ec04a20a45cfc95e00843634d522762cfa7239dd310cfae5e1765a3d82c663c3b2";
    const V3_ADDR: &str = "SD1b28a5f7b7efee64a334f32f0fb72e736276a3bd9";

    #[test]
    fn v1_address_from_public_key_matches_chain() {
        let pk_hex = hex::encode([1u8; 32]);
        assert_eq!(
            address_from_public_key(&pk_hex, "mainnet").unwrap(),
            V1_PUBKEY_ONES_ADDR
        );
    }

    #[test]
    fn v2_seed_derivation_matches_chain() {
        let seed_hex = hex::encode([2u8; 64]);
        // Pubkey check.
        let sk = derive_signing_key(&[2u8; 64], 0, 0, false);
        assert_eq!(hex::encode(sk.verifying_key().to_bytes()), V2_SEED_TWOS_PUBKEY);
        // Address check via the public API.
        assert_eq!(
            address_from_seed(&seed_hex, 0, 0, false, "mainnet").unwrap(),
            V2_SEED_TWOS_ADDR
        );
    }

    #[test]
    fn v3_full_mnemonic_path_matches_chain() {
        // entropy -> mnemonic (wordlist + SHA3 path)
        assert_eq!(entropy_to_mnemonic(&[3u8; 32]).join(" "), V3_MNEMONIC);
        // mnemonic -> seed (PBKDF2)
        assert_eq!(mnemonic_to_seed_hex(V3_MNEMONIC, ""), V3_SEED_HEX);
        // mnemonic -> address (full chain)
        assert_eq!(address_from_mnemonic(V3_MNEMONIC, "", "mainnet"), V3_ADDR);
    }

    #[test]
    fn network_prefixes_and_validation() {
        let pk_hex = hex::encode([1u8; 32]);
        assert!(address_from_public_key(&pk_hex, "testnet").unwrap().starts_with("ST1"));
        assert!(address_from_public_key(&pk_hex, "regtest").unwrap().starts_with("SR1"));
        assert!(validate_address(V1_PUBKEY_ONES_ADDR));
        assert!(validate_address(V3_ADDR));
        assert!(!validate_address("SD1xyz")); // too short / non-hex
        assert!(!validate_address("BTC1deadbeef"));
    }

    #[test]
    fn new_wallet_roundtrips() {
        let out = new_wallet("mainnet").unwrap();
        let (mnemonic, address) = out.split_once('\n').unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert!(validate_address(address));
        // Restoring the mnemonic reproduces the same address.
        assert_eq!(address_from_mnemonic(mnemonic, "", "mainnet"), address);
    }
}
