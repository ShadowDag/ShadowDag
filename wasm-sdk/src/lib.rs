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

// ── Transaction building + signing (transparent transfers) ──────────────────
//
// Replicates the node's exact wire format so the node accepts SDK-built txs:
//   * txid hash  : SHA256("SHADOW_TX_ID_V1"  || chain_id || 2u32 || canonical)
//   * sign msg   : SHA256("SHADOW_TX_SIGN_V1" || chain_id || ...fields...)
//   * signature  : Ed25519 over sign msg (deterministic)
// `canonical` and the field order mirror transaction.rs::canonical_bytes and
// tx_hash.rs::signing_message_for_network. Verified against a reference vector
// (tx_builder.rs::tests::wasm_sdk_tx_reference_vector).

use ed25519_dalek::Signer;

fn chain_id_for(network: &str) -> u32 {
    match network {
        "testnet" => 0xDA0C_0002,
        "regtest" => 0xDA0C_0003,
        _ => 0xDA0C_0001, // mainnet (also the fail-safe default)
    }
}

const TX_HASH_VERSION: u32 = 2;

struct InRef {
    txid: String,
    index: u32,
    owner: String,
}
struct OutRef {
    address: String,
    amount: u64,
}

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Sorted input order used by BOTH canonical_bytes and signing_message.
fn sorted_input_order(inputs: &[InRef]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..inputs.len()).collect();
    idx.sort_by(|&a, &b| {
        inputs[a]
            .txid
            .cmp(&inputs[b].txid)
            .then(inputs[a].index.cmp(&inputs[b].index))
    });
    idx
}

/// transaction.rs::canonical_bytes for a transparent transfer (all privacy /
/// contract fields absent → 0x00 markers).
fn canonical_bytes_transparent(
    inputs: &[InRef],
    pub_key_hex: &str,
    outputs: &[OutRef],
    fee: u64,
    timestamp: u64,
    payload_hash: &Option<String>,
) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.push(0x00); // tx_type = Transfer
    b.push(0x00); // is_coinbase = false
    b.extend_from_slice(&timestamp.to_le_bytes());
    b.extend_from_slice(&fee.to_le_bytes());

    let order = sorted_input_order(inputs);
    b.extend_from_slice(&le32(inputs.len() as u32));
    for &i in &order {
        let inp = &inputs[i];
        b.extend_from_slice(&le32(inp.txid.len() as u32));
        b.extend_from_slice(inp.txid.as_bytes());
        b.extend_from_slice(&inp.index.to_le_bytes());
        b.extend_from_slice(&le32(inp.owner.len() as u32));
        b.extend_from_slice(inp.owner.as_bytes());
        b.extend_from_slice(&le32(pub_key_hex.len() as u32));
        b.extend_from_slice(pub_key_hex.as_bytes());
        b.push(0x00); // key_image
        b.push(0x00); // ring_members
        b.push(0x00); // ring_signature
        b.push(0x00); // ring_commitments
        b.push(0x00); // pseudo_commitment
    }

    b.extend_from_slice(&le32(outputs.len() as u32));
    for out in outputs {
        b.extend_from_slice(&le32(out.address.len() as u32));
        b.extend_from_slice(out.address.as_bytes());
        b.extend_from_slice(&out.amount.to_le_bytes());
        b.push(0x00); // commitment
        b.push(0x00); // range_proof
        b.push(0x00); // ephemeral_pubkey
        b.push(0x00); // one_time_pubkey
        b.push(0x00); // encrypted_amount
    }

    match payload_hash {
        Some(ph) => {
            b.push(0x01);
            b.extend_from_slice(&le32(ph.len() as u32));
            b.extend_from_slice(ph.as_bytes());
        }
        None => b.push(0x00),
    }
    b.push(0x00); // gas_limit
    b.push(0x00); // deploy_code
    b.push(0x00); // calldata
    b.push(0x00); // contract_address
    b.push(0x00); // vm_version
    b
}

fn tx_id_hash(canonical: &[u8], chain_id: u32) -> String {
    let mut h = Sha256::new();
    h.update(b"SHADOW_TX_ID_V1");
    h.update(chain_id.to_le_bytes());
    h.update(TX_HASH_VERSION.to_le_bytes());
    h.update(canonical);
    hex::encode(h.finalize())
}

fn signing_message(
    hash_hex: &str,
    inputs: &[InRef],
    outputs: &[OutRef],
    fee: u64,
    timestamp: u64,
    payload_hash: &Option<String>,
    chain_id: u32,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"SHADOW_TX_SIGN_V1");
    h.update(chain_id.to_le_bytes());
    h.update(le32(hash_hex.len() as u32));
    h.update(hash_hex.as_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(fee.to_le_bytes());
    h.update(le32(outputs.len() as u32));
    for out in outputs {
        h.update(le32(out.address.len() as u32));
        h.update(out.address.as_bytes());
        h.update(out.amount.to_le_bytes());
    }
    let order = sorted_input_order(inputs);
    h.update(le32(inputs.len() as u32));
    for &i in &order {
        let inp = &inputs[i];
        h.update(le32(inp.txid.len() as u32));
        h.update(inp.txid.as_bytes());
        h.update(inp.index.to_le_bytes());
    }
    match payload_hash {
        Some(ph) => {
            h.update([0x01]);
            h.update(le32(ph.len() as u32));
            h.update(ph.as_bytes());
        }
        None => h.update([0x00]),
    }
    h.finalize().to_vec()
}

struct Signed {
    hash: String,
    signature: String,
}

#[allow(clippy::too_many_arguments)]
fn sign_transfer(
    inputs: &[InRef],
    outputs: &[OutRef],
    fee: u64,
    timestamp: u64,
    payload_hash: &Option<String>,
    private_key_hex: &str,
    public_key_hex: &str,
    network: &str,
) -> Result<Signed, String> {
    let chain_id = chain_id_for(network);
    let canonical =
        canonical_bytes_transparent(inputs, public_key_hex, outputs, fee, timestamp, payload_hash);
    let hash = tx_id_hash(&canonical, chain_id);
    let msg = signing_message(&hash, inputs, outputs, fee, timestamp, payload_hash, chain_id);

    let sk_bytes = hex::decode(private_key_hex).map_err(|e| e.to_string())?;
    let sk_arr: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&sk_arr);
    let signature = hex::encode(sk.sign(&msg).to_bytes());
    Ok(Signed { hash, signature })
}

fn json_str(s: &str) -> String {
    // Addresses/hex/hashes contain no JSON-special chars, but escape defensively.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Build + sign a transparent transfer, returning the transaction as JSON ready
/// for the node's `sendrawtransaction` RPC.
///
/// `inputs` / `outputs` are JSON arrays:
///   inputs:  [{"txid":"<hex>","index":0,"owner":"SD1..."}, ...]
///   outputs: [{"address":"SD1...","amount":1000}, ...]
/// `anchor` is an optional recent tip hash (replay protection); pass "" for none.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_signed_transfer_json(
    inputs: Vec<JsValue>,
    outputs: Vec<JsValue>,
    fee: u64,
    timestamp: u64,
    anchor: &str,
    private_key_hex: &str,
    public_key_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let to_err = |e: String| JsValue::from_str(&e);
    let parsed_in = parse_inputs(&inputs).map_err(to_err)?;
    let parsed_out = parse_outputs(&outputs).map_err(to_err)?;
    let payload_hash = if anchor.is_empty() {
        None
    } else {
        Some(anchor.to_string())
    };
    let signed = sign_transfer(
        &parsed_in,
        &parsed_out,
        fee,
        timestamp,
        &payload_hash,
        private_key_hex,
        public_key_hex,
        network,
    )
    .map_err(to_err)?;

    Ok(transfer_json(
        &signed,
        &parsed_in,
        &parsed_out,
        fee,
        timestamp,
        &payload_hash,
        public_key_hex,
    ))
}

// Parsing of the JS-provided input/output objects via web JS values would
// require js-sys; to keep the crate dependency-light, inputs/outputs are passed
// as already-stringified JSON entries (one JsValue string per entry).
fn parse_inputs(items: &[JsValue]) -> Result<Vec<InRef>, String> {
    items
        .iter()
        .map(|v| {
            let s = v.as_string().ok_or("input entry must be a JSON string")?;
            let txid = json_field(&s, "txid").ok_or("input missing txid")?;
            let owner = json_field(&s, "owner").ok_or("input missing owner")?;
            let index = json_num(&s, "index").ok_or("input missing index")? as u32;
            Ok(InRef { txid, index, owner })
        })
        .collect()
}

fn parse_outputs(items: &[JsValue]) -> Result<Vec<OutRef>, String> {
    items
        .iter()
        .map(|v| {
            let s = v.as_string().ok_or("output entry must be a JSON string")?;
            let address = json_field(&s, "address").ok_or("output missing address")?;
            let amount = json_num(&s, "amount").ok_or("output missing amount")?;
            Ok(OutRef { address, amount })
        })
        .collect()
}

// Minimal field extractors for flat `{"k":"v"}` / `{"k":123}` JSON entries.
fn json_field(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let i = s.find(&pat)? + pat.len();
    let rest = &s[i..];
    let q1 = rest.find('"')?;
    let after = &rest[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

fn json_num(s: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{}\"", key);
    let i = s.find(&pat)? + pat.len();
    let rest = s[i..].trim_start_matches([':', ' ']);
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn transfer_json(
    signed: &Signed,
    inputs: &[InRef],
    outputs: &[OutRef],
    fee: u64,
    timestamp: u64,
    payload_hash: &Option<String>,
    public_key_hex: &str,
) -> String {
    let mut s = String::from("{");
    s.push_str(&format!("\"hash\":{},", json_str(&signed.hash)));
    s.push_str("\"inputs\":[");
    for (i, inp) in inputs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"txid\":{},\"index\":{},\"owner\":{},\"signature\":{},\"pub_key\":{}}}",
            json_str(&inp.txid),
            inp.index,
            json_str(&inp.owner),
            json_str(&signed.signature),
            json_str(public_key_hex),
        ));
    }
    s.push_str("],\"outputs\":[");
    for (i, out) in outputs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"address\":{},\"amount\":{}}}",
            json_str(&out.address),
            out.amount,
        ));
    }
    s.push_str(&format!(
        "],\"fee\":{},\"timestamp\":{},\"is_coinbase\":false,\"tx_type\":\"Transfer\"",
        fee, timestamp
    ));
    if let Some(ph) = payload_hash {
        s.push_str(&format!(",\"payload_hash\":{}", json_str(ph)));
    }
    s.push('}');
    s
}

/// Wrap a signed-tx JSON in a JSON-RPC 2.0 `sendrawtransaction` request body.
/// POST the result to the node's RPC endpoint (the JS layer does the `fetch`).
#[wasm_bindgen]
pub fn sendrawtransaction_body(tx_json: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[{}]}}",
        tx_json
    )
}

/// Build a JSON-RPC 2.0 request body for any method (params is a JSON array string).
#[wasm_bindgen]
pub fn json_rpc_body(method: &str, params_json_array: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":{},\"params\":{}}}",
        json_str(method),
        params_json_array
    )
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

    // Reference vector from tx_builder.rs::tests::wasm_sdk_tx_reference_vector.
    const TX_PRIV: [u8; 32] = [7u8; 32];
    const TX_PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const TX_OWNER: &str = "SD15733ef1109c71b28d117680dde4417876ea6bca5";
    const TX_HASH: &str = "4f7c71d635fcd3cedae89cf56baf4f8f85ff96104df1f6356b5b10c70fd46169";
    const TX_SIG: &str = "6fd6fd09c2f64c8f6267f0467cff2757cb47fed22497ad05cef355b5878148b8575356ba2942c0ae8e24602f2331369b7b98979c7a38d4b67268d42290f6150c";

    #[test]
    fn tx_build_sign_matches_chain_reference_vector() {
        // Address derivation reproduces the owner from the private key.
        assert_eq!(address_from_public_key(TX_PUBKEY, "mainnet").unwrap(), TX_OWNER);

        let sk_hex = hex::encode(TX_PRIV);
        let inputs = vec![InRef {
            txid: "aa".repeat(32),
            index: 0,
            owner: TX_OWNER.to_string(),
        }];
        let outputs = vec![OutRef {
            address: format!("SD1{}", "11".repeat(20)),
            amount: 1000,
        }];
        let signed = sign_transfer(
            &inputs, &outputs, 10, 1_700_000_000, &None, &sk_hex, TX_PUBKEY, "mainnet",
        )
        .unwrap();

        // Byte-identical hash + signature to the node.
        assert_eq!(signed.hash, TX_HASH);
        assert_eq!(signed.signature, TX_SIG);

        // JSON has the right shape for sendrawtransaction.
        let json = transfer_json(&signed, &inputs, &outputs, 10, 1_700_000_000, &None, TX_PUBKEY);
        assert!(json.contains("\"tx_type\":\"Transfer\""));
        assert!(json.contains("\"is_coinbase\":false"));
        assert!(json.contains(TX_HASH));
        assert!(json.contains(TX_SIG));
        assert!(json.contains(TX_PUBKEY));

        let body = sendrawtransaction_body(&json);
        assert!(body.contains("\"method\":\"sendrawtransaction\""));
        assert!(body.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn anchor_changes_the_signature() {
        let sk_hex = hex::encode(TX_PRIV);
        let inputs = vec![InRef { txid: "aa".repeat(32), index: 0, owner: TX_OWNER.to_string() }];
        let outputs = vec![OutRef { address: format!("SD1{}", "11".repeat(20)), amount: 1000 }];
        let no_anchor = sign_transfer(&inputs, &outputs, 10, 1_700_000_000, &None, &sk_hex, TX_PUBKEY, "mainnet").unwrap();
        let anchored = sign_transfer(&inputs, &outputs, 10, 1_700_000_000, &Some("bb".repeat(32)), &sk_hex, TX_PUBKEY, "mainnet").unwrap();
        assert_ne!(no_anchor.hash, anchored.hash);
        assert_ne!(no_anchor.signature, anchored.signature);
    }

    #[test]
    fn json_extractors_work() {
        let s = "{\"txid\":\"abc\",\"index\":5,\"owner\":\"SD1x\",\"amount\":1000}";
        assert_eq!(json_field(s, "txid").as_deref(), Some("abc"));
        assert_eq!(json_field(s, "owner").as_deref(), Some("SD1x"));
        assert_eq!(json_num(s, "index"), Some(5));
        assert_eq!(json_num(s, "amount"), Some(1000));
        assert_eq!(json_field(s, "missing"), None);
    }
}
