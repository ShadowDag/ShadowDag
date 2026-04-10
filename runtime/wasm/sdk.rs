// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// WASM SDK — Browser-compatible wallet and transaction operations.
//
// These functions are pure computation (no I/O) and can be compiled to WASM.
// They provide the same cryptographic operations as the full node but
// run in the browser for web wallets and dApps.
//
// Exposed functions:
//   - generate_keypair()     → {public_key, private_key, address}
//   - generate_address()     → address from public key
//   - sign_message()         → Ed25519 signature
//   - verify_signature()     → bool
//   - compute_tx_hash()      → transaction hash
//   - generate_stealth()     → stealth address
//   - validate_address()     → bool
//   - estimate_fee()         → fee in satoshis
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier, Signature};
use rand::rngs::OsRng;
use crate::errors::VmError;

// ── Network prefix helpers ──────────────────────────────────────────────

/// The three canonical network prefixes used by ShadowDAG addresses.
/// Matches the on-chain format used by [`generate_address`] / [`validate_address`].
const MAINNET_PREFIX: &str = "SD1";
const TESTNET_PREFIX: &str = "ST1";
const REGTEST_PREFIX: &str = "SR1";

/// Resolve a network name (`"mainnet"` / `"testnet"` / `"regtest"`) to its
/// 3-character on-chain prefix. Returns `None` for unknown networks so the
/// caller can surface a structured error instead of generating a
/// mainnet-looking address by accident.
fn network_prefix(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some(MAINNET_PREFIX),
        "testnet" => Some(TESTNET_PREFIX),
        "regtest" => Some(REGTEST_PREFIX),
        _ => None,
    }
}

/// Extract the 3-character network prefix from an existing ShadowDAG
/// address (`"SD1..."` / `"ST1..."` / `"SR1..."`). This lets
/// `generate_stealth_address` and `compute_contract_address` stay
/// network-aware without taking an explicit `network` argument: the
/// network identity of the output is tied to the network identity of
/// the input.
fn prefix_from_address(addr: &str) -> Option<&'static str> {
    if addr.starts_with(MAINNET_PREFIX) {
        Some(MAINNET_PREFIX)
    } else if addr.starts_with(TESTNET_PREFIX) {
        Some(TESTNET_PREFIX)
    } else if addr.starts_with(REGTEST_PREFIX) {
        Some(REGTEST_PREFIX)
    } else {
        None
    }
}

/// Keypair result (all hex-encoded)
pub struct WasmKeypair {
    pub private_key: String,
    pub public_key:  String,
    pub address:     String,
}

/// Transaction hash result
pub struct WasmTxHash {
    pub hash: String,
}

/// Signature result
pub struct WasmSignature {
    pub signature: String,
    pub public_key: String,
}

// ═══════════════════════════════════════════════════════════════════════════
//                     KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a new keypair (Ed25519).
///
/// Returns `Err` if `network` is not a known ShadowDAG network. The
/// internal `generate_address` call cannot fail here — we just encoded
/// the public key from raw bytes ourselves — so the only real error path
/// is an unknown network name.
pub fn generate_keypair(network: &str) -> Result<WasmKeypair, VmError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let sk_hex = hex::encode(signing_key.to_bytes());
    let pk_hex = hex::encode(verifying_key.to_bytes());
    let address = generate_address(&pk_hex, network)?;

    Ok(WasmKeypair {
        private_key: sk_hex,
        public_key:  pk_hex,
        address,
    })
}

/// Generate an address from a hex-encoded public key and a network name.
///
/// Returns `Err(VmError)` on:
///   - an unknown `network` (use `"mainnet"` / `"testnet"` / `"regtest"`)
///   - `public_key_hex` that is not a valid 64-character hex string
///   - a decoded key whose length is not exactly 32 bytes
///
/// Errors are returned via `Result` rather than embedded in the address
/// string (the old behaviour produced literal `"ERROR: ..."` values that
/// could be mistaken for real addresses if a caller forgot to filter).
pub fn generate_address(public_key_hex: &str, network: &str) -> Result<String, VmError> {
    let prefix = network_prefix(network).ok_or_else(|| {
        VmError::Other(format!(
            "unknown network '{}': expected mainnet/testnet/regtest",
            network
        ))
    })?;

    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| VmError::Other(format!("invalid public key hex: {}", e)))?;
    if pk_bytes.len() != 32 {
        return Err(VmError::Other(format!(
            "public key must be 32 bytes (got {})",
            pk_bytes.len()
        )));
    }

    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Addr_v1");
    h.update(&pk_bytes);
    let hash = h.finalize();

    Ok(format!("{}{}", prefix, hex::encode(&hash[..20])))
}

/// Validate an address format
pub fn validate_address(address: &str) -> bool {
    if address.len() < 43 || address.len() > 64 {
        return false;
    }
    let valid_prefix = address.starts_with("SD1")
        || address.starts_with("ST1")
        || address.starts_with("SR1");
    if !valid_prefix { return false; }

    // Check hex portion
    let hex_part = &address[3..];
    hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

// ═══════════════════════════════════════════════════════════════════════════
//                     SIGNING
// ═══════════════════════════════════════════════════════════════════════════

/// Sign a message with a private key
pub fn sign_message(private_key_hex: &str, message: &[u8]) -> Result<WasmSignature, VmError> {
    let sk_bytes = hex::decode(private_key_hex)
        .map_err(|e| VmError::Other(format!("Invalid private key hex: {}", e)))?;
    if sk_bytes.len() != 32 {
        return Err(VmError::Other("Private key must be 32 bytes".to_string()));
    }

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_arr);
    let signature = signing_key.sign(message);
    let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());

    Ok(WasmSignature {
        signature:  hex::encode(signature.to_bytes()),
        public_key: pk_hex,
    })
}

/// Verify a signature
pub fn verify_signature(
    public_key_hex: &str,
    message:        &[u8],
    signature_hex:  &str,
) -> bool {
    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).is_ok()
}

// ═══════════════════════════════════════════════════════════════════════════
//                     TRANSACTION HASHING
// ═══════════════════════════════════════════════════════════════════════════

/// Compute transaction hash from components
pub fn compute_tx_hash(
    inputs:    &[(String, u32)], // (txid, index)
    outputs:   &[(String, u64)], // (address, amount)
    fee:       u64,
    timestamp: u64,
) -> WasmTxHash {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_TxHash_v1");
    h.update((0xDA0C_0001u32).to_le_bytes()); // Chain ID
    h.update(timestamp.to_le_bytes());
    h.update(fee.to_le_bytes());

    h.update((inputs.len() as u32).to_le_bytes());
    for (txid, index) in inputs {
        h.update(txid.as_bytes());
        h.update(index.to_le_bytes());
    }

    h.update((outputs.len() as u32).to_le_bytes());
    for (address, amount) in outputs {
        h.update(address.as_bytes());
        h.update(amount.to_le_bytes());
    }

    WasmTxHash { hash: hex::encode(h.finalize()) }
}

// ═══════════════════════════════════════════════════════════════════════════
//                     STEALTH ADDRESSES
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a one-time stealth address.
///
/// The stealth address inherits the network of `base_address`:
///   - `SD1…` base → `SD1s…` stealth (mainnet)
///   - `ST1…` base → `ST1s…` stealth (testnet)
///   - `SR1…` base → `SR1s…` stealth (regtest)
///
/// Returns `Err(VmError)` if `base_address` does not start with a known
/// ShadowDAG prefix. The previous implementation hard-coded `SD1s`
/// regardless of the base network, which produced mainnet-looking
/// stealth addresses even on testnet/regtest.
pub fn generate_stealth_address(base_address: &str) -> Result<String, VmError> {
    let net_prefix = prefix_from_address(base_address).ok_or_else(|| {
        VmError::Other(format!(
            "stealth base address '{}' has unknown network prefix \
             (expected SD1/ST1/SR1)",
            base_address
        ))
    })?;

    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Stealth_v1");
    h.update(base_address.as_bytes());
    h.update(entropy);
    let hash = h.finalize();

    Ok(format!("{}s{}", net_prefix, hex::encode(&hash[..20])))
}

// ═══════════════════════════════════════════════════════════════════════════
//                     FEE ESTIMATION
// ═══════════════════════════════════════════════════════════════════════════

/// Estimate transaction fee based on input/output count
pub fn estimate_fee(input_count: usize, output_count: usize) -> u64 {
    // Base fee + per-input + per-output cost
    let base = 1_000u64;
    let per_input = 500u64;
    let per_output = 200u64;
    base + (input_count as u64 * per_input) + (output_count as u64 * per_output)
}

/// Format satoshis as human-readable SDAG string
pub fn format_amount(satoshis: u64) -> String {
    let whole = satoshis / 100_000_000;
    let frac = satoshis % 100_000_000;
    format!("{}.{:08} SDAG", whole, frac)
}

/// Parse SDAG string to satoshis
pub fn parse_amount(sdag_str: &str) -> Result<u64, VmError> {
    let s = sdag_str.trim().trim_end_matches(" SDAG").trim_end_matches(" sdag");
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        1 => {
            let whole: u64 = parts[0].parse().map_err(|e| VmError::Other(format!("{}", e)))?;
            whole.checked_mul(100_000_000).ok_or(VmError::Other("Overflow".to_string()))
        }
        2 => {
            let whole: u64 = parts[0].parse().map_err(|e| VmError::Other(format!("{}", e)))?;
            if parts[1].len() > 8 {
                return Err(VmError::Other("Max 8 decimal places".to_string()));
            }
            let frac_str = format!("{:0<8}", parts[1]);
            let frac: u64 = frac_str[..8].parse().map_err(|e| VmError::Other(format!("{}", e)))?;
            whole.checked_mul(100_000_000)
                .and_then(|w| w.checked_add(frac))
                .ok_or(VmError::Other("Overflow".to_string()))
        }
        _ => Err(VmError::Other("Invalid format".to_string())),
    }
}

use rand::RngCore;

// ── Smart Contract Helpers ─────────────────────────────────────────

/// Encode a contract method call using ABI-like encoding.
/// The selector is the first 4 bytes of SHA256(method_signature).
/// Arguments are 32-byte zero-padded, big-endian encoded.
///
/// Example: encode_contract_call("transfer(address,uint256)", &[addr_bytes, amount_bytes])
pub fn encode_contract_call(method_signature: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(method_signature.as_bytes());
    let selector = &hasher.finalize()[..4];

    let mut encoded = Vec::with_capacity(4 + args.len() * 32);
    encoded.extend_from_slice(selector);

    for arg in args {
        // Zero-pad to 32 bytes (right-aligned, big-endian)
        let mut padded = [0u8; 32];
        let start = 32usize.saturating_sub(arg.len());
        let copy_len = arg.len().min(32);
        padded[start..start + copy_len].copy_from_slice(&arg[..copy_len]);
        encoded.extend_from_slice(&padded);
    }

    encoded
}

/// Decode a contract call result into 32-byte chunks.
pub fn decode_contract_result(output: &[u8]) -> Vec<Vec<u8>> {
    output.chunks(32).map(|chunk| chunk.to_vec()).collect()
}

/// Compute deterministic contract address from deployer, bytecode, and timestamp.
///
/// The contract address inherits the network of `deployer`:
///   - `SD1…` deployer → `SD1c…` contract (mainnet)
///   - `ST1…` deployer → `ST1c…` contract (testnet)
///   - `SR1…` deployer → `SR1c…` contract (regtest)
///
/// address = SHA256("ShadowDAG_Contract_v1" || deployer || bytecode ||
/// timestamp)[0..20], hex-encoded with the inherited `{net}c` prefix.
///
/// Returns `Err(VmError)` if `deployer` does not start with a known
/// ShadowDAG prefix. The previous implementation hard-coded `SD1c`
/// regardless of the deployer network, which meant a testnet deployer
/// would produce a mainnet-looking contract address — inconsistent with
/// the rest of the address system.
pub fn compute_contract_address(
    deployer: &str,
    bytecode: &[u8],
    timestamp: u64,
) -> Result<String, VmError> {
    let net_prefix = prefix_from_address(deployer).ok_or_else(|| {
        VmError::Other(format!(
            "contract deployer '{}' has unknown network prefix \
             (expected SD1/ST1/SR1)",
            deployer
        ))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(b"ShadowDAG_Contract_v1");
    hasher.update(deployer.as_bytes());
    hasher.update(bytecode);
    hasher.update(timestamp.to_le_bytes());
    let hash = hasher.finalize();
    Ok(format!("{}c{}", net_prefix, hex::encode(&hash[..20])))
}

/// Encode a contract deployment payload.
/// Format: [bytecode_len (4 bytes LE)] [bytecode] [constructor_args...]
pub fn encode_deploy_tx(bytecode: &[u8], constructor_args: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + bytecode.len() + constructor_args.len() * 32);
    payload.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    payload.extend_from_slice(bytecode);
    for arg in constructor_args {
        let mut padded = [0u8; 32];
        let start = 32usize.saturating_sub(arg.len());
        let copy_len = arg.len().min(32);
        padded[start..start + copy_len].copy_from_slice(&arg[..copy_len]);
        payload.extend_from_slice(&padded);
    }
    payload
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let kp = generate_keypair("mainnet").expect("mainnet ok");
        assert_eq!(kp.private_key.len(), 64);
        assert_eq!(kp.public_key.len(), 64);
        assert!(kp.address.starts_with("SD1"));
    }

    #[test]
    fn keypair_unknown_network_errors() {
        assert!(generate_keypair("unknownnet").is_err());
    }

    #[test]
    fn keypair_unique() {
        let k1 = generate_keypair("mainnet").unwrap();
        let k2 = generate_keypair("mainnet").unwrap();
        assert_ne!(k1.private_key, k2.private_key);
    }

    #[test]
    fn address_from_pubkey() {
        let kp = generate_keypair("mainnet").unwrap();
        let addr = generate_address(&kp.public_key, "mainnet").unwrap();
        assert_eq!(addr, kp.address);
    }

    #[test]
    fn address_network_prefixes() {
        let kp = generate_keypair("mainnet").unwrap();
        assert!(generate_address(&kp.public_key, "mainnet").unwrap().starts_with("SD1"));
        assert!(generate_address(&kp.public_key, "testnet").unwrap().starts_with("ST1"));
        assert!(generate_address(&kp.public_key, "regtest").unwrap().starts_with("SR1"));
    }

    #[test]
    fn address_rejects_unknown_network() {
        let kp = generate_keypair("mainnet").unwrap();
        let err = generate_address(&kp.public_key, "devnet").unwrap_err();
        assert!(format!("{}", err).contains("unknown network"));
    }

    #[test]
    fn address_rejects_invalid_pubkey_hex() {
        assert!(generate_address("not-hex", "mainnet").is_err());
        assert!(generate_address("abcd", "mainnet").is_err()); // too short
    }

    #[test]
    fn validate_address_valid() {
        let kp = generate_keypair("mainnet").unwrap();
        assert!(validate_address(&kp.address));
    }

    #[test]
    fn validate_address_invalid() {
        assert!(!validate_address(""));
        assert!(!validate_address("BTC1abc"));
        assert!(!validate_address("SD1"));
    }

    #[test]
    fn sign_and_verify() {
        let kp = generate_keypair("mainnet").unwrap();
        let msg = b"Hello ShadowDAG!";
        let sig = sign_message(&kp.private_key, msg).unwrap();
        assert!(verify_signature(&sig.public_key, msg, &sig.signature));
    }

    #[test]
    fn verify_fails_wrong_message() {
        let kp = generate_keypair("mainnet").unwrap();
        let sig = sign_message(&kp.private_key, b"original").unwrap();
        assert!(!verify_signature(&sig.public_key, b"tampered", &sig.signature));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let kp1 = generate_keypair("mainnet").unwrap();
        let kp2 = generate_keypair("mainnet").unwrap();
        let sig = sign_message(&kp1.private_key, b"msg").unwrap();
        assert!(!verify_signature(&kp2.public_key, b"msg", &sig.signature));
    }

    #[test]
    fn tx_hash_deterministic() {
        let inputs = vec![("prev_tx".to_string(), 0u32)];
        let outputs = vec![("SD1addr".to_string(), 1000u64)];
        let h1 = compute_tx_hash(&inputs, &outputs, 100, 1000);
        let h2 = compute_tx_hash(&inputs, &outputs, 100, 1000);
        assert_eq!(h1.hash, h2.hash);
    }

    #[test]
    fn tx_hash_differs_with_fee() {
        let inputs = vec![("prev".to_string(), 0u32)];
        let outputs = vec![("addr".to_string(), 100u64)];
        let h1 = compute_tx_hash(&inputs, &outputs, 10, 1000);
        let h2 = compute_tx_hash(&inputs, &outputs, 20, 1000);
        assert_ne!(h1.hash, h2.hash);
    }

    #[test]
    fn stealth_address_unique() {
        let a1 = generate_stealth_address("SD1base").unwrap();
        let a2 = generate_stealth_address("SD1base").unwrap();
        assert_ne!(a1, a2);
        assert!(a1.starts_with("SD1s"));
    }

    #[test]
    fn stealth_address_inherits_network_prefix() {
        // Each network base must produce a stealth address with the
        // matching `{net}s` prefix — the previous hard-coded "SD1s"
        // would have mis-tagged testnet / regtest bases as mainnet.
        let mainnet = generate_stealth_address("SD1mainnetbase").unwrap();
        assert!(mainnet.starts_with("SD1s"), "got: {}", mainnet);

        let testnet = generate_stealth_address("ST1testnetbase").unwrap();
        assert!(testnet.starts_with("ST1s"), "got: {}", testnet);
        assert!(!testnet.starts_with("SD1"), "testnet stealth must not be tagged mainnet");

        let regtest = generate_stealth_address("SR1regtestbase").unwrap();
        assert!(regtest.starts_with("SR1s"), "got: {}", regtest);
        assert!(!regtest.starts_with("SD1"), "regtest stealth must not be tagged mainnet");
    }

    #[test]
    fn stealth_address_rejects_unknown_prefix() {
        assert!(generate_stealth_address("BTC1base").is_err());
        assert!(generate_stealth_address("").is_err());
    }

    #[test]
    fn fee_estimation() {
        let fee = estimate_fee(2, 3);
        assert_eq!(fee, 1000 + 2 * 500 + 3 * 200); // 2600
    }

    #[test]
    fn format_amount_correct() {
        assert_eq!(format_amount(1_050_000_000), "10.50000000 SDAG");
        assert_eq!(format_amount(1), "0.00000001 SDAG");
    }

    #[test]
    fn parse_amount_correct() {
        assert_eq!(parse_amount("10.5").unwrap(), 1_050_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        assert_eq!(parse_amount("100 SDAG").unwrap(), 10_000_000_000);
    }

    #[test]
    fn parse_format_roundtrip() {
        let original = 123_456_789u64;
        let formatted = format_amount(original);
        let parsed = parse_amount(&formatted).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn contract_call_encoding() {
        let encoded = encode_contract_call("transfer(address,uint256)", &[&[0x01; 20], &42u64.to_be_bytes()]);
        assert_eq!(encoded.len(), 4 + 32 + 32); // 4-byte selector + 2 args
        // Selector is first 4 bytes of SHA256("transfer(address,uint256)")
        assert_eq!(encoded.len(), 68);
    }

    #[test]
    fn contract_address_deterministic() {
        let addr1 = compute_contract_address("SD1abc", b"code", 1000).unwrap();
        let addr2 = compute_contract_address("SD1abc", b"code", 1000).unwrap();
        assert_eq!(addr1, addr2);
        assert!(addr1.starts_with("SD1c"));
        assert_eq!(addr1.len(), 4 + 40); // "SD1c" + 40 hex chars
    }

    #[test]
    fn contract_address_inherits_network_prefix() {
        // A testnet deployer must produce a testnet contract address,
        // NOT a mainnet-looking one. The old implementation hard-coded
        // "SD1c" regardless of the deployer network.
        let mainnet = compute_contract_address("SD1deployer", b"code", 1).unwrap();
        assert!(mainnet.starts_with("SD1c"), "got: {}", mainnet);

        let testnet = compute_contract_address("ST1deployer", b"code", 1).unwrap();
        assert!(testnet.starts_with("ST1c"), "got: {}", testnet);
        assert!(!testnet.starts_with("SD1"), "testnet contract must not be tagged mainnet");

        let regtest = compute_contract_address("SR1deployer", b"code", 1).unwrap();
        assert!(regtest.starts_with("SR1c"), "got: {}", regtest);
        assert!(!regtest.starts_with("SD1"), "regtest contract must not be tagged mainnet");
    }

    #[test]
    fn contract_address_rejects_unknown_deployer_prefix() {
        assert!(compute_contract_address("BTC1deployer", b"code", 1).is_err());
        assert!(compute_contract_address("", b"code", 1).is_err());
    }

    #[test]
    fn deploy_tx_encoding() {
        let bytecode = vec![0x60, 0x80, 0x60, 0x40]; // sample bytecode
        let payload = encode_deploy_tx(&bytecode, &[&[0x01]]);
        // 4 bytes length + 4 bytes bytecode + 32 bytes arg
        assert_eq!(payload.len(), 4 + 4 + 32);
        let len = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        assert_eq!(len, 4);
    }

    #[test]
    fn decode_result_chunks() {
        let data = vec![0u8; 96]; // 3 chunks of 32 bytes
        let chunks = decode_contract_result(&data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 32);
    }
}
