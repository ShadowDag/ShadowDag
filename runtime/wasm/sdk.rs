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

/// Generate a new keypair (Ed25519)
pub fn generate_keypair(network: &str) -> WasmKeypair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let sk_hex = hex::encode(signing_key.to_bytes());
    let pk_hex = hex::encode(verifying_key.to_bytes());
    let address = generate_address(&pk_hex, network);

    WasmKeypair {
        private_key: sk_hex,
        public_key:  pk_hex,
        address,
    }
}

/// Generate address from public key hex
pub fn generate_address(public_key_hex: &str, network: &str) -> String {
    let prefix = match network {
        "mainnet" => "SD1",
        "testnet" => "ST1",
        "regtest" => "SR1",
        other => panic!("Unknown network '{}' — expected mainnet/testnet/regtest", other),
    };

    let pk_bytes = hex::decode(public_key_hex).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Addr_v1");
    h.update(&pk_bytes);
    let hash = h.finalize();

    format!("{}{}", prefix, hex::encode(&hash[..20]))
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

/// Generate a one-time stealth address
pub fn generate_stealth_address(base_address: &str) -> String {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Stealth_v1");
    h.update(base_address.as_bytes());
    h.update(entropy);
    let hash = h.finalize();

    format!("SD1s{}", hex::encode(&hash[..20]))
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
/// address = SHA256(deployer || bytecode || timestamp)[0..20], hex-encoded with "SD1c" prefix.
pub fn compute_contract_address(deployer: &str, bytecode: &[u8], timestamp: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ShadowDAG_Contract_v1");
    hasher.update(deployer.as_bytes());
    hasher.update(bytecode);
    hasher.update(timestamp.to_le_bytes());
    let hash = hasher.finalize();
    format!("SD1c{}", hex::encode(&hash[..20]))
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
        let kp = generate_keypair("mainnet");
        assert_eq!(kp.private_key.len(), 64);
        assert_eq!(kp.public_key.len(), 64);
        assert!(kp.address.starts_with("SD1"));
    }

    #[test]
    fn keypair_unique() {
        let k1 = generate_keypair("mainnet");
        let k2 = generate_keypair("mainnet");
        assert_ne!(k1.private_key, k2.private_key);
    }

    #[test]
    fn address_from_pubkey() {
        let kp = generate_keypair("mainnet");
        let addr = generate_address(&kp.public_key, "mainnet");
        assert_eq!(addr, kp.address);
    }

    #[test]
    fn address_network_prefixes() {
        let kp = generate_keypair("mainnet");
        assert!(generate_address(&kp.public_key, "mainnet").starts_with("SD1"));
        assert!(generate_address(&kp.public_key, "testnet").starts_with("ST1"));
        assert!(generate_address(&kp.public_key, "regtest").starts_with("SR1"));
    }

    #[test]
    fn validate_address_valid() {
        let kp = generate_keypair("mainnet");
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
        let kp = generate_keypair("mainnet");
        let msg = b"Hello ShadowDAG!";
        let sig = sign_message(&kp.private_key, msg).unwrap();
        assert!(verify_signature(&sig.public_key, msg, &sig.signature));
    }

    #[test]
    fn verify_fails_wrong_message() {
        let kp = generate_keypair("mainnet");
        let sig = sign_message(&kp.private_key, b"original").unwrap();
        assert!(!verify_signature(&sig.public_key, b"tampered", &sig.signature));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let kp1 = generate_keypair("mainnet");
        let kp2 = generate_keypair("mainnet");
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
        let a1 = generate_stealth_address("SD1base");
        let a2 = generate_stealth_address("SD1base");
        assert_ne!(a1, a2);
        assert!(a1.starts_with("SD1s"));
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
        let addr1 = compute_contract_address("SD1abc", b"code", 1000);
        let addr2 = compute_contract_address("SD1abc", b"code", 1000);
        assert_eq!(addr1, addr2);
        assert!(addr1.starts_with("SD1c"));
        assert_eq!(addr1.len(), 4 + 40); // "SD1c" + 40 hex chars
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
