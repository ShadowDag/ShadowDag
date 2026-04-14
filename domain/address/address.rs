// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// ShadowDAG address prefixes by network
pub const MAINNET_PREFIX: &str = "SD1";
pub const TESTNET_PREFIX: &str = "ST1";
pub const REGTEST_PREFIX: &str = "SR1";
pub const STEALTH_PREFIX: &str = "SD1s";
pub const SCHNORR_PREFIX: &str = "SD1k"; // k for key (Schnorr)
pub const P2SH_PREFIX: &str = "SD1h"; // h for hash (P2SH)

/// Resolve a network name (`"mainnet"` / `"testnet"` / `"regtest"`) to its
/// 3-character on-chain prefix. Returns `None` for unknown networks so the
/// caller can surface a structured error instead of silently defaulting to
/// mainnet.
pub fn network_prefix(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some(MAINNET_PREFIX),
        "testnet" => Some(TESTNET_PREFIX),
        "regtest" => Some(REGTEST_PREFIX),
        _ => None,
    }
}

/// Extract the 3-character network prefix from an existing ShadowDAG
/// address (`"SD1…"` / `"ST1…"` / `"SR1…"`).
///
/// This is the canonical helper for "derive a child address on the same
/// network as the input", used by the WASM wallet SDK and the in-VM
/// contract-address computation so they stay consistent.
///
/// Returns `None` if the address does not start with any known
/// ShadowDAG prefix, so callers can refuse to silently tag output as
/// mainnet when the input was on testnet/regtest (or vice versa).
pub fn prefix_from_address(addr: &str) -> Option<&'static str> {
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

/// Address types — ShadowDAG supports more address types than Kaspa
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Standard P2PKH (Ed25519) address
    Standard,
    /// Stealth address (one-time ECDH-based)
    Stealth,
    /// Multi-signature address (M-of-N threshold)
    MultiSig,
    /// Contract address (ShadowVM deployment)
    Contract,
    /// Schnorr signature address (BIP-340 compatible)
    Schnorr,
    /// Pay-to-Script-Hash address (script-locked outputs)
    P2SH,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub value: String,
    pub address_type: AddressType,
}

impl Address {
    pub fn new(value: String) -> Self {
        let address_type = Self::detect_type(&value);
        Self {
            value,
            address_type,
        }
    }

    pub fn from_public_key(public_key: &[u8], network: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_Addr_v1");
        h.update(public_key);
        let hash = h.finalize();

        let prefix = match network {
            "mainnet" => MAINNET_PREFIX,
            "testnet" => TESTNET_PREFIX,
            _ => REGTEST_PREFIX,
        };

        let value = format!("{}{}", prefix, hex::encode(&hash[..20]));
        Self {
            value,
            address_type: AddressType::Standard,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.value.len() < 4 {
            return false;
        }

        let has_valid_prefix = self.value.starts_with(MAINNET_PREFIX)
            || self.value.starts_with(TESTNET_PREFIX)
            || self.value.starts_with(REGTEST_PREFIX);

        if !has_valid_prefix {
            return false;
        }

        // Determine prefix length based on address type subtype prefix
        // Standard: "SD1" / "ST1" / "SR1"   → prefix 3, hex part = 40 chars (20 bytes)
        // Stealth:  "SD1s" / "ST1s" / "SR1s" → prefix 4, hex part = 40 chars
        // Schnorr:  "SD1k" / "ST1k" / "SR1k" → prefix 4, hex part = 40 chars
        // P2SH:     "SD1h" / "ST1h" / "SR1h" → prefix 4, hex part = 40 chars
        let (prefix_len, expected_hex_len) = if self.value.len() > 3 {
            match self.value.as_bytes()[3] {
                b's' | b'k' | b'h' => (4, 40), // subtype prefix + 20-byte hash
                _ => (3, 40),                  // standard address: 20-byte hash
            }
        } else {
            return false;
        };

        if self.value.len() != prefix_len + expected_hex_len {
            return false;
        }

        let hex_part = &self.value[prefix_len..];

        // STRICT: hex part must be exactly 40 chars (20 bytes) and all hex
        hex_part.len() == expected_hex_len && hex_part.bytes().all(|b: u8| b.is_ascii_hexdigit())
    }

    /// Create a Schnorr address from a 32-byte x-only public key (BIP-340 style)
    pub fn from_schnorr_key(x_only_pubkey: &[u8; 32], network: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_Schnorr_v1");
        h.update(x_only_pubkey);
        let hash = h.finalize();

        let prefix = match network {
            "testnet" => "ST1k",
            "regtest" => "SR1k",
            _ => SCHNORR_PREFIX,
        };
        let value = format!("{}{}", prefix, hex::encode(&hash[..20]));
        Self {
            value,
            address_type: AddressType::Schnorr,
        }
    }

    /// Create a P2SH address from a redeem script hash
    pub fn from_script_hash(script_hash: &[u8], network: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_P2SH_v1");
        h.update(script_hash);
        let hash = h.finalize();

        let prefix = match network {
            "testnet" => "ST1h",
            "regtest" => "SR1h",
            _ => P2SH_PREFIX,
        };
        let value = format!("{}{}", prefix, hex::encode(&hash[..20]));
        Self {
            value,
            address_type: AddressType::P2SH,
        }
    }

    pub fn is_schnorr(&self) -> bool {
        self.value.contains("1k") || self.address_type == AddressType::Schnorr
    }

    pub fn is_p2sh(&self) -> bool {
        self.value.contains("1h") || self.address_type == AddressType::P2SH
    }

    pub fn is_stealth(&self) -> bool {
        self.value.starts_with(STEALTH_PREFIX) || self.address_type == AddressType::Stealth
    }

    pub fn network(&self) -> &str {
        if self.value.starts_with("SD") {
            "mainnet"
        } else if self.value.starts_with("ST") {
            "testnet"
        } else {
            "regtest"
        }
    }

    fn detect_type(value: &str) -> AddressType {
        if value.contains("1s") {
            AddressType::Stealth
        } else if value.contains("1k") {
            AddressType::Schnorr
        } else if value.contains("1h") {
            AddressType::P2SH
        } else {
            AddressType::Standard
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_public_key_mainnet() {
        let pk = [0x42u8; 32];
        let addr = Address::from_public_key(&pk, "mainnet");
        assert!(addr.value.starts_with("SD1"));
        assert!(addr.is_valid());
    }

    #[test]
    fn from_public_key_testnet() {
        let pk = [0x42u8; 32];
        let addr = Address::from_public_key(&pk, "testnet");
        assert!(addr.value.starts_with("ST1"));
        assert!(addr.is_valid());
    }

    #[test]
    fn is_valid_rejects_empty() {
        let addr = Address::new(String::new());
        assert!(!addr.is_valid());
    }

    #[test]
    fn is_valid_rejects_bad_prefix() {
        let addr = Address::new("BTC1abc123".to_string());
        assert!(!addr.is_valid());
    }

    #[test]
    fn stealth_detection() {
        let addr = Address::new("SD1s1234567890abcdef1234567890abcdef12345678".to_string());
        assert!(addr.is_stealth());
        assert_eq!(addr.address_type, AddressType::Stealth);
    }

    #[test]
    fn network_detection() {
        assert_eq!(Address::new("SD1abc".to_string()).network(), "mainnet");
        assert_eq!(Address::new("ST1abc".to_string()).network(), "testnet");
        assert_eq!(Address::new("SR1abc".to_string()).network(), "regtest");
    }

    #[test]
    fn is_valid_rejects_short_hex() {
        // "SD1abc" has only 3 hex chars — must be exactly 40
        let addr = Address::new("SD1abc".to_string());
        assert!(!addr.is_valid(), "short hex part must be rejected");
    }

    #[test]
    fn is_valid_rejects_long_hex() {
        // 42 hex chars — one too many
        let addr = Address::new(format!("SD1{}", "ab".repeat(21)));
        assert!(!addr.is_valid(), "long hex part must be rejected");
    }

    #[test]
    fn is_valid_accepts_exact_length() {
        // 40 hex chars — exactly right
        let addr = Address::new(format!("SD1{}", "ab".repeat(20)));
        assert!(addr.is_valid());
    }

    #[test]
    fn is_valid_accepts_stealth_exact() {
        let addr = Address::new(format!("SD1s{}", "ff".repeat(20)));
        assert!(addr.is_valid());
        assert!(addr.is_stealth());
    }

    #[test]
    fn is_valid_rejects_non_hex_in_body() {
        let addr = Address::new(format!("SD1{}zz", "ab".repeat(19)));
        assert!(!addr.is_valid(), "non-hex chars must be rejected");
    }

    #[test]
    fn deterministic_from_same_key() {
        let pk = [0xFFu8; 32];
        let a1 = Address::from_public_key(&pk, "mainnet");
        let a2 = Address::from_public_key(&pk, "mainnet");
        assert_eq!(a1.value, a2.value);
    }
}
