// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Key Derivation — Derives child keys from parent keys using HMAC-SHA256
// for hierarchical deterministic (HD) wallet support.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use curve25519_dalek::scalar::Scalar;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tags for different derivation contexts
const TAG_VIEW_KEY:    &[u8] = b"ShadowDAG_DeriveView_v1";
const TAG_CHILD_KEY:   &[u8] = b"ShadowDAG_DeriveChild_v1";
const TAG_ADDRESS:     &[u8] = b"ShadowDAG_DeriveAddr_v1";

pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a shared key from a view key and transaction public key
    /// Used in stealth address scanning
    pub fn derive(view_key: &str, tx_public_key: &str) -> String {
        let mut h = Sha256::new();
        h.update(TAG_VIEW_KEY);
        h.update(view_key.as_bytes());
        h.update(tx_public_key.as_bytes());
        hex::encode(h.finalize())
    }

    /// Derive a child private key using HMAC-SHA256
    /// parent_key: 32-byte hex-encoded parent private key
    /// index: child index for derivation
    pub fn derive_child(parent_key: &[u8; 32], index: u32) -> [u8; 32] {
        // Use from_bytes_mod_order to reduce the HMAC output into a valid
        // Scalar encoding.  This avoids the skip-ahead loop that caused
        // derive_child(k, 0) == derive_child(k, 1) when index 0 happened
        // to produce a non-canonical result and wrapped to index 1.
        let mut mac = HmacSha256::new_from_slice(parent_key)
            .expect("HMAC key length");
        mac.update(TAG_CHILD_KEY);
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let mut raw = [0u8; 32];
        raw.copy_from_slice(&result);
        Scalar::from_bytes_mod_order(raw).to_bytes()
    }

    /// Derive an address from a public key
    pub fn derive_address(public_key: &[u8; 32], network_prefix: &str) -> String {
        let mut h = Sha256::new();
        h.update(TAG_ADDRESS);
        h.update(public_key);
        let hash = h.finalize();
        format!("{}{}", network_prefix, hex::encode(&hash[..20]))
    }

    /// Derive a view key from a master private key.
    /// Returns bytes guaranteed to be a canonical Scalar encoding.
    pub fn derive_view_key(master_key: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .expect("HMAC key length");
        mac.update(b"shadowdag_view_key_v2");
        let result = mac.finalize().into_bytes();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&result);
        Scalar::from_bytes_mod_order(raw).to_bytes()
    }

    /// Derive a spend key from a master private key.
    /// Returns bytes guaranteed to be a canonical Scalar encoding.
    pub fn derive_spend_key(master_key: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .expect("HMAC key length");
        mac.update(b"shadowdag_spend_key_v2");
        let result = mac.finalize().into_bytes();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&result);
        Scalar::from_bytes_mod_order(raw).to_bytes()
    }

    /// Derive multiple child keys at sequential indices
    pub fn derive_children(parent_key: &[u8; 32], start: u32, count: u32) -> Vec<[u8; 32]> {
        (start..start + count)
            .map(|i| Self::derive_child(parent_key, i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let a = KeyDerivation::derive("view123", "txpub456");
        let b = KeyDerivation::derive("view123", "txpub456");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_is_hex_64() {
        let r = KeyDerivation::derive("vk", "tp");
        assert_eq!(r.len(), 64);
        assert!(r.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn child_derivation_deterministic() {
        let parent = [0xABu8; 32];
        let c1 = KeyDerivation::derive_child(&parent, 0);
        let c2 = KeyDerivation::derive_child(&parent, 0);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_indices_different_keys() {
        let parent = [0xCDu8; 32];
        let c0 = KeyDerivation::derive_child(&parent, 0);
        let c1 = KeyDerivation::derive_child(&parent, 1);
        assert_ne!(c0, c1);
    }

    #[test]
    fn address_derivation() {
        let pk = [0x42u8; 32];
        let addr = KeyDerivation::derive_address(&pk, "SD1");
        assert!(addr.starts_with("SD1"));
        assert_eq!(addr.len(), 3 + 40); // prefix + 20 bytes hex
    }

    #[test]
    fn view_and_spend_keys_differ() {
        let master = [0x99u8; 32];
        let view = KeyDerivation::derive_view_key(&master);
        let spend = KeyDerivation::derive_spend_key(&master);
        assert_ne!(view, spend);
    }
}
