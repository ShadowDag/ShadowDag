// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// View Key — Allows watching incoming stealth transactions without spending.
// Safe to share with auditors or watch-only wallets.
//
// The view key is a Scalar on Curve25519 (Ristretto) derived via HMAC-SHA256
// from the master private key, ensuring it cannot be used to derive spend keys.
// The corresponding public point V = v*G is what the sender uses for ECDH.
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const VIEW_KEY_TAG: &[u8] = b"ShadowDAG_ViewKey_v1";

#[derive(Clone, Debug)]
pub struct ViewKey {
    /// The view private scalar on the curve
    pub scalar: Scalar,
    /// The corresponding public point V = scalar * G
    pub public: RistrettoPoint,
    /// Raw 32-byte view key (scalar encoding)
    pub key_bytes: [u8; 32],
    /// Hex-encoded view key
    pub key: String,
}

impl ViewKey {
    /// Create from a hex-encoded 64-char key, or derive from string via HMAC.
    ///
    /// When the input is exactly 64 characters (looks like hex), we require
    /// it to be valid hex decoding to exactly 32 bytes.  Malformed hex is
    /// rejected instead of silently falling through to HMAC derivation.
    pub fn new(key: String) -> Result<Self, CryptoError> {
        let raw = if key.len() == 64 {
            match hex::decode(&key) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                Ok(_) => return Err(CryptoError::InvalidKey("hex key must be 32 bytes".into())),
                Err(e) => return Err(CryptoError::InvalidKey(format!("malformed hex: {}", e))),
            }
        } else {
            Self::hmac_derive(key.as_bytes())
        };

        Self::from_raw(raw)
    }

    /// Derive a view key from a private key string using HMAC-SHA256.
    pub fn from_private_key(private_key: &str) -> Result<Self, CryptoError> {
        let raw = Self::hmac_derive(private_key.as_bytes());
        Self::from_raw(raw)
    }

    /// Derive from raw private key bytes.
    pub fn from_private_key_bytes(private_key: &[u8; 32]) -> Result<Self, CryptoError> {
        let raw = Self::hmac_derive(private_key);
        Self::from_raw(raw)
    }

    /// Build from a pre-existing Scalar (e.g. from StealthKeys).
    pub fn from_scalar(s: Scalar) -> Self {
        let key_bytes = s.to_bytes();
        Self {
            scalar: s,
            public: s * RISTRETTO_BASEPOINT_POINT,
            key: hex::encode(key_bytes),
            key_bytes,
        }
    }

    /// Get the hex-encoded view key (safe to share).
    pub fn to_hex(&self) -> &str {
        &self.key
    }

    /// Get the view public point (safe to publish).
    pub fn public_point(&self) -> RistrettoPoint {
        self.public
    }

    // ── internal helpers ─────────────────────────────────────────────────

    fn hmac_derive(data: &[u8]) -> [u8; 32] {
        // SAFETY: HMAC-SHA256 accepts any key length (RFC 2104).
        // `new_from_slice` only returns Err for key lengths rejected by the
        // algorithm, but HMAC has no such restriction.  The `unwrap_or_else`
        // fallback uses a raw SHA-256 hash as a defense-in-depth alternative
        // that can never panic — but will never be reached in practice.
        let mut mac = match HmacSha256::new_from_slice(VIEW_KEY_TAG) {
            Ok(m) => m,
            Err(_) => {
                // Unreachable with HMAC-SHA256, but defensive: fall back to
                // plain SHA-256 keyed hash so we never panic in production.
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(VIEW_KEY_TAG);
                h.update(data);
                let result = h.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                return arr;
            }
        };
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }

    fn from_raw(raw: [u8; 32]) -> Result<Self, CryptoError> {
        // HMAC-SHA256 output is arbitrary 32 bytes which may exceed the
        // Ristretto group order L.  Reduce mod L so the result is always
        // a valid Scalar.  This is standard practice (cf. RFC 8032 key
        // derivation) and does not weaken the key space.
        let scalar = Scalar::from_bytes_mod_order(raw);
        let key_bytes = scalar.to_bytes();
        let public = scalar * RISTRETTO_BASEPOINT_POINT;
        Ok(Self {
            scalar,
            public,
            key_bytes,
            key: hex::encode(key_bytes),
        })
    }
}

impl Drop for ViewKey {
    fn drop(&mut self) {
        // Zero out key material
        self.key_bytes = [0u8; 32];
        self.key = String::new(); // Clear hex representation
                                  // scalar is on the stack/register — can't fully zeroize Scalar in safe Rust
                                  // but we clear the bytes representation above.
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_private_key_deterministic() {
        let vk1 = ViewKey::from_private_key("my_secret_key").unwrap();
        let vk2 = ViewKey::from_private_key("my_secret_key").unwrap();
        assert_eq!(vk1.key, vk2.key);
    }

    #[test]
    fn different_keys_different_views() {
        let vk1 = ViewKey::from_private_key("key_a").unwrap();
        let vk2 = ViewKey::from_private_key("key_b").unwrap();
        assert_ne!(vk1.key, vk2.key);
    }

    #[test]
    fn hex_is_64_chars() {
        let vk = ViewKey::from_private_key("test").unwrap();
        assert_eq!(vk.to_hex().len(), 64);
    }

    #[test]
    fn from_bytes_deterministic() {
        let pk = [0xABu8; 32];
        let vk1 = ViewKey::from_private_key_bytes(&pk).unwrap();
        let vk2 = ViewKey::from_private_key_bytes(&pk).unwrap();
        assert_eq!(vk1.key, vk2.key);
    }

    #[test]
    fn public_point_matches_scalar() {
        let vk = ViewKey::from_private_key("test_key").unwrap();
        let expected = vk.scalar * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(vk.public.compress(), expected.compress());
    }

    #[test]
    fn from_scalar_roundtrip() {
        let vk1 = ViewKey::from_private_key("roundtrip_test").unwrap();
        let vk2 = ViewKey::from_scalar(vk1.scalar);
        assert_eq!(vk1.public.compress(), vk2.public.compress());
    }
}
