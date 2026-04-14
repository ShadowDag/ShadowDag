// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Engine-level stealth address generation with full ECDH on Ristretto.
// Delegates to domain::address::stealth_address for the core primitives.
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::domain::address::stealth_address::{
    StealthAddress as DomainStealth, StealthAddressResult, StealthKeys,
};
use crate::errors::CryptoError;

pub struct StealthAddress;

impl StealthAddress {
    /// Generate a simple one-time stealth address (hash-based).
    pub fn generate(address: &str) -> String {
        DomainStealth::generate(address)
    }

    /// Generate with full ECDH derivation on Ristretto.
    pub fn generate_full(
        view_pub: &RistrettoPoint,
        spend_pub: &RistrettoPoint,
    ) -> Result<StealthAddressResult, CryptoError> {
        DomainStealth::generate_full(view_pub, spend_pub)
    }

    /// Convenience: generate from raw 32-byte compressed keys.
    pub fn generate_full_from_bytes(
        view_pub_bytes: &[u8; 32],
        spend_pub_bytes: &[u8; 32],
    ) -> Result<StealthAddressResult, CryptoError> {
        DomainStealth::generate_full_from_bytes(view_pub_bytes, spend_pub_bytes)
    }

    /// Generate a new stealth key set (real curve keys).
    pub fn generate_keys() -> StealthKeys {
        DomainStealth::generate_keys()
    }

    /// Scan to check ownership using real ECDH.
    pub fn scan(
        ephemeral_pubkey: &RistrettoPoint,
        view_private: &Scalar,
        spend_public: &RistrettoPoint,
        candidate: &str,
    ) -> Result<bool, CryptoError> {
        DomainStealth::scan(ephemeral_pubkey, view_private, spend_public, candidate)
    }

    /// Generate a batch of stealth addresses for multi-output transactions.
    pub fn generate_batch(
        view_pub: &RistrettoPoint,
        spend_pub: &RistrettoPoint,
        count: usize,
    ) -> Result<Vec<StealthAddressResult>, CryptoError> {
        (0..count)
            .map(|_| DomainStealth::generate_full(view_pub, spend_pub))
            .collect()
    }
}
