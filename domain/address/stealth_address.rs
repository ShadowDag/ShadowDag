// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Stealth Addresses — One-time destination addresses using real ECDH on
// Curve25519 (Ristretto group), matching the CryptoNote protocol:
//
// Protocol:
//   1. Recipient publishes (V = v*G, S = s*G)  where v = view key, s = spend key
//   2. Sender generates ephemeral keypair: r = random Scalar, R = r*G
//   3. Shared secret: ss = r * V = r*v*G  (Diffie–Hellman on Ristretto)
//   4. Hash scalar:   hs = Scalar::from(SHA256("ShadowDAG_StealthDH_v1" || ss))
//   5. One-time pubkey: P = hs*G + S
//   6. One-time address: "SD1s" + hex(P.compress()[0..20])
//   7. Sender broadcasts R alongside the transaction
//
// Recipient scanning:
//   1. Compute ss = v * R  (same point as sender computed)
//   2. hs = Scalar::from(SHA256("ShadowDAG_StealthDH_v1" || ss))
//   3. P' = hs*G + S
//   4. If P' matches the address → funds are ours
//   5. One-time private key: x = hs + s  (for spending)
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

const DOMAIN_DH: &[u8] = b"ShadowDAG_StealthDH_v1";
const DOMAIN_SIMPLE: &[u8] = b"ShadowDAG_Stealth_v1";

/// Generator point G (Ristretto basepoint)
fn g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// Derive a deterministic Scalar from a shared-secret RistrettoPoint.
///
/// Returns an error if the SHA-256 output is not a canonical scalar encoding.
fn derive_hash_scalar(shared_secret: &RistrettoPoint) -> Result<Scalar, CryptoError> {
    derive_hash_scalar_with_context(shared_secret, "", 0)
}

/// Derive a hash scalar with domain separation context.
///
/// Including `tx_hash` and `output_index` in the hash ensures each output
/// derives a unique one-time address, preventing cross-transaction key reuse
/// from leaking linkability.  When both are empty/zero the result is
/// identical to `derive_hash_scalar` for backward compatibility.
pub fn derive_hash_scalar_with_context(
    shared_secret: &RistrettoPoint,
    tx_hash: &str,
    output_index: usize,
) -> Result<Scalar, CryptoError> {
    let mut h = Sha256::new();
    h.update(DOMAIN_DH);
    h.update(shared_secret.compress().as_bytes());
    if !tx_hash.is_empty() || output_index != 0 {
        h.update(tx_hash.as_bytes());
        h.update((output_index as u64).to_le_bytes());
    }
    let hash: [u8; 32] = h.finalize().into();
    // SHA-256 output is arbitrary 32 bytes which may exceed the Ristretto
    // group order L.  Reduce mod L so the result is always a valid Scalar.
    // This is standard practice in hash-to-scalar constructions (cf.
    // CryptoNote / Monero) and does not weaken the derived key space.
    Ok(Scalar::from_bytes_mod_order(hash))
}

// ─────────────────────────────────────────────────────────────────────────

/// A stealth address pair: the one-time address + the ephemeral public key
#[derive(Debug, Clone)]
pub struct StealthAddressResult {
    /// The one-time stealth address (SD1s + 40 hex chars)
    pub one_time_address: String,
    /// Ephemeral public key R that the sender broadcasts (64 hex chars, compressed)
    pub ephemeral_pubkey: String,
    /// The one-time public key P on the curve (compressed, 64 hex chars)
    pub one_time_pubkey: String,
}

/// Stealth address keys published by the recipient.
/// Private keys are Scalars; public keys are RistrettoPoints.
#[derive(Debug, Clone)]
pub struct StealthKeys {
    pub view_private: Scalar,
    pub view_public: RistrettoPoint,
    pub spend_private: Scalar,
    pub spend_public: RistrettoPoint,
}

impl StealthKeys {
    /// Hex-encoded view public key (for publishing)
    pub fn view_pub_hex(&self) -> String {
        hex::encode(self.view_public.compress().as_bytes())
    }
    /// Hex-encoded spend public key (for publishing)
    pub fn spend_pub_hex(&self) -> String {
        hex::encode(self.spend_public.compress().as_bytes())
    }
}

pub struct StealthAddress;

/// Compute the stealth address prefix for a given network.
fn stealth_prefix(network: &str) -> &'static str {
    match network {
        "testnet" => "ST1s",
        "regtest" => "SR1s",
        _ => "SD1s",
    }
}

impl StealthAddress {
    /// Quick one-time address from a base address (hash-based, for simple use).
    /// Defaults to mainnet prefix. Use `generate_for_network` for other networks.
    pub fn generate(base_address: &str) -> String {
        Self::generate_for_network(base_address, "mainnet")
    }

    /// Quick one-time address from a base address with explicit network selection.
    pub fn generate_for_network(base_address: &str, network: &str) -> String {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mut h = Sha256::new();
        h.update(DOMAIN_SIMPLE);
        h.update(base_address.as_bytes());
        h.update(entropy);
        let hash = h.finalize();

        format!("{}{}", stealth_prefix(network), hex::encode(&hash[..20]))
    }

    /// Generate a stealth address using real ECDH on Ristretto.
    /// Defaults to mainnet prefix. Use `generate_full_for_network` for other networks.
    ///
    /// The sender calls this with the recipient's published view and spend
    /// public keys. The returned `ephemeral_pubkey` must be included in the
    /// transaction so the recipient can scan for it.
    pub fn generate_full(
        recipient_view_pub: &RistrettoPoint,
        recipient_spend_pub: &RistrettoPoint,
    ) -> Result<StealthAddressResult, CryptoError> {
        Self::generate_full_for_network(recipient_view_pub, recipient_spend_pub, "mainnet")
    }

    /// Generate a stealth address using real ECDH on Ristretto with explicit network.
    pub fn generate_full_for_network(
        recipient_view_pub: &RistrettoPoint,
        recipient_spend_pub: &RistrettoPoint,
        network: &str,
    ) -> Result<StealthAddressResult, CryptoError> {
        // Step 1: ephemeral keypair  r, R = r*G
        let r = Scalar::random(&mut OsRng);
        let big_r = r * g();

        // Step 2: ECDH shared secret  ss = r * V
        let shared_secret = r * recipient_view_pub;

        // Step 3: hash scalar  hs = H(ss)
        let hs = derive_hash_scalar(&shared_secret)?;

        // Step 4: one-time public key  P = hs*G + S
        let one_time_pub = hs * g() + recipient_spend_pub;

        // Step 5: address from compressed P
        let compressed = one_time_pub.compress();
        let prefix = stealth_prefix(network);
        let addr = format!("{}{}", prefix, hex::encode(&compressed.as_bytes()[..20]));

        Ok(StealthAddressResult {
            one_time_address: addr,
            ephemeral_pubkey: hex::encode(big_r.compress().as_bytes()),
            one_time_pubkey: hex::encode(compressed.as_bytes()),
        })
    }

    /// Generate a stealth address with domain separation context.
    /// Defaults to mainnet prefix. Use the `network` parameter variant for other networks.
    ///
    /// Like `generate_full`, but includes `tx_hash` and `output_index` in the
    /// hash derivation so that each output produces a unique one-time address
    /// even if the same ephemeral key were reused.  The scanner must use the
    /// same context values when checking ownership.
    pub fn generate_full_with_context(
        recipient_view_pub: &RistrettoPoint,
        recipient_spend_pub: &RistrettoPoint,
        tx_hash: &str,
        output_index: usize,
    ) -> Result<StealthAddressResult, CryptoError> {
        Self::generate_full_with_context_for_network(
            recipient_view_pub,
            recipient_spend_pub,
            tx_hash,
            output_index,
            "mainnet",
        )
    }

    /// Generate a stealth address with domain separation context and explicit network.
    pub fn generate_full_with_context_for_network(
        recipient_view_pub: &RistrettoPoint,
        recipient_spend_pub: &RistrettoPoint,
        tx_hash: &str,
        output_index: usize,
        network: &str,
    ) -> Result<StealthAddressResult, CryptoError> {
        let r = Scalar::random(&mut OsRng);
        let big_r = r * g();
        let shared_secret = r * recipient_view_pub;
        let hs = derive_hash_scalar_with_context(&shared_secret, tx_hash, output_index)?;
        let one_time_pub = hs * g() + recipient_spend_pub;
        let compressed = one_time_pub.compress();
        let prefix = stealth_prefix(network);
        let addr = format!("{}{}", prefix, hex::encode(&compressed.as_bytes()[..20]));

        Ok(StealthAddressResult {
            one_time_address: addr,
            ephemeral_pubkey: hex::encode(big_r.compress().as_bytes()),
            one_time_pubkey: hex::encode(compressed.as_bytes()),
        })
    }

    /// Generate from raw 32-byte compressed keys (convenience wrapper).
    pub fn generate_full_from_bytes(
        view_pub_bytes: &[u8; 32],
        spend_pub_bytes: &[u8; 32],
    ) -> Result<StealthAddressResult, CryptoError> {
        let view_pub = CompressedRistretto::from_slice(view_pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid view pubkey: {}", e)))?
            .decompress()
            .ok_or(CryptoError::InvalidKey(
                "View pubkey not on curve".to_string(),
            ))?;
        let spend_pub = CompressedRistretto::from_slice(spend_pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid spend pubkey: {}", e)))?
            .decompress()
            .ok_or(CryptoError::InvalidKey(
                "Spend pubkey not on curve".to_string(),
            ))?;
        Self::generate_full(&view_pub, &spend_pub)
    }

    /// Check if a stealth address belongs to us (recipient scanning).
    /// Defaults to mainnet prefix. Use `scan_for_network` for other networks.
    ///
    /// The recipient uses their view private scalar and the ephemeral R
    /// from the transaction to recompute the same shared secret.
    pub fn scan(
        ephemeral_pubkey: &RistrettoPoint,
        view_private: &Scalar,
        spend_public: &RistrettoPoint,
        candidate_address: &str,
    ) -> Result<bool, CryptoError> {
        Self::scan_for_network(
            ephemeral_pubkey,
            view_private,
            spend_public,
            candidate_address,
            "mainnet",
        )
    }

    /// Check if a stealth address belongs to us with explicit network.
    pub fn scan_for_network(
        ephemeral_pubkey: &RistrettoPoint,
        view_private: &Scalar,
        spend_public: &RistrettoPoint,
        candidate_address: &str,
        network: &str,
    ) -> Result<bool, CryptoError> {
        // ss = v * R  (same as sender's r * V because r*v*G == v*r*G)
        let shared_secret = view_private * ephemeral_pubkey;
        let hs = derive_hash_scalar(&shared_secret)?;
        let expected_pub = hs * g() + spend_public;
        let prefix = stealth_prefix(network);
        let expected_addr = format!(
            "{}{}",
            prefix,
            hex::encode(&expected_pub.compress().as_bytes()[..20])
        );
        Ok(expected_addr == candidate_address)
    }

    /// Convenience scan from raw bytes.
    pub fn scan_from_bytes(
        ephemeral_pub_bytes: &[u8; 32],
        view_priv_bytes: &[u8; 32],
        spend_pub_bytes: &[u8; 32],
        candidate_address: &str,
    ) -> Result<bool, CryptoError> {
        let eph = CompressedRistretto::from_slice(ephemeral_pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid ephemeral pubkey: {}", e)))?
            .decompress()
            .ok_or(CryptoError::InvalidKey(
                "Ephemeral pubkey not on curve".to_string(),
            ))?;
        let spend_pub = CompressedRistretto::from_slice(spend_pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid spend pubkey: {}", e)))?
            .decompress()
            .ok_or(CryptoError::InvalidKey(
                "Spend pubkey not on curve".to_string(),
            ))?;
        let view_priv =
            Option::from(Scalar::from_canonical_bytes(*view_priv_bytes)).ok_or_else(|| {
                CryptoError::InvalidKey("View private key is not canonical".to_string())
            })?;
        Self::scan(&eph, &view_priv, &spend_pub, candidate_address)
    }

    /// Derive the one-time private key for spending a stealth output.
    ///
    /// x = hs + s, where hs is the hash scalar and s is the spend private key.
    pub fn derive_one_time_private_key(
        ephemeral_pubkey: &RistrettoPoint,
        view_private: &Scalar,
        spend_private: &Scalar,
    ) -> Result<Scalar, CryptoError> {
        let shared_secret = view_private * ephemeral_pubkey;
        let hs = derive_hash_scalar(&shared_secret)?;
        Ok(hs + spend_private)
    }

    /// Generate a new stealth key set for a recipient (real curve keys).
    pub fn generate_keys() -> StealthKeys {
        let view_priv = Scalar::random(&mut OsRng);
        let spend_priv = Scalar::random(&mut OsRng);
        StealthKeys {
            view_private: view_priv,
            view_public: view_priv * g(),
            spend_private: spend_priv,
            spend_public: spend_priv * g(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_stealth_address() {
        let addr = StealthAddress::generate("SD1abc123");
        assert!(addr.starts_with("SD1s"));
        assert_eq!(addr.len(), 44); // "SD1s" + 40 hex chars
    }

    #[test]
    fn generate_is_unique_each_call() {
        let a1 = StealthAddress::generate("SD1test");
        let a2 = StealthAddress::generate("SD1test");
        assert_ne!(a1, a2, "Each stealth address must be unique");
    }

    #[test]
    fn full_stealth_flow() {
        let keys = StealthAddress::generate_keys();
        let result = StealthAddress::generate_full(&keys.view_public, &keys.spend_public).unwrap();

        assert!(result.one_time_address.starts_with("SD1s"));
        assert_eq!(result.ephemeral_pubkey.len(), 64);
        assert_eq!(result.one_time_pubkey.len(), 64);
    }

    #[test]
    fn generate_keys_are_unique() {
        let k1 = StealthAddress::generate_keys();
        let k2 = StealthAddress::generate_keys();
        assert_ne!(k1.view_private, k2.view_private);
        assert_ne!(k1.spend_private, k2.spend_private);
    }

    // ── New ECDH-specific tests ──────────────────────────────────────────

    #[test]
    fn ecdh_stealth_full_flow() {
        // Recipient generates keys
        let keys = StealthAddress::generate_keys();

        // Sender creates stealth address for recipient
        let result = StealthAddress::generate_full(&keys.view_public, &keys.spend_public).unwrap();

        // Recipient scans — must detect their own address
        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap()
            .decompress()
            .unwrap();

        assert!(
            StealthAddress::scan(
                &eph,
                &keys.view_private,
                &keys.spend_public,
                &result.one_time_address,
            )
            .unwrap(),
            "Recipient must detect their own stealth output"
        );
    }

    #[test]
    fn scan_rejects_wrong_recipient() {
        let alice = StealthAddress::generate_keys();
        let bob = StealthAddress::generate_keys();

        // Sender sends to Alice
        let result =
            StealthAddress::generate_full(&alice.view_public, &alice.spend_public).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap()
            .decompress()
            .unwrap();

        // Bob tries to scan — must fail
        assert!(
            !StealthAddress::scan(
                &eph,
                &bob.view_private,
                &bob.spend_public,
                &result.one_time_address,
            )
            .unwrap(),
            "Wrong recipient must not match"
        );
    }

    #[test]
    fn different_recipients_different_addresses() {
        let alice = StealthAddress::generate_keys();
        let bob = StealthAddress::generate_keys();

        let r1 = StealthAddress::generate_full(&alice.view_public, &alice.spend_public).unwrap();
        let r2 = StealthAddress::generate_full(&bob.view_public, &bob.spend_public).unwrap();

        assert_ne!(r1.one_time_address, r2.one_time_address);
    }

    #[test]
    fn spend_key_derivation_from_stealth() {
        let keys = StealthAddress::generate_keys();
        let result = StealthAddress::generate_full(&keys.view_public, &keys.spend_public).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap()
            .decompress()
            .unwrap();

        // Derive the one-time private key
        let one_time_priv = StealthAddress::derive_one_time_private_key(
            &eph,
            &keys.view_private,
            &keys.spend_private,
        )
        .unwrap();

        // The corresponding public key must equal the one-time pubkey from generation
        let derived_pub = one_time_priv * g();
        let expected_bytes: [u8; 32] = hex::decode(&result.one_time_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let expected_pub = CompressedRistretto::from_slice(&expected_bytes)
            .unwrap()
            .decompress()
            .unwrap();

        assert_eq!(
            derived_pub.compress(),
            expected_pub.compress(),
            "One-time private key must correspond to the one-time public key"
        );
    }

    #[test]
    fn same_sender_different_ephemeral_different_address() {
        let keys = StealthAddress::generate_keys();
        let r1 = StealthAddress::generate_full(&keys.view_public, &keys.spend_public).unwrap();
        let r2 = StealthAddress::generate_full(&keys.view_public, &keys.spend_public).unwrap();
        assert_ne!(r1.one_time_address, r2.one_time_address);
        assert_ne!(r1.ephemeral_pubkey, r2.ephemeral_pubkey);
    }
}
