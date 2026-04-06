// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Invisible Wallets — Wallets that don't appear on the blockchain.
// Each transaction uses a fresh one-time stealth address, making it
// impossible to link transactions or track balances from chain data.
//
// Features:
//   - Auto-rotating stealth addresses per transaction
//   - View key for balance scanning without spend capability
//   - Ghost mode: no address reuse ever
//   - Real ECDH on Ristretto curve for stealth scanning
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::domain::address::stealth_address::StealthAddress;
use crate::domain::address::key_derivation::KeyDerivation;
use crate::errors::CryptoError;

/// An invisible wallet that auto-rotates addresses using real curve crypto.
pub struct InvisibleWallet {
    /// Master private key (never exposed)
    master_key:    [u8; 32],
    /// View private scalar (for ECDH scanning)
    view_scalar:   Scalar,
    /// View public point V = view_scalar * G (safe to publish)
    view_public:   RistrettoPoint,
    /// Spend private scalar (for signing)
    spend_scalar:  Scalar,
    /// Spend public point S = spend_scalar * G (safe to publish)
    spend_public:  RistrettoPoint,
    /// Current derivation index
    address_index: u32,
    /// Network prefix
    network:       String,
}

impl InvisibleWallet {
    /// Create a new invisible wallet with fresh random keys.
    pub fn new(network: &str) -> Result<Self, CryptoError> {
        let mut master_key = [0u8; 32];
        OsRng.fill_bytes(&mut master_key);
        Self::from_master_key(master_key, network)
    }

    /// Create from an existing master key (for wallet restore).
    pub fn from_master_key(master_key: [u8; 32], network: &str) -> Result<Self, CryptoError> {
        let view_bytes  = KeyDerivation::derive_view_key(&master_key);
        let spend_bytes = KeyDerivation::derive_spend_key(&master_key);

        let view_scalar  = Scalar::from_canonical_bytes(view_bytes)
            .ok_or(CryptoError::NonCanonicalScalar)?;
        let spend_scalar = Scalar::from_canonical_bytes(spend_bytes)
            .ok_or(CryptoError::NonCanonicalScalar)?;

        Ok(Self {
            master_key,
            view_scalar,
            view_public:   view_scalar * RISTRETTO_BASEPOINT_POINT,
            spend_scalar,
            spend_public:  spend_scalar * RISTRETTO_BASEPOINT_POINT,
            address_index: 0,
            network:       network.to_string(),
        })
    }

    /// Generate a fresh one-time stealth address (auto-rotates).
    pub fn next_address(&mut self) -> String {
        let child = KeyDerivation::derive_child(
            &self.spend_scalar.to_bytes(),
            self.address_index,
        );
        self.address_index += 1;

        let prefix = match self.network.as_str() {
            "mainnet" => "SD1",
            "testnet" => "ST1",
            _         => "SR1",
        };

        KeyDerivation::derive_address(&child, prefix)
    }

    /// Rotate: generate a fresh stealth address from any base address.
    pub fn rotate(address: &str) -> String {
        StealthAddress::generate(address)
    }

    /// Get the view key hex (safe to share — allows watching, not spending).
    pub fn view_key_hex(&self) -> String {
        hex::encode(self.view_scalar.to_bytes())
    }

    /// Get the view public point (safe to publish for senders).
    pub fn view_public(&self) -> RistrettoPoint {
        self.view_public
    }

    /// Get the spend public point (safe to publish for senders).
    pub fn spend_public(&self) -> RistrettoPoint {
        self.spend_public
    }

    /// Get the current address index.
    pub fn current_index(&self) -> u32 {
        self.address_index
    }

    /// Scan using real ECDH: check if a stealth output belongs to us.
    pub fn is_mine(&self, ephemeral_pubkey: &RistrettoPoint, candidate_address: &str) -> Result<bool, CryptoError> {
        StealthAddress::scan(
            ephemeral_pubkey,
            &self.view_scalar,
            &self.spend_public,
            candidate_address,
        )
    }

    /// Convenience scan from raw ephemeral pubkey bytes.
    pub fn is_mine_from_bytes(&self, ephemeral_pub_bytes: &[u8; 32], candidate_address: &str) -> Result<bool, CryptoError> {
        let eph = CompressedRistretto::from_slice(ephemeral_pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid ephemeral pubkey: {}", e)))?
            .decompress()
            .ok_or_else(|| CryptoError::InvalidKey("Ephemeral pubkey not on curve".to_string()))?;
        self.is_mine(&eph, candidate_address)
    }

    /// Derive the one-time private key to spend a stealth output.
    pub fn derive_spend_key_for(&self, ephemeral_pubkey: &RistrettoPoint) -> Result<Scalar, CryptoError> {
        StealthAddress::derive_one_time_private_key(
            ephemeral_pubkey,
            &self.view_scalar,
            &self.spend_scalar,
        )
    }
}

impl Drop for InvisibleWallet {
    fn drop(&mut self) {
        self.master_key = [0u8; 32];
        self.view_scalar = Scalar::ZERO;
        self.spend_scalar = Scalar::ZERO;
        self.view_public = RistrettoPoint::default();
        self.spend_public = RistrettoPoint::default();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wallet_starts_at_index_zero() {
        let w = InvisibleWallet::new("mainnet").unwrap();
        assert_eq!(w.current_index(), 0);
    }

    #[test]
    fn next_address_increments_index() {
        let mut w = InvisibleWallet::new("mainnet").unwrap();
        let _a1 = w.next_address();
        assert_eq!(w.current_index(), 1);
        let _a2 = w.next_address();
        assert_eq!(w.current_index(), 2);
    }

    #[test]
    fn addresses_never_repeat() {
        let mut w = InvisibleWallet::new("mainnet").unwrap();
        let a1 = w.next_address();
        let a2 = w.next_address();
        let a3 = w.next_address();
        assert_ne!(a1, a2);
        assert_ne!(a2, a3);
        assert_ne!(a1, a3);
    }

    #[test]
    fn mainnet_prefix() {
        let mut w = InvisibleWallet::new("mainnet").unwrap();
        let addr = w.next_address();
        assert!(addr.starts_with("SD1"));
    }

    #[test]
    fn testnet_prefix() {
        let mut w = InvisibleWallet::new("testnet").unwrap();
        let addr = w.next_address();
        assert!(addr.starts_with("ST1"));
    }

    #[test]
    fn rotate_produces_unique_addresses() {
        let a1 = InvisibleWallet::rotate("SD1test");
        let a2 = InvisibleWallet::rotate("SD1test");
        assert_ne!(a1, a2);
    }

    #[test]
    fn view_key_is_64_hex() {
        let w = InvisibleWallet::new("mainnet").unwrap();
        let vk = w.view_key_hex();
        assert_eq!(vk.len(), 64);
    }

    #[test]
    fn restore_from_master_key() {
        let mut master = [0u8; 32];
        OsRng.fill_bytes(&mut master);

        let w1 = InvisibleWallet::from_master_key(master, "mainnet").unwrap();
        let w2 = InvisibleWallet::from_master_key(master, "mainnet").unwrap();

        assert_eq!(w1.view_key_hex(), w2.view_key_hex());
    }

    #[test]
    fn ecdh_is_mine_detects_own_output() {
        let w = InvisibleWallet::new("mainnet").unwrap();

        // Sender creates stealth address for this wallet
        let result = StealthAddress::generate_full(
            &w.view_public,
            &w.spend_public,
        ).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap().try_into().unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap().decompress().unwrap();

        assert!(w.is_mine(&eph, &result.one_time_address).unwrap());
    }

    #[test]
    fn ecdh_is_mine_rejects_other_wallet() {
        let w1 = InvisibleWallet::new("mainnet").unwrap();
        let w2 = InvisibleWallet::new("mainnet").unwrap();

        let result = StealthAddress::generate_full(
            &w1.view_public,
            &w1.spend_public,
        ).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap().try_into().unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap().decompress().unwrap();

        assert!(!w2.is_mine(&eph, &result.one_time_address).unwrap());
    }
}
