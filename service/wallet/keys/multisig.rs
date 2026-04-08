// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Multi-Signature Wallet — M-of-N threshold signature support.
//
// Allows N parties to jointly control funds, requiring M signatures
// to authorize a transaction (e.g., 2-of-3, 3-of-5).
//
// Features:
//   - Flexible M-of-N thresholds (1 ≤ M ≤ N ≤ 16)
//   - Deterministic multisig address generation
//   - Partial signature aggregation
//   - Signer ordering (deterministic)
//   - Timeout for incomplete signatures
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use std::collections::{HashMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::errors::WalletError;

/// Maximum signers in a multisig
pub const MAX_SIGNERS: usize = 16;

/// Signature timeout (1 hour)
pub const SIG_TIMEOUT_SECS: u64 = 3_600;

/// Multisig configuration
#[derive(Debug, Clone)]
pub struct MultisigConfig {
    /// Required signatures (M)
    pub threshold:    usize,
    /// Total signers (N)
    pub total:        usize,
    /// Public keys of all signers (sorted deterministically)
    pub signers:      Vec<String>,
    /// Multisig address (derived from config)
    pub address:      String,
}

impl MultisigConfig {
    /// Create a new M-of-N multisig configuration
    pub fn new(threshold: usize, public_keys: Vec<String>, network: &str) -> Result<Self, WalletError> {
        let total = public_keys.len();

        if threshold == 0 {
            return Err(WalletError::Other("Threshold must be >= 1".to_string()));
        }
        if threshold > total {
            return Err(WalletError::Other(format!("Threshold {} > total signers {}", threshold, total)));
        }
        if total > MAX_SIGNERS {
            return Err(WalletError::Other(format!("Max {} signers allowed", MAX_SIGNERS)));
        }

        // Sort public keys deterministically
        let mut sorted_keys = public_keys;
        sorted_keys.sort();
        sorted_keys.dedup();

        if sorted_keys.len() != total {
            return Err(WalletError::Other("Duplicate public keys detected".to_string()));
        }

        let address = Self::compute_address(threshold, &sorted_keys, network);

        Ok(Self {
            threshold,
            total: sorted_keys.len(),
            signers: sorted_keys,
            address,
        })
    }

    /// Generate deterministic multisig address
    fn compute_address(threshold: usize, sorted_keys: &[String], network: &str) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_MultiSig_v2"); // v2 includes network
        h.update(network.as_bytes()); // Network separation
        h.update((threshold as u32).to_le_bytes());
        h.update((sorted_keys.len() as u32).to_le_bytes());
        for key in sorted_keys {
            h.update(key.as_bytes());
        }
        let hash = h.finalize();
        let prefix = match network {
            "testnet" => "ST1m",
            "regtest" => "SR1m",
            _ => "SD1m", // mainnet default
        };
        format!("{}{}", prefix, hex::encode(&hash[..20]))
    }

    /// Check if a public key is a signer
    pub fn is_signer(&self, public_key: &str) -> bool {
        self.signers.iter().any(|s| s == public_key)
    }

    /// Get the signer index for a public key
    pub fn signer_index(&self, public_key: &str) -> Option<usize> {
        self.signers.iter().position(|s| s == public_key)
    }

    /// Display as "M-of-N"
    pub fn display(&self) -> String {
        format!("{}-of-{}", self.threshold, self.total)
    }
}

/// A partial signature from one signer
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub signer_pubkey: String,
    pub signature:     String,
    pub signed_at:     u64,
}

/// Pending multisig transaction (collecting signatures)
#[derive(Debug, Clone)]
pub struct PendingMultisig {
    /// Transaction hash to sign
    pub tx_hash:      String,
    /// Multisig config
    pub config:       MultisigConfig,
    /// Collected partial signatures
    pub signatures:   Vec<PartialSignature>,
    /// When this pending tx was created
    pub created_at:   u64,
    /// Transaction data (serialized)
    pub tx_data:      Vec<u8>,
}

impl PendingMultisig {
    pub fn new(tx_hash: String, config: MultisigConfig, tx_data: Vec<u8>) -> Self {
        Self {
            tx_hash,
            config,
            signatures: Vec::new(),
            created_at: now_secs(),
            tx_data,
        }
    }

    /// Add a partial signature from a signer.
    ///
    /// TODO: This is a placeholder. Real Ed25519 signature verification is needed
    /// before production. Currently only validates that the signer is authorized,
    /// the signature is not a duplicate, and the signature has the expected length
    /// (64 bytes = 128 hex chars). Cryptographic verification of the signature
    /// against the signer's public key and the transaction hash is NOT performed.
    pub fn add_signature(&mut self, pubkey: &str, signature: &str) -> Result<(), WalletError> {
        // Verify signer is authorized
        if !self.config.is_signer(pubkey) {
            return Err(WalletError::Other(format!("Public key {} is not a signer", pubkey)));
        }

        // Check for duplicate signature
        if self.signatures.iter().any(|s| s.signer_pubkey == pubkey) {
            return Err(WalletError::Other("Already signed by this key".to_string()));
        }

        // Check if already have enough
        if self.is_complete() {
            return Err(WalletError::Other("Already have enough signatures".to_string()));
        }

        // Basic format validation: Ed25519 signatures are 64 bytes = 128 hex chars
        if signature.len() != 128 || !signature.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletError::Other(
                "Invalid signature format: expected 128 hex characters (64 bytes Ed25519)".to_string(),
            ));
        }

        self.signatures.push(PartialSignature {
            signer_pubkey: pubkey.to_string(),
            signature:     signature.to_string(),
            signed_at:     now_secs(),
        });

        Ok(())
    }

    /// Check if we have enough signatures
    pub fn is_complete(&self) -> bool {
        self.signatures.len() >= self.config.threshold
    }

    /// How many more signatures needed
    pub fn remaining(&self) -> usize {
        self.config.threshold.saturating_sub(self.signatures.len())
    }

    /// Check if the pending tx has expired
    pub fn is_expired(&self) -> bool {
        now_secs().saturating_sub(self.created_at) > SIG_TIMEOUT_SECS
    }

    /// Get aggregated signature (when complete).
    ///
    /// TODO: This is a placeholder that hashes partial signatures together.
    /// Real Ed25519 multi-signature aggregation (e.g., MuSig2 or similar)
    /// must be implemented before production use. The current approach does
    /// NOT provide cryptographic security.
    #[deprecated(note = "Placeholder: uses SHA-256 hash, not real Ed25519 signature aggregation. Needs real crypto before production.")]
    pub fn aggregate_signatures(&self) -> Option<String> {
        if !self.is_complete() { return None; }

        // Combine all signatures deterministically
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_AggSig_v1");
        h.update(self.tx_hash.as_bytes());
        for sig in &self.signatures {
            h.update(sig.signer_pubkey.as_bytes());
            h.update(sig.signature.as_bytes());
        }
        Some(hex::encode(h.finalize()))
    }

    /// Who has signed so far
    pub fn signed_by(&self) -> Vec<String> {
        self.signatures.iter().map(|s| s.signer_pubkey.clone()).collect()
    }

    /// Who still needs to sign
    pub fn pending_signers(&self) -> Vec<String> {
        let signed: BTreeSet<_> = self.signatures.iter().map(|s| &s.signer_pubkey).collect();
        self.config.signers.iter()
            .filter(|s| !signed.contains(s))
            .cloned()
            .collect()
    }
}

/// Multisig manager — tracks all pending multisig transactions
pub struct MultisigManager {
    configs: HashMap<String, MultisigConfig>,  // address → config
    pending: HashMap<String, PendingMultisig>, // tx_hash → pending
}

impl Default for MultisigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigManager {
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Register a multisig wallet
    pub fn register(&mut self, config: MultisigConfig) -> String {
        let addr = config.address.clone();
        self.configs.insert(addr.clone(), config);
        addr
    }

    /// Get multisig config by address
    pub fn get_config(&self, address: &str) -> Option<&MultisigConfig> {
        self.configs.get(address)
    }

    /// Start collecting signatures for a transaction
    pub fn initiate(&mut self, tx_hash: String, address: &str, tx_data: Vec<u8>) -> Result<(), WalletError> {
        let config = self.configs.get(address)
            .ok_or_else(|| WalletError::AddressNotFound(format!("Multisig address {} not found", address)))?
            .clone();

        let pending = PendingMultisig::new(tx_hash.clone(), config, tx_data);
        self.pending.insert(tx_hash, pending);
        Ok(())
    }

    /// Add a signature to a pending transaction
    pub fn sign(&mut self, tx_hash: &str, pubkey: &str, signature: &str) -> Result<bool, WalletError> {
        let pending = self.pending.get_mut(tx_hash)
            .ok_or_else(|| WalletError::Other(format!("No pending multisig for {}", tx_hash)))?;

        if pending.is_expired() {
            return Err(WalletError::Other("Pending multisig has expired".to_string()));
        }

        pending.add_signature(pubkey, signature)?;
        Ok(pending.is_complete())
    }

    /// Get completed transaction (ready to broadcast)
    pub fn get_completed(&self, tx_hash: &str) -> Option<&PendingMultisig> {
        self.pending.get(tx_hash).filter(|p| p.is_complete())
    }

    /// Remove completed or expired entries
    pub fn cleanup(&mut self) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, p| !p.is_expired() && !p.is_complete());
        before - self.pending.len()
    }

    pub fn pending_count(&self) -> usize { self.pending.len() }
    pub fn config_count(&self) -> usize { self.configs.len() }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("pubkey_{:02}", i)).collect()
    }

    /// Generate a valid 128-hex-char fake signature for testing
    fn fake_sig(id: u8) -> String {
        format!("{:0>128}", format!("{:02x}", id))
    }

    #[test]
    fn create_2_of_3() {
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total, 3);
        assert!(config.address.starts_with("SD1m"));
        assert_eq!(config.display(), "2-of-3");
    }

    #[test]
    fn threshold_exceeds_total_fails() {
        assert!(MultisigConfig::new(4, make_keys(3), "mainnet").is_err());
    }

    #[test]
    fn duplicate_keys_fail() {
        let keys = vec!["same".into(), "same".into(), "other".into()];
        assert!(MultisigConfig::new(2, keys, "mainnet").is_err());
    }

    #[test]
    fn add_signatures_until_complete() {
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        let mut pending = PendingMultisig::new("tx1".into(), config, vec![]);

        assert!(!pending.is_complete());
        assert_eq!(pending.remaining(), 2);

        pending.add_signature("pubkey_00", &fake_sig(0)).unwrap();
        assert_eq!(pending.remaining(), 1);

        pending.add_signature("pubkey_01", &fake_sig(1)).unwrap();
        assert!(pending.is_complete());
        #[allow(deprecated)]
        let agg = pending.aggregate_signatures();
        assert!(agg.is_some());
    }

    #[test]
    fn duplicate_signature_rejected() {
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        let mut pending = PendingMultisig::new("tx1".into(), config, vec![]);
        pending.add_signature("pubkey_00", &fake_sig(0)).unwrap();
        assert!(pending.add_signature("pubkey_00", &fake_sig(99)).is_err());
    }

    #[test]
    fn unauthorized_signer_rejected() {
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        let mut pending = PendingMultisig::new("tx1".into(), config, vec![]);
        assert!(pending.add_signature("unknown_key", &fake_sig(0)).is_err());
    }

    #[test]
    fn pending_signers_tracked() {
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        let mut pending = PendingMultisig::new("tx1".into(), config, vec![]);
        pending.add_signature("pubkey_00", &fake_sig(0)).unwrap();

        let remaining = pending.pending_signers();
        assert_eq!(remaining.len(), 2);
        assert!(!remaining.contains(&"pubkey_00".to_string()));
    }

    #[test]
    fn manager_full_flow() {
        let mut mgr = MultisigManager::new();
        let config = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap();
        let addr = mgr.register(config);

        mgr.initiate("tx1".into(), &addr, vec![1, 2, 3]).unwrap();
        assert!(!mgr.sign("tx1", "pubkey_00", &fake_sig(0)).unwrap());
        assert!(mgr.sign("tx1", "pubkey_01", &fake_sig(1)).unwrap()); // Complete!

        let completed = mgr.get_completed("tx1").unwrap();
        #[allow(deprecated)]
        let agg = completed.aggregate_signatures();
        assert!(agg.is_some());
    }

    #[test]
    fn address_is_deterministic() {
        let a1 = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap().address;
        let a2 = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap().address;
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_threshold_different_address() {
        let a2 = MultisigConfig::new(2, make_keys(3), "mainnet").unwrap().address;
        let a3 = MultisigConfig::new(3, make_keys(3), "mainnet").unwrap().address;
        assert_ne!(a2, a3);
    }
}
