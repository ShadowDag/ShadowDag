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

use crate::errors::WalletError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum signers in a multisig
pub const MAX_SIGNERS: usize = 16;

/// Signature timeout (1 hour)
pub const SIG_TIMEOUT_SECS: u64 = 3_600;

/// Multisig configuration
#[derive(Debug, Clone)]
pub struct MultisigConfig {
    /// Required signatures (M)
    pub threshold: usize,
    /// Total signers (N)
    pub total: usize,
    /// Public keys of all signers (sorted deterministically)
    pub signers: Vec<String>,
    /// Multisig address (derived from config)
    pub address: String,
}

impl MultisigConfig {
    /// Create a new M-of-N multisig configuration
    pub fn new(
        threshold: usize,
        public_keys: Vec<String>,
        network: &str,
    ) -> Result<Self, WalletError> {
        let total = public_keys.len();

        if threshold == 0 {
            return Err(WalletError::Other("Threshold must be >= 1".to_string()));
        }
        if threshold > total {
            return Err(WalletError::Other(format!(
                "Threshold {} > total signers {}",
                threshold, total
            )));
        }
        if total > MAX_SIGNERS {
            return Err(WalletError::Other(format!(
                "Max {} signers allowed",
                MAX_SIGNERS
            )));
        }

        // Sort public keys deterministically
        let mut sorted_keys = public_keys;
        sorted_keys.sort();
        sorted_keys.dedup();

        if sorted_keys.len() != total {
            return Err(WalletError::Other(
                "Duplicate public keys detected".to_string(),
            ));
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
    pub signature: String,
    pub signed_at: u64,
}

/// Pending multisig transaction (collecting signatures)
#[derive(Debug, Clone)]
pub struct PendingMultisig {
    /// Transaction hash to sign
    pub tx_hash: String,
    /// Multisig config
    pub config: MultisigConfig,
    /// Collected partial signatures
    pub signatures: Vec<PartialSignature>,
    /// When this pending tx was created
    pub created_at: u64,
    /// Transaction data (serialized)
    pub tx_data: Vec<u8>,
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
    pub fn add_signature(&mut self, pubkey: &str, signature: &str) -> Result<(), WalletError> {
        // Verify signer is authorized
        if !self.config.is_signer(pubkey) {
            return Err(WalletError::Other(format!(
                "Public key {} is not a signer",
                pubkey
            )));
        }

        // Check for duplicate signature
        if self.signatures.iter().any(|s| s.signer_pubkey == pubkey) {
            return Err(WalletError::Other("Already signed by this key".to_string()));
        }

        // Check if already have enough
        if self.is_complete() {
            return Err(WalletError::Other(
                "Already have enough signatures".to_string(),
            ));
        }

        // Basic format validation: Ed25519 signatures are 64 bytes = 128 hex chars
        if signature.len() != 128 || !signature.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletError::Other(
                "Invalid signature format: expected 128 hex characters (64 bytes Ed25519)"
                    .to_string(),
            ));
        }
        verify_ed25519_signature(pubkey, &self.tx_hash, signature)?;

        self.signatures.push(PartialSignature {
            signer_pubkey: pubkey.to_string(),
            signature: signature.to_string(),
            signed_at: now_secs(),
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
    /// Disabled in production until a real threshold aggregation scheme
    /// (for example MuSig2/FROST) is implemented.
    #[deprecated(
        note = "Disabled: real threshold signature aggregation is not implemented yet."
    )]
    pub fn aggregate_signatures(&self) -> Option<String> {
        if !self.is_complete() {
            return None;
        }
        None
    }

    /// Who has signed so far
    pub fn signed_by(&self) -> Vec<String> {
        self.signatures
            .iter()
            .map(|s| s.signer_pubkey.clone())
            .collect()
    }

    /// Who still needs to sign
    pub fn pending_signers(&self) -> Vec<String> {
        let signed: BTreeSet<_> = self.signatures.iter().map(|s| &s.signer_pubkey).collect();
        self.config
            .signers
            .iter()
            .filter(|s| !signed.contains(s))
            .cloned()
            .collect()
    }
}

/// Multisig manager — tracks all pending multisig transactions
pub struct MultisigManager {
    configs: HashMap<String, MultisigConfig>, // address → config
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
    pub fn initiate(
        &mut self,
        tx_hash: String,
        address: &str,
        tx_data: Vec<u8>,
    ) -> Result<(), WalletError> {
        let config = self
            .configs
            .get(address)
            .ok_or_else(|| {
                WalletError::AddressNotFound(format!("Multisig address {} not found", address))
            })?
            .clone();

        let pending = PendingMultisig::new(tx_hash.clone(), config, tx_data);
        self.pending.insert(tx_hash, pending);
        Ok(())
    }

    /// Add a signature to a pending transaction
    pub fn sign(
        &mut self,
        tx_hash: &str,
        pubkey: &str,
        signature: &str,
    ) -> Result<bool, WalletError> {
        let pending = self
            .pending
            .get_mut(tx_hash)
            .ok_or_else(|| WalletError::Other(format!("No pending multisig for {}", tx_hash)))?;

        if pending.is_expired() {
            return Err(WalletError::Other(
                "Pending multisig has expired".to_string(),
            ));
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
        self.pending
            .retain(|_, p| !p.is_expired() && !p.is_complete());
        before - self.pending.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn config_count(&self) -> usize {
        self.configs.len()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verify_ed25519_signature(
    signer_pubkey_hex: &str,
    tx_hash: &str,
    signature_hex: &str,
) -> Result<(), WalletError> {
    if tx_hash.len() != 64 || !tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WalletError::Other(
            "tx_hash must be 64 hex characters".to_string(),
        ));
    }
    let tx_hash_bytes = hex::decode(tx_hash)
        .map_err(|_| WalletError::Other("tx_hash must be valid hex".to_string()))?;

    let pubkey_bytes = hex::decode(signer_pubkey_hex)
        .map_err(|_| WalletError::Other("Signer public key must be hex".to_string()))?;
    if pubkey_bytes.len() != 32 {
        return Err(WalletError::Other(
            "Signer public key must be 32 bytes (64 hex chars)".to_string(),
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|_| WalletError::Other("Invalid Ed25519 public key".to_string()))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| WalletError::Other("Signature must be hex".to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(WalletError::Other(
            "Signature must be 64 bytes (128 hex chars)".to_string(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(&tx_hash_bytes, &sig)
        .map_err(|_| WalletError::Other("Invalid Ed25519 signature".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signing_keys(n: usize) -> Vec<SigningKey> {
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed.fill((i as u8).saturating_add(1));
                SigningKey::from_bytes(&seed)
            })
            .collect()
    }

    fn pubkeys_hex(keys: &[SigningKey]) -> Vec<String> {
        keys.iter()
            .map(|sk| hex::encode(sk.verifying_key().as_bytes()))
            .collect()
    }

    fn sign_tx_hash(sk: &SigningKey, tx_hash: &str) -> String {
        let tx_hash_bytes = hex::decode(tx_hash).expect("test tx_hash must be valid hex");
        let sig = sk.sign(&tx_hash_bytes);
        hex::encode(sig.to_bytes())
    }

    #[test]
    fn create_2_of_3() {
        let keys = make_signing_keys(3);
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total, 3);
        assert!(config.address.starts_with("SD1m"));
        assert_eq!(config.display(), "2-of-3");
    }

    #[test]
    fn threshold_exceeds_total_fails() {
        let keys = make_signing_keys(3);
        assert!(MultisigConfig::new(4, pubkeys_hex(&keys), "mainnet").is_err());
    }

    #[test]
    fn duplicate_keys_fail() {
        let keys = vec!["same".into(), "same".into(), "other".into()];
        assert!(MultisigConfig::new(2, keys, "mainnet").is_err());
    }

    #[test]
    fn add_signatures_until_complete() {
        let tx_hash = "1111111111111111111111111111111111111111111111111111111111111111";
        let keys = make_signing_keys(3);
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        let mut pending = PendingMultisig::new(tx_hash.into(), config, vec![]);

        assert!(!pending.is_complete());
        assert_eq!(pending.remaining(), 2);

        let p0 = hex::encode(keys[0].verifying_key().as_bytes());
        let p1 = hex::encode(keys[1].verifying_key().as_bytes());
        pending
            .add_signature(&p0, &sign_tx_hash(&keys[0], tx_hash))
            .unwrap();
        assert_eq!(pending.remaining(), 1);

        pending
            .add_signature(&p1, &sign_tx_hash(&keys[1], tx_hash))
            .unwrap();
        assert!(pending.is_complete());
        #[allow(deprecated)]
        let agg = pending.aggregate_signatures();
        assert!(agg.is_none());
    }

    #[test]
    fn duplicate_signature_rejected() {
        let tx_hash = "2222222222222222222222222222222222222222222222222222222222222222";
        let keys = make_signing_keys(3);
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        let mut pending = PendingMultisig::new(tx_hash.into(), config, vec![]);
        let p0 = hex::encode(keys[0].verifying_key().as_bytes());
        pending
            .add_signature(&p0, &sign_tx_hash(&keys[0], tx_hash))
            .unwrap();
        assert!(
            pending
                .add_signature(&p0, &sign_tx_hash(&keys[0], tx_hash))
                .is_err()
        );
    }

    #[test]
    fn unauthorized_signer_rejected() {
        let tx_hash = "3333333333333333333333333333333333333333333333333333333333333333";
        let keys = make_signing_keys(3);
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        let mut pending = PendingMultisig::new(tx_hash.into(), config, vec![]);
        let unknown = SigningKey::from_bytes(&[9u8; 32]);
        let unknown_pub = hex::encode(unknown.verifying_key().as_bytes());
        assert!(
            pending
                .add_signature(&unknown_pub, &sign_tx_hash(&unknown, tx_hash))
                .is_err()
        );
    }

    #[test]
    fn pending_signers_tracked() {
        let tx_hash = "4444444444444444444444444444444444444444444444444444444444444444";
        let keys = make_signing_keys(3);
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        let mut pending = PendingMultisig::new(tx_hash.into(), config, vec![]);
        let p0 = hex::encode(keys[0].verifying_key().as_bytes());
        pending
            .add_signature(&p0, &sign_tx_hash(&keys[0], tx_hash))
            .unwrap();

        let remaining = pending.pending_signers();
        assert_eq!(remaining.len(), 2);
        assert!(!remaining.contains(&p0));
    }

    #[test]
    fn manager_full_flow() {
        let tx_hash = "5555555555555555555555555555555555555555555555555555555555555555";
        let keys = make_signing_keys(3);
        let mut mgr = MultisigManager::new();
        let config = MultisigConfig::new(2, pubkeys_hex(&keys), "mainnet").unwrap();
        let addr = mgr.register(config);

        mgr.initiate(tx_hash.into(), &addr, vec![1, 2, 3]).unwrap();
        let p0 = hex::encode(keys[0].verifying_key().as_bytes());
        let p1 = hex::encode(keys[1].verifying_key().as_bytes());
        assert!(
            !mgr.sign(tx_hash, &p0, &sign_tx_hash(&keys[0], tx_hash))
                .unwrap()
        );
        assert!(mgr.sign(tx_hash, &p1, &sign_tx_hash(&keys[1], tx_hash)).unwrap()); // Complete!

        let completed = mgr.get_completed(tx_hash).unwrap();
        #[allow(deprecated)]
        let agg = completed.aggregate_signatures();
        assert!(agg.is_none());
    }

    #[test]
    fn address_is_deterministic() {
        let keys = make_signing_keys(3);
        let pubs = pubkeys_hex(&keys);
        let a1 = MultisigConfig::new(2, pubs.clone(), "mainnet")
            .unwrap()
            .address;
        let a2 = MultisigConfig::new(2, pubs, "mainnet")
            .unwrap()
            .address;
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_threshold_different_address() {
        let keys = make_signing_keys(3);
        let pubs = pubkeys_hex(&keys);
        let a2 = MultisigConfig::new(2, pubs.clone(), "mainnet")
            .unwrap()
            .address;
        let a3 = MultisigConfig::new(3, pubs, "mainnet")
            .unwrap()
            .address;
        assert_ne!(a2, a3);
    }
}
