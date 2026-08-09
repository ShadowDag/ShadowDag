// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Hierarchical deterministic wallet: BIP39 mnemonic + SLIP-0010 (Ed25519).
//!
//! Derivation path: `m/44'/9333'/account'/0'/index'` (all hardened — SLIP-0010
//! ed25519 supports hardened derivation only). Coin type `9333'` is PROVISIONAL
//! (no registered SLIP-0044 id for ShadowDAG; mirrors the mainnet P2P port).

use crate::domain::address::address::Address;
use crate::errors::WalletError;
use crate::service::wallet::keys::key_manager::KeyManager;
use crate::service::wallet::keys::mnemonic::{generate_mnemonic, mnemonic_to_seed, WordCount};
use crate::service::wallet::keys::slip10::Slip10Node;
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// BIP44 purpose and provisional ShadowDAG coin type.
const PURPOSE: u32 = 44;
const COIN_TYPE: u32 = 9333; // PROVISIONAL — see module docs.

/// Storage key id under which the encrypted mnemonic lives in KeyManager.
const MNEMONIC_KEY_ID: &str = "hdwallet:mnemonic";

/// A single derived account key.
pub struct DerivedKey {
    pub signing_key: SigningKey,
    pub public_key_hex: String,
    pub address: String,
}

pub struct HDWallet {
    /// Held in memory only; never persisted in plaintext.
    mnemonic: Zeroizing<String>,
    key_manager: KeyManager,
}

impl HDWallet {
    /// Create a brand-new wallet, storing the mnemonic encrypted at rest.
    pub fn generate(
        words: WordCount,
        password: &str,
        key_manager: KeyManager,
    ) -> Result<Self, WalletError> {
        let phrase = generate_mnemonic(words)?;
        key_manager.store_key_encrypted(MNEMONIC_KEY_ID, phrase.clone(), password)?;
        Ok(Self {
            mnemonic: Zeroizing::new(phrase),
            key_manager,
        })
    }

    /// Restore from an existing mnemonic phrase (validates + re-encrypts).
    pub fn restore_from_mnemonic(
        phrase: &str,
        password: &str,
        key_manager: KeyManager,
    ) -> Result<Self, WalletError> {
        // Validate by attempting a seed derivation; propagates on a bad phrase.
        let _ = mnemonic_to_seed(phrase, "")?;
        key_manager.store_key_encrypted(MNEMONIC_KEY_ID, phrase.to_string(), password)?;
        Ok(Self {
            mnemonic: Zeroizing::new(phrase.to_string()),
            key_manager,
        })
    }

    /// Load a previously-stored wallet by decrypting its mnemonic.
    pub fn load(password: &str, key_manager: KeyManager) -> Result<Self, WalletError> {
        let phrase = key_manager.get_key_decrypted(MNEMONIC_KEY_ID, password)?;
        Ok(Self {
            mnemonic: Zeroizing::new(phrase),
            key_manager,
        })
    }

    /// Expose the phrase for one-time backup display.
    pub fn mnemonic_phrase(&self) -> &str {
        &self.mnemonic
    }

    /// Borrow the underlying key manager (e.g. to store additional secrets).
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Derive `m/44'/9333'/account'/0'/index'` for the given network.
    pub fn derive(
        &self,
        account: u32,
        index: u32,
        network: &str,
    ) -> Result<DerivedKey, WalletError> {
        let seed = mnemonic_to_seed(&self.mnemonic, "")?;
        Self::derive_from_seed(&seed, account, index, network)
    }

    /// Pure derivation from a raw BIP39 seed (no persistence) — also the test seam.
    pub fn derive_from_seed(
        seed: &[u8],
        account: u32,
        index: u32,
        network: &str,
    ) -> Result<DerivedKey, WalletError> {
        let path = [PURPOSE, COIN_TYPE, account, 0u32, index];
        let node = Slip10Node::derive_path_ed25519(seed, &path);

        let signing_key = SigningKey::from_bytes(&node.key);
        let verifying = signing_key.verifying_key();
        let pk_bytes = verifying.to_bytes();

        let address = Address::from_public_key(&pk_bytes, network).value;

        Ok(DerivedKey {
            signing_key,
            public_key_hex: hex::encode(pk_bytes),
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";

    fn seed() -> [u8; 64] {
        crate::service::wallet::keys::mnemonic::mnemonic_to_seed(PHRASE, "").unwrap()
    }

    #[test]
    fn derive_is_deterministic() {
        let a = HDWallet::derive_from_seed(&seed(), 0, 0, "mainnet").unwrap();
        let b = HDWallet::derive_from_seed(&seed(), 0, 0, "mainnet").unwrap();
        assert_eq!(a.public_key_hex, b.public_key_hex);
        assert_eq!(a.address, b.address);
    }

    #[test]
    fn different_index_yields_different_key() {
        let a = HDWallet::derive_from_seed(&seed(), 0, 0, "mainnet").unwrap();
        let b = HDWallet::derive_from_seed(&seed(), 0, 1, "mainnet").unwrap();
        assert_ne!(a.public_key_hex, b.public_key_hex);
    }

    #[test]
    fn address_uses_network_prefix() {
        let m = HDWallet::derive_from_seed(&seed(), 0, 0, "mainnet").unwrap();
        let t = HDWallet::derive_from_seed(&seed(), 0, 0, "testnet").unwrap();
        assert!(m.address.starts_with("SD1"), "got {}", m.address);
        assert!(t.address.starts_with("ST1"), "got {}", t.address);
        assert_eq!(m.public_key_hex.len(), 64);
    }

    #[test]
    fn generate_persist_then_load_recovers_same_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("km").to_string_lossy().to_string();

        // Generate + persist
        let km1 = KeyManager::new(&path).unwrap();
        let w1 = HDWallet::generate(WordCount::Twelve, "pw-correct", km1).unwrap();
        let addr1 = w1.derive(0, 0, "mainnet").unwrap().address;
        let phrase = w1.mnemonic_phrase().to_string();
        drop(w1); // releases the RocksDB handle

        // Load with the correct password recovers the same first address
        let km2 = KeyManager::new(&path).unwrap();
        let w2 = HDWallet::load("pw-correct", km2).unwrap();
        assert_eq!(w2.mnemonic_phrase(), phrase);
        assert_eq!(w2.derive(0, 0, "mainnet").unwrap().address, addr1);
        drop(w2);

        // Wrong password fails cleanly
        let km3 = KeyManager::new(&path).unwrap();
        assert!(matches!(
            HDWallet::load("pw-wrong", km3),
            Err(WalletError::AuthFailed)
        ));
    }
}
