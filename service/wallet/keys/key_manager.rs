// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;
use crate::errors::WalletError;

const PBKDF2_ITER: u32 = 600_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub struct KeyManager {
    db: DB,
}

impl KeyManager {
    pub fn new(path: &str) -> Result<Self, WalletError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| WalletError::Other(format!("KeyManager DB open error: {}", e)))?;
        Ok(Self { db })
    }

    pub fn store_key_encrypted(
        &self,
        key_id: &str,
        mut private_key: String,
        password: &str,
    ) -> Result<(), WalletError> {
        let salt = Self::random_bytes::<SALT_LEN>();

        let mut enc_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut enc_key);

        let nonce_bytes = Self::random_bytes::<NONCE_LEN>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| WalletError::Encryption(format!("AES key error: {}", e)))?;
        let ciphertext = cipher
            .encrypt(nonce, private_key.as_bytes())
            .map_err(|e| WalletError::Encryption(format!("Encryption error: {}", e)))?;

        enc_key.zeroize();
        private_key.zeroize();

        let mut stored = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        stored.extend_from_slice(&salt);
        stored.extend_from_slice(&nonce_bytes);
        stored.extend_from_slice(&ciphertext);

        self.db
            .put(key_id.as_bytes(), &stored)
            .map_err(|e| WalletError::Other(format!("DB store error: {}", e)))?;

        Ok(())
    }

    pub fn get_key_decrypted(
        &self,
        key_id: &str,
        password: &str,
    ) -> Result<String, WalletError> {
        let stored = self.db
            .get(key_id.as_bytes())
            .map_err(|e| WalletError::Other(format!("DB get error: {}", e)))?
            .ok_or_else(|| WalletError::Other(format!("Key '{}' not found", key_id)))?;

        if stored.len() < SALT_LEN + NONCE_LEN + 16 {
            return Err(WalletError::Other("Stored data too short".to_string()));
        }

        let salt = &stored[..SALT_LEN];
        let nonce_bytes = &stored[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &stored[SALT_LEN + NONCE_LEN..];

        let mut dec_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITER, &mut dec_key);

        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&dec_key)
            .map_err(|e| WalletError::Encryption(format!("AES key error: {}", e)))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| WalletError::AuthFailed)?;

        dec_key.zeroize();

        String::from_utf8(plaintext)
            .map_err(|e| WalletError::Other(format!("UTF-8 decode error: {}", e)))
    }

    pub fn delete_key(&self, key_id: &str) -> Result<(), WalletError> {
        self.db
            .delete(key_id.as_bytes())
            .map_err(|e| WalletError::Other(format!("DB delete error: {}", e)))
    }

    pub fn key_exists(&self, key_id: &str) -> bool {
        matches!(self.db.get(key_id.as_bytes()), Ok(Some(_)))
    }

    fn random_bytes<const N: usize>() -> [u8; N] {
        use rand::RngCore;
        let mut buf = [0u8; N];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    // Plaintext key storage has been removed. Use store_key_encrypted() and
    // get_key_decrypted() instead. Private keys must NEVER be stored in
    // plaintext on disk.
}
