// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::WalletError;
use crate::service::wallet::keys::key_manager::KeyManager;

pub struct HDWallet {
    key_manager: KeyManager,
    password: String,
}

impl HDWallet {
    pub fn new(key_manager: KeyManager, password: String) -> Self {
        Self {
            key_manager,
            password,
        }
    }

    pub fn save_key(&self, id: &str, key: &str) -> Result<(), WalletError> {
        self.key_manager
            .store_key_encrypted(id, key.to_string(), &self.password)
    }

    pub fn load_key(&self, id: &str) -> Result<String, WalletError> {
        self.key_manager.get_key_decrypted(id, &self.password)
    }
}
