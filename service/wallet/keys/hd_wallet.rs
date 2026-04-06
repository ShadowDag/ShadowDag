// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::wallet::keys::key_manager::KeyManager;

pub struct HDWallet {
    key_manager: KeyManager,

}

impl HDWallet {
    pub fn new(key_manager: KeyManager) -> Self {
        Self { key_manager }

    }

    #[allow(deprecated)]
    pub fn save_key(&self, id: &str, key: &str) {
        self.key_manager.store_key(id, key);
    }

    #[allow(deprecated)]
    pub fn load_key(&self, id: &str) -> Option<String> {
        self.key_manager.get_key(id)
    }

}
