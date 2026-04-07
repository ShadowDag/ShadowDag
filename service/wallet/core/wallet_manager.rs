// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::wallet::storage::wallet_db::WalletDB;
use crate::service::wallet::core::wallet::Wallet;
use crate::errors::WalletError;

pub struct WalletManager {
    db: WalletDB,
}

impl WalletManager {
    pub fn new(db: WalletDB) -> Self {
        Self { db }
    }

    pub fn create_wallet(&self, wallet: Wallet) -> Result<(), WalletError> {
        self.db.save_wallet(&wallet)
    }

    pub fn load_wallet(&self, address: &str) -> Result<Option<Wallet>, WalletError> {
        self.db.get_wallet(address)
    }
}
