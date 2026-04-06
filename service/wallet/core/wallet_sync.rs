// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Wallet Sync — Synchronizes wallet state with the blockchain by scanning
// blocks for transactions that belong to our addresses.
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::wallet::storage::wallet_db::WalletDB;

pub struct WalletSync {
    db:               WalletDB,
    last_sync_height: u64,
}

impl WalletSync {
    pub fn new(db: WalletDB) -> Self {
        Self {
            db,
            last_sync_height: 0,
        }
    }

    /// Sync wallet state for a given address by loading from DB
    pub fn sync_wallet(&self, address: &str) {
        let wallet_data = self.db.get_wallet(address);

        match wallet_data {
            Some(wallet) => {
                eprintln!("[WalletSync] Synced wallet for address: {}", wallet.address());
            }
            None => {
                eprintln!("[WalletSync] No wallet found for {}", address);
            }
        }
    }

    /// Update the last synced block height
    pub fn set_sync_height(&mut self, height: u64) {
        self.last_sync_height = height;
    }

    /// Get the last synced block height
    pub fn sync_height(&self) -> u64 {
        self.last_sync_height
    }

    /// Check if wallet needs syncing (behind the chain tip)
    pub fn needs_sync(&self, chain_tip_height: u64) -> bool {
        self.last_sync_height < chain_tip_height
    }
}
