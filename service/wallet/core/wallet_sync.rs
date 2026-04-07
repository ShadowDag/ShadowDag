// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Wallet Sync — Synchronizes wallet state with the blockchain by scanning
// blocks for transactions that belong to our addresses.
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::wallet::storage::wallet_db::WalletDB;
use crate::service::wallet::core::wallet::Wallet;
use crate::errors::WalletError;

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

    /// Load wallet state from the LOCAL database.
    ///
    /// NOTE: This does NOT perform network synchronization (block scanning,
    /// UTXO matching, confirmation tracking). It only retrieves the locally
    /// cached wallet state. Full chain sync requires the node's UTXO set
    /// and block processing pipeline.
    ///
    /// TODO: Implement real wallet sync with:
    /// - Block scanning for relevant transactions
    /// - UTXO set querying for balance calculation
    /// - Confirmation depth tracking
    pub fn sync_wallet(&self, address: &str) -> Result<Option<Wallet>, WalletError> {
        self.db.get_wallet(address)
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
