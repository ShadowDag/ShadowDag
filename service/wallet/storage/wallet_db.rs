// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use bincode;
use rocksdb::{Options, DB};
use std::path::Path;

use crate::errors::WalletError;
use crate::service::wallet::core::wallet::Wallet;

pub struct WalletDB {
    db: DB,
}

impl WalletDB {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| {
            crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(Self { db })
    }

    pub fn save_wallet(&self, wallet: &Wallet) -> Result<(), WalletError> {
        let key = wallet.address();
        if key.is_empty() || key == "__no_address__" {
            return Err(WalletError::Other(
                "cannot save wallet with empty address".into(),
            ));
        }
        let data = bincode::serialize(wallet)
            .map_err(|e| WalletError::Other(format!("serialize failed: {}", e)))?;
        self.db
            .put(&key, data)
            .map_err(|e| WalletError::Other(format!("db put failed: {}", e)))?;
        Ok(())
    }

    pub fn get_wallet(&self, address: &str) -> Result<Option<Wallet>, WalletError> {
        match self.db.get(address) {
            Ok(Some(data)) => {
                let mut wallet: Wallet = bincode::deserialize(&data)
                    .map_err(|e| WalletError::Other(format!("deserialize failed: {}", e)))?;
                wallet.force_locked_after_load();
                Ok(Some(wallet))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WalletError::Other(format!("db read failed: {}", e))),
        }
    }
}
