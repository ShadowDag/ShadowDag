// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use bincode;

use crate::service::wallet::core::wallet::Wallet;
use crate::slog_error;

pub struct WalletDB {
    db: DB,

}

impl WalletDB {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { db })

    }

    pub fn save_wallet(&self, wallet: &Wallet) {
        let data = bincode::serialize(wallet).unwrap_or_default();

        if let Err(_e) = self.db.put(wallet.address(), data) { slog_error!("wallet", "db_put_error", error => &_e.to_string()); }

    }

    pub fn get_wallet(&self, address: &str) -> Option<Wallet> {
        match self.db.get(address).unwrap_or(None) {
            Some(data) => {
                let wallet: Wallet =
                    bincode::deserialize(&data).ok()?;

                Some(wallet)

            }

            None => None

        }

    }

}
