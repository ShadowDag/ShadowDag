// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use crate::errors::WalletError;
use crate::slog_error;

pub struct AddressBook {
    db: DB,
}

impl AddressBook {
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

    pub fn add_address(&self, name: &str, address: &str) -> Result<(), crate::errors::StorageError> {
        self.db.put(name, address).map_err(|e| {
            slog_error!("wallet", "db_put_error", error => &e.to_string());
            crate::errors::StorageError::WriteFailed(format!("add_address '{}': {}", name, e))
        })
    }

    pub fn get_address(&self, name: &str) -> Result<Option<String>, WalletError> {
        match self.db.get(name) {
            Ok(Some(data)) => Ok(Some(String::from_utf8(data.to_vec())
                .map_err(|e| WalletError::Other(format!("utf8 error: {}", e)))?)),
            Ok(None) => Ok(None),
            Err(e) => Err(WalletError::Other(format!("db read failed: {}", e))),
        }
    }
}
