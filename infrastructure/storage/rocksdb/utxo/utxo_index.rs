// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;

pub struct UtxoIndex {
    db: DB,

}

impl UtxoIndex {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))?;

        Ok(Self { db })
    }

    pub fn index(&self, key: &str, owner: &str) -> Result<(), StorageError> {
        self.db.put(key, owner).map_err(|e| {
            eprintln!("[UtxoIndex] put error for key '{}': {}", key, e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    pub fn get_owner(&self, key: &str) -> Option<String> {
        match self.db.get(key) {
            Ok(Some(data)) => String::from_utf8(data.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("[UtxoIndex] DB read error for key '{}': {}", key, e);
                None
            }
        }
    }

}
