// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;

pub struct PowStore {
    db: DB,
}

impl PowStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        Ok(Self { db })
    }

    pub fn store_work(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.db.put(key, value).map_err(StorageError::RocksDb)
    }
}
