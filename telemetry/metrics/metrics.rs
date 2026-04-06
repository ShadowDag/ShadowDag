// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

pub struct Metrics {
    db: DB,

}

impl Metrics {
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

    pub fn set_metric(&self, name: &str, value: u64) {
        if let Err(_e) = self.db.put(name, value.to_be_bytes()) { eprintln!("[DB] put error: {}", _e); }

    }

    pub fn get_metric(&self, name: &str) -> Option<u64> {
        match self.db.get(name).unwrap_or(None) {
            Some(bytes) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);

                Some(u64::from_be_bytes(arr))

            }

            None => None

        }

    }

}
