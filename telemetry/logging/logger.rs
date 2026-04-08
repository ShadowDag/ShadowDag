// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
pub struct Logger {
    db: DB,

}

impl Logger {
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

    pub fn log(&self, id: &str, message: &str) {
        if let Err(e) = self.db.put(id, message) {
            eprintln!("[TELEMETRY] log write failed: {}", e);
        }
    }

    pub fn get_log(&self, id: &str) -> Option<String> {
        match self.db.get(id) {
            Ok(Some(v)) => String::from_utf8(v.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("[TELEMETRY] log read failed: {}", e);
                None
            }
        }
    }

}
