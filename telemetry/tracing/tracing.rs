// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
pub struct Tracing {
    db: DB,

}

impl Tracing {
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

    pub fn trace(&self, event_id: &str, payload: &str) {
        if let Err(e) = self.db.put(event_id, payload) {
            eprintln!("[TELEMETRY] trace write failed: {}", e);
        }
    }

    pub fn get_trace(&self, event_id: &str) -> Option<String> {
        match self.db.get(event_id) {
            Ok(Some(v)) => String::from_utf8(v.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("[TELEMETRY] trace read failed: {}", e);
                None
            }
        }
    }

}
