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
        if let Err(_e) = self.db.put(event_id, payload) { eprintln!("[DB] put error: {}", _e); }

    }

    pub fn get_trace(&self, event_id: &str) -> Option<String> {
        match self.db.get(event_id).unwrap_or(None) {
            Some(data) => {
                Some(String::from_utf8(data.to_vec()).ok()?)
            }

            None => None

        }

    }

}
