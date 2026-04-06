// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

pub struct DagIndex {
    db: DB,
}

impl DagIndex {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, Path::new(path))?;
        Ok(Self { db })
    }

    pub fn index_block(&self, hash: &str, height: u64) {
        let key = format!("height:{}", height);
        if let Err(e) = self.db.put(key.as_bytes(), hash.as_bytes()) { slog_error!("storage", "dag_index_put_error", error => e); }
    }

    pub fn get_hash_at_height(&self, height: u64) -> Option<String> {
        let key = format!("height:{}", height);
        match self.db.get(key.as_bytes()).unwrap_or(None) {
            Some(data) => Some(String::from_utf8(data.to_vec()).ok()?),
            None => None,
        }
    }
}
