// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

use serde_json;

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

    /// Index a block hash at a given height.
    ///
    /// **Concurrency note:** This performs a read-modify-write without
    /// locking. It is safe only under the single-writer assumption
    /// (one thread indexes blocks at a time). Concurrent calls for the
    /// same height may lose an insertion. A dedup check prevents
    /// duplicates when the same block is re-indexed.
    pub fn index_block(&self, hash: &str, height: u64) {
        let key = format!("height:{}", height);
        let mut hashes = self.get_hashes_at_height(height);
        if !hashes.contains(&hash.to_string()) {
            hashes.push(hash.to_string());
        }
        let serialized = match serde_json::to_vec(&hashes) {
            Ok(data) => data,
            Err(e) => {
                slog_error!("storage", "dag_index_serialize_error", error => e);
                return;
            }
        };
        if let Err(e) = self.db.put(key.as_bytes(), &serialized) {
            slog_error!("storage", "dag_index_put_error", error => e);
        }
    }

    /// Returns the first hash at the given height (legacy compatibility).
    pub fn get_hash_at_height(&self, height: u64) -> Option<String> {
        self.get_hashes_at_height(height).into_iter().next()
    }

    /// Returns all block hashes stored at the given height (DAG-compatible).
    pub fn get_hashes_at_height(&self, height: u64) -> Vec<String> {
        let key = format!("height:{}", height);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => {
                // Try JSON (new format) first, then fall back to plain string (old format)
                if let Ok(hashes) = serde_json::from_slice::<Vec<String>>(&data) {
                    hashes
                } else if let Ok(s) = String::from_utf8(data.to_vec()) {
                    vec![s]
                } else {
                    slog_error!("storage", "dag_index_deserialize_failed", height => height);
                    vec![]
                }
            }
            Ok(None) => vec![],
            Err(e) => {
                slog_error!("storage", "dag_index_read_failed", height => height, error => e);
                vec![]
            }
        }
    }
}
