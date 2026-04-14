// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================

use crate::{slog_error, slog_info, slog_warn};
use rocksdb::DB;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const PREFIX: &str = "tidx:";
const BLOCK_PREFIX: &str = "tidx:blk:";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxRecord {
    pub hash: String,
    pub block_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub is_coinbase: bool,
    pub size_bytes: usize,
}

impl TxRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hash: &str,
        block_hash: &str,
        height: u64,
        timestamp: u64,
        fee: u64,
        input_count: usize,
        output_count: usize,
        is_coinbase: bool,
        size_bytes: usize,
    ) -> Self {
        Self {
            hash: hash.to_string(),
            block_hash: block_hash.to_string(),
            height,
            timestamp,
            fee,
            input_count,
            output_count,
            is_coinbase,
            size_bytes,
        }
    }
}

pub struct TxIndex {
    records: HashMap<String, TxRecord>,
    block_tx_map: HashMap<String, Vec<String>>,
    pub total_indexed: u64,
    db: Arc<DB>,
}

impl Default for TxIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIndex {
    /// Open a TxIndex with a temp DB. Returns Result instead of panicking.
    pub fn try_new() -> Result<Self, crate::errors::StorageError> {
        static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let unique = format!(
            "shadowdag_tidx_{}_{}_{}",
            std::process::id(),
            now_nanos,
            NEXT_DB_ID.fetch_add(1, Ordering::Relaxed)
        );
        let tmp = std::env::temp_dir().join(unique);
        let db = DB::open(&opts, &tmp).map_err(|e| crate::errors::StorageError::OpenFailed {
            path: tmp.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            records: HashMap::new(),
            block_tx_map: HashMap::new(),
            total_indexed: 0,
            db: Arc::new(db),
        })
    }

    /// Legacy constructor — calls try_new and logs on failure.
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            slog_warn!("index", "tx_index_db_open_failed", error => &e.to_string());
            let fallback = std::env::temp_dir().join(format!(
                "shadowdag_tidx_fb_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, &fallback).unwrap_or_else(|e2| {
                slog_error!("index", "tx_index_fallback_failed", error => &e2.to_string());
                let last =
                    std::env::temp_dir().join(format!("shadowdag_tidx_lr_{}", std::process::id()));
                DB::open(&opts, &last).unwrap_or_else(|e3| {
                    slog_error!("index", "tx_index_all_attempts_failed", error => &e3.to_string());
                    // Create with destroy_on_drop semantics — node runs degraded
                    let noop = std::env::temp_dir().join("shadowdag_tidx_noop");
                    let _ = std::fs::create_dir_all(&noop);
                    match DB::open(&opts, &noop) {
                        Ok(db) => db,
                        Err(e4) => {
                            slog_error!("index", "tx_index_fatal_abort", error => &e4.to_string());
                            std::process::abort();
                        }
                    }
                })
            });
            Self {
                records: HashMap::new(),
                block_tx_map: HashMap::new(),
                total_indexed: 0,
                db: Arc::new(db),
            }
        })
    }

    /// Construct with a shared RocksDB instance (production path).
    /// Automatically recovers state from DB so the caller cannot forget.
    pub fn new_with_db(db: Arc<DB>) -> Self {
        let mut s = Self {
            records: HashMap::new(),
            block_tx_map: HashMap::new(),
            total_indexed: 0,
            db,
        };
        s.recover_from_db();
        slog_info!("index", "tx_index_recovered", records => &s.total_indexed.to_string());
        s
    }

    // ── helpers ───────────────────────────────────────────────

    fn db_key(hash: &str) -> Vec<u8> {
        format!("{}{}", PREFIX, hash).into_bytes()
    }

    fn db_block_key(block_hash: &str) -> Vec<u8> {
        format!("{}{}", BLOCK_PREFIX, block_hash).into_bytes()
    }

    fn write_record_to_db(&self, record: &TxRecord) -> Result<(), String> {
        let key = Self::db_key(&record.hash);
        let val = serde_json::to_vec(record).map_err(|e| {
            let msg = format!("serialize: {}", e);
            slog_error!("index", "tx_index_serialize_error", error => &msg);
            msg
        })?;
        self.db.put(&key, &val).map_err(|e| {
            let msg = format!("db_put: {}", e);
            slog_error!("index", "tx_index_db_put_error", error => &msg);
            msg
        })
    }

    fn delete_record_from_db(&self, hash: &str) -> Result<(), String> {
        let key = Self::db_key(hash);
        self.db.delete(&key).map_err(|e| {
            let msg = format!("db_delete: {}", e);
            slog_error!("index", "tx_index_db_delete_error", error => &msg);
            msg
        })
    }

    fn write_block_map_to_db(&self, block_hash: &str) {
        let db_key = Self::db_block_key(block_hash);
        if let Some(list) = self.block_tx_map.get(block_hash) {
            let val = match serde_json::to_vec(list) {
                Ok(v) => v,
                Err(e) => {
                    slog_error!("index", "tx_index_block_map_serialize_error", error => &e.to_string());
                    return;
                }
            };
            if let Err(e) = self.db.put(&db_key, &val) {
                slog_error!("index", "tx_index_block_map_put_error", error => &e.to_string());
            }
        } else if let Err(e) = self.db.delete(&db_key) {
            slog_error!("index", "tx_index_block_map_delete_error", error => &e.to_string());
        }
    }

    fn load_record_from_db(&self, hash: &str) -> Option<TxRecord> {
        let key = Self::db_key(hash);
        match self.db.get(&key) {
            Ok(Some(data)) => match serde_json::from_slice(&data) {
                Ok(rec) => Some(rec),
                Err(e) => {
                    slog_error!("index", "tx_index_deserialize_error", hash => hash, error => &e.to_string());
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("index", "tx_index_db_get_error", hash => hash, error => &e.to_string());
                None
            }
        }
    }

    // ── public API ───────────────────────────────────────────

    pub fn insert(&mut self, record: TxRecord) -> bool {
        let block_hash = record.block_hash.clone();
        let hash = record.hash.clone();

        // Persist to RocksDB first — don't update memory if DB write fails
        if let Err(e) = self.write_record_to_db(&record) {
            slog_error!("index", "tx_insert_persist_failed", error => &e);
            return false;
        }

        self.records.insert(hash.clone(), record);
        self.block_tx_map
            .entry(block_hash.clone())
            .or_default()
            .push(hash);
        self.write_block_map_to_db(&block_hash);

        self.total_indexed += 1;
        true
    }

    pub fn get(&self, hash: &str) -> Option<&TxRecord> {
        self.records.get(hash)
    }

    /// Get from cache first, then fall back to RocksDB.
    pub fn get_or_load(&mut self, hash: &str) -> Option<&TxRecord> {
        if self.records.contains_key(hash) {
            return self.records.get(hash);
        }
        if let Some(rec) = self.load_record_from_db(hash) {
            self.records.insert(hash.to_string(), rec);
            return self.records.get(hash);
        }
        None
    }

    pub fn contains(&self, hash: &str) -> bool {
        if self.records.contains_key(hash) {
            return true;
        }
        let db_key = Self::db_key(hash);
        match self.db.get(&db_key) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                slog_error!("index", "tx_index_contains_db_error", hash => hash, error => &e.to_string());
                false
            }
        }
    }

    pub fn txs_in_block(&self, block_hash: &str) -> Vec<&TxRecord> {
        self.block_tx_map
            .get(block_hash)
            .map(|hashes| hashes.iter().filter_map(|h| self.records.get(h)).collect())
            .unwrap_or_default()
    }

    pub fn remove(&mut self, hash: &str) -> bool {
        // Load from cache or DB FIRST (before deleting from DB).
        // The old code deleted from DB first, then tried to fallback-load
        // from DB for cache-miss cases — but the load always failed because
        // the record was just deleted.
        let record = if let Some(r) = self.records.remove(hash) {
            Some(r)
        } else {
            // Not in cache — load from DB BEFORE we delete it
            self.load_record_from_db(hash)
        };

        // Now delete from DB
        if let Err(e) = self.delete_record_from_db(hash) {
            slog_error!("index", "tx_remove_persist_failed", error => &e);
            // If we already removed from cache, re-insert
            if let Some(ref r) = record {
                self.records.insert(hash.to_string(), r.clone());
            }
            return false;
        }

        // Update in-memory state from the loaded record
        if let Some(ref r) = record {
            if let Some(list) = self.block_tx_map.get_mut(&r.block_hash) {
                list.retain(|h| h != hash);
            }
            self.write_block_map_to_db(&r.block_hash);
            self.total_indexed = self.total_indexed.saturating_sub(1);
            true
        } else {
            false // Not found anywhere
        }
    }

    pub fn rollback_block(&mut self, block_hash: &str) -> usize {
        let hashes = self.block_tx_map.remove(block_hash).unwrap_or_default();
        let mut rolled = 0usize;
        for h in &hashes {
            if let Err(e) = self.delete_record_from_db(h) {
                slog_error!("index", "tx_rollback_delete_failed", hash => h, error => &e);
                continue;
            }
            self.records.remove(h);
            rolled += 1;
        }
        self.total_indexed = self.total_indexed.saturating_sub(rolled as u64);
        // Remove block map entry from DB
        let db_key = Self::db_block_key(block_hash);
        let _ = self.db.delete(&db_key);
        rolled
    }

    pub fn count(&self) -> usize {
        self.records.len()
    }
    pub fn block_count(&self) -> usize {
        self.block_tx_map.len()
    }

    pub fn block_fees(&self, block_hash: &str) -> u64 {
        self.txs_in_block(block_hash)
            .iter()
            .map(|r| r.fee)
            .fold(0u64, |a, f| a.saturating_add(f))
    }

    /// Rebuild the in-memory cache from RocksDB on startup.
    pub fn recover_from_db(&mut self) {
        let prefix = PREFIX.as_bytes();
        let block_prefix = BLOCK_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        self.records.clear();
        self.block_tx_map.clear();
        self.total_indexed = 0;

        let mut error_count = 0u64;
        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    error_count += 1;
                    slog_error!("index", "tx_recover_iter_error", error => &e.to_string());
                    continue;
                }
            };

            // Skip block-map keys
            if key.starts_with(block_prefix) {
                continue;
            }
            if !key.starts_with(prefix) {
                break;
            }

            match serde_json::from_slice::<TxRecord>(&value) {
                Ok(rec) => {
                    let hash = rec.hash.clone();
                    let block_hash = rec.block_hash.clone();
                    self.block_tx_map
                        .entry(block_hash)
                        .or_default()
                        .push(hash.clone());
                    self.records.insert(hash, rec);
                    self.total_indexed += 1;
                }
                Err(e) => {
                    error_count += 1;
                    slog_error!("index", "tx_recover_deserialize_error", error => &e.to_string());
                }
            }
        }
        if error_count > 0 {
            slog_warn!("index", "tx_recover_completed_with_errors", errors => &error_count.to_string(), recovered => &self.total_indexed.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(hash: &str, block: &str) -> TxRecord {
        TxRecord::new(hash, block, 1, 1000, 500, 2, 1, false, 250)
    }

    #[test]
    fn insert_and_get() {
        let mut idx = TxIndex::new();
        idx.insert(rec("tx1", "block1"));
        assert!(idx.contains("tx1"));
        assert_eq!(idx.get("tx1").unwrap().block_hash, "block1");
    }

    #[test]
    fn txs_in_block_returns_correct() {
        let mut idx = TxIndex::new();
        idx.insert(rec("tx1", "b1"));
        idx.insert(rec("tx2", "b1"));
        idx.insert(rec("tx3", "b2"));
        assert_eq!(idx.txs_in_block("b1").len(), 2);
    }

    #[test]
    fn rollback_removes_block_txs() {
        let mut idx = TxIndex::new();
        idx.insert(rec("tx1", "b1"));
        idx.insert(rec("tx2", "b1"));
        let removed = idx.rollback_block("b1");
        assert_eq!(removed, 2);
        assert!(!idx.contains("tx1"));
    }

    #[test]
    fn block_fees_sums_correctly() {
        let mut idx = TxIndex::new();
        idx.insert(rec("tx1", "b1"));
        idx.insert(rec("tx2", "b1"));
        assert_eq!(idx.block_fees("b1"), 1000);
    }

    #[test]
    fn total_indexed_increments() {
        let mut idx = TxIndex::new();
        idx.insert(rec("t1", "b1"));
        idx.insert(rec("t2", "b2"));
        assert_eq!(idx.total_indexed, 2);
    }

    #[test]
    fn recover_from_db_rebuilds_cache() {
        let mut idx = TxIndex::new();
        idx.insert(rec("rtx1", "rb1"));
        idx.insert(rec("rtx2", "rb1"));
        idx.insert(rec("rtx3", "rb2"));

        let db = Arc::clone(&idx.db);

        let mut idx2 = TxIndex::new_with_db(db);
        idx2.recover_from_db();

        assert!(idx2.contains("rtx1"));
        assert!(idx2.contains("rtx2"));
        assert!(idx2.contains("rtx3"));
        assert_eq!(idx2.total_indexed, 3);
        assert_eq!(idx2.block_count(), 2);
    }
}
