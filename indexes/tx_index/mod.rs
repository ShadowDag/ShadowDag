// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use rocksdb::DB;

const PREFIX: &str = "tidx:";
const BLOCK_PREFIX: &str = "tidx:blk:";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxRecord {
    pub hash:        String,
    pub block_hash:  String,
    pub height:      u64,
    pub timestamp:   u64,
    pub fee:         u64,
    pub input_count:  usize,
    pub output_count: usize,
    pub is_coinbase:  bool,
    pub size_bytes:   usize,
}

impl TxRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hash: &str, block_hash: &str, height: u64,
        timestamp: u64, fee: u64,
        input_count: usize, output_count: usize,
        is_coinbase: bool, size_bytes: usize,
    ) -> Self {
        Self {
            hash:         hash.to_string(),
            block_hash:   block_hash.to_string(),
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
    records:        HashMap<String, TxRecord>,
    block_tx_map:   HashMap<String, Vec<String>>,
    pub total_indexed: u64,
    db:             Arc<DB>,
}

impl Default for TxIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIndex {
    /// Open a TxIndex with a temp DB. Returns Result instead of panicking.
    pub fn try_new() -> Result<Self, crate::errors::StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let unique = format!("shadowdag_tidx_{}_{:?}",
            std::process::id(), std::thread::current().id());
        let tmp = std::env::temp_dir().join(unique);
        let db = DB::open(&opts, &tmp)
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: tmp.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            records: HashMap::new(), block_tx_map: HashMap::new(),
            total_indexed: 0, db: Arc::new(db),
        })
    }

    /// Legacy constructor — calls try_new and logs on failure.
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            eprintln!("[TxIndex] WARNING: DB open failed ({}), using fallback", e);
            let fallback = std::env::temp_dir().join(format!(
                "shadowdag_tidx_fb_{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
            ));
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, &fallback).unwrap_or_else(|e2| {
                eprintln!("[TxIndex] ERROR: Fallback also failed: {}", e2);
                let last = std::env::temp_dir().join(format!("shadowdag_tidx_lr_{}", std::process::id()));
                DB::open(&opts, &last).unwrap_or_else(|e3| {
                    eprintln!("[TxIndex] CRITICAL: All attempts failed: {}", e3);
                    // Create with destroy_on_drop semantics — node runs degraded
                    let noop = std::env::temp_dir().join("shadowdag_tidx_noop");
                    let _ = std::fs::create_dir_all(&noop);
                    match DB::open(&opts, &noop) {
                        Ok(db) => db,
                        Err(e4) => {
                            eprintln!(
                                "[TxIndex] FATAL: /tmp not writable after all attempts ({}). Aborting.",
                                e4
                            );
                            std::process::abort();
                        }
                    }
                })
            });
            Self { records: HashMap::new(), block_tx_map: HashMap::new(), total_indexed: 0, db: Arc::new(db) }
        })
    }

    /// Construct with a shared RocksDB instance (production path).
    /// Automatically recovers state from DB so the caller cannot forget.
    pub fn new_with_db(db: Arc<DB>) -> Self {
        let mut s = Self {
            records:       HashMap::new(),
            block_tx_map:  HashMap::new(),
            total_indexed: 0,
            db,
        };
        s.recover_from_db();
        eprintln!(
            "[TxIndex] Auto-recovered {} tx records from DB",
            s.total_indexed
        );
        s
    }

    // ── helpers ───────────────────────────────────────────────

    fn db_key(hash: &str) -> Vec<u8> {
        format!("{}{}", PREFIX, hash).into_bytes()
    }

    fn db_block_key(block_hash: &str) -> Vec<u8> {
        format!("{}{}", BLOCK_PREFIX, block_hash).into_bytes()
    }

    fn write_record_to_db(&self, record: &TxRecord) {
        let key = Self::db_key(&record.hash);
        let val = serde_json::to_vec(record).unwrap_or_default();
        if let Err(e) = self.db.put(&key, &val) {
            eprintln!("[TxIndex] DB put error: {}", e);
        }
    }

    fn delete_record_from_db(&self, hash: &str) {
        let key = Self::db_key(hash);
        if let Err(e) = self.db.delete(&key) {
            eprintln!("[TxIndex] DB delete error: {}", e);
        }
    }

    fn write_block_map_to_db(&self, block_hash: &str) {
        let db_key = Self::db_block_key(block_hash);
        if let Some(list) = self.block_tx_map.get(block_hash) {
            let val = serde_json::to_vec(list).unwrap_or_default();
            let _ = self.db.put(&db_key, &val);
        } else {
            let _ = self.db.delete(&db_key);
        }
    }

    fn load_record_from_db(&self, hash: &str) -> Option<TxRecord> {
        let key = Self::db_key(hash);
        match self.db.get(&key) {
            Ok(Some(data)) => serde_json::from_slice(&data).ok(),
            _ => None,
        }
    }

    // ── public API ───────────────────────────────────────────

    pub fn insert(&mut self, record: TxRecord) {
        let block_hash = record.block_hash.clone();
        let hash       = record.hash.clone();

        // Persist to RocksDB first
        self.write_record_to_db(&record);

        self.records.insert(hash.clone(), record);
        self.block_tx_map
            .entry(block_hash.clone())
            .or_default()
            .push(hash);
        self.write_block_map_to_db(&block_hash);

        self.total_indexed += 1;
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
        matches!(self.db.get(&db_key), Ok(Some(_)))
    }

    pub fn txs_in_block(&self, block_hash: &str) -> Vec<&TxRecord> {
        self.block_tx_map.get(block_hash)
            .map(|hashes| hashes.iter()
                .filter_map(|h| self.records.get(h))
                .collect())
            .unwrap_or_default()
    }

    pub fn remove(&mut self, hash: &str) -> bool {
        // Always delete from DB
        self.delete_record_from_db(hash);

        if let Some(rec) = self.records.remove(hash) {
            if let Some(list) = self.block_tx_map.get_mut(&rec.block_hash) {
                list.retain(|h| h != hash);
            }
            self.write_block_map_to_db(&rec.block_hash);
            return true;
        }
        // Check DB even if not in cache
        if let Some(rec) = self.load_record_from_db(hash) {
            self.delete_record_from_db(hash);
            self.write_block_map_to_db(&rec.block_hash);
            return true;
        }
        false
    }

    pub fn rollback_block(&mut self, block_hash: &str) -> usize {
        let hashes = self.block_tx_map.remove(block_hash).unwrap_or_default();
        let count  = hashes.len();
        for h in &hashes {
            self.records.remove(h);
            self.delete_record_from_db(h);
        }
        // Remove block map entry from DB
        let db_key = Self::db_block_key(block_hash);
        let _ = self.db.delete(&db_key);
        count
    }

    pub fn count(&self) -> usize         { self.records.len() }
    pub fn block_count(&self) -> usize   { self.block_tx_map.len() }

    pub fn block_fees(&self, block_hash: &str) -> u64 {
        self.txs_in_block(block_hash).iter().map(|r| r.fee).fold(0u64, |a, f| a.saturating_add(f))
    }

    /// Rebuild the in-memory cache from RocksDB on startup.
    pub fn recover_from_db(&mut self) {
        let prefix = PREFIX.as_bytes();
        let block_prefix = BLOCK_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        self.records.clear();
        self.block_tx_map.clear();
        self.total_indexed = 0;

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };

            // Skip block-map keys
            if key.starts_with(block_prefix) {
                continue;
            }
            if !key.starts_with(prefix) {
                break;
            }

            if let Ok(rec) = serde_json::from_slice::<TxRecord>(&value) {
                let hash = rec.hash.clone();
                let block_hash = rec.block_hash.clone();
                self.block_tx_map
                    .entry(block_hash)
                    .or_default()
                    .push(hash.clone());
                self.records.insert(hash, rec);
                self.total_indexed += 1;
            }
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
