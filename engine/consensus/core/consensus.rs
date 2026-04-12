// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    WriteBatch, IteratorMode,
    BlockBasedOptions, SliceTransform, Cache,
};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::errors::{ConsensusError, StorageError};
use crate::{slog_error, slog_warn};

// prefixes
const PFX_STATE: &[u8] = b"s:";
const DELETE_BATCH_SIZE: usize = 1000;

/// Key-value pair from a RocksDB scan (owned copies of key and value bytes).
pub type KvPair = (Vec<u8>, Vec<u8>);

pub struct ConsensusStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    _read_opts: ReadOptions,
    _iter_read_opts: ReadOptions,
    upper_bound: Vec<u8>,
    /// Guards read-modify-write sequences (e.g. atomic_update) against races.
    /// Readers acquire a shared lock; writers acquire an exclusive lock.
    write_lock: RwLock<()>,
}

impl ConsensusStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(2));

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(256 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&block_opts);

        opts.set_paranoid_checks(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Consensus state is safety-critical — always sync + WAL.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);

        let mut _iter_read_opts = ReadOptions::default();
        _iter_read_opts.set_prefix_same_as_start(true);
        _iter_read_opts.fill_cache(false);

        let mut upper = PFX_STATE.to_vec();
        upper.push(0xFF);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            _read_opts: read_opts,
            _iter_read_opts,
            upper_bound: upper,
            write_lock: RwLock::new(()),
        })
    }

    // ─────────────────────────────────────────
    // CONFIG
    // ─────────────────────────────────────────
    /// Set sync mode. WAL is ALWAYS enabled regardless — consensus
    /// state corruption is unrecoverable.
    pub fn set_sync(&mut self, enabled: bool) {
        self.write_opts.set_sync(enabled);
        // WAL must NEVER be disabled for consensus data
        self.write_opts.disable_wal(false);
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn build_key(prefix: &[u8], key: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(prefix.len() + key.len());
        k.extend_from_slice(prefix);
        k.extend_from_slice(key.as_bytes());
        k
    }

    // ─────────────────────────────────────────
    // SET
    // ─────────────────────────────────────────
    pub fn set_state(&self, key: &str, value: &str) -> Result<(), ConsensusError> {
        self.db
            .put_opt(Self::build_key(PFX_STATE, key), value.as_bytes(), &self.write_opts)
            .map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // ─────────────────────────────────────────
    // GET STRING
    // Returns Err on I/O failure (not None).
    // ─────────────────────────────────────────
    pub fn get_state(&self, key: &str) -> Result<Option<String>, ConsensusError> {
        match self.db.get_pinned(Self::build_key(PFX_STATE, key)) {
            Ok(Some(v)) => match std::str::from_utf8(&v) {
                Ok(s) => Ok(Some(s.to_owned())),
                Err(e) => {
                    slog_error!("consensus", "state_utf8_corrupt",
                        key => key, error => &format!("{}", e));
                    Err(StorageError::ReadFailed(
                        format!("get_state '{}': UTF-8 corruption: {}", key, e)
                    ).into())
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("consensus", "state_read_failed", key => key, error => e);
                Err(StorageError::ReadFailed(format!("get_state '{}': {}", key, e)).into())
            }
        }
    }

    // ─────────────────────────────────────────
    // GET RAW
    // Returns Err on I/O failure (not None).
    // ─────────────────────────────────────────
    pub fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, ConsensusError> {
        match self.db.get_pinned(Self::build_key(PFX_STATE, key)) {
            Ok(Some(v)) => Ok(Some(v.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("consensus", "state_read_failed", key => key, error => e);
                Err(StorageError::ReadFailed(format!("get_raw '{}': {}", key, e)).into())
            }
        }
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // Returns Err on first I/O failure — partial results are never returned.
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, ConsensusError> {
        let mut results = Vec::with_capacity(keys.len());

        for k in keys {
            let val = match self.db.get_pinned(Self::build_key(PFX_STATE, k)) {
                Ok(Some(v)) => Some(v.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    slog_error!("consensus", "state_read_failed", key => *k, error => e);
                    return Err(StorageError::ReadFailed(format!("multi_get '{}': {}", k, e)).into());
                }
            };

            results.push(val);
        }

        Ok(results)
    }

    // ─────────────────────────────────────────
    // EXISTS
    // Returns Err on I/O failure (not false).
    // ─────────────────────────────────────────
    pub fn exists(&self, key: &str) -> Result<bool, ConsensusError> {
        match self.db.get_pinned(Self::build_key(PFX_STATE, key)) {
            Ok(v) => Ok(v.is_some()),
            Err(e) => {
                slog_error!("consensus", "state_read_failed", key => key, error => e);
                Err(StorageError::ReadFailed(format!("exists '{}': {}", key, e)).into())
            }
        }
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    pub fn delete_state(&self, key: &str) -> Result<(), ConsensusError> {
        self.db
            .delete_opt(Self::build_key(PFX_STATE, key), &self.write_opts)
            .map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // ─────────────────────────────────────────
    // ATOMIC UPDATE
    // ─────────────────────────────────────────
    pub fn atomic_update(
        &self,
        puts: &[(&str, &str)],
        deletes: &[&str],
    ) -> Result<(), ConsensusError> {
        let _guard = self.write_lock.write()
            .map_err(|_| ConsensusError::BlockValidation("write lock poisoned".into()))?;

        let mut batch = WriteBatch::default();

        for (k, v) in puts {
            batch.put(Self::build_key(PFX_STATE, k), v.as_bytes());
        }

        for k in deletes {
            batch.delete(Self::build_key(PFX_STATE, k));
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // ─────────────────────────────────────────
    // CLEAR PREFIX
    // ─────────────────────────────────────────
    pub fn clear_prefix(&self) -> Result<(), ConsensusError> {
        let mut opts = ReadOptions::default();
        opts.set_prefix_same_as_start(true);
        opts.fill_cache(false);
        opts.set_iterate_upper_bound(self.upper_bound.clone());

        let iter = self.db.iterator_opt(
            IteratorMode::From(PFX_STATE, rocksdb::Direction::Forward),
            opts,
        );

        let mut batch = WriteBatch::default();
        let mut count = 0;
        let mut had_error = false;

        for item in iter {
            match item {
                Ok((k, _)) => {
                    batch.delete(&k);
                    count += 1;

                    if count >= DELETE_BATCH_SIZE {
                        self.db.write_opt(batch, &self.write_opts).map_err(StorageError::RocksDb)?;
                        batch = WriteBatch::default();
                        count = 0;
                    }
                }
                Err(e) => {
                    slog_error!("consensus", "clear_prefix_iter_error", error => e);
                    had_error = true;
                    break;
                }
            }
        }

        if count > 0 {
            self.db.write_opt(batch, &self.write_opts).map_err(StorageError::RocksDb)?;
        }

        if had_error {
            return Err(StorageError::ReadFailed("iterator error during clear_prefix".into()).into());
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    // SCAN FROM
    // Returns Err on iterator failure — partial results are never returned.
    // ─────────────────────────────────────────
    pub fn scan_from(
        &self,
        start_key: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KvPair>, ConsensusError> {

        let start = match start_key {
            Some(k) => Self::build_key(PFX_STATE, k),
            None => PFX_STATE.to_vec(),
        };

        let mut opts = ReadOptions::default();
        opts.set_prefix_same_as_start(true);
        opts.fill_cache(false);
        opts.set_iterate_upper_bound(self.upper_bound.clone());

        let iter = self.db.iterator_opt(
            IteratorMode::From(&start, rocksdb::Direction::Forward),
            opts,
        );

        let mut results = Vec::with_capacity(limit.min(1024));

        for (n, item) in iter.enumerate() {
            if n >= limit { break; }
            match item {
                Ok((k, v)) => results.push((k.to_vec(), v.to_vec())),
                Err(e) => {
                    slog_error!("consensus", "scan_from_iter_error",
                        error => e, results_so_far => results.len());
                    return Err(StorageError::ReadFailed(
                        format!("scan_from iterator error after {} results: {}", results.len(), e)
                    ).into());
                }
            }
        }

        Ok(results)
    }

    // ─────────────────────────────────────────
    // COMPACT RANGE (🔥 مهم بعد الحذف)
    // ─────────────────────────────────────────
    pub fn compact(&self) {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) -> Result<(), ConsensusError> {
        self.db.flush().map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // ─────────────────────────────────────────
    // DB SIZE
    // Returns None on property read failure (logged) instead of fake 0.
    // ─────────────────────────────────────────
    pub fn size_estimate(&self) -> Option<u64> {
        match self.db.property_int_value("rocksdb.estimate-live-data-size") {
            Ok(val) => val,
            Err(e) => {
                slog_warn!("consensus", "size_estimate_failed", error => e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("/tmp/test_consensus_store_{}", ts)
    }

    #[test]
    fn set_and_get_state() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("best_hash", "abc123").unwrap();
        assert_eq!(store.get_state("best_hash").unwrap(), Some("abc123".to_string()));
    }

    #[test]
    fn get_unknown_returns_none() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        assert_eq!(store.get_state("nonexistent").unwrap(), None);
    }

    #[test]
    fn exists_check() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        assert!(!store.exists("tip").unwrap());
        store.set_state("tip", "hash1").unwrap();
        assert!(store.exists("tip").unwrap());
    }

    #[test]
    fn delete_state_removes() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("key", "val").unwrap();
        assert!(store.exists("key").unwrap());
        store.delete_state("key").unwrap();
        assert!(!store.exists("key").unwrap());
    }

    #[test]
    fn overwrite_updates_value() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("k", "v1").unwrap();
        assert_eq!(store.get_state("k").unwrap(), Some("v1".to_string()));
        store.set_state("k", "v2").unwrap();
        assert_eq!(store.get_state("k").unwrap(), Some("v2".to_string()));
    }

    #[test]
    fn get_raw_returns_bytes() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("raw_key", "hello").unwrap();
        let raw = store.get_raw("raw_key").unwrap().unwrap();
        assert_eq!(raw, b"hello");
    }

    #[test]
    fn multi_get_returns_correct() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("a", "1").unwrap();
        store.set_state("b", "2").unwrap();
        let results = store.multi_get(&["a", "b", "c"]).unwrap();
        assert_eq!(results[0], Some(b"1".to_vec()));
        assert_eq!(results[1], Some(b"2".to_vec()));
        assert_eq!(results[2], None);
    }

    #[test]
    fn atomic_update_puts_and_deletes() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("old", "val").unwrap();
        store.atomic_update(
            &[("new1", "v1"), ("new2", "v2")],
            &["old"],
        ).unwrap();
        assert_eq!(store.get_state("new1").unwrap(), Some("v1".to_string()));
        assert_eq!(store.get_state("new2").unwrap(), Some("v2".to_string()));
        assert!(!store.exists("old").unwrap());
    }

    #[test]
    fn clear_prefix_removes_all() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("x", "1").unwrap();
        store.set_state("y", "2").unwrap();
        store.clear_prefix().unwrap();
        assert!(!store.exists("x").unwrap());
        assert!(!store.exists("y").unwrap());
    }

    #[test]
    fn scan_from_returns_entries() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("a", "1").unwrap();
        store.set_state("b", "2").unwrap();
        store.set_state("c", "3").unwrap();
        let results = store.scan_from(None, 10).unwrap();
        assert!(results.len() >= 3);
    }

    #[test]
    fn flush_succeeds() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        store.set_state("k", "v").unwrap();
        assert!(store.flush().is_ok());
    }

    #[test]
    fn size_estimate_returns_value() {
        let store = ConsensusStore::new(&tmp_path()).unwrap();
        // Fresh DB — property should be readable (possibly None or Some(0))
        let _size = store.size_estimate();
    }
}
