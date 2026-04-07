// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteOptions, DBRecoveryMode};
use std::path::Path;
use std::sync::Arc;

use crate::errors::StorageError;
use crate::{slog_warn, slog_error};

pub enum SharedDbSource {
    Path(String),
    Shared(Arc<DB>),
}

impl From<&str> for SharedDbSource {
    fn from(path: &str) -> Self {
        Self::Path(path.to_string())
    }
}

impl From<String> for SharedDbSource {
    fn from(path: String) -> Self {
        Self::Path(path)
    }
}

impl From<&String> for SharedDbSource {
    fn from(path: &String) -> Self {
        Self::Path(path.clone())
    }
}

impl From<Arc<DB>> for SharedDbSource {
    fn from(db: Arc<DB>) -> Self {
        Self::Shared(db)
    }
}

pub fn open_shared_db<S: Into<SharedDbSource>>(source: S, opts: &Options) -> Result<Arc<DB>, rocksdb::Error> {
    match source.into() {
        SharedDbSource::Shared(db) => Ok(db),
        SharedDbSource::Path(path) => {
            // Apply safety-critical settings that callers may not set.
            // WAL + atomic flush + recovery are non-negotiable for a blockchain.
            let mut safe_opts = opts.clone();
            safe_opts.set_wal_recovery_mode(DBRecoveryMode::TolerateCorruptedTailRecords);
            safe_opts.set_atomic_flush(true);

            let wal_dir = format!("{}/wal", path);
            if let Err(e) = std::fs::create_dir_all(&wal_dir) {
                slog_warn!("storage", "wal_dir_create_failed", path => wal_dir, error => e);
            }
            safe_opts.set_wal_dir(Path::new(&wal_dir));

            DB::open(&safe_opts, Path::new(&path)).map(Arc::new)
        }
    }
}

pub struct NodeDB {
    pub db: Arc<DB>,
}

impl NodeDB {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let opts = Self::safe_options(path);
        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn shared(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }

    pub fn open_with_recovery(path: &str) -> Result<Self, StorageError> {
        let opts = Self::safe_options(path);

        match DB::open(&opts, Path::new(path)) {
            Ok(db) => {
                return Ok(Self { db: Arc::new(db) });
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                let looks_corrupt = msg.contains("corruption")
                    || msg.contains("checksum")
                    || msg.contains("manifest");
                if !looks_corrupt {
                    return Err(StorageError::OpenFailed {
                        path: path.to_string(),
                        reason: e.to_string(),
                    });
                }
                slog_warn!("storage", "db_corruption_detected", path => path, error => &e.to_string());
            }
        }

        // Only reach here for corruption errors — attempt repair
        DB::repair(&opts, Path::new(path))
            .map_err(|re| StorageError::OpenFailed { path: path.to_string(), reason: format!("repair failed: {}", re) })?;

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: format!("open after repair failed: {}", e) })?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn try_open(path: &str) -> Result<Self, StorageError> {
        let opts = Self::safe_options(path);
        DB::open(&opts, Path::new(path))
            .map(|db| Self { db: Arc::new(db) })
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })
    }

    fn safe_options(path: &str) -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Scale parallelism to available cores
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) as i32;
        opts.increase_parallelism(cores);

        opts.set_max_open_files(4_000);

        // 256 MB write buffer (4x previous) — critical for 10 BPS write throughput
        opts.set_write_buffer_size(256 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);

        // Aggressive L0 compaction to prevent write stalls
        opts.set_level_zero_file_num_compaction_trigger(4);
        opts.set_max_background_jobs(cores.min(8));

        // LZ4 compression — fast decompression for read-heavy workloads
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Read-ahead for sequential scans (UTXO iteration, pruning)
        opts.set_compaction_readahead_size(4 * 1024 * 1024); // 4 MB

        opts.set_wal_recovery_mode(DBRecoveryMode::TolerateCorruptedTailRecords);
        opts.set_atomic_flush(true);

        let wal_dir = format!("{}/wal", path);
        if let Err(e) = std::fs::create_dir_all(&wal_dir) {
            slog_warn!("storage", "wal_dir_create_failed", path => wal_dir, error => e);
        }
        opts.set_wal_dir(Path::new(&wal_dir));

        opts
    }

    fn write_opts(sync: bool) -> WriteOptions {
        let mut wo = WriteOptions::default();
        wo.set_sync(sync);
        wo
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db.put(key, value).map_err(|e| {
            slog_error!("storage", "write_error", error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    pub fn put_sync(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let wo = Self::write_opts(true);
        self.db.put_opt(key, value, &wo).map_err(|e| {
            slog_error!("storage", "sync_write_error", error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.db.get(key) {
            Ok(Some(value)) => Some(value.to_vec()),
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "read_error", error => e);
                None
            }
        }
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.db.delete(key).map_err(|e| {
            slog_error!("storage", "delete_error", error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    pub fn delete_sync(&self, key: &[u8]) -> Result<(), StorageError> {
        let wo = Self::write_opts(true);
        self.db.delete_opt(key, &wo).map_err(|e| {
            slog_error!("storage", "sync_delete_error", error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        format!("/tmp/test_nodedb_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos())
    }

    #[test]
    fn open_creates_db() {
        let db = NodeDB::new(&tmp_path()).unwrap();
        db.put(b"k", b"v").unwrap();
        assert_eq!(db.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn try_open_succeeds_on_valid_path() {
        let result = NodeDB::try_open(&tmp_path());
        assert!(result.is_ok());
    }

    #[test]
    fn put_sync_survives_and_readable() {
        let db = NodeDB::new(&tmp_path()).unwrap();
        db.put_sync(b"sync_key", b"sync_value").unwrap();
        assert_eq!(db.get(b"sync_key"), Some(b"sync_value".to_vec()));
    }

    #[test]
    fn delete_removes_key() {
        let db = NodeDB::new(&tmp_path()).unwrap();
        db.put(b"del_key", b"1").unwrap();
        db.delete(b"del_key").unwrap();
        assert_eq!(db.get(b"del_key"), None);
    }

    #[test]
    fn open_with_recovery_succeeds_on_fresh_path() {
        let db = NodeDB::open_with_recovery(&tmp_path()).unwrap();
        db.put(b"key", b"val").unwrap();
        assert_eq!(db.get(b"key"), Some(b"val".to_vec()));
    }
}
