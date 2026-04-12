// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, ReadOptions, WriteOptions, WriteBatch};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{ConsensusError, StorageError};
use crate::slog_error;

// prefix
const TIP_PREFIX: &[u8] = b"tip:";

pub struct ConsensusManagerStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl ConsensusManagerStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Consensus state is safety-critical — sync writes to disk.
        // set_sync(true) = fsync after every write. Slower but crash-safe.
        // Without this, a power failure could lose the latest consensus state
        // and cause the node to fork on restart.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
        })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn build_key(buf: &mut Vec<u8>, key: &str) {
        buf.clear();
        buf.extend_from_slice(TIP_PREFIX);
        buf.extend_from_slice(key.as_bytes());
    }

    // ─────────────────────────────────────────
    // INTERNAL ACCESS (zero-copy)
    // Returns Result<Option<R>> to distinguish:
    //   Ok(Some(r)) — key found, mapped via f
    //   Ok(None)    — key genuinely missing
    //   Err(e)      — RocksDB I/O or corruption error
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_value<F, R>(&self, key: &str, f: F) -> Result<Option<R>, ConsensusError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        match self.db.get_pinned_opt(&*buf, &self.read_opts) {
            Ok(Some(data)) => Ok(Some(f(&data))),
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("consensus", "consensus_mgr_read_failed", key => key, error => e);
                Err(StorageError::ReadFailed(format!("consensus_manager read '{}': {}", key, e)).into())
            }
        }
    }

    // ─────────────────────────────────────────
    // STORE TIP
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip(&self, key: &str, hash: &str) -> Result<(), ConsensusError> {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        if let Err(e) = self.db.put_opt(&*buf, hash.as_bytes(), &self.write_opts) {
            slog_error!("consensus", "tip_write_failed", key => key, error => e);
            return Err(StorageError::WriteFailed(format!("store_tip '{}': {}", key, e)).into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────
    // STORE IF NOT EXISTS
    // Returns Ok(true) if written, Ok(false) if already existed,
    // Err on any I/O failure (read OR write).
    //
    // NOTE: The get-then-put sequence is NOT atomic (TOCTOU).
    // This is acceptable under the single-writer assumption:
    // only one consensus thread writes tips at any given time.
    // If multi-writer access is ever introduced, this must be
    // replaced with a compare-and-swap or protected by a mutex.
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip_if_absent(&self, key: &str, hash: &str) -> Result<bool, ConsensusError> {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        match self.db.get_pinned_opt(&*buf, &self.read_opts) {
            Ok(Some(_)) => Ok(false), // Already exists
            Ok(None) => {
                if let Err(e) = self.db.put_opt(&*buf, hash.as_bytes(), &self.write_opts) {
                    slog_error!("consensus", "store_tip_write_failed", key => key, error => e);
                    return Err(StorageError::WriteFailed(
                        format!("store_tip_if_absent write '{}': {}", key, e)
                    ).into());
                }
                Ok(true)
            }
            Err(e) => {
                slog_error!("consensus", "store_tip_read_failed", key => key, error => e);
                Err(StorageError::ReadFailed(
                    format!("store_tip_if_absent read '{}': {}", key, e)
                ).into())
            }
        }
    }

    // ─────────────────────────────────────────
    // STORE MULTIPLE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip_batch(&self, entries: &[(&str, &str)]) -> Result<(), ConsensusError> {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for (key, hash) in entries {
            Self::build_key(&mut buf, key);
            batch.put(&*buf, hash.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("consensus", "tip_batch_write_failed", error => e);
            return Err(StorageError::WriteFailed(format!("store_tip_batch: {}", e)).into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────
    // DELETE MULTIPLE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_tip_batch(&self, keys: &[&str]) -> Result<(), ConsensusError> {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for key in keys {
            Self::build_key(&mut buf, key);
            batch.delete(&*buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("consensus", "tip_batch_delete_failed", error => e);
            return Err(StorageError::WriteFailed(format!("delete_tip_batch: {}", e)).into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────
    // GET TIP (zero-copy path)
    // Returns Err on storage failure (not None).
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_tip(&self, key: &str) -> Result<Option<String>, ConsensusError> {
        self.with_value(key, |data| {
            match std::str::from_utf8(data) {
                Ok(s) => Some(s.to_owned()),
                Err(_) => {
                    slog_error!("consensus", "tip_utf8_corrupt", key => key);
                    None
                }
            }
        }).map(|opt| opt.flatten())
    }

    // ─────────────────────────────────────────
    // GET RAW (copy only when needed)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_tip_raw(&self, key: &str) -> Result<Option<Vec<u8>>, ConsensusError> {
        self.with_value(key, |data| data.to_vec())
    }

    // ─────────────────────────────────────────
    // DELETE TIP
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_tip(&self, key: &str) -> Result<(), ConsensusError> {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        if let Err(e) = self.db.delete_opt(&*buf, &self.write_opts) {
            slog_error!("consensus", "tip_delete_failed", key => key, error => e);
            return Err(StorageError::WriteFailed(format!("delete_tip '{}': {}", key, e)).into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────
    // EXISTS (no copy)
    // Returns Err on storage failure (not false).
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &str) -> Result<bool, ConsensusError> {
        self.with_value(key, |_| ()).map(|opt| opt.is_some())
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
        format!("/tmp/test_consensus_mgr_{}", ts)
    }

    #[test]
    fn store_and_get_tip() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("best", "hash_abc").unwrap();
        assert_eq!(store.get_tip("best").unwrap(), Some("hash_abc".to_string()));
    }

    #[test]
    fn get_unknown_returns_none() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert_eq!(store.get_tip("nonexistent").unwrap(), None);
    }

    #[test]
    fn exists_check() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert!(!store.exists("tip").unwrap());
        store.store_tip("tip", "hash1").unwrap();
        assert!(store.exists("tip").unwrap());
    }

    #[test]
    fn delete_tip_removes() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("del", "hash").unwrap();
        assert!(store.exists("del").unwrap());
        store.delete_tip("del").unwrap();
        assert!(!store.exists("del").unwrap());
    }

    #[test]
    fn store_tip_if_absent_only_first() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert!(store.store_tip_if_absent("key", "first").unwrap());
        assert!(!store.store_tip_if_absent("key", "second").unwrap());
        assert_eq!(store.get_tip("key").unwrap(), Some("first".to_string()));
    }

    #[test]
    fn overwrite_tip() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("t", "v1").unwrap();
        store.store_tip("t", "v2").unwrap();
        assert_eq!(store.get_tip("t").unwrap(), Some("v2".to_string()));
    }

    #[test]
    fn store_tip_batch_writes_all() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip_batch(&[("a", "h1"), ("b", "h2"), ("c", "h3")]).unwrap();
        assert_eq!(store.get_tip("a").unwrap(), Some("h1".to_string()));
        assert_eq!(store.get_tip("b").unwrap(), Some("h2".to_string()));
        assert_eq!(store.get_tip("c").unwrap(), Some("h3".to_string()));
    }

    #[test]
    fn delete_tip_batch_removes_all() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip_batch(&[("x", "h1"), ("y", "h2")]).unwrap();
        store.delete_tip_batch(&["x", "y"]).unwrap();
        assert!(!store.exists("x").unwrap());
        assert!(!store.exists("y").unwrap());
    }

    #[test]
    fn get_tip_raw_returns_bytes() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("raw", "data").unwrap();
        let raw = store.get_tip_raw("raw").unwrap().unwrap();
        assert_eq!(raw, b"data");
    }
}
