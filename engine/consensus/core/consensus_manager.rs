// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, ReadOptions, WriteOptions, WriteBatch};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{ConsensusError, StorageError};

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
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_value<F, R>(&self, key: &str, f: F) -> Option<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        match self.db.get_pinned_opt(&*buf, &self.read_opts) {
            Ok(Some(data)) => Some(f(&data)),
            _ => None,
        }
    }

    // ─────────────────────────────────────────
    // STORE TIP
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip(&self, key: &str, hash: &str) {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        let _ = self.db.put_opt(&*buf, hash.as_bytes(), &self.write_opts);
    }

    // ─────────────────────────────────────────
    // STORE IF NOT EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip_if_absent(&self, key: &str, hash: &str) -> bool {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        if matches!(
            self.db.get_pinned_opt(&*buf, &self.read_opts),
            Ok(Some(_))
        ) {
            return false;
        }

        let _ = self.db.put_opt(&*buf, hash.as_bytes(), &self.write_opts);
        true
    }

    // ─────────────────────────────────────────
    // STORE MULTIPLE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_tip_batch(&self, entries: &[(&str, &str)]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for (key, hash) in entries {
            Self::build_key(&mut buf, key);
            batch.put(&*buf, hash.as_bytes());
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // DELETE MULTIPLE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_tip_batch(&self, keys: &[&str]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for key in keys {
            Self::build_key(&mut buf, key);
            batch.delete(&*buf);
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // GET TIP (zero-copy path)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_tip(&self, key: &str) -> Option<String> {
        self.with_value(key, |data| {
            std::str::from_utf8(data).ok().map(|s| s.to_owned())
        }).flatten()
    }

    // ─────────────────────────────────────────
    // GET RAW (copy only when needed)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_tip_raw(&self, key: &str) -> Option<Vec<u8>> {
        self.with_value(key, |data| data.to_vec())
    }

    // ─────────────────────────────────────────
    // DELETE TIP
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_tip(&self, key: &str) {
        let mut buf = Vec::with_capacity(64);
        Self::build_key(&mut buf, key);

        let _ = self.db.delete_opt(&*buf, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // EXISTS (no copy)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &str) -> bool {
        self.with_value(key, |_| ()).is_some()
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
        store.store_tip("best", "hash_abc");
        assert_eq!(store.get_tip("best"), Some("hash_abc".to_string()));
    }

    #[test]
    fn get_unknown_returns_none() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert_eq!(store.get_tip("nonexistent"), None);
    }

    #[test]
    fn exists_check() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert!(!store.exists("tip"));
        store.store_tip("tip", "hash1");
        assert!(store.exists("tip"));
    }

    #[test]
    fn delete_tip_removes() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("del", "hash");
        assert!(store.exists("del"));
        store.delete_tip("del");
        assert!(!store.exists("del"));
    }

    #[test]
    fn store_tip_if_absent_only_first() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        assert!(store.store_tip_if_absent("key", "first"));
        assert!(!store.store_tip_if_absent("key", "second"));
        assert_eq!(store.get_tip("key"), Some("first".to_string()));
    }

    #[test]
    fn overwrite_tip() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("t", "v1");
        store.store_tip("t", "v2");
        assert_eq!(store.get_tip("t"), Some("v2".to_string()));
    }

    #[test]
    fn store_tip_batch_writes_all() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip_batch(&[("a", "h1"), ("b", "h2"), ("c", "h3")]);
        assert_eq!(store.get_tip("a"), Some("h1".to_string()));
        assert_eq!(store.get_tip("b"), Some("h2".to_string()));
        assert_eq!(store.get_tip("c"), Some("h3".to_string()));
    }

    #[test]
    fn delete_tip_batch_removes_all() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip_batch(&[("x", "h1"), ("y", "h2")]);
        store.delete_tip_batch(&["x", "y"]);
        assert!(!store.exists("x"));
        assert!(!store.exists("y"));
    }

    #[test]
    fn get_tip_raw_returns_bytes() {
        let store = ConsensusManagerStore::new(&tmp_path()).unwrap();
        store.store_tip("raw", "data");
        let raw = store.get_tip_raw("raw").unwrap();
        assert_eq!(raw, b"data");
    }
}