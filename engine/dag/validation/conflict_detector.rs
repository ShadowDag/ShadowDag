// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    WriteBatch, DBPinnableSlice,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{DagError, StorageError};

const CONFLICT_PREFIX: &[u8] = b"conflict:";

pub struct ConflictStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl ConflictStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Conflict detection is safety-critical — must survive crashes.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        let read_opts = ReadOptions::default();

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
    fn make_key_into(buf: &mut Vec<u8>, key: &str) {
        buf.clear();
        buf.reserve_exact(CONFLICT_PREFIX.len() + key.len());
        buf.extend_from_slice(CONFLICT_PREFIX);
        buf.extend_from_slice(key.as_bytes());
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline]
    pub fn store_conflict(&self, key: &str, value: &str) {
        self.store_bytes(key, value.as_bytes());
    }

    #[inline]
    pub fn store_bytes(&self, key: &str, value: &[u8]) {
        let mut k = Vec::with_capacity(CONFLICT_PREFIX.len() + key.len());
        Self::make_key_into(&mut k, key);

        if let Err(e) = self.db.put_opt(k, value, &self.write_opts) {
            eprintln!("[ConflictStore::store] {}", e);
        }
    }

    // ─────────────────────────────────────────
    // STORE IF ABSENT (true check first)
    // ─────────────────────────────────────────
    pub fn store_if_absent(&self, key: &str, value: &str) -> bool {
        let mut k = Vec::with_capacity(CONFLICT_PREFIX.len() + key.len());
        Self::make_key_into(&mut k, key);

        // ✅ تحقق أولاً (actual absent)
        match self.db.get_pinned_opt(&k, &self.read_opts) {
            Ok(Some(_)) => return false,
            Ok(None) => {}
            Err(e) => {
                eprintln!("[ConflictStore::store_if_absent:get] {}", e);
                return false;
            }
        }

        // كتابة
        if let Err(e) = self.db.put_opt(&k, value.as_bytes(), &self.write_opts) {
            eprintln!("[ConflictStore::store_if_absent:put] {}", e);
            return false;
        }

        true
    }

    // ─────────────────────────────────────────
    // STORE BATCH
    // ─────────────────────────────────────────
    pub fn store_batch(&self, entries: &[(String, String)]) {
        let mut batch = WriteBatch::default();
        let mut key_buf = Vec::new();

        for (key, value) in entries {
            Self::make_key_into(&mut key_buf, key);
            batch.put(&key_buf, value.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[ConflictStore::batch_store] {}", e);
        }
    }

    // ─────────────────────────────────────────
    // GET PINNED
    // ─────────────────────────────────────────
    #[inline]
    pub fn get_pinned(&self, key: &str) -> Option<DBPinnableSlice<'_>> {
        let mut k = Vec::with_capacity(CONFLICT_PREFIX.len() + key.len());
        Self::make_key_into(&mut k, key);

        self.db.get_pinned_opt(k, &self.read_opts).ok().flatten()
    }

    // ─────────────────────────────────────────
    // MULTI GET PINNED
    // ─────────────────────────────────────────
    pub fn get_pinned_multi(&self, keys: &[String]) -> Vec<Option<Vec<u8>>> {
        let mut keys_vec = Vec::with_capacity(keys.len());

        for k in keys {
            let mut buf = Vec::with_capacity(CONFLICT_PREFIX.len() + k.len());
            Self::make_key_into(&mut buf, k);
            keys_vec.push(buf);
        }

        let mut result = Vec::with_capacity(keys.len());

        for r in self.db.multi_get_opt(keys_vec, &self.read_opts) {
            result.push(r.ok().flatten());
        }

        result
    }

    // ─────────────────────────────────────────
    // GET RAW
    // ─────────────────────────────────────────
    #[inline]
    pub fn get_raw(&self, key: &str) -> Option<Vec<u8>> {
        self.get_pinned(key).map(|d| d.to_vec())
    }

    // ─────────────────────────────────────────
    // GET STRING
    // ─────────────────────────────────────────
    #[inline]
    pub fn get_conflict(&self, key: &str) -> Option<String> {
        self.get_pinned(key)
            .and_then(|d| std::str::from_utf8(&d).ok().map(|s| s.to_string()))
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline]
    pub fn exists(&self, key: &str) -> bool {
        let mut k = Vec::with_capacity(CONFLICT_PREFIX.len() + key.len());
        Self::make_key_into(&mut k, key);

        self.db
            .get_pinned_opt(k, &self.read_opts)
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    pub fn delete_conflict(&self, key: &str) {
        let mut k = Vec::with_capacity(CONFLICT_PREFIX.len() + key.len());
        Self::make_key_into(&mut k, key);

        if let Err(e) = self.db.delete_opt(k, &self.write_opts) {
            eprintln!("[ConflictStore::delete] {}", e);
        }
    }

    // ─────────────────────────────────────────
    // DELETE IF EXISTS
    // ─────────────────────────────────────────
    pub fn delete_if_exists(&self, key: &str) -> bool {
        if !self.exists(key) {
            return false;
        }

        self.delete_conflict(key);
        true
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    pub fn delete_batch(&self, keys: &[String]) {
        let mut batch = WriteBatch::default();
        let mut key_buf = Vec::new();

        for key in keys {
            Self::make_key_into(&mut key_buf, key);
            batch.delete(&key_buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[ConflictStore::batch_delete] {}", e);
        }
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("[ConflictStore::flush] {}", e);
        }
    }

    // ─────────────────────────────────────────
    // DEBUG
    // ─────────────────────────────────────────
    pub fn len_hint(&self) -> usize {
        self.db
            .property_int_value("rocksdb.estimate-num-keys")
            .unwrap_or(Some(0))
            .unwrap_or(0) as usize
    }

}