// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    WriteBatch, DBPinnableSlice, IteratorMode,
};
use std::path::Path;
use crate::errors::CryptoError;

const CLEAR_BATCH_SIZE: usize = 1000;

pub struct Blake3Store {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl Blake3Store {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| CryptoError::Other(format!("[Blake3Store] cannot open DB: {}", e)))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_verify_checksums(false);

        Ok(Self {
            db,
            write_opts,
            read_opts,
        })
    }

    // ─────────────────────────────────────────
    // CORE
    // ─────────────────────────────────────────
    #[inline(always)]
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), rocksdb::Error> {
        self.db.put_opt(key, value, &self.write_opts)
    }

    #[inline(always)]
    fn delete(&self, key: &[u8]) -> Result<(), rocksdb::Error> {
        self.db.delete_opt(key, &self.write_opts)
    }

    // 🔥 optimized read (uses pinned internally)
    #[inline(always)]
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.db.get_pinned_opt(key, &self.read_opts) {
            Ok(Some(v)) => Some(v.to_vec()),
            _ => None,
        }
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_hash(&self, key: &str, hash: &str) {
        self.store_bytes(key.as_bytes(), hash.as_bytes());
    }

    #[inline(always)]
    pub fn store_bytes(&self, key: &[u8], value: &[u8]) {
        if let Err(e) = self.put(key, value) {
            eprintln!("[Blake3Store] CRITICAL: DB write failed: {}", e);
        }
    }

    // 🔥 أقل syscalls
    pub fn store_if_absent(&self, key: &[u8], value: &[u8]) -> bool {
        let exists = matches!(
            self.db.get_pinned_opt(key, &self.read_opts),
            Ok(Some(_))
        );

        if exists {
            return false;
        }

        if self.put(key, value).is_ok() {
            return true;
        }

        // fallback (race)
        !matches!(
            self.db.get_pinned_opt(key, &self.read_opts),
            Ok(Some(_))
        )
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub fn get_hash(&self, key: &str) -> Option<String> {
        self.get(key.as_bytes())
            .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_owned()))
    }

    #[inline(always)]
    #[must_use]
    pub fn get_bytes(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key)
    }

    #[inline(always)]
    pub fn get_pinned(&self, key: &[u8]) -> Option<DBPinnableSlice<'_>> {
        self.db.get_pinned_opt(key, &self.read_opts).unwrap_or_default()
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&[u8]]) -> Vec<Option<Vec<u8>>> {
        self.db
            .multi_get_opt(keys, &self.read_opts)
            .into_iter()
            .map(|r| match r {
                Ok(Some(v)) => Some(v.to_vec()),
                _ => None,
            })
            .collect()
    }

    pub fn multi_get_pinned(&self, keys: &[&[u8]]) -> Vec<Option<Vec<u8>>> {
        self.db
            .multi_get_opt(keys, &self.read_opts)
            .into_iter()
            .map(|r| r.ok().flatten())
            .collect()
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_hash(&self, key: &str) {
        self.delete_bytes(key.as_bytes());
    }

    #[inline(always)]
    pub fn delete_bytes(&self, key: &[u8]) {
        if let Err(e) = self.delete(key) {
            eprintln!("[Blake3Store] CRITICAL: DB delete failed: {}", e);
        }
    }

    pub fn delete_if_exists(&self, key: &[u8]) -> bool {
        match self.db.get_pinned_opt(key, &self.read_opts) {
            Ok(Some(_)) => self.delete(key).is_ok(),
            _ => false,
        }
    }

    // ─────────────────────────────────────────
    // BATCH
    // ─────────────────────────────────────────
    pub fn batch_store(&self, items: &[(&[u8], &[u8])]) {
        let mut batch = WriteBatch::default();

        for (k, v) in items {
            batch.put(k, v);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[Blake3Store] CRITICAL: DB batch write failed: {}", e);
        }
    }

    pub fn batch_store_str(&self, items: &[(&str, &str)]) {
        let mut batch = WriteBatch::default();

        for (k, v) in items {
            batch.put(k.as_bytes(), v.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[Blake3Store] CRITICAL: DB batch write failed: {}", e);
        }
    }

    pub fn batch_delete(&self, keys: &[&[u8]]) {
        let mut batch = WriteBatch::default();

        for k in keys {
            batch.delete(k);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[Blake3Store] CRITICAL: DB batch delete failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // MAINTENANCE
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("[Blake3Store] CRITICAL: DB flush failed: {}", e);
        }
    }

    pub fn clear(&self) {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        for item in self.db.iterator(IteratorMode::Start) {
            let (k, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            batch.delete(&*k);
            count += 1;

            if count >= CLEAR_BATCH_SIZE {
                if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                    eprintln!("[Blake3Store] CRITICAL: DB clear failed: {}", e);
                    return;
                }

                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                eprintln!("[Blake3Store] CRITICAL: DB clear failed: {}", e);
            }
        }
    }

    #[must_use]
    pub fn len_estimate(&self) -> u64 {
        self.db.property_int_value("rocksdb.estimate-num-keys")
            .unwrap_or(None)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        if self.len_estimate() == 0 {
            return true;
        }

        matches!(self.db.iterator(IteratorMode::Start).next(), None | Some(Err(_)))
    }

    pub fn set_sync(&mut self, enabled: bool) {
        self.write_opts.set_sync(enabled);
    }
}