// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    DBPinnableSlice, WriteBatch,
    SliceTransform,
    IteratorMode, Direction,
};
use std::path::Path;
use crate::errors::StorageError;

// ─────────────────────────────────────────
// PREFIX
// ─────────────────────────────────────────
const PREFIX: &[u8] = b"entropy:";
const PREFIX_LEN: usize = 8;
const PREFIX_UPPER_BOUND: &[u8] = b"entropy:\xFF";
const DELETE_BATCH_SIZE: usize = 1000;

pub struct EntropyStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    _iter_read_opts: ReadOptions,
}

impl EntropyStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32
        );

        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_verify_checksums(false);

        // 🔥 iterator tuning
        let mut _iter_read_opts = ReadOptions::default();
        _iter_read_opts.set_iterate_lower_bound(PREFIX.to_vec());
        _iter_read_opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND.to_vec());
        _iter_read_opts.set_prefix_same_as_start(true); // 🔥 مهم

        Ok(Self {
            db,
            write_opts,
            read_opts,
            _iter_read_opts,
        })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_key<F, R>(key: &[u8], f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(PREFIX);
        buf.extend_from_slice(key);
        f(&buf)
    }

    // ─────────────────────────────────────────
    // PUT
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        Self::with_key(key, |k| {
            self.db.put_opt(k, value, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("DB put: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get(&self, key: &[u8]) -> Result<Option<DBPinnableSlice<'_>>, StorageError> {
        Self::with_key(key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .map_err(|e| StorageError::Other(format!("DB get: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // GET BYTES (🔥 بدون UTF8)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.get(key)?
            .map(|v| v.to_vec()))
    }

    // ─────────────────────────────────────────
    // GET STRING
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_string(&self, key: &[u8]) -> Result<Option<String>, StorageError> {
        match self.get(key)? {
            Some(data) => {
                let s = std::str::from_utf8(&data)
                    .map_err(|e| StorageError::Serialization(format!("UTF8: {}", e)))?;
                Ok(Some(s.to_owned()))
            }
            None => Ok(None),
        }
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        Self::with_key(key, |k| {
            self.db.delete_opt(k, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("DB delete: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(key)?.is_some())
    }

    // ─────────────────────────────────────────
    // BATCH PUT
    // ─────────────────────────────────────────
    pub fn batch_put(&self, items: &[(&[u8], &[u8])]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for (key, value) in items {
            Self::with_key(key, |k| batch.put(k, *value));
        }

        self.db.write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("DB batch_put: {}", e)))
    }

    // ─────────────────────────────────────────
    // BATCH DELETE
    // ─────────────────────────────────────────
    pub fn batch_delete(&self, keys: &[&[u8]]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for key in keys {
            Self::with_key(key, |k| batch.delete(k));
        }

        self.db.write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("DB batch_delete: {}", e)))
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    pub fn multi_get(
        &self,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StorageError> {

        let mut prefixed = Vec::with_capacity(keys.len());

        for k in keys {
            let mut v = Vec::with_capacity(PREFIX.len() + k.len());
            v.extend_from_slice(PREFIX);
            v.extend_from_slice(k);
            prefixed.push(v);
        }

        let results = self.db.multi_get(prefixed);

        Ok(results.into_iter()
            .map(|r| r.ok().flatten().map(|v| v.to_vec()))
            .collect())
    }

    // ─────────────────────────────────────────
    // SCAN
    // ─────────────────────────────────────────
    fn new_iter_opts() -> ReadOptions {
        let mut opts = ReadOptions::default();
        opts.set_prefix_same_as_start(true);
        opts.fill_cache(false);
        opts
    }

    pub fn scan(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::with_capacity(128);

        let iter = self.db.iterator_opt(
            IteratorMode::From(PREFIX, Direction::Forward),
            Self::new_iter_opts(),
        );

        for (k, v) in iter.flatten() {
            out.push((k.to_vec(), v.to_vec()));
        }

        out
    }

    // ─────────────────────────────────────────
    // SCAN KEYS
    // ─────────────────────────────────────────
    pub fn scan_keys(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(128);

        let iter = self.db.iterator_opt(
            IteratorMode::From(PREFIX, Direction::Forward),
            Self::new_iter_opts(),
        );

        for (k, _) in iter.flatten() {
            out.push(k.to_vec());
        }

        out
    }

    // ─────────────────────────────────────────
    // CLEAR
    // ─────────────────────────────────────────
    pub fn clear_all(&self) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        let iter = self.db.iterator_opt(
            IteratorMode::From(PREFIX, Direction::Forward),
            Self::new_iter_opts(),
        );

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            batch.delete(&*key);
            count += 1;

            if count >= DELETE_BATCH_SIZE {
                self.db.write_opt(batch, &self.write_opts)
                    .map_err(|e| StorageError::WriteFailed(format!("DB clear batch: {}", e)))?;
                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            self.db.write_opt(batch, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("DB final clear: {}", e)))?;
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    // LEGACY
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn add_entropy(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.put(key.as_bytes(), value.as_bytes())
    }

    #[inline(always)]
    pub fn get_entropy(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.get_string(key.as_bytes())
    }
}