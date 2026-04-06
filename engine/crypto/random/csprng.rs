// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions, WriteBatch,
    BlockBasedOptions, Cache, SliceTransform,
    DBPinnableSlice,
};
use std::path::Path;
use crate::errors::CryptoError;

// ─────────────────────────────────────────
// PREFIX
// ─────────────────────────────────────────
const PREFIX: &[u8] = b"csprng:";
const PREFIX_LEN: usize = 7;
const PREFIX_UPPER_BOUND: &[u8] = b"csprng:\xFF";
const DELETE_BATCH_SIZE: usize = 1000;

pub struct CSPRNG {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    iter_read_opts: ReadOptions,
}

impl CSPRNG {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32
        );

        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(64 * 1024 * 1024));
        opts.set_block_based_table_factory(&block_opts);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| CryptoError::Other(format!("[CSPRNG] cannot open DB: {}", e)))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);

        let mut iter_read_opts = ReadOptions::default();
        iter_read_opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND);
        iter_read_opts.set_prefix_same_as_start(true);
        iter_read_opts.fill_cache(false);

        Ok(Self {
            db,
            write_opts,
            read_opts,
            iter_read_opts,
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
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_state(&self, key: &[u8], value: &[u8]) {
        Self::with_key(key, |k| {
            if let Err(e) = self.db.put_opt(k, value, &self.write_opts) {
                eprintln!("[CSPRNG] CRITICAL: store_state failed: {}", e);
            }
        });
    }

    // ─────────────────────────────────────────
    // STORE BATCH (🔥 مهم)
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: &[(&[u8], &[u8])]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for (key, value) in items {
            buf.clear();
            buf.extend_from_slice(PREFIX);
            buf.extend_from_slice(key);
            batch.put(&*buf, value);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[CSPRNG] CRITICAL: store_batch failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // LOAD
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn load_state(&self, key: &[u8]) -> Option<Vec<u8>> {
        Self::with_key(key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(data)) => Some(data.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("[CSPRNG] CRITICAL: load_state failed: {}", e);
                    None
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // LOAD PINNED
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn load_state_pinned(&self, key: &[u8]) -> Option<DBPinnableSlice<'_>> {
        Self::with_key(key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(data)) => Some(data),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("[CSPRNG] CRITICAL: load_state_pinned failed: {}", e);
                    None
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET (ZERO COPY)
    // ─────────────────────────────────────────
    pub fn multi_get_pinned(&self, keys: &[&[u8]]) -> Vec<Option<DBPinnableSlice<'_>>> {
        keys.iter()
            .map(|k| self.load_state_pinned(k))
            .collect()
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_state(&self, key: &[u8]) {
        Self::with_key(key, |k| {
            if let Err(e) = self.db.delete_opt(k, &self.write_opts) {
                eprintln!("[CSPRNG] CRITICAL: delete_state failed: {}", e);
            }
        });
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    pub fn delete_batch(&self, keys: &[&[u8]]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for key in keys {
            buf.clear();
            buf.extend_from_slice(PREFIX);
            buf.extend_from_slice(key);
            batch.delete(&*buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[CSPRNG] CRITICAL: delete_batch failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &[u8]) -> bool {
        Self::with_key(key, |k| {
            if !self.db.key_may_exist_opt(k, &self.read_opts) {
                return false;
            }

            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    eprintln!("[CSPRNG] CRITICAL: exists check failed: {}", e);
                    false
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("[CSPRNG] CRITICAL: flush failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // CLEAR ALL
    // ─────────────────────────────────────────
    pub fn clear_all(&self) {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        let iter = self.db.prefix_iterator(PREFIX);

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            if !key.starts_with(PREFIX) {
                break;
            }

            batch.delete(&*key);
            count += 1;

            if count >= DELETE_BATCH_SIZE {
                if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                    eprintln!("[CSPRNG] CRITICAL: clear_all batch failed: {}", e);
                    return;
                }
                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                eprintln!("[CSPRNG] CRITICAL: clear_all final batch failed: {}", e);
            }
        }
    }
}