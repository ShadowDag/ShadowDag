// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    BlockBasedOptions, Cache, SliceTransform, WriteBatch,
    IteratorMode, Direction,
};
use std::path::Path;
use crate::errors::StorageError;
use crate::slog_error;

// prefix
const KEY_PREFIX: &[u8] = b"pk:";
const PREFIX_LEN: usize = 3;
const PREFIX_UPPER_BOUND: &[u8] = b"pk:\xFF";

pub struct PublicKeyStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    read_opts_no_cache: ReadOptions,
}

impl PublicKeyStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32
        );

        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        let mut block_opts = BlockBasedOptions::default();
        let cache = Cache::new_lru_cache(64 * 1024 * 1024);

        block_opts.set_block_cache(&cache);
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        opts.set_block_based_table_factory(&block_opts);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);

        let mut read_opts_no_cache = ReadOptions::default();
        read_opts_no_cache.fill_cache(false);

        Ok(Self {
            db,
            write_opts,
            read_opts,
            read_opts_no_cache,
        })
    }

    // ─────────────────────────────────────────
    // INTERNAL KEY
    // ─────────────────────────────────────────
    #[inline(always)]
    fn build_key<F, R>(key_id: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(KEY_PREFIX);
        buf.extend_from_slice(key_id.as_bytes());
        f(&buf)
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store(&self, key_id: &str, key: &str) {
        self.store_raw(key_id, key.as_bytes());
    }

    #[inline(always)]
    pub fn store_raw(&self, key_id: &str, value: &[u8]) {
        Self::build_key(key_id, |k| {
            if let Err(e) = self.db.put_opt(k, value, &self.write_opts) {
                slog_error!("crypto", "public_key_store_write_failed", error => e);
            }
        });
    }

    // ─────────────────────────────────────────
    // STORE BATCH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_batch(&self, items: &[(&str, &str)]) {
        let mut batch = WriteBatch::default();

        for (key_id, key) in items {
            Self::build_key(key_id, |k| {
                batch.put(k, key.as_bytes());
            });
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "public_key_store_batch_write_failed", error => e);
        }
    }

    #[inline(always)]
    pub fn store_batch_raw(&self, items: &[(&str, &[u8])]) {
        let mut batch = WriteBatch::default();

        for (key_id, value) in items {
            Self::build_key(key_id, |k| {
                batch.put(k, value);
            });
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "public_key_store_batch_write_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // LOAD
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn load(&self, key_id: &str) -> Option<String> {
        self.load_raw(key_id)
            .and_then(|v| String::from_utf8(v).ok())
    }

    #[inline(always)]
    pub fn load_raw(&self, key_id: &str) -> Option<Vec<u8>> {
        Self::build_key(key_id, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .map(|v| v.as_ref().to_vec())
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn multi_get(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let mut real_keys = Vec::with_capacity(keys.len());

        for key_id in keys {
            Self::build_key(key_id, |k| {
                real_keys.push(k.to_vec());
            });
        }

        self.db.multi_get_opt(real_keys, &self.read_opts)
            .into_iter()
            .map(|r| r.ok().flatten().map(|v| v.to_vec()))
            .collect()
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key_id: &str) -> bool {
        Self::build_key(key_id, |k| {
            self.db.get_pinned_opt(k, &self.read_opts_no_cache)
                .map(|opt| opt.is_some())
                .unwrap_or(false)
        })
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete(&self, key_id: &str) {
        Self::build_key(key_id, |k| {
            if let Err(e) = self.db.delete_opt(k, &self.write_opts) {
                slog_error!("crypto", "public_key_store_delete_failed", error => e);
            }
        });
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_batch(&self, keys: &[&str]) {
        let mut batch = WriteBatch::default();

        for key_id in keys {
            Self::build_key(key_id, |k| {
                batch.delete(k);
            });
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "public_key_store_batch_delete_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // SCAN PREFIX (values + keys بدون prefix)
    // ─────────────────────────────────────────
    pub fn scan_prefix(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut opts = ReadOptions::default();
        opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND);

        let iter = self.db.iterator_opt(
            IteratorMode::From(KEY_PREFIX, Direction::Forward),
            opts,
        );

        let mut result = Vec::with_capacity(128);

        for item in iter {
            let (k, v) = match item {
                Ok(pair) => pair,
                Err(_) => break,
            };

            if !k.starts_with(KEY_PREFIX) {
                break;
            }

            // إزالة prefix
            let key = k[PREFIX_LEN..].to_vec();

            result.push((key, v.to_vec()));
        }

        result
    }

    // ─────────────────────────────────────────
    // SCAN KEYS ONLY (🔥 أخف)
    // ─────────────────────────────────────────
    pub fn scan_keys(&self) -> Vec<Vec<u8>> {
        let mut opts = ReadOptions::default();
        opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND);

        let iter = self.db.iterator_opt(
            IteratorMode::From(KEY_PREFIX, Direction::Forward),
            opts,
        );

        let mut result = Vec::with_capacity(128);

        for item in iter {
            let (k, _) = match item {
                Ok(pair) => pair,
                Err(_) => break,
            };

            if !k.starts_with(KEY_PREFIX) {
                break;
            }

            result.push(k[PREFIX_LEN..].to_vec());
        }

        result
    }

    // ─────────────────────────────────────────
    // PREFIX UPPER BOUND
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn prefix_upper_bound() -> &'static [u8] {
        PREFIX_UPPER_BOUND
    }
}