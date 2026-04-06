// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    WriteBatch, DBPinnableSlice,
    IteratorMode, Direction,
    BlockBasedOptions, SliceTransform, Cache,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{DagError, StorageError};

// prefix
const PARENT_PREFIX: &[u8] = b"parent:";
const RANGE_END_SUFFIX: u8 = 0xFF;

pub struct ParentValidatorStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    iter_read_opts: ReadOptions,
    range_end: Vec<u8>, // 🔥 ثابت
}

impl ParentValidatorStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) as i32;

        opts.increase_parallelism(cpus);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        // prefix extractor
        opts.set_prefix_extractor(
            SliceTransform::create_fixed_prefix(PARENT_PREFIX.len())
        );

        // cache + bloom
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(
            &Cache::new_lru_cache(128 * 1024 * 1024)
        );
        block_opts.set_bloom_filter(10.0, false);

        opts.set_block_based_table_factory(&block_opts);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Parent validation is consensus-critical — durable writes.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        // read opts
        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        read_opts.set_total_order_seek(false);

        // 🔥 range_end يبنى مرة وحدة فقط
        let mut range_end = Vec::with_capacity(PARENT_PREFIX.len() + 1);
        range_end.extend_from_slice(PARENT_PREFIX);
        range_end.push(RANGE_END_SUFFIX);

        // iterator opts
        let mut iter_read_opts = ReadOptions::default();
        iter_read_opts.set_prefix_same_as_start(true);
        iter_read_opts.set_total_order_seek(false);
        iter_read_opts.fill_cache(false);
        iter_read_opts.set_iterate_upper_bound(range_end.clone());

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
            iter_read_opts,
            range_end,
        })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn make_key(key: &str) -> Vec<u8> {
        let mut full = Vec::with_capacity(PARENT_PREFIX.len() + key.len());
        full.extend_from_slice(PARENT_PREFIX);
        full.extend_from_slice(key.as_bytes());
        full
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    pub fn store_parent_check(&self, key: &str, value: &str) {
        if let Err(e) = self.db.put_opt(
            Self::make_key(key),
            value.as_bytes(),
            &self.write_opts,
        ) {
            eprintln!("[ParentValidatorStore] put error: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // STORE BATCH
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: &[(&str, &str)]) {
        let mut batch = WriteBatch::default();

        for &(key, value) in items {
            batch.put(Self::make_key(key), value.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[ParentValidatorStore] batch write error: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    pub fn get_parent_check(&self, key: &str) -> Option<String> {
        self.db.get_pinned_opt(Self::make_key(key), &self.read_opts)
            .ok()
            .flatten()
            .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
    }

    // ─────────────────────────────────────────
    // RAW GET
    // ─────────────────────────────────────────
    pub fn get_raw(&self, key: &str) -> Option<DBPinnableSlice<'_>> {
        self.db.get_pinned_opt(Self::make_key(key), &self.read_opts)
            .ok()
            .flatten()
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    pub fn exists(&self, key: &str) -> bool {
        self.db.get_pinned_opt(Self::make_key(key), &self.read_opts)
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    // ─────────────────────────────────────────
    // MULTI GET (🔥 optimized)
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&str]) -> Vec<Option<String>> {
        let mut rocks_keys = Vec::with_capacity(keys.len());

        for &k in keys {
            rocks_keys.push(Self::make_key(k));
        }

        let mut result = Vec::with_capacity(keys.len());

        for res in self.db.multi_get_opt(rocks_keys, &self.read_opts) {
            result.push(
                res.ok()
                    .flatten()
                    .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
            );
        }

        result
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    pub fn delete_parent_check(&self, key: &str) {
        if let Err(e) = self.db.delete_opt(Self::make_key(key), &self.write_opts) {
            eprintln!("[ParentValidatorStore] delete error: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // DELETE ALL (🔥 zero alloc)
    // ─────────────────────────────────────────
    pub fn delete_all(&self) {
        let iter = self.db.prefix_iterator(PARENT_PREFIX);
        for (k, _) in iter.flatten() {
            if !k.starts_with(PARENT_PREFIX) { break; }
            let _ = self.db.delete(&*k);
        }
    }

    // ─────────────────────────────────────────
    // ITERATOR (🔥 fastest path)
    // ─────────────────────────────────────────
    pub fn iter_prefix<F>(&self, mut f: F)
    where
        F: FnMut(&[u8], &[u8]),
    {
        let mut iter_opts = ReadOptions::default();
        iter_opts.set_prefix_same_as_start(true);
        iter_opts.set_total_order_seek(false);
        let iter = self.db.iterator_opt(
            IteratorMode::From(PARENT_PREFIX, Direction::Forward),
            iter_opts,
        );

        for (key, value) in iter.flatten() {
            f(&key[PARENT_PREFIX.len()..], &value);
        }
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("[ParentValidatorStore] flush error: {}", e);
        }
    }
}