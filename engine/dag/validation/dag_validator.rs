// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, DBCompressionType, DBPinnableSlice, Direction, IteratorMode, Options,
    ReadOptions, SliceTransform, WriteBatch, WriteOptions, DB,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{DagError, StorageError};
use crate::slog_error;

// prefix
const VALIDATION_PREFIX: &[u8] = b"val:";

/// Persistent key-value store for validation results.
///
/// NOTE: This is a **storage wrapper**, not a block validator. It does not
/// perform structural checks such as parent existence or ordering.
///
/// Parent existence is enforced in `DagManager::add_block_validated()`
/// (`engine/dag/core/dag_manager.rs`) which rejects blocks whose parents
/// are not already in the DAG (`if !self.block_exists(p)`).
///
/// Parent ordering (strict ascending lexicographic) is likewise enforced
/// in `DagManager::add_block_validated()`.
pub struct DagValidatorStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl DagValidatorStore {
    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut opts = Options::default();

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        opts.create_if_missing(true);
        opts.increase_parallelism(cpus as i32);
        opts.set_max_background_jobs(cpus as i32);
        opts.set_max_open_files(1000);

        // compaction
        opts.optimize_level_style_compaction(256 * 1024 * 1024);
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_max_bytes_for_level_base(256 * 1024 * 1024);

        // memory
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);

        // stall prevention
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(20);
        opts.set_level_zero_stop_writes_trigger(36);

        // concurrency
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_pipelined_write(true);

        // IO
        opts.set_bytes_per_sync(1024 * 1024);
        opts.set_use_fsync(true);
        opts.set_atomic_flush(true);

        // compression
        opts.set_compression_type(DBCompressionType::Lz4);

        // prefix
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(VALIDATION_PREFIX.len()));
        opts.set_memtable_prefix_bloom_ratio(0.1);

        // cache
        let cache = Cache::new_lru_cache(128 * 1024 * 1024);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&cache);
        block_opts.set_bloom_filter(10.0, false);
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        opts.set_block_based_table_factory(&block_opts);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false); // ⚠️ mainnet = false

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);
        read_opts.set_verify_checksums(false);

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
    fn build_key_into(buf: &mut Vec<u8>, key: &str) {
        buf.clear();
        buf.extend_from_slice(VALIDATION_PREFIX);
        buf.extend_from_slice(key.as_bytes());
    }

    // ─────────────────────────────────────────
    // STORE SINGLE
    // ─────────────────────────────────────────
    pub fn store_validation(&self, key: &str, value: &str) {
        let mut buf = Vec::with_capacity(VALIDATION_PREFIX.len() + key.len());
        Self::build_key_into(&mut buf, key);

        if let Err(e) = self.db.put_opt(&buf, value.as_bytes(), &self.write_opts) {
            slog_error!("dag_validator", "store_validation_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // STORE BATCH
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: Vec<(&str, &str)>) {
        let mut batch = WriteBatch::default();
        let mut key_buf = Vec::with_capacity(64);

        for (key, value) in items {
            Self::build_key_into(&mut key_buf, key);
            batch.put(&key_buf, value.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("dag_validator", "store_batch_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    pub fn get_validation(&self, key: &str) -> Option<String> {
        let mut buf = Vec::with_capacity(VALIDATION_PREFIX.len() + key.len());
        Self::build_key_into(&mut buf, key);

        self.db
            .get_pinned_opt(&buf, &self.read_opts)
            .ok()
            .flatten()
            .and_then(Self::pinned_to_string)
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: Vec<&str>) -> Vec<Option<String>> {
        let mut key_bufs = Vec::with_capacity(keys.len());

        for k in keys {
            let mut buf = Vec::with_capacity(VALIDATION_PREFIX.len() + k.len());
            Self::build_key_into(&mut buf, k);
            key_bufs.push(buf);
        }

        self.db
            .multi_get_opt(key_bufs, &self.read_opts)
            .into_iter()
            .map(|res| {
                res.ok()
                    .flatten()
                    .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
            })
            .collect()
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    pub fn delete_validation(&self, key: &str) {
        let mut buf = Vec::with_capacity(VALIDATION_PREFIX.len() + key.len());
        Self::build_key_into(&mut buf, key);

        let _ = self.db.delete_opt(&buf, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // PREFIX SCAN
    // ─────────────────────────────────────────
    pub fn scan_prefix(&self) -> Vec<(String, String)> {
        let mut ro = ReadOptions::default();
        ro.set_prefix_same_as_start(true);
        ro.set_readahead_size(64 * 1024);

        let mut upper = Vec::with_capacity(VALIDATION_PREFIX.len() + 1);
        upper.extend_from_slice(VALIDATION_PREFIX);
        upper.push(0xFF);
        ro.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_opt(
            IteratorMode::From(VALIDATION_PREFIX, Direction::Forward),
            ro,
        );

        let mut result = Vec::new();

        for (k, v) in iter.flatten() {
            let key = &k[VALIDATION_PREFIX.len()..];

            if let (Ok(k), Ok(v)) = (std::str::from_utf8(key), std::str::from_utf8(&v)) {
                result.push((k.to_string(), v.to_string()));
            }
        }

        result
    }

    // ─────────────────────────────────────────
    // INTERNAL
    // ─────────────────────────────────────────
    #[inline(always)]
    fn pinned_to_string(data: DBPinnableSlice) -> Option<String> {
        std::str::from_utf8(&data).ok().map(|s| s.to_string())
    }
}
