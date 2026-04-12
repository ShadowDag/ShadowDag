// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions, WriteBatch,
    BlockBasedOptions, Cache, SliceTransform,
    IteratorMode, Direction,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{ConsensusError, StorageError};
use crate::slog_error;

pub struct ConsensusValidatorStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl ConsensusValidatorStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────

    pub fn new(path: &str) -> Result<Self, ConsensusError> {

        let mut opts = Options::default();
        opts.create_if_missing(true);

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32
        );

        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        let mut block_opts = BlockBasedOptions::default();

        let cache = Cache::new_lru_cache(256 * 1024 * 1024);
        block_opts.set_block_cache(&cache);

        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        block_opts.set_bloom_filter(10.0, false);

        opts.set_block_based_table_factory(&block_opts);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(1));

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Consensus validation state — must be durable across crashes.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
        })
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn store_result(&self, key: &str, value: &str) -> bool {
        match self.db.put_opt(key.as_bytes(), value.as_bytes(), &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "store_result_failed", key => key, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // BATCH STORE
    // ─────────────────────────────────────────

    pub fn store_batch(&self, items: &[(&str, &str)]) -> bool {

        if items.is_empty() {
            return true;
        }

        let mut batch = WriteBatch::default();

        for (k, v) in items {
            batch.put(k.as_bytes(), v.as_bytes());
        }

        match self.db.write_opt(batch, &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "store_batch_failed", count => items.len(), error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // BATCH DELETE
    // ─────────────────────────────────────────

    pub fn delete_batch(&self, keys: &[&str]) -> bool {

        if keys.is_empty() {
            return true;
        }

        let mut batch = WriteBatch::default();

        for k in keys {
            batch.delete(k.as_bytes());
        }

        match self.db.write_opt(batch, &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "delete_batch_failed", count => keys.len(), error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn delete(&self, key: &str) -> bool {
        match self.db.delete_opt(key.as_bytes(), &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "delete_failed", key => key, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn exists(&self, key: &str) -> bool {
        match self.db.get_pinned_opt(key.as_bytes(), &self.read_opts) {
            Ok(v) => v.is_some(),
            Err(e) => {
                slog_error!("consensus", "exists_check_failed", key => key, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn get_result(&self, key: &str) -> Option<String> {
        match self.db.get_pinned_opt(key.as_bytes(), &self.read_opts) {
            Ok(Some(v)) => {
                std::str::from_utf8(v.as_ref()).ok().map(str::to_owned)
            }
            Ok(None) => None,
            Err(e) => {
                slog_error!("consensus", "get_result_db_error", key => key, error => &e.to_string());
                None
            }
        }
    }

    // ─────────────────────────────────────────
    // GET RAW (🔥 zero-copy path)
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn get_raw(&self, key: &str) -> Option<Vec<u8>> {
        match self.db.get_pinned_opt(key.as_bytes(), &self.read_opts) {
            Ok(Some(v)) => Some(v.to_vec()),
            Ok(None) => None,
            Err(e) => {
                slog_error!("consensus", "get_raw_db_error", key => key, error => &e.to_string());
                None
            }
        }
    }

    // ─────────────────────────────────────────
    // FAST CHECK
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn is_validated(&self, hash: &str) -> bool {
        match self.db.get_pinned_opt(hash.as_bytes(), &self.read_opts) {
            Ok(Some(v)) => v.as_ref() == b"ok",
            Ok(None) => false,
            Err(e) => {
                slog_error!("consensus", "is_validated_db_error", hash => hash, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // MARK VALID
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn mark_validated(&self, hash: &str) -> bool {
        match self.db.put_opt(hash.as_bytes(), b"ok", &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "mark_validated_failed", hash => hash, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // MARK REJECTED
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn mark_rejected(&self, hash: &str, reason: &str) -> bool {

        let mut value = Vec::with_capacity(reason.len() + 9);
        value.extend_from_slice(b"rejected:");
        value.extend_from_slice(reason.as_bytes());

        match self.db.put_opt(hash.as_bytes(), value, &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "mark_rejected_failed", hash => hash, error => &e.to_string());
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // STATUS
    // ─────────────────────────────────────────

    pub fn get_status(&self, hash: &str) -> Option<ValidationStatus> {

        let val = self.get_result(hash)?;

        if val == "ok" {
            return Some(ValidationStatus::Valid);
        }

        if let Some(reason) = val.strip_prefix("rejected:") {
            return Some(ValidationStatus::Rejected(reason.to_owned()));
        }

        None
    }

    // ─────────────────────────────────────────
    // PREFIX CLEAR (🔥 DAG pruning)
    // ─────────────────────────────────────────

    pub fn clear_prefix(&self, prefix: &str) -> bool {

        let mut batch = WriteBatch::default();

        let iter = self.db.iterator(IteratorMode::From(
            prefix.as_bytes(),
            Direction::Forward,
        ));

        for item in iter {
            match item {
                Ok((k, _)) => {
                    if !k.starts_with(prefix.as_bytes()) {
                        break;
                    }
                    batch.delete(&*k);
                }
                Err(_) => break,
            }
        }

        match self.db.write_opt(batch, &self.write_opts) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("consensus", "clear_prefix_failed", prefix => prefix, error => &e.to_string());
                false
            }
        }
    }
}

// ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ValidationStatus {
    Valid,
    Rejected(String),
}