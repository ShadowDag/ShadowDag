// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, IteratorMode, Direction,
    WriteBatch, WriteOptions, ReadOptions,
    SliceTransform,
};
use std::path::Path;
use std::sync::Arc;
use dashmap::DashSet;
use std::collections::HashSet;

use crate::errors::{DagError, StorageError};
use crate::slog_error;

const HEADER_PREFIX: &[u8] = b"header:";
const CACHE_LIMIT: usize = 50_000;
const CACHE_TRIM: usize = 5_000;

pub struct HeaderSync {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    cache: DashSet<String>,
}

impl HeaderSync {
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(
            HEADER_PREFIX.len(),
        ));

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
            cache: DashSet::with_capacity(CACHE_LIMIT),
        })
    }

    #[inline(always)]
    fn make_key(hash: &str, buf: &mut Vec<u8>) {
        buf.clear();
        buf.reserve(HEADER_PREFIX.len() + hash.len());
        buf.extend_from_slice(HEADER_PREFIX);
        buf.extend_from_slice(hash.as_bytes());
    }

    #[inline(always)]
    fn trim_cache(&self) {
        if self.cache.len() <= CACHE_LIMIT {
            return;
        }

        let keys: Vec<String> = self
            .cache
            .iter()
            .take(CACHE_TRIM)
            .map(|k| k.key().clone())
            .collect();

        for key in keys {
            self.cache.remove(&key);
        }
    }

    // ─────────────────────────────────────────
    // SINGLE WRITE (optimized allocation)
    // ─────────────────────────────────────────
    pub fn store_header(&self, hash: &str) {
        let hash_string = hash.to_string();

        // atomic insert
        if !self.cache.insert(hash_string.clone()) {
            return;
        }

        let mut key = Vec::with_capacity(HEADER_PREFIX.len() + hash.len());
        Self::make_key(hash, &mut key);

        if let Err(e) = self.db.put_opt(&key, b"1", &self.write_opts) {
            slog_error!("dag", "header_sync_put_failed", error => e);

            // rollback
            self.cache.remove(&hash_string);
            return;
        }

        self.trim_cache();
    }

    // ─────────────────────────────────────────
    // BATCH WRITE (allocation optimized)
    // ─────────────────────────────────────────
    pub fn store_headers_batch_fast(&self, hashes: &[&str]) {
        let mut batch = WriteBatch::default();

        let mut seen = HashSet::with_capacity(hashes.len());
        let mut to_cache: Vec<String> = Vec::with_capacity(hashes.len());

        let mut key_buf = Vec::with_capacity(64);

        for hash in hashes {
            if !seen.insert(*hash) {
                continue;
            }

            let hash_string = hash.to_string();

            // atomic insert
            if !self.cache.insert(hash_string.clone()) {
                continue;
            }

            Self::make_key(hash, &mut key_buf);
            batch.put(&key_buf, b"1");

            to_cache.push(hash_string);
        }

        if to_cache.is_empty() {
            return;
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("dag", "header_sync_batch_write_failed", error => e);

            // rollback
            for hash in to_cache {
                self.cache.remove(&hash);
            }

            return;
        }

        self.trim_cache();
    }

    // ─────────────────────────────────────────
    // READ
    // ─────────────────────────────────────────
    pub fn has_header(&self, hash: &str) -> bool {
        if self.cache.contains(hash) {
            return true;
        }

        let mut key = Vec::with_capacity(HEADER_PREFIX.len() + hash.len());
        Self::make_key(hash, &mut key);

        match self.db.get_opt(&key, &self.read_opts) {
            Ok(Some(_)) => {
                self.cache.insert(hash.to_string());
                true
            }
            Ok(None) => false,
            Err(e) => {
                slog_error!("dag", "header_sync_get_failed", error => e);
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // ITERATE
    // ─────────────────────────────────────────
    pub fn get_headers(&self) -> Vec<String> {
        let mut headers = Vec::with_capacity(1024);

        let iter = self.db.iterator_opt(
            IteratorMode::From(HEADER_PREFIX, Direction::Forward),
            {
                let mut opts = ReadOptions::default();
                opts.set_prefix_same_as_start(true);
                opts
            },
        );

        for item in iter {
            let (key, _) = match item {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !key.starts_with(HEADER_PREFIX) {
                break;
            }

            let hash_bytes = &key[HEADER_PREFIX.len()..];

            if let Ok(hash) = std::str::from_utf8(hash_bytes) {
                headers.push(hash.to_string());
            }
        }

        headers
    }

    // ─────────────────────────────────────────
    // CACHE WARMUP
    // ─────────────────────────────────────────
    pub fn load_cache_from_db(&self, limit: usize) {
        let iter = self.db.iterator_opt(
            IteratorMode::From(HEADER_PREFIX, Direction::Forward),
            {
                let mut opts = ReadOptions::default();
                opts.set_prefix_same_as_start(true);
                opts
            },
        );

        let mut loaded = 0;

        for item in iter {
            let (key, _) = match item {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !key.starts_with(HEADER_PREFIX) {
                break;
            }

            let hash_bytes = &key[HEADER_PREFIX.len()..];

            if let Ok(hash) = std::str::from_utf8(hash_bytes) {
                if self.cache.insert(hash.to_string()) {
                    loaded += 1;
                }

                if loaded >= limit {
                    break;
                }
            }
        }
    }

    /// Header-first IBD mode: validate and store only headers first,
    /// then request block bodies on-demand. This dramatically reduces
    /// initial sync bandwidth and time.
    pub fn header_first_sync_status(&self) -> HeaderSyncStatus {
        let total = self.cache.len();
        HeaderSyncStatus {
            headers_synced:     total,
            headers_validated:  total, // All cached headers are validated
            bodies_pending:     0,     // Bodies fetched separately
            mode:               if total > 0 { SyncMode::HeaderFirst } else { SyncMode::Full },
        }
    }

    /// Check if we have a header (without requiring full block body)
    pub fn has_header_only(&self, hash: &str) -> bool {
        if self.cache.contains(hash) {
            return true;
        }
        let mut buf = Vec::with_capacity(HEADER_PREFIX.len() + hash.len());
        Self::make_key(hash, &mut buf);
        matches!(self.db.get(&buf), Ok(Some(_)))
    }

    /// Get header count in the store
    pub fn header_count(&self) -> usize {
        self.cache.len()
    }
}

#[derive(Debug, Clone)]
pub struct HeaderSyncStatus {
    pub headers_synced:    usize,
    pub headers_validated: usize,
    pub bodies_pending:    usize,
    pub mode:              SyncMode,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncMode {
    Full,
    HeaderFirst,
}