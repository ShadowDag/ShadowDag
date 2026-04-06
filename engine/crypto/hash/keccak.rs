// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    WriteBatch, DBPinnableSlice,
    IteratorMode, Direction,
};
use std::path::Path;
use crate::slog_error;

pub struct KeccakStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl KeccakStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
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
        write_opts.set_sync(false); // ⚡ speed

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);

        Ok(Self {
            db,
            write_opts,
            read_opts,
        })
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_hash(&self, key: &str, hash: &str) {
        self.store_hash_bytes(key.as_bytes(), hash.as_bytes());
    }

    #[inline(always)]
    pub fn store_hash_bytes(&self, key: &[u8], hash: &[u8]) {
        if let Err(e) = self.db.put_opt(key, hash, &self.write_opts) {
            slog_error!("crypto", "keccak_store_hash_bytes_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // BATCH STORE
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: &[(&[u8], &[u8])]) {
        let mut batch = WriteBatch::default();

        for (k, v) in items {
            batch.put(k, v);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "keccak_store_batch_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_hash(&self, key: &str) -> Option<Vec<u8>> {
        self.get_hash_bytes(key.as_bytes())
    }

    #[inline(always)]
    pub fn get_hash_bytes(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.db.get_opt(key, &self.read_opts) {
            Ok(Some(value)) => Some(value.to_vec()),
            Ok(None) => None,
            Err(e) => {
                slog_error!("crypto", "keccak_get_hash_bytes_failed", error => e);
                None
            }
        }
    }

    // ─────────────────────────────────────────
    // ZERO COPY GET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_pinned(&self, key: &[u8]) -> Option<DBPinnableSlice<'_>> {
        self.db.get_pinned_opt(key, &self.read_opts).ok().flatten()
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&[u8]]) -> Vec<Option<Vec<u8>>> {
        let results = self.db.multi_get_opt(keys, &self.read_opts);

        let mut out = Vec::with_capacity(results.len());

        for res in results {
            out.push(res.ok().flatten().map(|v| v.to_vec()));
        }

        out
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_hash(&self, key: &str) {
        self.delete_hash_bytes(key.as_bytes());
    }

    #[inline(always)]
    pub fn delete_hash_bytes(&self, key: &[u8]) {
        if let Err(e) = self.db.delete_opt(key, &self.write_opts) {
            slog_error!("crypto", "keccak_delete_hash_bytes_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    pub fn delete_batch(&self, keys: &[&[u8]]) {
        let mut batch = WriteBatch::default();

        for k in keys {
            batch.delete(k);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "keccak_delete_batch_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // EXISTS (ZERO COPY FAST PATH)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &str) -> bool {
        self.exists_bytes(key.as_bytes())
    }

    #[inline(always)]
    pub fn exists_bytes(&self, key: &[u8]) -> bool {
        self.db.get_pinned_opt(key, &self.read_opts)
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    // ─────────────────────────────────────────
    // PREFIX RANGE HELPER 🔥
    // ─────────────────────────────────────────
    fn prefix_upper_bound(prefix: &[u8]) -> Vec<u8> {
        let mut upper = prefix.to_vec();

        for i in (0..upper.len()).rev() {
            if upper[i] != 0xFF {
                upper[i] += 1;
                upper.truncate(i + 1);
                return upper;
            }
        }

        vec![0xFF]
    }

    // ─────────────────────────────────────────
    // PREFIX SCAN (OPTIMIZED + UPPER BOUND)
    // ─────────────────────────────────────────
    pub fn prefix_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut results = Vec::with_capacity(64);

        let upper = Self::prefix_upper_bound(prefix);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);
        read_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_opt(
            IteratorMode::From(prefix, Direction::Forward),
            read_opts,
        );

        for (k, v) in iter.flatten() {
            results.push((k.to_vec(), v.to_vec()));
        }

        results
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            slog_error!("crypto", "keccak_flush_failed", error => e);
        }
    }
}