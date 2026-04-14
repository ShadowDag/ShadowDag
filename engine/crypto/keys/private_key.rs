// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;
use rocksdb::{
    BlockBasedOptions, Cache, DBCompressionType, Options, ReadOptions, SliceTransform, WriteBatch,
    WriteOptions, DB,
};
use std::path::Path;
use zeroize::Zeroizing;

// prefix
const KEY_PREFIX: &[u8] = b"pk:";
const PREFIX_LEN: usize = 3;
const KEY_ESTIMATED_SIZE: usize = 64;

pub struct PrivateKeyStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    read_opts_no_cache: ReadOptions,
}

impl PrivateKeyStore {
    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32,
        );

        opts.optimize_level_style_compaction(256 * 1024 * 1024);
        opts.set_target_file_size_base(64 * 1024 * 1024);

        opts.set_compression_type(DBCompressionType::Lz4);

        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);

        let cache = Cache::new_lru_cache(128 * 1024 * 1024);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&cache);
        block_opts.set_bloom_filter(10.0, false);

        opts.set_block_based_table_factory(&block_opts);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);

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
    // INTERNAL KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn build_key<'a>(buf: &'a mut Vec<u8>, key_id: &str) -> &'a [u8] {
        buf.clear();
        buf.extend_from_slice(KEY_PREFIX);
        buf.extend_from_slice(key_id.as_bytes());
        buf
    }

    #[inline(always)]
    fn with_key<F, R>(&self, key_id: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        let k = Self::build_key(&mut buf, key_id);
        f(k)
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store(&self, key_id: &str, key: &[u8]) -> Result<(), StorageError> {
        self.with_key(key_id, |k| {
            self.db
                .put_opt(k, key, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("store failed: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // LOAD
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn load(&self, key_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.with_key(key_id, |k| {
            self.db
                .get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .map(|v| Zeroizing::new(v.to_vec()))
        })
    }

    // ─────────────────────────────────────────
    // LOAD STRING
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn load_string(&self, key_id: &str) -> Option<Zeroizing<String>> {
        self.load(key_id)
            .and_then(|v| String::from_utf8((*v).clone()).ok().map(Zeroizing::new))
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete(&self, key_id: &str) -> Result<(), StorageError> {
        self.with_key(key_id, |k| {
            self.db
                .delete_opt(k, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("delete failed: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key_id: &str) -> bool {
        self.with_key(key_id, |k| {
            self.db
                .get_pinned_opt(k, &self.read_opts)
                .map(|v| v.is_some())
                .unwrap_or(false)
        })
    }

    // ─────────────────────────────────────────
    // BUILD KEYS (optimized allocation)
    // ─────────────────────────────────────────
    fn build_keys(keys: &[&str]) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(keys.len());

        for k in keys {
            let mut buf = Vec::with_capacity(KEY_ESTIMATED_SIZE);
            buf.extend_from_slice(KEY_PREFIX);
            buf.extend_from_slice(k.as_bytes());
            out.push(buf);
        }

        out
    }

    // ─────────────────────────────────────────
    // BATCH STORE
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: &[(&str, &[u8])]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for (key_id, value) in items {
            let k = Self::build_key(&mut buf, key_id);
            batch.put(k, value);
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("batch write: {}", e)))
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    pub fn delete_batch(&self, keys: &[&str]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for key_id in keys {
            let k = Self::build_key(&mut buf, key_id);
            batch.delete(k);
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("batch delete: {}", e)))
    }

    // ─────────────────────────────────────────
    // MULTI GET PINNED
    // ─────────────────────────────────────────
    pub fn multi_get_pinned(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let key_buffers = Self::build_keys(keys);

        self.db
            .multi_get_opt(key_buffers.iter(), &self.read_opts)
            .into_iter()
            .map(|r| r.ok().flatten())
            .collect()
    }

    // ─────────────────────────────────────────
    // MULTI GET (no extra vec)
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let key_buffers = Self::build_keys(keys);

        self.db
            .multi_get_opt(key_buffers.iter(), &self.read_opts)
            .into_iter()
            .map(|r| r.ok().flatten().map(|v| v.to_vec()))
            .collect()
    }

    // ─────────────────────────────────────────
    // MULTI GET NO CACHE
    // ─────────────────────────────────────────
    pub fn multi_get_no_cache(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let key_buffers = Self::build_keys(keys);

        self.db
            .multi_get_opt(key_buffers.iter(), &self.read_opts_no_cache)
            .into_iter()
            .map(|r| r.ok().flatten().map(|v| v.to_vec()))
            .collect()
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db
            .flush()
            .map_err(|e| StorageError::WriteFailed(format!("flush: {}", e)))
    }
}
