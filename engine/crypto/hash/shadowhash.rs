// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    WriteBatch,
    BlockBasedOptions, SliceTransform, Cache,
};
use std::path::Path;
use crate::errors::StorageError;

use crate::domain::block::block::Block;
use crate::engine::mining::algorithms::shadowhash::shadow_hash as algo_shadow_hash;
use crate::engine::mining::algorithms::shadowhash::shadow_hash_str as algo_shadow_hash_str;

// prefix
const HASH_PREFIX: &[u8] = b"h:";
const PREFIX_LEN: usize = 2;

// upper bound
const PREFIX_UPPER_BOUND: &[u8] = b"h:\xFF";

// ─────────────────────────────────────────
// HASH API
// ─────────────────────────────────────────

pub struct ShadowHash;

impl ShadowHash {
    #[inline(always)]
    pub fn hash_block(block: &Block) -> String {
        algo_shadow_hash(block)
    }
}

#[inline(always)]
pub fn shadow_hash_str(data: &str) -> String {
    algo_shadow_hash_str(data)
}

// ─────────────────────────────────────────
// STORE
// ─────────────────────────────────────────

pub struct ShadowHashStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl ShadowHashStore {

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

        // prefix + bloom
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(128 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);

        opts.set_block_based_table_factory(&block_opts);

        // write tuning
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);

        opts.set_level_zero_slowdown_writes_trigger(20);
        opts.set_level_zero_stop_writes_trigger(36);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND);

        Ok(Self {
            db,
            write_opts,
            read_opts,
        })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_key<F, R>(key: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(HASH_PREFIX);
        buf.extend_from_slice(key.as_bytes());
        f(&buf)
    }

    // ─────────────────────────────────────────
    // STORE HASH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_hash(&self, key: &str, hash: &str) -> Result<(), StorageError> {
        Self::with_key(key, |k| {
            self.db
                .put_opt(k, hash.as_bytes(), &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("store_hash: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // STORE MANY
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_many(&self, items: &[(&str, &str)]) -> Result<(), StorageError> {
        if items.is_empty() {
            return Ok(());
        }

        let mut batch = WriteBatch::default();

        for (key, hash) in items {
            Self::with_key(key, |k| batch.put(k, hash.as_bytes()));
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("store_many: {}", e)))
    }

    // ─────────────────────────────────────────
    // GET HASH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_hash(&self, key: &str) -> Result<Option<String>, StorageError> {
        Self::with_key(key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(v)) => Ok(Some(Self::slice_to_string(&v))),
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::Other(format!("get_hash: {}", e))),
            }
        })
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn contains(&self, key: &str) -> Result<bool, StorageError> {
        Self::with_key(key, |k| {
            self.db
                .get_pinned_opt(k, &self.read_opts)
                .map(|v| v.is_some())
                .map_err(|e| StorageError::Other(format!("contains: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET (محسن)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_many(&self, keys: &[&str]) -> Result<Vec<Option<String>>, StorageError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut rocks_keys = Vec::with_capacity(keys.len());

        for key in keys {
            let mut v = Vec::with_capacity(PREFIX_LEN + key.len());
            v.extend_from_slice(HASH_PREFIX);
            v.extend_from_slice(key.as_bytes());
            rocks_keys.push(v);
        }

        let results = self.db.multi_get_opt(rocks_keys, &self.read_opts);

        let mut out = Vec::with_capacity(results.len());

        for res in results {
            match res {
                Ok(Some(v)) => out.push(Some(Self::slice_to_string(&v))),
                Ok(None) => out.push(None),
                Err(e) => return Err(StorageError::Other(format!("get_many: {}", e))), // 🔥 مهم
            }
        }

        Ok(out)
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_hash(&self, key: &str) -> Result<(), StorageError> {
        Self::with_key(key, |k| {
            self.db
                .delete_opt(k, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(format!("delete_hash: {}", e)))
        })
    }

    // ─────────────────────────────────────────
    // DELETE MANY
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn delete_many(&self, keys: &[&str]) -> Result<(), StorageError> {
        if keys.is_empty() {
            return Ok(());
        }

        let mut batch = WriteBatch::default();

        for key in keys {
            Self::with_key(key, |k| batch.delete(k));
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(format!("delete_many: {}", e)))
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(|e| StorageError::WriteFailed(format!("flush: {}", e)))
    }

    // ─────────────────────────────────────────
    // COMPACT
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn compact(&self) {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    }

    // ─────────────────────────────────────────
    // HELPER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn slice_to_string(slice: &[u8]) -> String {
        if slice.is_empty() {
            return String::new();
        }
        String::from_utf8_lossy(slice).to_string()
    }
}