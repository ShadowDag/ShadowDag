// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteOptions, ReadOptions,
    WriteBatch, DBPinnableSlice,
    BlockBasedOptions, Cache, SliceTransform,
    IteratorMode, Direction,
};
use std::path::Path;
use crate::errors::CryptoError;

// prefix
const HASH_PREFIX: &[u8] = b"h:";
const PREFIX_LEN: usize = 2;
const CLEAR_BATCH_SIZE: usize = 1000;

pub struct Sha3Store {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    iter_read_opts: ReadOptions,
}

impl Sha3Store {

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
        block_opts.set_block_cache(&Cache::new_lru_cache(128 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        opts.set_block_based_table_factory(&block_opts);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| CryptoError::Other(format!("[Sha3Store] cannot open DB: {}", e)))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        let mut read_opts = ReadOptions::default();
        read_opts.set_verify_checksums(false);

        let mut iter_read_opts = ReadOptions::default();
        iter_read_opts.set_verify_checksums(false);
        iter_read_opts.fill_cache(false);

        Ok(Self {
            db,
            write_opts,
            read_opts,
            iter_read_opts,
        })
    }

    // ─────────────────────────────────────────
    // INTERNAL KEY
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
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_hash(&self, key: &str, hash: &str) {
        Self::with_key(key, |k| {
            if let Err(e) = self.db.put_opt(k, hash.as_bytes(), &self.write_opts) {
                eprintln!("[Sha3Store] CRITICAL: DB write failed: {}", e);
            }
        });
    }

    // ─────────────────────────────────────────
    // BATCH STORE
    // ─────────────────────────────────────────
    pub fn store_batch(&self, items: &[(&str, &str)]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for (key, hash) in items {
            buf.clear();
            buf.extend_from_slice(HASH_PREFIX);
            buf.extend_from_slice(key.as_bytes());
            batch.put(&*buf, hash.as_bytes());
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[Sha3Store] CRITICAL: DB batch write failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // DELETE BATCH
    // ─────────────────────────────────────────
    pub fn delete_batch(&self, keys: &[&str]) {
        let mut batch = WriteBatch::default();
        let mut buf = Vec::with_capacity(64);

        for key in keys {
            buf.clear();
            buf.extend_from_slice(HASH_PREFIX);
            buf.extend_from_slice(key.as_bytes());
            batch.delete(&*buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            eprintln!("[Sha3Store] CRITICAL: DB delete batch failed: {}", e);
        }
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_hash(&self, key: &str) -> Option<Vec<u8>> {
        Self::with_key(key, |k| {
            match self.db.get_opt(k, &self.read_opts) {
                Ok(Some(v)) => Some(v.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("[Sha3Store] CRITICAL: DB read failed: {}", e);
                    None
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET (optimized reuse buffer)
    // ─────────────────────────────────────────
    pub fn multi_get(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let mut key_bufs = Vec::with_capacity(keys.len());
        let mut buf = Vec::with_capacity(64);

        for key in keys {
            buf.clear();
            buf.extend_from_slice(HASH_PREFIX);
            buf.extend_from_slice(key.as_bytes());
            key_bufs.push(buf.clone());
        }

        self.db
            .multi_get_opt(key_bufs, &self.read_opts)
            .into_iter()
            .map(|r| match r {
                Ok(Some(v)) => Some(v.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("[Sha3Store] CRITICAL: DB multi_get failed: {}", e);
                    None
                }
            })
            .collect()
    }

    // ─────────────────────────────────────────
    // MULTI GET PINNED (🔥 zero-copy batch)
    // ─────────────────────────────────────────
    pub fn multi_get_pinned(&self, keys: &[&str]) -> Vec<Option<DBPinnableSlice<'_>>> {
        keys.iter().map(|k| self.get_hash_pinned(k)).collect()
    }

    // ─────────────────────────────────────────
    // GET PINNED
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_hash_pinned(&self, key: &str) -> Option<DBPinnableSlice<'_>> {
        Self::with_key(key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(v)) => Some(v),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("[Sha3Store] CRITICAL: DB read pinned failed: {}", e);
                    None
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn exists(&self, key: &str) -> bool {
        Self::with_key(key, |k| {
            if !self.db.key_may_exist(k) {
                return false;
            }

            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    eprintln!("[Sha3Store] CRITICAL: DB exists check failed: {}", e);
                    false
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // ITER (lazy)
    // ─────────────────────────────────────────
    pub fn iter(&self) -> impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_ {
        let mut iter_opts = ReadOptions::default();
        iter_opts.set_verify_checksums(false);
        iter_opts.fill_cache(false);

        self.db
            .iterator_opt(
                IteratorMode::From(HASH_PREFIX, Direction::Forward),
                iter_opts,
            )
            .take_while(|item| {
                item.as_ref()
                    .map(|(k, _)| k.starts_with(HASH_PREFIX))
                    .unwrap_or(false)
            })
            .filter_map(|item| item.ok())
    }

    // ─────────────────────────────────────────
    // COUNT (no allocation)
    // ─────────────────────────────────────────
    pub fn count(&self) -> usize {
        let mut count = 0;

        let mut iter_opts = ReadOptions::default();
        iter_opts.set_verify_checksums(false);
        iter_opts.fill_cache(false);

        let iter = self.db.iterator_opt(
            IteratorMode::From(HASH_PREFIX, Direction::Forward),
            iter_opts,
        );

        for (k, _) in iter.flatten() {
            if !k.starts_with(HASH_PREFIX) {
                break;
            }
            count += 1;
        }

        count
    }

    // ─────────────────────────────────────────
    // CLEAR
    // ─────────────────────────────────────────
    pub fn clear(&self) {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        let mut iter_opts = ReadOptions::default();
        iter_opts.set_verify_checksums(false);
        iter_opts.fill_cache(false);

        let iter = self.db.iterator_opt(
            IteratorMode::From(HASH_PREFIX, Direction::Forward),
            iter_opts,
        );

        for (k, _) in iter.flatten() {
            if !k.starts_with(HASH_PREFIX) {
                break;
            }

            batch.delete(&*k);
            count += 1;

            if count >= CLEAR_BATCH_SIZE {
                if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                    eprintln!("[Sha3Store] CRITICAL: DB clear failed: {}", e);
                    return;
                }
                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                eprintln!("[Sha3Store] CRITICAL: DB clear failed: {}", e);
            }
        }
    }

    // ─────────────────────────────────────────
    // FLUSH
    // ─────────────────────────────────────────
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("[Sha3Store] CRITICAL: DB flush failed: {}", e);
        }
    }
}