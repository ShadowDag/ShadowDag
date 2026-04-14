// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;
use crate::slog_error;
use rocksdb::{
    BlockBasedOptions, Cache, DBPinnableSlice, Direction, IteratorMode, Options, ReadOptions,
    SliceTransform, WriteBatch, WriteOptions, DB,
};
use std::path::Path;
use std::sync::Arc;

// prefix
const KEY_PREFIX: &[u8] = b"kp:";
const PREFIX_LEN: usize = 3;
const DELETE_BATCH_SIZE: usize = 1000;

// upper bound
const PREFIX_UPPER_BOUND_RAW: &[u8] = b"kp:\xFF";

pub struct KeyPairStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    _iter_read_opts: ReadOptions,
}

impl KeyPairStore {
    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        opts.increase_parallelism(cpus as i32);
        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(64 * 1024 * 1024));
        opts.set_block_based_table_factory(&block_opts);

        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        let write_opts = WriteOptions::default();
        let read_opts = ReadOptions::default();

        let mut _iter_read_opts = ReadOptions::default();
        _iter_read_opts.set_prefix_same_as_start(true);
        _iter_read_opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND_RAW.to_vec());

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
            _iter_read_opts,
        })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_key<F, R>(id: &[u8], f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(KEY_PREFIX);
        buf.extend_from_slice(id);
        f(&buf)
    }

    // ─────────────────────────────────────────
    // VALUE BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_value<F, R>(public_key: &[u8], private_key: &[u8], f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);

        let pub_len = public_key.len() as u32;

        buf.extend_from_slice(&pub_len.to_le_bytes());
        buf.extend_from_slice(public_key);
        buf.extend_from_slice(private_key);

        f(&buf)
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn store_pair(&self, id: &[u8], public_key: &[u8], private_key: &[u8]) {
        Self::with_key(id, |key| {
            Self::with_value(public_key, private_key, |value| {
                if let Err(e) = self.db.put_opt(key, value, &self.write_opts) {
                    slog_error!("crypto", "keypair_store_pair_failed", error => e);
                }
            });
        });
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────
    pub fn get_pair(&self, id: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        Self::with_key(id, |key| {
            let data = match self.db.get_opt(key, &self.read_opts) {
                Ok(v) => v?,
                Err(e) => {
                    slog_error!("crypto", "keypair_get_pair_failed", error => e);
                    return None;
                }
            };

            Self::decode_pair(&data)
        })
    }

    #[inline(always)]
    pub fn get_public_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        self.get_pair(id).map(|(p, _)| p)
    }

    #[inline(always)]
    pub fn get_private_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        self.get_pair(id).map(|(_, p)| p)
    }

    // ─────────────────────────────────────────
    // PINNED
    // ─────────────────────────────────────────
    pub fn get_pair_pinned(&self, id: &[u8]) -> Option<(DBPinnableSlice<'_>, usize)> {
        Self::with_key(id, |key| {
            let data = match self.db.get_pinned_opt(key, &self.read_opts) {
                Ok(v) => v?,
                Err(e) => {
                    slog_error!("crypto", "keypair_get_pair_pinned_failed", error => e);
                    return None;
                }
            };

            if data.len() < 4 {
                return None;
            }

            let pub_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

            if data.len() < 4 + pub_len {
                return None;
            }

            Some((data, pub_len))
        })
    }

    #[inline(always)]
    pub fn get_pair_pinned_split<'a>(
        data: &'a DBPinnableSlice,
        pub_len: usize,
    ) -> Option<(&'a [u8], &'a [u8])> {
        if data.len() < 4 + pub_len {
            slog_error!("crypto", "keypair_data_too_short", expected => 4 + pub_len, got => data.len());
            return None;
        }
        Some((&data[4..4 + pub_len], &data[4 + pub_len..]))
    }

    // ─────────────────────────────────────────
    // DECODE
    // ─────────────────────────────────────────
    #[inline(always)]
    fn decode_pair(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if data.len() < 4 {
            return None;
        }

        let pub_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if data.len() < 4 + pub_len {
            return None;
        }

        Some((data[4..4 + pub_len].to_vec(), data[4 + pub_len..].to_vec()))
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    pub fn exists(&self, id: &[u8]) -> bool {
        Self::with_key(id, |key| {
            match self.db.get_pinned_opt(key, &self.read_opts) {
                Ok(v) => v.is_some(),
                Err(e) => {
                    slog_error!("crypto", "keypair_exists_check_failed", error => e);
                    false
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────
    pub fn multi_get(&self, ids: &[Vec<u8>]) -> Vec<Option<(Vec<u8>, Vec<u8>)>> {
        let mut keys = Vec::with_capacity(ids.len());
        keys.reserve_exact(ids.len());

        for id in ids {
            let mut k = Vec::with_capacity(KEY_PREFIX.len() + id.len());
            k.extend_from_slice(KEY_PREFIX);
            k.extend_from_slice(id);
            keys.push(k);
        }

        self.db
            .multi_get_opt(keys, &self.read_opts)
            .into_iter()
            .map(|res| res.ok().flatten().and_then(|v| Self::decode_pair(&v)))
            .collect()
    }

    pub fn batch_exists(&self, ids: &[Vec<u8>]) -> Vec<bool> {
        self.multi_get(ids)
            .into_iter()
            .map(|v| v.is_some())
            .collect()
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    pub fn delete_pair(&self, id: &[u8]) {
        Self::with_key(id, |key| {
            if let Err(e) = self.db.delete_opt(key, &self.write_opts) {
                slog_error!("crypto", "keypair_delete_pair_failed", error => e);
            }
        })
    }

    // ─────────────────────────────────────────
    // BATCH STORE
    // ─────────────────────────────────────────
    pub fn batch_store(&self, items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) {
        let mut batch = WriteBatch::default();
        let mut key_buf = Vec::with_capacity(128);
        let mut val_buf = Vec::with_capacity(256);

        for (id, pub_key, priv_key) in items {
            key_buf.clear();
            key_buf.extend_from_slice(KEY_PREFIX);
            key_buf.extend_from_slice(id);

            val_buf.clear();
            let pub_len = pub_key.len() as u32;
            val_buf.extend_from_slice(&pub_len.to_le_bytes());
            val_buf.extend_from_slice(pub_key);
            val_buf.extend_from_slice(priv_key);

            batch.put(&key_buf, &val_buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "keypair_batch_store_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // BATCH DELETE
    // ─────────────────────────────────────────
    pub fn batch_delete(&self, ids: &[Vec<u8>]) {
        let mut batch = WriteBatch::default();
        let mut key_buf = Vec::with_capacity(128);

        for id in ids {
            key_buf.clear();
            key_buf.extend_from_slice(KEY_PREFIX);
            key_buf.extend_from_slice(id);

            batch.delete(&key_buf);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("crypto", "keypair_batch_delete_failed", error => e);
        }
    }

    // ─────────────────────────────────────────
    // CLEAR
    // ─────────────────────────────────────────
    fn new_iter_opts() -> ReadOptions {
        let mut opts = ReadOptions::default();
        opts.set_prefix_same_as_start(true);
        opts.set_iterate_upper_bound(PREFIX_UPPER_BOUND_RAW.to_vec());
        opts
    }

    pub fn clear(&self) {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        let iter = self.db.iterator_opt(
            IteratorMode::From(KEY_PREFIX, Direction::Forward),
            Self::new_iter_opts(),
        );

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };

            batch.delete(&*key);
            count += 1;

            if count >= DELETE_BATCH_SIZE {
                if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                    slog_error!("crypto", "keypair_clear_batch_failed", error => e);
                    return;
                }
                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                slog_error!("crypto", "keypair_clear_final_batch_failed", error => e);
            }
        }
    }

    // ─────────────────────────────────────────
    // COUNT
    // ─────────────────────────────────────────
    pub fn count(&self) -> usize {
        let mut total = 0;

        let iter = self.db.iterator_opt(
            IteratorMode::From(KEY_PREFIX, Direction::Forward),
            Self::new_iter_opts(),
        );

        for item in iter {
            if item.is_err() {
                break;
            }
            total += 1;
        }

        total
    }

    pub fn is_empty(&self) -> bool {
        matches!(
            self.db
                .iterator_opt(
                    IteratorMode::From(KEY_PREFIX, Direction::Forward),
                    Self::new_iter_opts(),
                )
                .next(),
            None | Some(Err(_))
        )
    }
}
