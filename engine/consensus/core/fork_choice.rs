// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, Direction, IteratorMode, Options, ReadOptions, SliceTransform,
    WriteBatch, WriteOptions, DB,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{ConsensusError, StorageError};
use crate::slog_error;

// prefix لعزل البيانات
const CHOICE_PREFIX: &[u8] = b"choice:";
const DELETE_BATCH_SIZE: usize = 1000;
const WRITE_BATCH_SIZE: usize = 1000;

pub struct ForkChoiceStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    _iter_read_opts: ReadOptions,
}

impl ForkChoiceStore {
    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        opts.increase_parallelism(cpus as i32);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        // 🔥 Block cache
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(128 * 1024 * 1024));
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        opts.set_block_based_table_factory(&block_opts);

        // 🔥 Prefix extractor
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(CHOICE_PREFIX.len()));

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        // Fork choice is consensus-critical — must survive crashes.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(false);

        let mut _iter_read_opts = ReadOptions::default();
        _iter_read_opts.set_prefix_same_as_start(true);
        _iter_read_opts.set_total_order_seek(false);

        // 🔥 safe upper bound
        let mut upper = CHOICE_PREFIX.to_vec();
        if let Some(last) = upper.last_mut() {
            if *last != u8::MAX {
                *last += 1;
            } else {
                upper.push(0x00);
            }
        }
        _iter_read_opts.set_iterate_upper_bound(upper);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
            _iter_read_opts,
        })
    }

    // ─────────────────────────────────────────
    // INTERNAL KEY
    // ─────────────────────────────────────────
    #[inline(always)]
    fn make_key(hash: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(CHOICE_PREFIX.len() + hash.len());
        key.extend_from_slice(CHOICE_PREFIX);
        key.extend_from_slice(hash.as_bytes());
        key
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────
    #[inline]
    pub fn store_choice(&self, hash: &str, score: u64) -> Result<(), String> {
        let key = Self::make_key(hash);
        self.db.put_opt(key, score.to_be_bytes(), &self.write_opts)
            .map_err(|e| {
                slog_error!("consensus", "store_choice_failed", hash => hash, error => &format!("{}", e));
                format!("store_choice '{}': {}", hash, e)
            })
    }

    // ─────────────────────────────────────────
    // GET (zero-copy)
    // ─────────────────────────────────────────
    #[inline]
    pub fn get_choice(&self, hash: &str) -> Option<u64> {
        let key = Self::make_key(hash);

        match self.db.get_pinned_opt(key, &self.read_opts) {
            Ok(Some(value)) if value.len() == 8 => {
                let arr: [u8; 8] = value.as_ref().try_into().ok()?;
                Some(u64::from_be_bytes(arr))
            }
            Ok(_) => None,
            Err(e) => {
                slog_error!("consensus", "fork_choice_read_failed", key => hash, error => e);
                None
            }
        }
    }

    // ─────────────────────────────────────────
    // MULTI GET (optimized)
    // ─────────────────────────────────────────
    pub fn get_many_ref(&self, hashes: &[&str]) -> Vec<Option<u64>> {
        let mut keys = Vec::with_capacity(hashes.len());

        for h in hashes {
            keys.push(Self::make_key(h));
        }

        self.db
            .multi_get_opt(keys, &self.read_opts)
            .into_iter()
            .map(|res| match res {
                Ok(Some(value)) if value.len() == 8 => {
                    let arr: [u8; 8] = value.as_slice().try_into().ok()?;
                    Some(u64::from_be_bytes(arr))
                }
                _ => None,
            })
            .collect()
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────
    #[inline]
    pub fn exists(&self, hash: &str) -> bool {
        let key = Self::make_key(hash);
        match self.db.get_pinned_opt(key, &self.read_opts) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                slog_error!("consensus", "fork_choice_exists_read_failed", key => hash, error => e);
                false
            }
        }
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────
    #[inline]
    pub fn delete_choice(&self, hash: &str) -> Result<(), String> {
        let key = Self::make_key(hash);
        self.db.delete_opt(key, &self.write_opts)
            .map_err(|e| {
                slog_error!("consensus", "delete_choice_failed", hash => hash, error => &format!("{}", e));
                format!("delete_choice '{}': {}", hash, e)
            })
    }

    // ─────────────────────────────────────────
    // CLEAR PREFIX
    // ─────────────────────────────────────────
    pub fn clear_all(&self) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        let mut iter_opts = ReadOptions::default();
        iter_opts.set_prefix_same_as_start(true);
        iter_opts.set_total_order_seek(false);
        let mut upper = CHOICE_PREFIX.to_vec();
        if let Some(last) = upper.last_mut() {
            if *last != u8::MAX {
                *last += 1;
            } else {
                upper.push(0x00);
            }
        }
        iter_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_opt(
            IteratorMode::From(CHOICE_PREFIX, Direction::Forward),
            iter_opts,
        );

        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    let msg = format!("clear_all iterator error: {}", e);
                    slog_error!("consensus", "fork_choice_clear_failed", error => &msg);
                    return Err(msg);
                }
            };
            if !key.starts_with(CHOICE_PREFIX) {
                break;
            }

            batch.delete(&*key);
            count += 1;

            if count >= DELETE_BATCH_SIZE {
                self.db.write_opt(batch, &self.write_opts).map_err(|e| {
                    slog_error!("consensus", "fork_choice_clear_failed", error => &format!("{}", e));
                    format!("clear_all batch write: {}", e)
                })?;
                batch = WriteBatch::default();
                count = 0;
            }
        }

        if count > 0 {
            self.db.write_opt(batch, &self.write_opts).map_err(|e| {
                slog_error!("consensus", "fork_choice_clear_failed", error => &format!("{}", e));
                format!("clear_all final batch write: {}", e)
            })?;
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    // COUNT
    // ─────────────────────────────────────────
    pub fn len_prefix(&self) -> usize {
        let mut count = 0;

        let mut iter_opts = ReadOptions::default();
        iter_opts.set_prefix_same_as_start(true);
        iter_opts.set_total_order_seek(false);
        let mut upper = CHOICE_PREFIX.to_vec();
        if let Some(last) = upper.last_mut() {
            if *last != u8::MAX {
                *last += 1;
            } else {
                upper.push(0x00);
            }
        }
        iter_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_opt(
            IteratorMode::From(CHOICE_PREFIX, Direction::Forward),
            iter_opts,
        );

        for item in iter {
            match item {
                Ok((key, _)) => {
                    if !key.starts_with(CHOICE_PREFIX) {
                        break;
                    }
                    count += 1;
                }
                Err(_) => break,
            }
        }

        count
    }

    // ─────────────────────────────────────────
    // BATCH STORE (split flush 🔥)
    // ─────────────────────────────────────────
    pub fn store_batch_split(&self, entries: &[(&str, u64)]) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        let mut key = Vec::with_capacity(64);
        let mut count = 0;
        let mut batch_num: usize = 0;

        for (hash, score) in entries {
            key.clear();
            key.extend_from_slice(CHOICE_PREFIX);
            key.extend_from_slice(hash.as_bytes());

            batch.put(&key, score.to_be_bytes());
            count += 1;

            if count >= WRITE_BATCH_SIZE {
                self.db.write_opt(batch, &self.write_opts).map_err(|e| {
                    slog_error!("consensus", "fork_choice_batch_write_failed", batch => batch_num, error => &format!("{}", e));
                    format!("store_batch_split batch {}: {}", batch_num, e)
                })?;
                batch = WriteBatch::default();
                count = 0;
                batch_num += 1;
            }
        }

        if count > 0 {
            self.db.write_opt(batch, &self.write_opts).map_err(|e| {
                slog_error!("consensus", "fork_choice_batch_write_failed", batch => batch_num, error => &format!("{}", e));
                format!("store_batch_split batch {}: {}", batch_num, e)
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("/tmp/test_fork_choice_{}", ts)
    }

    #[test]
    fn store_and_get_choice() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store.store_choice("block_a", 100).unwrap();
        assert_eq!(store.get_choice("block_a"), Some(100));
    }

    #[test]
    fn get_unknown_returns_none() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        assert_eq!(store.get_choice("nonexistent"), None);
    }

    #[test]
    fn exists_check() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        assert!(!store.exists("x"));
        store.store_choice("x", 42).unwrap();
        assert!(store.exists("x"));
    }

    #[test]
    fn delete_choice_removes() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store.store_choice("del_me", 99).unwrap();
        assert!(store.exists("del_me"));
        store.delete_choice("del_me").unwrap();
        assert!(!store.exists("del_me"));
    }

    #[test]
    fn overwrite_updates_score() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store.store_choice("tip", 10).unwrap();
        assert_eq!(store.get_choice("tip"), Some(10));
        store.store_choice("tip", 200).unwrap();
        assert_eq!(store.get_choice("tip"), Some(200));
    }

    #[test]
    fn get_many_ref_returns_correct() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store.store_choice("a", 1).unwrap();
        store.store_choice("b", 2).unwrap();
        let results = store.get_many_ref(&["a", "b", "c"]);
        assert_eq!(results, vec![Some(1), Some(2), None]);
    }

    #[test]
    fn batch_store_split() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store
            .store_batch_split(&[("b1", 10), ("b2", 20), ("b3", 30)])
            .unwrap();
        assert_eq!(store.get_choice("b1"), Some(10));
        assert_eq!(store.get_choice("b2"), Some(20));
        assert_eq!(store.get_choice("b3"), Some(30));
    }

    #[test]
    fn len_prefix_counts() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        assert_eq!(store.len_prefix(), 0);
        store.store_choice("x", 1).unwrap();
        store.store_choice("y", 2).unwrap();
        assert_eq!(store.len_prefix(), 2);
    }

    #[test]
    fn clear_all_removes_everything() {
        let store = ForkChoiceStore::new(&tmp_path()).unwrap();
        store.store_choice("a", 1).unwrap();
        store.store_choice("b", 2).unwrap();
        assert_eq!(store.len_prefix(), 2);
        store.clear_all().unwrap();
        assert_eq!(store.len_prefix(), 0);
        assert!(!store.exists("a"));
    }
}
