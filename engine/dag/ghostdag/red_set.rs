// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options, WriteBatch, WriteOptions, ReadOptions,
    SliceTransform
};
use std::collections::{HashSet, HashMap};
use std::path::Path;

use crate::errors::{DagError, StorageError};
use crate::slog_error;
pub use crate::engine::dag::ghostdag::ghostdag::GHOSTDAG_K;

const PFX_RED:  &[u8] = b"red:";
const PFX_RSET: &[u8] = b"rset:";

pub struct RedSetStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl RedSetStore {
    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(5));

        
        opts.increase_parallelism(4);
        opts.set_max_open_files(1000);

        match DB::open(&opts, Path::new(path)) {
            Ok(db) => {
                let mut write_opts = WriteOptions::default();

                
                write_opts.disable_wal(false);

                let mut read_opts = ReadOptions::default();
                read_opts.set_prefix_same_as_start(true);

                Some(Self {
                    db,
                    write_opts,
                    read_opts,
                })
            }
            Err(e) => {
                slog_error!("ghostdag", "red_set_store_open_failed", error => e);
                None
            }
        }
    }

    pub fn new_required(path: &str) -> Result<Self, DagError> {
        Self::new(path).ok_or_else(|| {
            slog_error!("ghostdag", "red_set_store_fatal_open", path => path);
            StorageError::OpenFailed { path: path.to_string(), reason: "cannot open DB".to_string() }.into()
        })
    }

    #[inline(always)]
    fn red_key(hash: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(PFX_RED.len() + hash.len());
        key.extend_from_slice(PFX_RED);
        key.extend_from_slice(hash.as_bytes());
        key
    }

    #[inline(always)]
    fn rset_key(block: &str, member: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(PFX_RSET.len() + block.len() + 1 + member.len());
        key.extend_from_slice(PFX_RSET);
        key.extend_from_slice(block.as_bytes());
        key.push(0);
        key.extend_from_slice(member.as_bytes());
        key
    }

    #[inline(always)]
    fn rset_prefix(block: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(PFX_RSET.len() + block.len() + 1);
        key.extend_from_slice(PFX_RSET);
        key.extend_from_slice(block.as_bytes());
        key.push(0);
        key
    }

    #[inline(always)]
    pub fn store_red(&self, hash: &str) {
        let key = Self::red_key(hash);
        let _ = self.db.put_opt(key, b"1", &self.write_opts);
    }

    #[inline(always)]
    pub fn exists(&self, hash: &str) -> bool {
        let key = Self::red_key(hash);

        matches!(
            self.db.get_pinned_opt(key, &self.read_opts),
            Ok(Some(_))
        )
    }

    #[inline(always)]
    pub fn remove_red(&self, hash: &str) {
        let _ = self.db.delete_opt(Self::red_key(hash), &self.write_opts);
    }

    #[inline(always)]
    pub fn add_to_red_set(&self, block: &str, member: &str) {
        let _ = self.db.put_opt(Self::rset_key(block, member), b"1", &self.write_opts);
    }

    #[inline(always)]
    pub fn get_red_set(&self, block: &str) -> HashSet<String> {
        self.scan_set(&Self::rset_prefix(block))
    }

    pub fn store_red_set(&self, block: &str, members: &HashSet<String>) {
        let mut batch = WriteBatch::default();

        for m in members {
            batch.put(Self::rset_key(block, m), b"1");
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    pub fn build_red_set(
        &self,
        block_hash: &str,
        _all_blocks: &HashMap<String, Vec<String>>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> HashSet<String> {
        let past = ghostdag.get_past_set(
            block_hash,
            crate::engine::dag::ghostdag::ghostdag::MAX_ANTICONE_WALK,
        );

        let blue_set = ghostdag.get_blue_set(block_hash);

        let mut red_set = HashSet::with_capacity(past.len());

        for b in past {
            if !blue_set.contains(&b) {
                red_set.insert(b);
            }
        }

        let mut batch = WriteBatch::default();

        for r in &red_set {
            batch.put(Self::red_key(r), b"1");
            batch.put(Self::rset_key(block_hash, r), b"1");
        }

        let _ = self.db.write_opt(batch, &self.write_opts);

        red_set
    }

    #[inline(always)]
    fn scan_set(&self, prefix: &[u8]) -> HashSet<String> {
        let mut set = HashSet::new();

        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (k, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            if !k.starts_with(prefix) { break; }
            if let Ok(s) = std::str::from_utf8(&k[prefix.len()..]) {
                set.insert(s.to_string());
            }
        }

        set
    }
}

impl Drop for RedSetStore {
    fn drop(&mut self) {
        let _ = self.db.flush();
    }
}