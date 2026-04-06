// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, Options,
    WriteBatch, ReadOptions, WriteOptions, SliceTransform,
    DBCompressionType,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::errors::{DagError, StorageError};
use crate::{slog_warn, slog_error};
pub use crate::engine::dag::ghostdag::ghostdag::GHOSTDAG_K;

const CF_BLUE: &str = "blue_cf";
const CF_BSET: &str = "bset_cf";

pub struct BlueSetStore {
    db: DB,
    write_opts: WriteOptions,
}

fn bset_prefix_extractor() -> SliceTransform {
    SliceTransform::create(
        "bset_prefix",
        |key: &[u8]| {
            match key.iter().position(|&b| b == 0) {
                Some(pos) => &key[..=pos],
                None => key,
            }
        },
        Some(|key: &[u8]| key.starts_with(b"bset:")),
    )
}

impl BlueSetStore {
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);

        opts.set_max_open_files(512);
        opts.set_use_fsync(true);
        opts.set_bytes_per_sync(1 << 20);

        opts.set_compression_type(DBCompressionType::Zstd);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(256 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, true);
        opts.set_block_based_table_factory(&block_opts);

        // CF_BLUE
        let mut cf_blue_opts = Options::default();
        cf_blue_opts.set_compression_type(DBCompressionType::Zstd);

        let mut blue_block_opts = BlockBasedOptions::default();
        blue_block_opts.set_block_cache(&Cache::new_lru_cache(128 * 1024 * 1024));
        blue_block_opts.set_bloom_filter(10.0, true);
        cf_blue_opts.set_block_based_table_factory(&blue_block_opts);

        // CF_BSET
        let mut cf_bset_opts = Options::default();
        cf_bset_opts.set_prefix_extractor(bset_prefix_extractor());
        cf_bset_opts.set_compression_type(DBCompressionType::Zstd);

        let mut bset_block_opts = BlockBasedOptions::default();
        bset_block_opts.set_block_cache(&Cache::new_lru_cache(256 * 1024 * 1024));
        bset_block_opts.set_bloom_filter(10.0, true);
        cf_bset_opts.set_block_based_table_factory(&bset_block_opts);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLUE, cf_blue_opts),
            ColumnFamilyDescriptor::new(CF_BSET, cf_bset_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, Path::new(path), cfs)
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        // Blue set is consensus-critical — determines block ordering.
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);
        write_opts.set_sync(true);

        Ok(Self { db, write_opts })
    }

    pub fn new_required(path: &str) -> Result<Self, DagError> {
        Self::new(path)
    }

    #[inline(always)]
    fn blue_cf(&self) -> Option<&rocksdb::ColumnFamily> {
        self.db.cf_handle(CF_BLUE).or_else(|| {
            slog_warn!("ghostdag", "cf_blue_missing", fallback => "default CF");
            self.db.cf_handle("default")
        })
    }

    #[inline(always)]
    fn bset_cf(&self) -> Option<&rocksdb::ColumnFamily> {
        self.db.cf_handle(CF_BSET).or_else(|| {
            slog_warn!("ghostdag", "cf_bset_missing", fallback => "default CF");
            self.db.cf_handle("default")
        })
    }

    #[inline(always)]
    fn key_blue(hash: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(hash.len() + 5);
        k.extend_from_slice(b"blue:");
        k.extend_from_slice(hash.as_bytes());
        k
    }

    #[inline(always)]
    fn key_bset(block: &str, member: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(block.len() + member.len() + 6);
        k.extend_from_slice(b"bset:");
        k.extend_from_slice(block.as_bytes());
        k.push(0);
        k.extend_from_slice(member.as_bytes());
        k
    }

    #[inline(always)]
    fn prefix_bset(block: &str) -> Vec<u8> {
        let mut p = Vec::with_capacity(block.len() + 6);
        p.extend_from_slice(b"bset:");
        p.extend_from_slice(block.as_bytes());
        p.push(0);
        p
    }

    pub fn store_blue(&self, hash: &str) {
        let cf = match self.blue_cf() {
            Some(cf) => cf,
            None => { slog_error!("ghostdag", "store_blue_no_cf"); return; }
        };
        if let Err(e) = self.db.put_cf_opt(cf, Self::key_blue(hash), [1], &self.write_opts) {
            slog_error!("ghostdag", "store_blue_failed", error => e);
        }
    }

    pub fn exists(&self, hash: &str) -> bool {
        let cf = match self.blue_cf() {
            Some(cf) => cf,
            None => return false,
        };
        matches!(self.db.get_pinned_cf(cf, Self::key_blue(hash)), Ok(Some(_)))
    }

    pub fn remove_blue(&self, hash: &str) {
        let cf = match self.blue_cf() {
            Some(cf) => cf,
            None => { slog_error!("ghostdag", "remove_blue_no_cf"); return; }
        };
        if let Err(e) = self.db.delete_cf(cf, Self::key_blue(hash)) {
            slog_error!("ghostdag", "remove_blue_failed", error => e);
        }
    }

    pub fn add_to_blue_set(&self, block: &str, member: &str) {
        let cf = match self.bset_cf() {
            Some(cf) => cf,
            None => { slog_error!("ghostdag", "add_to_blue_set_no_cf"); return; }
        };
        if let Err(e) = self.db.put_cf_opt(cf, Self::key_bset(block, member), [1], &self.write_opts) {
            slog_error!("ghostdag", "add_to_blue_set_failed", error => e);
        }
    }

    pub fn get_blue_set(&self, block: &str) -> HashSet<String> {
        self.scan_set(&Self::prefix_bset(block))
    }

    pub fn store_blue_set(&self, block: &str, members: &HashSet<String>) {
        let cf = match self.bset_cf() {
            Some(cf) => cf,
            None => { slog_error!("ghostdag", "store_blue_set_no_cf"); return; }
        };
        let mut batch = WriteBatch::default();

        for m in members {
            batch.put_cf(cf, Self::key_bset(block, m), [1]);
        }

        if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
            slog_error!("ghostdag", "store_blue_set_failed", error => e);
        }
    }

    pub fn is_blue_block(
        &self,
        block_hash: &str,
        all_blocks: &HashMap<String, Vec<String>>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> bool {
        ghostdag.is_blue_block(block_hash, all_blocks)
    }

    pub fn build_blue_set(
        &self,
        block_hash: &str,
        parents: &[String],
        all_blocks: &HashMap<String, Vec<String>>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> HashSet<String> {
        let blue_set =
            ghostdag.build_blue_set_for_past(block_hash, parents, all_blocks);

        let blue_cf = self.blue_cf();
        let bset_cf = self.bset_cf();

        if let (Some(bcf), Some(bscf)) = (blue_cf, bset_cf) {
            let mut batch = WriteBatch::default();

            for b in &blue_set {
                batch.put_cf(bcf, Self::key_blue(b), [1]);
                batch.put_cf(bscf, Self::key_bset(block_hash, b), [1]);
            }

            if let Err(e) = self.db.write_opt(batch, &self.write_opts) {
                slog_error!("ghostdag", "build_blue_set_failed", error => e);
            }
        } else {
            slog_warn!("ghostdag", "build_blue_set_cf_unavailable");
        }

        blue_set
    }

    fn scan_set(&self, prefix: &[u8]) -> HashSet<String> {
        let mut set = HashSet::new();

        let cf = match self.bset_cf() {
            Some(cf) => cf,
            None => { slog_error!("ghostdag", "scan_set_no_cf"); return set; }
        };

        let mut ro = ReadOptions::default();
        ro.set_prefix_same_as_start(true);
        ro.set_total_order_seek(false);
        ro.fill_cache(true);
        ro.set_readahead_size(64 * 1024);
        ro.set_pin_data(true);

        let mut iter = self.db.raw_iterator_cf_opt(cf, ro);

        iter.seek(prefix);

        while iter.valid() {
            let k = match iter.key() {
                Some(k) => k,
                None => break,
            };

            if !k.starts_with(prefix) {
                break;
            }

            let suffix = std::str::from_utf8(&k[prefix.len()..]).unwrap_or("");

            if !suffix.is_empty() {
                set.insert(suffix.to_string());
            }

            iter.next();
        }

        set
    }
}