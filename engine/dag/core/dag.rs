// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options, ReadOptions,
    SliceTransform, WriteBatch, WriteOptions, DB,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use crate::errors::{DagError, StorageError};

const CF_BLOCKS: &str = "blocks";
use crate::config::consensus::consensus_params::ConsensusParams;
const MAX_PARENTS: usize = ConsensusParams::MAX_PARENTS;

#[derive(Serialize, Deserialize, Clone)]
pub struct DAGBlock {
    pub hash: String,
    pub parents: Vec<String>,
}

pub struct BlockDAG {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl BlockDAG {
    /// Create a new BlockDAG backed by RocksDB.
    /// WAL is ALWAYS enabled — correctness over performance.
    pub fn new(path: &str) -> Result<Self, DagError> {
        let mut base_opts = Options::default();
        base_opts.create_if_missing(true);
        base_opts.create_missing_column_families(true);

        // 🔥 block cache + bloom
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(256 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);

        // 🔥 CF options
        let mut cf_opts = Options::default();
        cf_opts.set_block_based_table_factory(&block_opts);
        cf_opts.set_compression_type(DBCompressionType::Lz4);
        cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(8));

        let cfs = vec![ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts)];

        let db = DB::open_cf_descriptors(&base_opts, Path::new(path), cfs).map_err(|e| {
            StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;

        // Write options — WAL always ON, sync always ON.
        // correctness > determinism > performance
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);
        write_opts.set_sync(true);

        // Read options — checksums always verified.
        // Silent corruption is worse than slow reads.
        let mut read_opts = ReadOptions::default();
        read_opts.set_verify_checksums(true);

        Ok(Self {
            db,
            write_opts,
            read_opts,
        })
    }

    #[inline(always)]
    fn cf(&self) -> Result<&rocksdb::ColumnFamily, DagError> {
        self.db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_BLOCKS.to_string()).into())
    }

    pub fn add_block(&self, block: &DAGBlock) -> Result<(), DagError> {
        if block.hash.is_empty() {
            return Err(DagError::BlockNotFound("Empty hash".into()));
        }

        if block.parents.contains(&block.hash) {
            return Err(DagError::SelfParent(block.hash.clone()));
        }

        if block.parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents(block.parents.len(), MAX_PARENTS));
        }

        // 🔥 no alloc duplicate check
        let mut set = HashSet::with_capacity(block.parents.len());
        for p in &block.parents {
            if !set.insert(p) {
                return Err(DagError::DuplicateParents(p.clone()));
            }
        }

        let data = bincode::serialize(block).map_err(|e| DagError::Serialization(e.to_string()))?;

        let cf = self.cf()?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, &block.hash, data);

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(StorageError::RocksDb)?;

        Ok(())
    }

    pub fn get_block(&self, hash: &str) -> Option<DAGBlock> {
        let cf = self.cf().ok()?;
        let data = match self.db.get_pinned_cf_opt(cf, hash, &self.read_opts) {
            Ok(Some(d)) => d,
            _ => return None,
        };

        bincode::deserialize(&data).ok()
    }

    pub fn block_exists(&self, hash: &str) -> bool {
        let cf = match self.cf() {
            Ok(cf) => cf,
            Err(_) => return false,
        };
        self.db
            .get_pinned_cf(cf, hash)
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    pub fn delete_block(&self, hash: &str) -> Result<(), DagError> {
        let cf = self.cf()?;
        self.db.delete_cf(cf, hash).map_err(StorageError::RocksDb)?;
        Ok(())
    }
}
