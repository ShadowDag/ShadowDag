// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, Options,
    WriteBatch, WriteOptions, ReadOptions,
    DBCompressionType, IteratorMode,
};

use dashmap::DashSet;
use rayon::ThreadPool;
use rayon::ThreadPoolBuilder;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::domain::block::block::Block;
use crate::domain::traits::sync_peers::SyncPeers;
use crate::domain::traits::block_processor::BlockProcessor;
use crate::errors::{DagError, StorageError};

// Column Families
const CF_DEFAULT: &str = "default";
const CF_SYNC: &str = "dag_sync";

const MAX_BATCH_REQUEST: usize = 128;
const CACHE_LIMIT: usize = 50_000;
const CACHE_TRIM: usize = 2_000;
const MAX_INFLIGHT_TASKS: usize = 1024;

pub struct DagSync {
    db: Arc<DB>,
    peer_manager: Arc<dyn SyncPeers>,
    full_node: Arc<dyn BlockProcessor>,

    seen_cache: Arc<DashSet<[u8; 32]>>,

    read_opts: ReadOptions,
    fast_write_opts: WriteOptions,
    safe_write_opts: WriteOptions,

    pool: Arc<ThreadPool>,

    inflight: AtomicUsize,
    counter: AtomicUsize,
}

//////////////////////////////////////////////////////////////
/// RAII Guard
//////////////////////////////////////////////////////////////
struct InflightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> Drop for InflightGuard<'a> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

impl DagSync {
    pub fn new(
        path: &str,
        peer_manager: Arc<dyn SyncPeers>,
        full_node: Arc<dyn BlockProcessor>,
    ) -> Result<Self, DagError> {

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);
        opts.set_compression_type(DBCompressionType::Lz4);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(256 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);

        opts.set_block_based_table_factory(&block_opts);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, Options::default()),
            ColumnFamilyDescriptor::new(CF_SYNC, opts.clone()),
        ];

        let db = DB::open_cf_descriptors(&opts, Path::new(path), cfs)
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(false);
        read_opts.fill_cache(false);

        let mut fast_write_opts = WriteOptions::default();
        fast_write_opts.disable_wal(false);

        let safe_write_opts = WriteOptions::default();

        let pool = ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .map_err(|e| DagError::Other(format!("[DagSync] failed to build thread pool: {}", e)))?;

        Ok(Self {
            db: Arc::new(db),
            peer_manager,
            full_node,
            seen_cache: Arc::new(DashSet::new()),
            read_opts,
            fast_write_opts,
            safe_write_opts,
            pool: Arc::new(pool),
            inflight: AtomicUsize::new(0),
            counter: AtomicUsize::new(0),
        })
    }

    fn cf_sync(&self) -> Option<&rocksdb::ColumnFamily> {
        match self.db.cf_handle(CF_SYNC) {
            Some(cf) => Some(cf),
            None => {
                eprintln!("[DagSync] CF_SYNC missing — using default CF");
                self.db.cf_handle("default")
            }
        }
    }

    //////////////////////////////////////////////////////////////
    /// RECEIVE BLOCK (ULTIMATE VERSION)
    //////////////////////////////////////////////////////////////
    pub fn receive_block(&self, block: Block) {
        let hash_bytes = block.header.hash.as_bytes();

        if hash_bytes.len() != 32 {
            return;
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_bytes);

        //////////////////////////////////////////////////////////////
        // CACHE FIRST
        //////////////////////////////////////////////////////////////
        if !self.seen_cache.insert(hash) {
            return;
        }

        //////////////////////////////////////////////////////////////
        // DB CHECK
        //////////////////////////////////////////////////////////////
        let cf = match self.cf_sync() {
            Some(cf) => cf,
            None => { eprintln!("[DagSync] CRITICAL: no CF available"); return; }
        };
        match self.db.get_cf_opt(cf, hash, &self.read_opts) {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return,
        }

        //////////////////////////////////////////////////////////////
        // CACHE TRIM (no alloc)
        //////////////////////////////////////////////////////////////
        let c = self.counter.fetch_add(1, Ordering::Relaxed);

        if c.is_multiple_of(1000) && self.seen_cache.len() > CACHE_LIMIT {
            let mut removed = 0;

            for entry in self.seen_cache.iter() {
                self.seen_cache.remove(entry.key());
                removed += 1;

                if removed >= CACHE_TRIM {
                    break;
                }
            }
        }

        //////////////////////////////////////////////////////////////
        // WRITE
        //////////////////////////////////////////////////////////////
        let mut batch = WriteBatch::default();
        let cf = match self.cf_sync() {
            Some(cf) => cf,
            None => { eprintln!("[DagSync] CRITICAL: no CF available for write"); return; }
        };
        batch.put_cf(cf, hash, b"1");

        if self.db.write_opt(batch, &self.fast_write_opts).is_err() {
            let mut batch2 = WriteBatch::default();
            let cf = match self.cf_sync() {
                Some(cf) => cf,
                None => { eprintln!("[DagSync] CRITICAL: no CF available for retry write"); return; }
            };
            batch2.put_cf(cf, hash, b"1");

            if self.db.write_opt(batch2, &self.safe_write_opts).is_err() {
                return;
            }
        }

        //////////////////////////////////////////////////////////////
        // BACKPRESSURE (CAS)
        //////////////////////////////////////////////////////////////
        loop {
            let current = self.inflight.load(Ordering::Relaxed);

            if current >= MAX_INFLIGHT_TASKS {
                return;
            }

            if self.inflight.compare_exchange(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ).is_ok() {
                break;
            }
        }

        let node = self.full_node.clone();
        let block_clone = block.clone();

        // Note: inflight counter decrement is handled inline since
        // we can't send a reference to self across thread boundaries.
        if let Err(e) = node.process_block(&block_clone) {
            eprintln!("[DagSync] block rejected: {}", e);
        }
        self.inflight.fetch_sub(1, Ordering::Release);
    }

    //////////////////////////////////////////////////////////////
    /// REQUEST SYNC
    //////////////////////////////////////////////////////////////
    pub fn request_sync(&self) {
        let peers = self.peer_manager.get_peers();

        if peers.is_empty() {
            return;
        }

        let _locator = self.build_locator();

        // Sync requests handled by peer manager
    }

    fn build_locator(&self) -> Vec<String> {
        self.full_node
            .get_tips()
            .into_iter()
            .take(32)
            .collect()
    }

    pub fn debug_iterate(&self) {
        let cf = match self.cf_sync() {
            Some(cf) => cf,
            None => { eprintln!("[DagSync] CRITICAL: no CF available for debug_iterate"); return; }
        };
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for (key, _) in iter.flatten() {
            eprintln!("[SYNC] seen block: {}", String::from_utf8_lossy(&key));
        }
    }
}
