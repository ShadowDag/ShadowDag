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
use hex;
use rayon::ThreadPool;
use rayon::ThreadPoolBuilder;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::domain::block::block::Block;
use crate::domain::traits::sync_peers::SyncPeers;
use crate::domain::traits::block_processor::BlockProcessor;
use crate::errors::{DagError, StorageError};
use crate::{slog_warn, slog_error, slog_debug};

// Column Families
const CF_DEFAULT: &str = "default";
const CF_SYNC: &str = "dag_sync";

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

    _pool: Arc<ThreadPool>,

    inflight: AtomicUsize,
    counter: AtomicUsize,
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
            _pool: Arc::new(pool),
            inflight: AtomicUsize::new(0),
            counter: AtomicUsize::new(0),
        })
    }

    fn cf_sync(&self) -> Option<&rocksdb::ColumnFamily> {
        match self.db.cf_handle(CF_SYNC) {
            Some(cf) => Some(cf),
            None => {
                slog_warn!("dag", "cf_sync_missing", fallback => "default CF");
                self.db.cf_handle("default")
            }
        }
    }

    //////////////////////////////////////////////////////////////
    /// RECEIVE BLOCK (ULTIMATE VERSION)
    //////////////////////////////////////////////////////////////
    pub fn receive_block(&self, block: Block) {
        // Fix #3: Hashes are 64-char hex strings, not 32 raw bytes.
        // Validate length and decode hex to get 32-byte hash for cache/DB keys.
        if block.header.hash.len() != 64 {
            slog_warn!("dag", "dag_sync_invalid_hash_len", len => block.header.hash.len());
            return;
        }

        let hash: [u8; 32] = match hex::decode(&block.header.hash) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                slog_warn!("dag", "dag_sync_invalid_hash_hex");
                return;
            }
        };

        //////////////////////////////////////////////////////////////
        // CACHE CHECK (don't insert yet — Fix #4: insert after success)
        //////////////////////////////////////////////////////////////
        if self.seen_cache.contains(&hash) {
            return;
        }

        //////////////////////////////////////////////////////////////
        // DB CHECK
        //////////////////////////////////////////////////////////////
        let cf = match self.cf_sync() {
            Some(cf) => cf,
            None => { slog_error!("dag", "dag_sync_no_cf_read"); return; }
        };
        match self.db.get_cf_opt(cf, hash, &self.read_opts) {
            Ok(Some(_)) => {
                self.seen_cache.insert(hash); // already processed, cache it
                return;
            }
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
        // BACKPRESSURE (CAS)
        // Fix #10: Check inflight pressure BEFORE writing to DB.
        // Previously, the hash was written to DB first, so if we
        // returned early here the block was permanently "seen" but
        // never processed — lost forever.
        //////////////////////////////////////////////////////////////
        loop {
            let current = self.inflight.load(Ordering::Relaxed);

            if current >= MAX_INFLIGHT_TASKS {
                // Don't mark hash as seen — the block hasn't been processed.
                // It will be retried on the next receive_block call.
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
            slog_warn!("dag", "dag_sync_block_rejected", error => e);
            // Don't cache on failure — block may be retried
        } else {
            // Fix #9: Only persist to DB AFTER successful processing.
            // Previously the DB write happened before process_block, so
            // failed blocks were permanently marked as "seen" and never
            // retried. Now we write only on success.
            let mut batch = WriteBatch::default();
            let cf = match self.cf_sync() {
                Some(cf) => cf,
                None => { slog_error!("dag", "dag_sync_no_cf_write"); self.inflight.fetch_sub(1, Ordering::Release); return; }
            };
            batch.put_cf(cf, hash, b"1");

            if self.db.write_opt(batch, &self.fast_write_opts).is_err() {
                let mut batch2 = WriteBatch::default();
                let cf = match self.cf_sync() {
                    Some(cf) => cf,
                    None => { slog_error!("dag", "dag_sync_no_cf_retry_write"); self.inflight.fetch_sub(1, Ordering::Release); return; }
                };
                batch2.put_cf(cf, hash, b"1");

                if self.db.write_opt(batch2, &self.safe_write_opts).is_err() {
                    // DB write failed but block was processed successfully.
                    // The block won't be de-duped on disk, but the in-memory
                    // cache will still prevent double-processing this session.
                    slog_warn!("dag", "dag_sync_db_write_failed_after_process");
                }
            }

            // Only insert into seen_cache AFTER successful processing
            self.seen_cache.insert(hash);
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
            None => { slog_error!("dag", "dag_sync_no_cf_debug_iterate"); return; }
        };
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for (key, _) in iter.flatten() {
            slog_debug!("dag", "sync_seen_block", hash => String::from_utf8_lossy(&key));
        }
    }
}
