// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, Options,
    WriteBatch, WriteOptions, ReadOptions,
    DBCompressionType, IteratorMode, Direction,
};
use std::path::Path;
use std::sync::Arc;

use crate::errors::{DagError, StorageError};

// Column Families
pub const CF_DEFAULT: &str = "default";
pub const CF_LOCATORS: &str = "locators";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_UTXO: &str = "utxo";

// prefix
const LOCATOR_PREFIX: &[u8] = b"l:";

//////////////////////////////////////////////////////////////
// STORAGE ENGINE
//////////////////////////////////////////////////////////////

pub struct StorageEngine {
    pub db: Arc<DB>,
    write_opts_no_wal: WriteOptions,
    read_opts: ReadOptions,
}

impl StorageEngine {

    pub fn open(path: &str) -> Result<Self, DagError> {

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(128 * 1024 * 1024));
        opts.set_block_based_table_factory(&block_opts);

        opts.set_compression_type(DBCompressionType::Lz4);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, Options::default()),
            ColumnFamilyDescriptor::new(CF_LOCATORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXO, Options::default()),
        ];

        let db = Arc::new(
            DB::open_cf_descriptors(&opts, Path::new(path), cfs)
                .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?
        );

        let mut write_opts_no_wal = WriteOptions::default();
        write_opts_no_wal.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(false);

        Ok(Self {
            db,
            write_opts_no_wal,
            read_opts,
        })
    }

    #[inline(always)]
    fn make_key(hash: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + hash.len());
        key.extend_from_slice(LOCATOR_PREFIX);
        key.extend_from_slice(hash.as_bytes());
        key
    }
}

//////////////////////////////////////////////////////////////
// LOCATOR MODULE
//////////////////////////////////////////////////////////////

pub struct BlockLocator<'a> {
    engine: &'a StorageEngine,
}

impl<'a> BlockLocator<'a> {

    pub fn new(engine: &'a StorageEngine) -> Self {
        Self { engine }
    }

    #[inline(always)]
    pub fn add(&self, hash: &str) {

        let key = StorageEngine::make_key(hash);
        let cf = match self.engine.db.cf_handle(CF_LOCATORS) {
            Some(cf) => cf,
            None => { eprintln!("[Locator] CF_LOCATORS missing"); return; }
        };

        if let Err(e) = self.engine.db.put_cf_opt(
            cf,
            &key,
            b"1",
            &self.engine.write_opts_no_wal,
        ) {
            eprintln!("[Locator] put error: {}", e);
        }
    }

    #[inline(always)]
    pub fn exists(&self, hash: &str) -> bool {

        let key = StorageEngine::make_key(hash);
        let cf = match self.engine.db.cf_handle(CF_LOCATORS) {
            Some(cf) => cf,
            None => { eprintln!("[Locator] CF_LOCATORS missing"); return false; }
        };

        matches!(
            self.engine.db.get_cf_opt(
                cf,
                &key,
                &self.engine.read_opts
            ),
            Ok(Some(_))
        )
    }

    pub fn list(&self, limit: usize) -> Vec<String> {

        let mut result = Vec::with_capacity(limit.min(1024));
        let cf = match self.engine.db.cf_handle(CF_LOCATORS) {
            Some(cf) => cf,
            None => { eprintln!("[Locator] CF_LOCATORS missing"); return result; }
        };

        let mut iter_opts = ReadOptions::default();
        iter_opts.fill_cache(false);

        let iter = self.engine.db.iterator_cf_opt(
            cf,
            iter_opts,
            IteratorMode::From(LOCATOR_PREFIX, Direction::Forward),
        );

        for item in iter {

            let (key, _) = match item {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !key.starts_with(LOCATOR_PREFIX) {
                break;
            }

            let hash_bytes = &key[LOCATOR_PREFIX.len()..];

            if let Ok(hash) = std::str::from_utf8(hash_bytes) {
                result.push(hash.to_string());
            }

            if result.len() >= limit {
                break;
            }
        }

        result
    }
}

//////////////////////////////////////////////////////////////
// BATCH WRITES
//////////////////////////////////////////////////////////////

impl StorageEngine {

    pub fn batch_write_example(&self) {

        let cf_locators = match self.db.cf_handle(CF_LOCATORS) {
            Some(cf) => cf,
            None => { eprintln!("[StorageEngine] CF_LOCATORS missing"); return; }
        };
        let cf_blocks = match self.db.cf_handle(CF_BLOCKS) {
            Some(cf) => cf,
            None => { eprintln!("[StorageEngine] CF_BLOCKS missing"); return; }
        };

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_locators, b"l:hash1", b"1");
        batch.put_cf(cf_blocks, b"block1", b"...");

        if let Err(e) = self.db.write_opt(batch, &self.write_opts_no_wal) {
            eprintln!("[DB] batch error: {}", e);
        }
    }
}
