// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DBCompressionType, IteratorMode, Options, ReadOptions, SliceTransform, WriteBatch,
    WriteOptions, DB,
};
use std::collections::HashSet;
use std::sync::Arc;

use crate::errors::{DagError, StorageError};
use crate::slog_error;
// prefixes
const PFX_SCORE: &[u8] = b"score:";
const PFX_SP: &[u8] = b"sp___:";
const PFX_BLUE: &[u8] = b"blue_:";
const PFX_RED: &[u8] = b"red__:";
const PFX_BSET: &[u8] = b"bset_:";
const PFX_RSET: &[u8] = b"rset_:";
const PFX_DONE: &[u8] = b"done_:";
const KEY_TIP: &[u8] = b"dag:tip";

// buffer
type KeyBuf = Vec<u8>;

#[inline]
fn key_into(buf: &mut KeyBuf, prefix: &[u8], hash: &str) {
    buf.clear();
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(hash.as_bytes());
}

#[inline]
fn key_set_into(buf: &mut KeyBuf, prefix: &[u8], block: &str, member: &str) {
    buf.clear();
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(block.as_bytes());
    buf.push(b'\x00');
    buf.extend_from_slice(member.as_bytes());
}

pub struct DagState {
    db: Arc<DB>,
    write_opts: WriteOptions,
}

impl DagState {
    // ==============================
    // 🔥 INIT (ULTRA OPTIMIZED)
    // ==============================

    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.set_write_buffer_size(16 * 1024 * 1024);

        // 💣 prefix optimization
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(6));
        opts.set_memtable_prefix_bloom_ratio(0.1);

        // 💣 compaction
        opts.set_level_compaction_dynamic_level_bytes(true);

        // 💣 IO tuning
        opts.set_bytes_per_sync(1 << 20);
        opts.set_use_fsync(true);

        // 💣 compression
        opts.set_compression_type(DBCompressionType::Lz4);

        // 💣 CPU scaling
        opts.increase_parallelism(4);

        let db = DB::open(&opts, path).ok()?;

        // WAL enabled for crash safety (disable_wal=false).
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);

        Some(Self {
            db: Arc::new(db),
            write_opts,
        })
    }

    pub fn new_required(path: &str) -> Result<Self, DagError> {
        Self::new(path).ok_or_else(|| {
            slog_error!("dag", "dag_state_fatal_open", path => path);
            StorageError::OpenFailed {
                path: path.to_string(),
                reason: "cannot open DB".to_string(),
            }
            .into()
        })
    }

    // ==============================
    // 🔥 SCORE
    // ==============================

    pub fn set_blue_score(&self, hash: &str, score: u64) {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_SCORE, hash);
        let _ = self.db.put_opt(&key, score.to_le_bytes(), &self.write_opts);
    }

    pub fn get_blue_score(&self, hash: &str) -> Option<u64> {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_SCORE, hash);

        let v = self.db.get(&key).ok().flatten()?;
        if v.len() < 8 {
            return None;
        }

        let mut arr = [0u8; 8];
        arr.copy_from_slice(&v[..8]);
        Some(u64::from_le_bytes(arr))
    }

    // ==============================
    // 🔥 SELECTED PARENT
    // ==============================

    pub fn set_selected_parent(&self, hash: &str, parent: &str) {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_SP, hash);
        let _ = self.db.put_opt(&key, parent.as_bytes(), &self.write_opts);
    }

    pub fn get_selected_parent(&self, hash: &str) -> Option<String> {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_SP, hash);

        self.db
            .get(&key)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
    }

    // ==============================
    // 🔥 COLOR
    // ==============================

    pub fn mark_blue(&self, hash: &str) {
        let mut batch = WriteBatch::default();
        let mut key = KeyBuf::new();

        key_into(&mut key, PFX_BLUE, hash);
        batch.put(&key, b"1");

        key_into(&mut key, PFX_RED, hash);
        batch.delete(&key);

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    pub fn mark_red(&self, hash: &str) {
        let mut batch = WriteBatch::default();
        let mut key = KeyBuf::new();

        key_into(&mut key, PFX_RED, hash);
        batch.put(&key, b"1");

        key_into(&mut key, PFX_BLUE, hash);
        batch.delete(&key);

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    pub fn is_blue(&self, hash: &str) -> bool {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_BLUE, hash);
        self.db.get(&key).map(|v| v.is_some()).unwrap_or(false)
    }

    pub fn is_red(&self, hash: &str) -> bool {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_RED, hash);
        self.db.get(&key).map(|v| v.is_some()).unwrap_or(false)
    }

    // ==============================
    // 🔥 SET SCAN
    // ==============================

    fn scan_set(&self, prefix: &[u8], block: &str) -> HashSet<String> {
        let mut key_prefix = KeyBuf::new();
        key_prefix.extend_from_slice(prefix);
        key_prefix.extend_from_slice(block.as_bytes());
        key_prefix.push(b'\x00');

        let mut opts = ReadOptions::default();
        opts.set_prefix_same_as_start(true);
        opts.set_total_order_seek(false);

        let mut set = HashSet::new();

        let iter = self.db.iterator_opt(
            IteratorMode::From(&key_prefix, rocksdb::Direction::Forward),
            opts,
        );

        for item in iter.flatten() {
            let (k, _) = item;

            if !k.starts_with(&key_prefix) {
                break;
            }

            if let Ok(s) = std::str::from_utf8(&k[key_prefix.len()..]) {
                set.insert(s.to_owned());
            }
        }

        set
    }

    pub fn get_blue_set(&self, block: &str) -> HashSet<String> {
        self.scan_set(PFX_BSET, block)
    }

    pub fn get_red_set(&self, block: &str) -> HashSet<String> {
        self.scan_set(PFX_RSET, block)
    }

    // ==============================
    // 🔥 METADATA
    // ==============================

    pub fn store_block_metadata(
        &self,
        block: &str,
        blue_score: u64,
        selected_parent: Option<&str>,
        is_blue: bool,
        blue_set: &HashSet<String>,
        red_set: &HashSet<String>,
    ) {
        let mut batch = WriteBatch::default();
        let mut key = KeyBuf::new();

        key_into(&mut key, PFX_SCORE, block);
        batch.put(&key, blue_score.to_le_bytes());

        if let Some(sp) = selected_parent {
            key_into(&mut key, PFX_SP, block);
            batch.put(&key, sp.as_bytes());
        }

        key_into(&mut key, if is_blue { PFX_BLUE } else { PFX_RED }, block);
        batch.put(&key, b"1");

        for m in blue_set {
            key_set_into(&mut key, PFX_BSET, block, m);
            batch.put(&key, b"1");
        }

        for m in red_set {
            key_set_into(&mut key, PFX_RSET, block, m);
            batch.put(&key, b"1");
        }

        key_into(&mut key, PFX_DONE, block);
        batch.put(&key, b"1");

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ==============================
    // 🔥 VALIDATION
    // ==============================

    pub fn is_block_complete(&self, block: &str) -> bool {
        let mut key = KeyBuf::new();
        key_into(&mut key, PFX_DONE, block);
        self.db.get(&key).map(|v| v.is_some()).unwrap_or(false)
    }

    // ==============================
    // 🔥 TIP
    // ==============================

    pub fn set_tip(&self, hash: &str) {
        let mut batch = WriteBatch::default();
        batch.put(KEY_TIP, hash.as_bytes());
        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    pub fn get_tip(&self) -> Option<String> {
        self.db
            .get(KEY_TIP)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
    }
}
