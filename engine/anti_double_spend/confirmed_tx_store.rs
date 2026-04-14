// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Confirmed TX Store — Tracks recently confirmed transaction hashes to
// prevent replay after shallow reorgs. When a reorg removes a block, the
// TXs in that block could theoretically be re-mined in a new block. This
// store keeps a rolling window of confirmed TX hashes so that the mempool
// and block validator can reject exact replays.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{Options, ReadOptions, WriteBatch, WriteOptions, DB};
use std::path::Path;
use std::sync::Arc;

use crate::errors::StorageError;
use crate::slog_error;
use crate::slog_warn;

/// How many blocks' worth of TX hashes to keep.
/// At 10 BPS this is ~28 hours of history. Deep reorgs beyond this
/// are protected by payload_hash (chain-state binding).
const RETENTION_BLOCKS: u64 = 1_000_000;

/// Prefix for confirmed TX entries: "ctx:" + tx_hash → block_height (u64 LE)
const PFX_CTX: &[u8] = b"ctx:";
/// Prefix for block→tx index: "btx:" + height (u64 BE) + ":" + tx_hash → []
const PFX_BTX: &[u8] = b"btx:";

pub struct ConfirmedTxStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl ConfirmedTxStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.increase_parallelism(2);
        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        // Confirmed TX tracking is consensus-adjacent — durable writes.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);

        let read_opts = ReadOptions::default();

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
        })
    }

    pub fn open_default() -> Result<Self, StorageError> {
        let path =
            crate::config::node::node_config::NetworkMode::base_data_dir().join("confirmed_txs");
        Self::new(&path.to_string_lossy())
    }

    /// Record a batch of confirmed TX hashes from a block.
    pub fn confirm_block_txs(&self, height: u64, tx_hashes: &[&str]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let height_bytes = height.to_be_bytes();

        for &tx_hash in tx_hashes {
            // ctx:tx_hash → height
            let mut ctx_key = Vec::with_capacity(PFX_CTX.len() + tx_hash.len());
            ctx_key.extend_from_slice(PFX_CTX);
            ctx_key.extend_from_slice(tx_hash.as_bytes());
            batch.put(&ctx_key, height_bytes);

            // btx:height:tx_hash → [] (for pruning by height)
            let mut btx_key = Vec::with_capacity(PFX_BTX.len() + 8 + 1 + tx_hash.len());
            btx_key.extend_from_slice(PFX_BTX);
            btx_key.extend_from_slice(&height_bytes);
            btx_key.push(b':');
            btx_key.extend_from_slice(tx_hash.as_bytes());
            batch.put(&btx_key, []);
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Remove confirmed TX records for a block being rolled back (reorg).
    pub fn unconfirm_block_txs(&self, height: u64) -> Result<Vec<String>, StorageError> {
        let height_bytes = height.to_be_bytes();
        let mut prefix = Vec::with_capacity(PFX_BTX.len() + 9);
        prefix.extend_from_slice(PFX_BTX);
        prefix.extend_from_slice(&height_bytes);
        prefix.push(b':');

        let mut batch = WriteBatch::default();
        let mut removed = Vec::new();

        let iter = self.db.prefix_iterator(&prefix);
        let mut iter_errors: u64 = 0;
        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    iter_errors += 1;
                    slog_error!("consensus", "unconfirm_iter_error", reason => &e.to_string(), height => &height.to_string());
                    continue;
                }
            };
            if !key.starts_with(&prefix) {
                break;
            }

            // Extract tx_hash from key
            let tx_hash_bytes = &key[prefix.len()..];
            if let Ok(tx_hash) = std::str::from_utf8(tx_hash_bytes) {
                // Only delete ctx:tx_hash if the stored height matches the one being unconfirmed.
                // If another confirmation superseded this one, leave the ctx entry intact.
                let mut ctx_key = Vec::with_capacity(PFX_CTX.len() + tx_hash.len());
                ctx_key.extend_from_slice(PFX_CTX);
                ctx_key.extend_from_slice(tx_hash.as_bytes());

                let should_delete = match self.db.get_pinned_opt(&ctx_key, &self.read_opts) {
                    Ok(Some(stored)) if stored.len() >= 8 => {
                        let stored_height =
                            u64::from_be_bytes(stored[..8].try_into().unwrap_or([0; 8]));
                        stored_height == height
                    }
                    _ => false,
                };

                if should_delete {
                    batch.delete(&ctx_key);
                }

                removed.push(tx_hash.to_string());
            }

            // Delete btx:height:tx_hash entry
            batch.delete(&*key);
        }

        if iter_errors > 0 {
            slog_warn!("consensus", "unconfirm_partial_operation", errors => &iter_errors.to_string(), height => &height.to_string());
        }

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        Ok(removed)
    }

    /// Check if a TX hash was recently confirmed.
    /// Returns the block height if found.
    #[inline]
    pub fn is_confirmed(&self, tx_hash: &str) -> Option<u64> {
        let mut key = Vec::with_capacity(PFX_CTX.len() + tx_hash.len());
        key.extend_from_slice(PFX_CTX);
        key.extend_from_slice(tx_hash.as_bytes());

        match self.db.get_pinned_opt(&key, &self.read_opts) {
            Ok(Some(v)) if v.len() == 8 => {
                let arr: [u8; 8] = v.as_ref().try_into().ok()?;
                Some(u64::from_be_bytes(arr))
            }
            _ => None,
        }
    }

    /// Prune old entries below the given height threshold.
    /// Called periodically to keep the store bounded.
    pub fn prune_below_height(&self, min_height: u64) -> Result<usize, StorageError> {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        // Iterate btx: entries from the beginning
        let iter = self.db.prefix_iterator(PFX_BTX);
        let mut iter_errors: u64 = 0;
        for item in iter {
            let (key, _) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    iter_errors += 1;
                    slog_error!("consensus", "prune_iter_error", reason => &e.to_string(), min_height => &min_height.to_string());
                    continue;
                }
            };
            if !key.starts_with(PFX_BTX) {
                break;
            }

            // Extract height from key (PFX_BTX + 8 bytes of height)
            if key.len() < PFX_BTX.len() + 8 {
                continue;
            }
            let height_slice = &key[PFX_BTX.len()..PFX_BTX.len() + 8];
            let height = match height_slice.try_into() {
                Ok(bytes) => u64::from_be_bytes(bytes),
                Err(_) => {
                    // Corrupted key — skip rather than misinterpret as height 0
                    // (height 0 = genesis, pruning genesis would corrupt the store)
                    slog_warn!("consensus", "malformed_height_key", bytes => &height_slice.len().to_string());
                    continue;
                }
            };

            if height >= min_height {
                break; // Keys are ordered by height (BE), so we're done
            }

            // Extract tx_hash and delete ctx entry only if stored height matches
            if key.len() > PFX_BTX.len() + 9 {
                let tx_hash_bytes = &key[PFX_BTX.len() + 9..]; // skip height + ':'
                let mut ctx_key = Vec::with_capacity(PFX_CTX.len() + tx_hash_bytes.len());
                ctx_key.extend_from_slice(PFX_CTX);
                ctx_key.extend_from_slice(tx_hash_bytes);

                let should_delete = match self.db.get_pinned_opt(&ctx_key, &self.read_opts) {
                    Ok(Some(stored)) if stored.len() >= 8 => {
                        let stored_height =
                            u64::from_be_bytes(stored[..8].try_into().unwrap_or([0; 8]));
                        // Only delete if the ctx entry still points to this (old) height
                        stored_height == height
                    }
                    _ => false,
                };

                if should_delete {
                    batch.delete(&ctx_key);
                }
            }

            batch.delete(&*key);
            count += 1;

            // Flush in batches to avoid huge write batches
            if count % 10_000 == 0 {
                self.db
                    .write_opt(batch, &self.write_opts)
                    .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                batch = WriteBatch::default();
            }
        }

        if iter_errors > 0 {
            slog_warn!("consensus", "prune_partial_operation", errors => &iter_errors.to_string(), min_height => &min_height.to_string());
        }

        if count % 10_000 != 0 {
            self.db
                .write_opt(batch, &self.write_opts)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        }

        Ok(count)
    }

    /// Auto-prune: keep only the last RETENTION_BLOCKS worth of entries.
    pub fn auto_prune(&self, current_height: u64) -> Result<usize, StorageError> {
        if current_height <= RETENTION_BLOCKS {
            return Ok(0);
        }
        self.prune_below_height(current_height - RETENTION_BLOCKS)
    }
}

#[cfg(test)]
mod confirmed_tx_tests {
    use super::*;

    fn tmp_store(name: &str) -> ConfirmedTxStore {
        let path = format!("/tmp/shadowdag_ctx_{}", name);
        let _ = std::fs::remove_dir_all(&path);
        ConfirmedTxStore::new(&path).unwrap()
    }

    #[test]
    fn confirm_and_check() {
        let store = tmp_store("confirm_check");
        let hashes = vec!["aabbcc01", "aabbcc02", "aabbcc03"];
        store.confirm_block_txs(100, &hashes).unwrap();

        assert_eq!(store.is_confirmed("aabbcc01"), Some(100));
        assert_eq!(store.is_confirmed("aabbcc02"), Some(100));
        assert_eq!(store.is_confirmed("aabbcc03"), Some(100));
        assert_eq!(store.is_confirmed("unknown"), None);
    }

    #[test]
    fn unconfirm_removes_entries() {
        let store = tmp_store("unconfirm");
        let hashes = vec!["tx_a", "tx_b"];
        store.confirm_block_txs(50, &hashes).unwrap();

        assert!(store.is_confirmed("tx_a").is_some());

        let removed = store.unconfirm_block_txs(50).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(store.is_confirmed("tx_a").is_none());
        assert!(store.is_confirmed("tx_b").is_none());
    }

    #[test]
    fn prune_old_entries() {
        let store = tmp_store("prune");
        store.confirm_block_txs(10, &["old_tx_1"]).unwrap();
        store.confirm_block_txs(20, &["old_tx_2"]).unwrap();
        store.confirm_block_txs(100, &["new_tx_1"]).unwrap();

        let pruned = store.prune_below_height(50).unwrap();
        assert!(pruned >= 2);

        assert!(store.is_confirmed("old_tx_1").is_none());
        assert!(store.is_confirmed("old_tx_2").is_none());
        assert!(store.is_confirmed("new_tx_1").is_some());
    }

    #[test]
    fn duplicate_confirm_overwrites() {
        let store = tmp_store("dup_confirm");
        store.confirm_block_txs(100, &["tx_x"]).unwrap();
        assert_eq!(store.is_confirmed("tx_x"), Some(100));

        // Re-confirm at different height (after reorg + re-mine)
        store.confirm_block_txs(101, &["tx_x"]).unwrap();
        assert_eq!(store.is_confirmed("tx_x"), Some(101));
    }
}
