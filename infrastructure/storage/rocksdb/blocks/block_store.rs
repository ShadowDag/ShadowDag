// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::sync::Arc;

use crate::domain::block::block::Block;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::{slog_error};

const BLK_PREFIX: &str = "blk:";
const BLK_BEST_HASH: &[u8] = b"blk:best_hash";

pub struct BlockStore {
    db: Arc<DB>,
}

impl BlockStore {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = open_shared_db(source, &opts)
            .map_err(|e| {
                slog_error!("storage", "block_store_unavailable", error => e);
                e
            })?;
        Ok(Self { db })
    }

    /// Save a block to the store.
    /// Height index uses `blk:height:{h}:{hash}` to support multiple blocks at the same
    /// height (DAG-compatible). This is NOT a linear chain — many blocks can share a height.
    pub fn save_block(&self, block: &Block) -> bool {
        let hash = &block.header.hash;
        let block_key = format!("{}{}", BLK_PREFIX, hash);
        // Check if block already exists — don't overwrite
        match self.db.get_pinned(block_key.as_bytes()) {
            Ok(Some(_)) => {
                return false; // Already exists — don't overwrite
            }
            Ok(None) => {} // Not a duplicate — proceed
            Err(e) => {
                slog_error!("storage", "block_store_dup_check_failed", error => e);
                // Treat read error as "proceed with caution" — don't silently skip
            }
        }
        match bincode::serialize(block) {
            Ok(data) => {
                let mut batch = rocksdb::WriteBatch::default();
                batch.put(block_key.as_bytes(), &data);
                // DAG-compatible height index: blk:height:{h}:{hash}
                // Multiple blocks can exist at the same height
                let height_key = format!("{}height:{}:{}", BLK_PREFIX, block.header.height, hash);
                batch.put(height_key.as_bytes(), hash.as_bytes());
                // Hash-to-height reverse index: survives pruning so
                // validate_parents_exist can check height without the full block.
                let h2h_key = format!("{}h2h:{}", BLK_PREFIX, hash);
                batch.put(h2h_key.as_bytes(), block.header.height.to_le_bytes());
                match self.db.write(batch) {
                    Ok(_) => true,
                    Err(e) => {
                        slog_error!("storage", "block_write_failed", error => e);
                        false
                    }
                }
            }
            Err(e) => {
                slog_error!("storage", "block_serialize_error", error => e);
                false
            }
        }
    }

    /// Update an existing block in the store (overwrites unconditionally).
    /// Used for post-execution header updates (receipt_root, state_root)
    /// where save_block would reject the write as a duplicate.
    pub fn update_block(&self, block: &Block) -> bool {
        let hash = &block.header.hash;
        let block_key = format!("{}{}", BLK_PREFIX, hash);
        match bincode::serialize(block) {
            Ok(data) => {
                match self.db.put(block_key.as_bytes(), &data) {
                    Ok(_) => true,
                    Err(e) => {
                        slog_error!("storage", "block_update_write_failed", hash => hash, error => e);
                        false
                    }
                }
            }
            Err(e) => {
                slog_error!("storage", "block_update_serialize_error", hash => hash, error => e);
                false
            }
        }
    }

    /// Store the UTXO commitment hash for a block.
    /// Called after UTXO state is applied, so recovery can verify integrity.
    pub fn set_utxo_commitment(&self, block_hash: &str, commitment: &str) {
        let key = format!("{}utxo_commit:{}", BLK_PREFIX, block_hash);
        if let Err(e) = self.db.put(key.as_bytes(), commitment.as_bytes()) {
            slog_error!("storage", "set_utxo_commitment_failed", error => e);
        }
    }

    /// Get the UTXO commitment hash for a block.
    pub fn get_utxo_commitment(&self, block_hash: &str) -> Option<String> {
        let key = format!("{}utxo_commit:{}", BLK_PREFIX, block_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("storage", "utxo_commitment_corrupt_utf8",
                        block_hash => block_hash, error => e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "utxo_commitment_read_error", block_hash => block_hash, error => e);
                None
            }
        }
    }

    /// Explicitly set the best (tip) block hash.
    /// The consensus layer / DAG manager should call this after determining
    /// which block is the true DAG tip (e.g., by blue score), not on every save.
    pub fn update_best_hash(&self, hash: &str) -> bool {
        match self.db.put(BLK_BEST_HASH, hash.as_bytes()) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("storage", "update_best_hash_failed", error => e);
                false
            }
        }
    }

    pub fn get_block(&self, hash: &str) -> Option<Block> {
        let key = format!("{}{}", BLK_PREFIX, hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match bincode::deserialize(&data) {
                Ok(block) => Some(block),
                Err(e) => {
                    slog_error!("storage", "block_deserialization_error", hash => hash, error => e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "block_read_error", hash => hash, error => e);
                None
            }
        }
    }

    pub fn block_exists(&self, hash: &str) -> bool {
        let key = format!("{}{}", BLK_PREFIX, hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(_)) => true,
            Ok(None)    => false,
            Err(e)      => {
                slog_error!("storage", "block_exists_read_failed_may_be_false_negative",
                    hash => hash, error => e);
                false // TODO: Consider Result<bool> return type
            }
        }
    }

    pub fn get_best_hash(&self) -> Option<String> {
        match self.db.get(BLK_BEST_HASH) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("storage", "best_hash_corrupt_utf8", error => e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "best_hash_read_error", error => e);
                None
            }
        }
    }

    /// Strict version of `get_best_hash` that distinguishes three states:
    /// - `Ok(None)` → key genuinely absent (no chain yet, safe to init genesis)
    /// - `Ok(Some(_))` → valid best tip present
    /// - `Err(StorageError)` → read failed or value corrupt (fail-closed: refuse
    ///   to proceed, caller must surface the error and abort)
    ///
    /// Callers making genesis-init decisions MUST use this method rather than
    /// `get_best_hash()`, because `Option<None>` from the non-strict version
    /// collapses corruption/read-failure into "no chain" and can wipe existing
    /// chain state on startup.
    pub fn get_best_hash_strict(&self) -> Result<Option<String>, crate::errors::StorageError> {
        match self.db.get(BLK_BEST_HASH) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) if s.is_empty() => {
                    slog_error!("storage", "best_hash_empty_value_treated_as_corrupt");
                    Err(crate::errors::StorageError::ReadFailed(
                        "best_hash key present but value is empty".to_string(),
                    ))
                }
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("storage", "best_hash_corrupt_utf8_strict", error => e);
                    Err(crate::errors::StorageError::ReadFailed(format!(
                        "best_hash corrupt utf8: {}",
                        e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("storage", "best_hash_read_error_strict", error => e);
                Err(crate::errors::StorageError::ReadFailed(e.to_string()))
            }
        }
    }

    pub fn get_recent_blocks(&self, limit: usize) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        let mut deserialize_errors = 0usize;
        let prefix = BLK_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    slog_error!("storage", "recent_blocks_iter_error", error => e);
                    continue;
                }
            };
            let key_str = String::from_utf8_lossy(&k).to_string();
            // Skip metadata keys (best_hash, height index, h2h index, utxo_commit)
            if !key_str.starts_with(BLK_PREFIX) { break; }
            if key_str == "blk:best_hash" { continue; }
            if key_str.contains(":height:") { continue; }
            if key_str.contains(":h2h:") { continue; }
            if key_str.contains(":utxo_commit:") { continue; }
            match bincode::deserialize::<Block>(&v) {
                Ok(block) => blocks.push(block),
                Err(e) => {
                    deserialize_errors += 1;
                    slog_error!("storage", "recent_blocks_deserialize_failed",
                        key => &key_str, error => e);
                }
            }
        }
        if deserialize_errors > 0 {
            slog_error!("storage", "recent_blocks_deserialize_errors_total",
                errors => deserialize_errors, loaded => blocks.len());
        }
        // Sort by height descending (most recent first), with hash tiebreaker
        // for deterministic ordering among blocks at the same height.
        blocks.sort_by(|a, b| {
            b.header.height.cmp(&a.header.height)
                .then_with(|| a.header.hash.cmp(&b.header.hash))
        });
        blocks.truncate(limit);
        blocks
    }

    pub fn count(&self) -> usize {
        let prefix = BLK_PREFIX.as_bytes();
        self.db.prefix_iterator(prefix)
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    slog_error!("storage", "block_iterator_error", error => e);
                    None
                }
            })
            .filter(|(k, _)| {
                // Only count primary block records (`blk:{hash}`).
                // Exclude every auxiliary entry that shares the `blk:` prefix:
                //   - `blk:best_hash`      (tip pointer)
                //   - `blk:height:{h}:{hash}` (height index)
                //   - `blk:h2h:{hash}`     (hash → height reverse index)
                //   - `blk:utxo_commit:{hash}` (UTXO commitment per block)
                let key_str = String::from_utf8(k.to_vec()).unwrap_or_default();
                key_str.starts_with(BLK_PREFIX)
                    && key_str != "blk:best_hash"
                    && !key_str.contains(":height:")
                    && !key_str.contains(":h2h:")
                    && !key_str.contains(":utxo_commit:")
            })
            .count()
    }

    /// Return all blocks sorted by height (ascending).
    /// Used by crash recovery to rebuild DAG and UTXO state from the source of truth.
    pub fn get_all_blocks_sorted_by_height(&self) -> Vec<Block> {
        let mut blocks = Vec::new();
        let prefix = BLK_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (k, v) = match item {
                Ok(pair) => pair,
                Err(e) => {
                    slog_error!("storage", "block_iterator_error", error => e);
                    continue;
                }
            };
            let key_str = String::from_utf8_lossy(&k);
            if !key_str.starts_with(BLK_PREFIX) {
                break;
            }
            // Skip metadata keys (best_hash, height index)
            if key_str == "blk:best_hash" {
                continue;
            }
            if key_str.starts_with("blk:height:") {
                continue;
            }
            if let Ok(block) = bincode::deserialize::<Block>(&v) {
                blocks.push(block);
            }
        }

        blocks.sort_by(|a, b| {
            a.header.height.cmp(&b.header.height)
                .then_with(|| a.header.hash.cmp(&b.header.hash))
        });
        blocks
    }

    pub fn save_block_height(&self, hash: &str, height: u64) {
        // DAG: multiple blocks per height → blk:height:{h}:{hash}
        let key = format!("{}height:{}:{}", BLK_PREFIX, height, hash);
        if let Err(e) = self.db.put(key.as_bytes(), hash.as_bytes()) {
            slog_error!("storage", "save_block_height_failed", error => e);
        }
    }

    /// Get ALL block hashes at a given height (DAG: multiple blocks per height).
    pub fn get_block_hashes_at_height(&self, height: u64) -> Vec<String> {
        let prefix = format!("{}height:{}:", BLK_PREFIX, height);
        let mut hashes = Vec::new();
        let iter = self.db.prefix_iterator(prefix.as_bytes());
        for item in iter {
            let (k, v) = match item {
                Ok(pair) => pair,
                Err(e) => {
                    slog_error!("storage", "block_iterator_error", error => e);
                    continue;
                }
            };
            let key_str = String::from_utf8_lossy(&k);
            if !key_str.starts_with(&prefix) {
                break;
            }
            if let Ok(hash) = String::from_utf8(v.to_vec()) {
                hashes.push(hash);
            }
        }
        hashes
    }

    /// Get ONE block hash at height (returns first found — use get_block_hashes_at_height
    /// for all blocks). Kept for backward compatibility.
    #[deprecated(note = "Returns only first hash at height. Use get_block_hashes_at_height() for DAG")]
    pub fn get_block_hash_at_height(&self, height: u64) -> Option<String> {
        self.get_block_hashes_at_height(height).into_iter().next()
    }

    /// Get the number of blocks at a specific height (DAG parallelism metric).
    pub fn blocks_at_height(&self, height: u64) -> usize {
        self.get_block_hashes_at_height(height).len()
    }

    // ── Height lookup (survives pruning) ────────────────────────────────

    /// Retrieve a block's height even after the block body has been pruned.
    /// First tries the full block; falls back to the dedicated height-by-hash
    /// index which survives pruning.
    pub fn get_block_height(&self, hash: &str) -> Option<u64> {
        // Fast path: full block still available
        if let Some(block) = self.get_block(hash) {
            return Some(block.header.height);
        }
        // Fallback: dedicated hash-to-height index (written by save_block)
        self.get_block_height_from_index(hash)
    }

    /// Read height from the dedicated `blk:h2h:{hash}` index.
    /// This key is written by `save_block` alongside the block data and
    /// is NOT deleted by `prune_block_body`, so it survives pruning.
    fn get_block_height_from_index(&self, hash: &str) -> Option<u64> {
        let key = format!("{}h2h:{}", BLK_PREFIX, hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) if data.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                Some(u64::from_le_bytes(buf))
            }
            _ => None,
        }
    }

    // ── Pruning ────────────────────────────────────────────────────────────

    /// Prune a block's body data while keeping its height index and UTXO commitment.
    /// After pruning, `get_block()` returns None but the height index still works.
    /// Returns true if the block existed and was pruned.
    pub fn prune_block_body(&self, hash: &str) -> bool {
        let block_key = format!("{}{}", BLK_PREFIX, hash);
        match self.db.get(block_key.as_bytes()) {
            Ok(Some(_)) => {
                if let Err(e) = self.db.delete(block_key.as_bytes()) {
                    slog_error!("storage", "prune_block_body_failed", error => e);
                    return false;
                }
                true
            }
            _ => false,
        }
    }

    /// Prune all block bodies below a given height.
    /// Height index entries and UTXO commitments are preserved.
    /// Returns the number of blocks pruned.
    pub fn prune_blocks_below_height(&self, below_height: u64) -> u64 {
        let mut pruned = 0u64;
        let mut pending = 0u64;
        let mut batch = rocksdb::WriteBatch::default();

        // Iterate actual blocks instead of every possible height (O(blocks) not O(height))
        let prefix = BLK_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (k, v) = match item {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            let key_str = String::from_utf8_lossy(&k);
            if !key_str.starts_with(BLK_PREFIX) {
                break;
            }
            // Skip metadata and height index keys
            if key_str == "blk:best_hash" || key_str.contains(":height:") || key_str.contains(":utxo_commit:") {
                continue;
            }

            // Deserialize to check height
            let block: Block = match bincode::deserialize(&v) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if block.header.height < below_height {
                batch.delete(&*k);
                pending += 1;

                // Write in batches of 1000 to limit memory
                if pending >= 1000 {
                    match self.db.write(batch) {
                        Ok(_) => {
                            pruned += pending;
                            pending = 0;
                        }
                        Err(e) => {
                            slog_error!("storage", "pruning_batch_write_failed", error => e);
                            return pruned;
                        }
                    }
                    batch = rocksdb::WriteBatch::default();
                }
            }
        }

        // Write remaining batch
        if pending > 0 {
            match self.db.write(batch) {
                Ok(_) => {
                    pruned += pending;
                }
                Err(e) => {
                    slog_error!("storage", "final_pruning_batch_failed", error => e);
                }
            }
        }
        pruned
    }

    /// Delete a block from the store (block data, height index, and h2h index).
    /// Used for cleanup when DAG insertion fails after a successful save.
    pub fn delete_block(&self, hash: &str) -> bool {
        let block_key = format!("{}{}", BLK_PREFIX, hash);
        // Get height from the block itself, or fall back to the h2h
        // index (which survives pruning). Without this fallback,
        // delete_block on a pruned block leaves a stale height index.
        let height = self.get_block(hash)
            .map(|b| b.header.height)
            .or_else(|| self.get_block_height_from_index(hash));

        let mut batch = rocksdb::WriteBatch::default();
        batch.delete(block_key.as_bytes());

        if let Some(h) = height {
            let height_key = format!("{}height:{}:{}", BLK_PREFIX, h, hash);
            batch.delete(height_key.as_bytes());
        }

        let h2h_key = format!("{}h2h:{}", BLK_PREFIX, hash);
        batch.delete(h2h_key.as_bytes());

        match self.db.write(batch) {
            Ok(_) => true,
            Err(e) => {
                slog_error!("storage", "delete_block_failed", hash => hash, error => e);
                false
            }
        }
    }

    /// Check if a block body exists (not pruned).
    pub fn has_block_body(&self, hash: &str) -> bool {
        self.block_exists(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::infrastructure::storage::rocksdb::core::db::NodeDB;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_block_store_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn make_block(hash: &str, height: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                hash: hash.to_string(),
                parents: vec![],
                merkle_root: "mr".into(),
                timestamp: 1000,
                nonce: 0,
                difficulty: 1,
                height,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody { transactions: vec![] },
        }
    }

    fn open_store() -> BlockStore {
        let path = tmp_path();
        let node_db = NodeDB::new(&path).expect("open NodeDB");
        BlockStore::new(node_db.shared()).expect("open BlockStore")
    }

    #[test]
    fn save_and_get_block_roundtrip() {
        let store = open_store();
        let block = make_block("abc123", 0);

        assert!(store.save_block(&block));

        let loaded = store.get_block("abc123").expect("block should exist");
        assert_eq!(loaded.header.hash, "abc123");
        assert_eq!(loaded.header.height, 0);
    }

    #[test]
    fn block_exists_true_for_saved_false_for_unknown() {
        let store = open_store();
        let block = make_block("exists_test", 1);

        assert!(!store.block_exists("exists_test"));
        store.save_block(&block);
        assert!(store.block_exists("exists_test"));
        assert!(!store.block_exists("no_such_block"));
    }

    #[test]
    fn get_best_hash_and_update_best_hash() {
        let store = open_store();

        assert!(store.get_best_hash().is_none());

        assert!(store.update_best_hash("tip_hash_1"));
        assert_eq!(store.get_best_hash().unwrap(), "tip_hash_1");

        assert!(store.update_best_hash("tip_hash_2"));
        assert_eq!(store.get_best_hash().unwrap(), "tip_hash_2");
    }

    #[test]
    fn get_block_hashes_at_height_returns_correct_hashes() {
        let store = open_store();

        let b1 = make_block("h5_block_a", 5);
        let b2 = make_block("h5_block_b", 5);
        let b3 = make_block("h7_block_c", 7);

        store.save_block(&b1);
        store.save_block(&b2);
        store.save_block(&b3);

        let mut hashes_at_5 = store.get_block_hashes_at_height(5);
        hashes_at_5.sort();
        assert_eq!(hashes_at_5, vec!["h5_block_a", "h5_block_b"]);

        let hashes_at_7 = store.get_block_hashes_at_height(7);
        assert_eq!(hashes_at_7, vec!["h7_block_c"]);

        let hashes_at_99 = store.get_block_hashes_at_height(99);
        assert!(hashes_at_99.is_empty());
    }

    #[test]
    fn prune_block_body_removes_body_but_keeps_height_index() {
        let store = open_store();
        let block = make_block("prune_me", 3);

        store.save_block(&block);
        assert!(store.block_exists("prune_me"));

        assert!(store.prune_block_body("prune_me"));
        assert!(!store.block_exists("prune_me"));
        assert!(store.get_block("prune_me").is_none());

        // Height index should still list the hash
        let hashes = store.get_block_hashes_at_height(3);
        assert!(hashes.contains(&"prune_me".to_string()));
    }

    #[test]
    fn prune_blocks_below_height_batch_pruning() {
        let store = open_store();

        store.save_block(&make_block("h0", 0));
        store.save_block(&make_block("h1", 1));
        store.save_block(&make_block("h2", 2));
        store.save_block(&make_block("h3", 3));

        let pruned = store.prune_blocks_below_height(2);
        assert_eq!(pruned, 2);

        // Blocks at height 0 and 1 should be pruned
        assert!(!store.block_exists("h0"));
        assert!(!store.block_exists("h1"));

        // Blocks at height 2 and 3 should remain
        assert!(store.block_exists("h2"));
        assert!(store.block_exists("h3"));

        // Height indices preserved for pruned blocks
        assert!(store.get_block_hashes_at_height(0).contains(&"h0".to_string()));
        assert!(store.get_block_hashes_at_height(1).contains(&"h1".to_string()));
    }

    #[test]
    fn count_returns_correct_number() {
        let store = open_store();

        assert_eq!(store.count(), 0);

        store.save_block(&make_block("c1", 0));
        assert_eq!(store.count(), 1);

        store.save_block(&make_block("c2", 1));
        store.save_block(&make_block("c3", 2));
        assert_eq!(store.count(), 3);
    }
}
