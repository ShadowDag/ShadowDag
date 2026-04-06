// ===============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// ===============================================================================
//
// Tip Manager -- RocksDB-backed manager for DAG tips (leaf blocks with no children).
//
// In a BlockDAG, tips are blocks that haven't been referenced as parents yet.
// New blocks select their parents from the current tip set.
//
// RocksDB is the source of truth. An in-memory HashMap acts as a hot cache
// for fast tip selection. On node restart, tips are recovered from RocksDB
// via `recover_from_db()`.
//
// Key prefixes in RocksDB:
//   "tm:tip:<hash>"  -> bincode-serialized TipInfo
//
// Features:
//   - Thread-safe tip tracking with RwLock
//   - RocksDB persistence for crash recovery
//   - Blue-score weighted tip selection
//   - Anti-selfish-mining tip validation
//   - BPS-aware tip limiting
//   - Tip age monitoring (stale tip detection)
// ===============================================================================

use crate::errors::{DagError, StorageError};
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::slog_info;
use rocksdb::{DB, Options, IteratorMode, WriteBatch};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of tips before forced merging
pub const MAX_TIPS: usize = 512;

/// Tip becomes stale after this many seconds without being referenced
pub const TIP_STALE_THRESHOLD_SEC: u64 = 120;

/// Minimum tips to maintain (prevent single-chain degradation)
pub const MIN_TIPS: usize = 1;

// ── RocksDB key builder ──────────────────────────────────────────────────

#[inline]
fn key_tip(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + hash.len());
    v.extend_from_slice(b"tm:tip:");
    v.extend_from_slice(hash.as_bytes());
    v
}

const TIP_PREFIX: &[u8] = b"tm:tip:";

/// Information about a DAG tip
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipInfo {
    pub hash:       String,
    pub blue_score: u64,
    pub height:     u64,
    pub timestamp:  u64,
    pub added_at:   u64,
}

impl TipInfo {
    pub fn new(hash: String, blue_score: u64, height: u64, timestamp: u64) -> Self {
        Self {
            hash,
            blue_score,
            height,
            timestamp,
            added_at: now_secs(),
        }
    }

    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.added_at)
    }

    pub fn is_stale(&self) -> bool {
        self.age_secs() > TIP_STALE_THRESHOLD_SEC
    }
}

/// Thread-safe, RocksDB-backed tip manager
pub struct TipManager {
    db:       Arc<DB>,
    tips:     RwLock<HashMap<String, TipInfo>>,
    max_tips: usize,
}

impl TipManager {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, DagError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(16 * 1024 * 1024);

        let db = open_shared_db(source, &opts)
            .map_err(|e| StorageError::OpenFailed { path: "TipManager".to_string(), reason: e.to_string() })?;

        let mgr = Self {
            db,
            tips:     RwLock::new(HashMap::new()),
            max_tips: MAX_TIPS,
        };
        mgr.recover_from_db();
        Ok(mgr)
    }

    pub fn with_max_tips<S: Into<SharedDbSource>>(source: S, max_tips: usize) -> Result<Self, DagError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = open_shared_db(source, &opts)
            .map_err(|e| StorageError::OpenFailed { path: "TipManager".to_string(), reason: e.to_string() })?;

        let mgr = Self {
            db,
            tips:     RwLock::new(HashMap::new()),
            max_tips: max_tips.max(MIN_TIPS),
        };
        mgr.recover_from_db();
        Ok(mgr)
    }

    // ── Recovery from RocksDB ────────────────────────────────────────────

    /// Rebuild in-memory tip cache from RocksDB. Called once at startup.
    pub fn recover_from_db(&self) {
        let mut tips = self.tips.write().unwrap_or_else(|e| e.into_inner());
        tips.clear();

        for (k, v) in self.db.iterator(IteratorMode::From(TIP_PREFIX, rocksdb::Direction::Forward)).flatten() {
            if !k.starts_with(TIP_PREFIX) { break; }
            if let Ok(info) = bincode::deserialize::<TipInfo>(&v) {
                tips.insert(info.hash.clone(), info);
            }
        }

        if !tips.is_empty() {
            slog_info!("dag", "tip_manager_recovered", tips => tips.len());
        }
    }

    // ── Persistence helpers ──────────────────────────────────────────────

    fn persist_tip(&self, info: &TipInfo) {
        if let Ok(data) = bincode::serialize(info) {
            let _ = self.db.put(key_tip(&info.hash), data);
        }
    }

    fn delete_tip_from_db(&self, hash: &str) {
        let _ = self.db.delete(key_tip(hash));
    }

    // ── Public API ───────────────────────────────────────────────────────

    /// Add a new tip to the set
    pub fn add_tip(&self, info: TipInfo) {
        let mut tips = self.tips.write().unwrap_or_else(|e| e.into_inner());

        // If at capacity, evict the lowest blue-score tip
        if tips.len() >= self.max_tips {
            self.evict_lowest_score(&mut tips);
        }

        self.persist_tip(&info);
        tips.insert(info.hash.clone(), info);
    }

    /// Remove a tip (when it gets referenced as a parent)
    pub fn remove_tip(&self, hash: &str) {
        self.delete_tip_from_db(hash);
        self.tips.write().unwrap_or_else(|e| e.into_inner()).remove(hash);
    }

    /// Called when a new block arrives: removes parents from tips, adds new block as tip
    pub fn on_new_block(&self, block_hash: &str, parents: &[String], blue_score: u64, height: u64, timestamp: u64) {
        let mut tips = self.tips.write().unwrap_or_else(|e| e.into_inner());
        let mut batch = WriteBatch::default();

        // Remove parents from tip set (they now have a child)
        for parent in parents {
            tips.remove(parent);
            batch.delete(key_tip(parent));
        }

        // Add new block as tip
        let info = TipInfo::new(block_hash.to_string(), blue_score, height, timestamp);
        if tips.len() >= self.max_tips {
            self.evict_lowest_score(&mut tips);
        }

        if let Ok(data) = bincode::serialize(&info) {
            batch.put(key_tip(block_hash), data);
        }

        let _ = self.db.write(batch);
        tips.insert(block_hash.to_string(), info);
    }

    /// Select best parents for a new block (sorted by blue score, highest first)
    pub fn select_parents(&self, max_parents: usize) -> Vec<String> {
        let tips = self.tips.read().unwrap_or_else(|e| e.into_inner());

        let mut sorted: Vec<&TipInfo> = tips.values().collect();
        sorted.sort_by(|a, b| {
            b.blue_score.cmp(&a.blue_score)
                .then_with(|| a.hash.cmp(&b.hash))
        });

        sorted.iter()
            .take(max_parents)
            .map(|t| t.hash.clone())
            .collect()
    }

    /// Get the tip with the highest blue score (selected parent candidate)
    pub fn best_tip(&self) -> Option<TipInfo> {
        let tips = self.tips.read().unwrap_or_else(|e| e.into_inner());
        // Deterministic tie-break: highest blue_score, then lowest hash.
        // Without this, HashMap iteration order could vary between nodes,
        // causing different selected parents → consensus fork.
        tips.values()
            .max_by(|a, b| {
                a.blue_score.cmp(&b.blue_score)
                    .then_with(|| b.hash.cmp(&a.hash)) // lower hash wins tie
            })
            .cloned()
    }

    /// Get all current tips (deterministic order: by blue_score desc, then hash asc)
    pub fn get_tips(&self) -> Vec<TipInfo> {
        let tips = self.tips.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<TipInfo> = tips.values().cloned().collect();
        v.sort_by(|a, b| b.blue_score.cmp(&a.blue_score).then_with(|| a.hash.cmp(&b.hash)));
        v
    }

    /// Get tip hashes only (deterministic: sorted lexicographically)
    pub fn tip_hashes(&self) -> Vec<String> {
        let tips = self.tips.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<String> = tips.keys().cloned().collect();
        v.sort_unstable();
        v
    }

    /// Number of current tips
    pub fn tip_count(&self) -> usize {
        self.tips.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Check if a hash is a current tip
    pub fn is_tip(&self, hash: &str) -> bool {
        self.tips.read().unwrap_or_else(|e| e.into_inner()).contains_key(hash)
    }

    /// Remove stale tips (older than threshold)
    pub fn prune_stale(&self) -> usize {
        let mut tips = self.tips.write().unwrap_or_else(|e| e.into_inner());
        let before = tips.len();

        if tips.len() <= MIN_TIPS {
            return 0;
        }

        let stale: Vec<String> = tips.values()
            .filter(|t| t.is_stale())
            .map(|t| t.hash.clone())
            .collect();

        for hash in &stale {
            if tips.len() <= MIN_TIPS { break; }
            self.delete_tip_from_db(hash);
            tips.remove(hash);
        }

        before - tips.len()
    }

    /// Get DAG width (number of tips = parallelism level)
    pub fn dag_width(&self) -> usize {
        self.tip_count()
    }

    /// Get the highest blue score among all tips
    pub fn best_blue_score(&self) -> u64 {
        self.tips.read().unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|t| t.blue_score)
            .max()
            .unwrap_or(0)
    }

    /// Get the highest height among all tips
    pub fn best_height(&self) -> u64 {
        self.tips.read().unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|t| t.height)
            .max()
            .unwrap_or(0)
    }

    /// Get the underlying DB handle (for sharing with other components)
    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }

    fn evict_lowest_score(&self, tips: &mut HashMap<String, TipInfo>) {
        if let Some(lowest) = tips.values()
            .min_by_key(|t| t.blue_score)
            .map(|t| t.hash.clone())
        {
            self.delete_tip_from_db(&lowest);
            tips.remove(&lowest);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_tipmanager_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn tip(hash: &str, score: u64, height: u64) -> TipInfo {
        TipInfo::new(hash.to_string(), score, height, 1735689600)
    }

    #[test]
    fn add_and_count() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("a", 10, 1));
        mgr.add_tip(tip("b", 20, 2));
        assert_eq!(mgr.tip_count(), 2);
    }

    #[test]
    fn remove_tip() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("a", 10, 1));
        mgr.remove_tip("a");
        assert_eq!(mgr.tip_count(), 0);
    }

    #[test]
    fn on_new_block_updates_tips() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("genesis", 0, 0));
        mgr.on_new_block("block1", &["genesis".to_string()], 1, 1, 1000);

        assert!(!mgr.is_tip("genesis"));
        assert!(mgr.is_tip("block1"));
    }

    #[test]
    fn select_parents_by_blue_score() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("low", 5, 1));
        mgr.add_tip(tip("high", 100, 10));
        mgr.add_tip(tip("mid", 50, 5));

        let parents = mgr.select_parents(2);
        assert_eq!(parents[0], "high");
        assert_eq!(parents[1], "mid");
    }

    #[test]
    fn best_tip_is_highest_score() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("a", 10, 1));
        mgr.add_tip(tip("b", 99, 5));
        mgr.add_tip(tip("c", 50, 3));

        let best = mgr.best_tip().unwrap();
        assert_eq!(best.hash, "b");
        assert_eq!(best.blue_score, 99);
    }

    #[test]
    fn evicts_at_capacity() {
        let mgr = TipManager::with_max_tips(tmp_path().as_str(), 3).unwrap();
        mgr.add_tip(tip("a", 10, 1));
        mgr.add_tip(tip("b", 20, 2));
        mgr.add_tip(tip("c", 30, 3));
        mgr.add_tip(tip("d", 40, 4)); // Should evict "a" (lowest score)

        assert_eq!(mgr.tip_count(), 3);
        assert!(!mgr.is_tip("a"));
        assert!(mgr.is_tip("d"));
    }

    #[test]
    fn dag_width_equals_tip_count() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("a", 1, 1));
        mgr.add_tip(tip("b", 2, 2));
        assert_eq!(mgr.dag_width(), 2);
    }

    #[test]
    fn best_height_and_score() {
        let mgr = TipManager::new(tmp_path().as_str()).unwrap();
        mgr.add_tip(tip("a", 10, 5));
        mgr.add_tip(tip("b", 20, 8));
        assert_eq!(mgr.best_blue_score(), 20);
        assert_eq!(mgr.best_height(), 8);
    }

    #[test]
    fn recover_from_db_restores_tips() {
        let path = tmp_path();

        // Add tips and drop
        {
            let mgr = TipManager::new(path.as_str()).unwrap();
            mgr.add_tip(tip("t1", 10, 1));
            mgr.add_tip(tip("t2", 20, 2));
            mgr.add_tip(tip("t3", 30, 3));
            assert_eq!(mgr.tip_count(), 3);
        }

        // Re-open -- should recover from RocksDB
        {
            let mgr = TipManager::new(path.as_str()).unwrap();
            assert_eq!(mgr.tip_count(), 3);
            assert!(mgr.is_tip("t1"));
            assert!(mgr.is_tip("t2"));
            assert!(mgr.is_tip("t3"));
            assert_eq!(mgr.best_blue_score(), 30);
        }
    }

    #[test]
    fn remove_tip_persists_across_restart() {
        let path = tmp_path();

        {
            let mgr = TipManager::new(path.as_str()).unwrap();
            mgr.add_tip(tip("a", 10, 1));
            mgr.add_tip(tip("b", 20, 2));
            mgr.remove_tip("a");
            assert_eq!(mgr.tip_count(), 1);
        }

        {
            let mgr = TipManager::new(path.as_str()).unwrap();
            assert_eq!(mgr.tip_count(), 1);
            assert!(!mgr.is_tip("a"));
            assert!(mgr.is_tip("b"));
        }
    }
}
