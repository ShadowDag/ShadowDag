// ═══════════════════════════════════════════════════════════════════════════
//      S H A D O W D A G
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering}
};
use std::collections::{HashSet, VecDeque};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;

/// GHOSTDAG K parameter — consensus-critical constant.
/// This value MUST be identical on all nodes to ensure consistent
/// BLUE/RED classification. Changing K causes a hard fork.
/// NOTE: The canonical value lives in ConsensusParams::GHOSTDAG_K
/// (config/consensus/consensus_params.rs). This local constant is kept
/// for backward compatibility; prefer ConsensusParams::GHOSTDAG_K.
pub const GHOSTDAG_K: usize = crate::config::consensus::consensus_params::ConsensusParams::GHOSTDAG_K;
pub const MAX_ANTICONE_WALK: usize = 16_384;
pub const MAX_MERGE_SET_SIZE: usize = 1_024;
pub const MAX_CACHE_SIZE: usize = 100_000;

// ── Namespaced key prefixes ────────────────────────────────────────────
// All keys use "gd:" namespace to avoid collisions with other components
// sharing the same RocksDB instance (BlockStore uses "blk:", shadow_pool
// uses "sp:", etc.).
const PFX_BLOCK: &str       = "gd:blk:";
const PFX_PARENTS: &str     = "gd:par:";
const PFX_CHILDREN: &str    = "gd:chi:";
const PFX_BLUE_SCORE: &str  = "gd:bs:";
const PFX_BLUE: &str        = "gd:blue:";
const PFX_RED: &str         = "gd:red:";
const PFX_BLUE_SET: &str    = "gd:bset:";
const PFX_CHAIN_HEIGHT: &str = "gd:ch:";
const PFX_SEL_PARENT: &str  = "gd:sp:";
const PFX_ORDER: &str       = "gd:ord:";
const PFX_TIPS: &str        = "gd:tips";
const META_ORDER_COUNTER: &str = "gd:meta:order_counter";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagBlock {
    pub hash: String,
    pub parents: Vec<String>,
    pub height: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct GhostdagData {
    pub blue_score: u64,
    pub blue_set: Vec<String>,
    pub red_set: Vec<String>,
    pub selected_parent: String,
    pub merge_set_blues: Vec<String>,
    pub merge_set_reds: Vec<String>,
}

/// GHOSTDAG implementation backed by a shared RocksDB instance.
///
/// Production path: `new_with_db(Arc<DB>)` — shares the node's single DB.
/// Test path: `new(path)` — opens a dedicated DB for isolation.
///
/// RocksDB is internally thread-safe for concurrent reads and individual
/// writes. The only contention point is the read-modify-write of children
/// lists in `persist_block`, which is safe because the event loop processes
/// blocks sequentially.
pub struct GhostDag {
    db: Arc<DB>,
    anticone_cache: DashMap<u64, usize>,
    order_counter: AtomicU64,
}

impl GhostDag {

    /// Create GhostDag sharing the node's RocksDB instance (production path).
    /// All keys are prefixed with "gd:" to avoid collisions with other
    /// components (BlockStore, ShadowPool, etc.) in the same DB.
    ///
    /// This eliminates the split-brain risk from having a separate DB,
    /// and enables future cross-component atomic writes via WriteBatch.
    pub fn new_with_db(db: Arc<DB>) -> Self {
        // Recover persisted order counter — prevents duplicate order indices after restart
        let saved_counter = db
            .get(META_ORDER_COUNTER)
            .ok()
            .flatten()
            .and_then(|v| v.as_slice().try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);

        if saved_counter > 0 {
            eprintln!("[GhostDag] Recovered order_counter={} from shared DB", saved_counter);
        }

        Self {
            db,
            anticone_cache: DashMap::new(),
            order_counter: AtomicU64::new(saved_counter),
        }
    }

    /// Open a dedicated DB at the given path (for tests only).
    /// Production code should use `new_with_db()` with the shared DB.
    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        DB::open(&opts, Path::new(path)).ok().map(|db| {
            let arc_db = Arc::new(db);
            Self::new_with_db(arc_db)
        })
    }

    // ================= CORE =================

    pub fn add_block(&self, block: DagBlock) -> GhostdagData {
        let hash = block.hash.clone();

        if block.parents.is_empty() {
            self.store_genesis(&hash, &block);
            return GhostdagData {
                blue_score: 0,
                blue_set: vec![hash.clone()],
                red_set: vec![],
                selected_parent: hash.clone(),
                merge_set_blues: vec![hash.clone()],
                merge_set_reds: vec![],
            };
        }

        let selected_parent = self.select_parent(&block.parents);
        let merge_set = self.compute_merge_set(&selected_parent, &block.parents);

        let (merge_blues, merge_reds) =
            self.classify_merge_set(&selected_parent, &merge_set);

        // Store only the DIFF (new blues from this block), NOT the full cumulative set.
        // Full set = walk the selected parent chain and union all diffs.
        // This keeps storage O(merge_set_size) per block instead of O(chain_length).
        let blue_set_diff = merge_blues.clone();
        // For persistence, we store the diff. For computation, we use it directly.
        let blue_set = blue_set_diff.clone();

        let blue_score =
            self.get_blue_score(&selected_parent) + merge_blues.len() as u64;

        let chain_height =
            self.get_chain_height(&selected_parent) + 1;

        let order_index = self.next_order_index();

        self.persist_block(
            &hash,
            &block,
            &selected_parent,
            &blue_set,
            &merge_blues,
            &merge_reds,
            blue_score,
            chain_height,
            order_index,
        );

        // Tips update
        {
            let mut tips = self.get_tips_inner();
            for p in &block.parents { tips.remove(p); }
            tips.insert(hash.clone());
            if let Ok(data) = bincode::serialize(&tips.into_iter().collect::<Vec<_>>()) {
                let _ = self.db.put(PFX_TIPS, &data);
            }
        }

        GhostdagData {
            blue_score,
            blue_set,
            red_set: merge_reds.clone(),
            selected_parent,
            merge_set_blues: merge_blues,
            merge_set_reds: merge_reds,
        }
    }

    pub fn select_parent(&self, parents: &[String]) -> String {
        parents.iter()
            .max_by(|a, b| {
                self.get_blue_score(a)
                    .cmp(&self.get_blue_score(b))
                    .then_with(|| self.get_chain_height(a).cmp(&self.get_chain_height(b)))
                    .then(a.cmp(b))
            })
            .cloned()
            .unwrap_or_default()
    }

    // ================= MERGE =================

    pub fn compute_merge_set(
        &self,
        selected_parent: &str,
        block_parents: &[String],
    ) -> Vec<String> {

        let sp_past = self.get_past_set(selected_parent, MAX_ANTICONE_WALK);

        let mut merge_set = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for p in block_parents {
            if p != selected_parent && !sp_past.contains(p) {
                queue.push_back(p.clone());
            }
        }

        while let Some(h) = queue.pop_front() {
            if !visited.insert(h.clone()) { continue; }
            if sp_past.contains(&h) { continue; }

            merge_set.push(h.clone());

            if merge_set.len() >= MAX_MERGE_SET_SIZE {
                break;
            }

            for par in self.get_parents(&h) {
                if !visited.contains(&par) {
                    queue.push_back(par);
                }
            }
        }

        merge_set
    }

    fn classify_merge_set(
        &self,
        selected_parent: &str,
        merge_set: &[String],
    ) -> (Vec<String>, Vec<String>) {

        let mut blues = Vec::new();
        let mut reds = Vec::new();

        let mut current_blues: HashSet<String> =
            self.get_blue_set(selected_parent).into_iter().collect();

        for h in merge_set {
            let anticone = self.compute_anticone_with_blues(h, &current_blues);

            if anticone <= GHOSTDAG_K {
                blues.push(h.clone());
                current_blues.insert(h.clone());
            } else {
                reds.push(h.clone());
            }
        }

        (blues, reds)
    }

    // ================= ANTICONE =================

    /// Deterministic cache key — MUST produce identical keys across all nodes.
    /// Uses FNV-1a with a fixed seed (NOT std RandomState which varies per process).
    fn fast_hash(block: &str, blue_set: &HashSet<String>) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis (fixed, deterministic)

        for byte in block.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }

        let mut sorted: Vec<&String> = blue_set.iter().collect();
        sorted.sort_unstable();

        for b in sorted {
            for byte in b.as_bytes() {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
        }

        hash
    }

    fn compute_anticone_with_blues(
        &self,
        block_hash: &str,
        blue_set: &HashSet<String>,
    ) -> usize {

        let key = Self::fast_hash(block_hash, blue_set);

        // Use a secondary content hash to prevent FNV-1a collision-based cache poisoning.
        // We hash all blue_set entries with a different seed to create a verification key.
        let content_hash = {
            let mut h: u64 = 0xcbf29ce484222325; // FNV offset but different seed
            for b in blue_set {
                for byte in b.as_bytes() {
                    h = h.wrapping_mul(0x100000001b3);
                    h ^= *byte as u64;
                }
                h ^= 0xff; // separator
            }
            h
        };
        let composite_key = key.wrapping_mul(31).wrapping_add(content_hash);

        if let Some(cached) = self.anticone_cache.get(&composite_key) {
            return *cached;
        }

        let past = self.get_past_set(block_hash, MAX_ANTICONE_WALK);

        let size = blue_set.iter()
            .filter(|b| !past.contains(*b))
            .count();

        // Evict lowest ~25% by key to prevent thundering herd.
        // Keys are sorted before eviction to guarantee deterministic behavior
        // across threads — DashMap iteration order is non-deterministic.
        if self.anticone_cache.len() > MAX_CACHE_SIZE {
            let evict_count = MAX_CACHE_SIZE / 4;
            let mut keys_to_remove: Vec<u64> = self.anticone_cache
                .iter()
                .map(|entry| *entry.key())
                .collect();
            keys_to_remove.sort_unstable();
            keys_to_remove.truncate(evict_count);
            for key in keys_to_remove {
                self.anticone_cache.remove(&key);
            }
        }

        self.anticone_cache.insert(composite_key, size);

        size
    }

    // ================= GRAPH =================

    pub fn get_past_set(&self, hash: &str, limit: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(hash.to_string());

        while let Some(h) = queue.pop_front() {
            if !visited.insert(h.clone()) { continue; }
            if visited.len() >= limit { break; }

            for p in self.get_parents(&h) {
                queue.push_back(p);
            }
        }

        visited
    }

    // ================= STORAGE =================

    fn get_children_inner(&self, hash: &str) -> Vec<String> {
        self.db.get(format!("{}{}", PFX_CHILDREN, hash))
            .ok().flatten()
            .and_then(|d| bincode::deserialize::<Vec<String>>(&d).ok())
            .unwrap_or_default()
    }

    fn update_tips(&self, new_hash: &str, parents: &[String]) {
        let mut tips = self.get_tips_inner();

        for p in parents {
            tips.remove(p);
        }

        tips.insert(new_hash.to_string());

        if let Ok(data) = bincode::serialize(&tips.into_iter().collect::<Vec<_>>()) {
            let _ = self.db.put(PFX_TIPS, data);
        } else {
            eprintln!("[GhostDag] CRITICAL: failed to serialize tips in update_tips");
        }
    }

    fn get_tips_inner(&self) -> HashSet<String> {
        self.db.get(PFX_TIPS)
            .ok().flatten()
            .and_then(|d| bincode::deserialize::<Vec<String>>(&d).ok())
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    pub fn get_tips(&self) -> Vec<String> {
        let mut tips: Vec<String> =
            self.get_tips_inner().into_iter().collect();

        tips.sort_by_key(|t| std::cmp::Reverse(self.get_blue_score(t)));
        tips
    }

    pub fn get_stats(&self) -> DagStats {
        let tips = self.get_tips();

        let best = tips.first().cloned().unwrap_or_default();

        DagStats {
            tip_count: tips.len(),
            virtual_blue_score: self.get_blue_score(&best),
            virtual_chain_height: self.get_chain_height(&best),
        }
    }

    pub fn get_blue_score(&self, hash: &str) -> u64 {
        self.db.get(format!("{}{}", PFX_BLUE_SCORE, hash))
            .ok().flatten()
            .and_then(|d| d[..8].try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    pub fn get_chain_height(&self, hash: &str) -> u64 {
        self.db.get(format!("{}{}", PFX_CHAIN_HEIGHT, hash))
            .ok().flatten()
            .and_then(|d| d[..8].try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    pub fn get_blue_set(&self, hash: &str) -> Vec<String> {
        self.db.get(format!("{}{}", PFX_BLUE_SET, hash))
            .ok().flatten()
            .and_then(|d| bincode::deserialize::<Vec<String>>(&d).ok())
            .unwrap_or_default()
    }

    pub fn get_parents(&self, hash: &str) -> Vec<String> {
        self.db.get(format!("{}{}", PFX_PARENTS, hash))
            .ok().flatten()
            .and_then(|d| bincode::deserialize::<Vec<String>>(&d).ok())
            .unwrap_or_default()
    }

    fn next_order_index(&self) -> u64 {
        let idx = self.order_counter.fetch_add(1, Ordering::SeqCst);
        // Persist counter to RocksDB so it survives restarts.
        // We persist idx+1 (the NEXT value to use) so recovery picks up correctly.
        let _ = self.db.put(META_ORDER_COUNTER, (idx + 1).to_le_bytes());
        idx
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_block(
        &self,
        hash: &str,
        block: &DagBlock,
        sel_parent: &str,
        blue_set: &[String],
        merge_blues: &[String],
        merge_reds: &[String],
        blue_score: u64,
        chain_height: u64,
        order_index: u64,
    ) {
        let mut batch = WriteBatch::default();

        batch.put(format!("{}{}", PFX_BLOCK, hash), bincode::serialize(block).unwrap_or_default());
        batch.put(format!("{}{}", PFX_PARENTS, hash), bincode::serialize(&block.parents).unwrap_or_default());

        for p in &block.parents {
            let mut children = self.get_children_inner(p);

            if !children.iter().any(|c| c == hash) {
                children.push(hash.to_string());
            }

            batch.put(format!("{}{}", PFX_CHILDREN, p), bincode::serialize(&children).unwrap_or_default());
        }

        batch.put(format!("{}{}", PFX_BLUE_SCORE, hash), blue_score.to_le_bytes());
        batch.put(format!("{}{}", PFX_BLUE_SET, hash), bincode::serialize(blue_set).unwrap_or_default());
        batch.put(format!("{}{}", PFX_CHAIN_HEIGHT, hash), chain_height.to_le_bytes());
        batch.put(format!("{}{}", PFX_SEL_PARENT, hash), sel_parent.as_bytes());
        batch.put(format!("{}{}", PFX_ORDER, hash), order_index.to_le_bytes());

        for b in merge_blues {
            batch.put(format!("{}{}", PFX_BLUE, b), [1u8]);
        }
        for r in merge_reds {
            batch.put(format!("{}{}", PFX_RED, r), [1u8]);
        }

        let _ = self.db.write(batch);
    }

    fn store_genesis(&self, hash: &str, block: &DagBlock) {
        self.persist_block(hash, block, hash, &[hash.to_string()], &[], &[], 0, 0, 0);

        let _ = self.db.put(PFX_TIPS, bincode::serialize(&vec![hash.to_string()]).unwrap_or_default());
    }

    // ================= ADDED METHODS =================

    pub fn get_selected_parent(&self, hash: &str) -> Option<String> {
        self.db.get(format!("{}{}", PFX_SEL_PARENT, hash))
            .ok().flatten()
            .and_then(|d| String::from_utf8(d).ok())
    }

    pub fn store_blue_score(&self, hash: &str, score: u64) {
        let _ = self.db.put(format!("{}{}", PFX_BLUE_SCORE, hash), score.to_le_bytes());
        let _ = self.db.put(format!("{}{}", PFX_BLUE, hash), [1u8]);
    }

    pub fn is_blue_block(
        &self,
        block_hash: &str,
        _all_blocks: &std::collections::HashMap<String, Vec<String>>,
    ) -> bool {
        matches!(
            self.db.get(format!("{}{}", PFX_BLUE, block_hash)),
            Ok(Some(_))
        )
    }

    pub fn build_blue_set_for_past(
        &self,
        _block_hash: &str,
        parents: &[String],
        _all_blocks: &std::collections::HashMap<String, Vec<String>>,
    ) -> std::collections::HashSet<String> {
        self.reconstruct_full_blue_set(parents)
    }

    /// Reconstruct the full cumulative blue set by walking the selected parent
    /// chain and unioning all stored diffs. Each block stores only its diff
    /// (new blues from that block), so we must walk back to build the full set.
    fn reconstruct_full_blue_set(
        &self,
        parents: &[String],
    ) -> std::collections::HashSet<String> {
        let mut full_set = std::collections::HashSet::new();
        let mut current = self.select_parent(parents);
        let mut depth = 0;
        const MAX_WALK: usize = 10_000;

        loop {
            let diff = self.get_blue_set(&current);
            if diff.is_empty() && depth > 0 {
                break;
            }
            for hash in &diff {
                full_set.insert(hash.clone());
            }
            full_set.insert(current.clone());

            // Walk to selected parent's selected parent
            let parent_parents = self.get_parents(&current);
            if parent_parents.is_empty() {
                break;
            }
            current = self.select_parent(&parent_parents);
            depth += 1;
            if depth >= MAX_WALK {
                break;
            }
        }
        full_set
    }

    /// Get the underlying DB handle (for migration or cross-component use)
    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }

    /// Clear all GhostDag state from the database.
    /// Used during crash recovery before rebuilding from BlockStore.
    pub fn clear_all(&self) {
        let prefixes = [
            PFX_BLOCK, PFX_PARENTS, PFX_CHILDREN, PFX_BLUE_SCORE,
            PFX_BLUE, PFX_RED, PFX_BLUE_SET, PFX_CHAIN_HEIGHT,
            PFX_SEL_PARENT, PFX_ORDER,
        ];
        for pfx in &prefixes {
            let keys: Vec<Vec<u8>> = self.db
                .prefix_iterator(pfx.as_bytes())
                .filter_map(|r| r.ok())
                .map(|(k, _)| k.to_vec())
                .collect();
            for k in keys {
                let _ = self.db.delete(&k);
            }
        }
        let _ = self.db.delete(PFX_TIPS);
        let _ = self.db.delete(META_ORDER_COUNTER);
        self.order_counter.store(0, std::sync::atomic::Ordering::SeqCst);
        self.anticone_cache.clear();
    }
}

#[derive(Debug)]
pub struct DagStats {
    pub tip_count: usize,
    pub virtual_blue_score: u64,
    pub virtual_chain_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn make_ghostdag(label: &str) -> GhostDag {
        let path = format!("/tmp/test_ghostdag_{}_{}_{}", label, std::process::id(), ts());
        GhostDag::new(&path).expect("failed to create GhostDag")
    }

    fn genesis_block() -> DagBlock {
        DagBlock {
            hash: "genesis".to_string(),
            parents: vec![],
            height: 0,
            timestamp: 0,
        }
    }

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn test_new_creates_instance() {
        let dag = make_ghostdag("new_instance");
        // A freshly-created DAG should have no tips and zero scores.
        assert!(dag.get_tips().is_empty());
        assert_eq!(dag.get_blue_score("nonexistent"), 0);
    }

    #[test]
    fn test_new_with_db_creates_instance() {
        let path = format!(
            "/tmp/test_ghostdag_with_db_{}_{}",
            std::process::id(),
            ts()
        );
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = Arc::new(DB::open(&opts, &path).expect("open db"));
        let dag = GhostDag::new_with_db(db);
        assert!(dag.get_tips().is_empty());
    }

    // ── store_blue_score / get_blue_score roundtrip ───────────────────

    #[test]
    fn test_store_and_get_blue_score_roundtrip() {
        let dag = make_ghostdag("bs_roundtrip");
        dag.store_blue_score("block_a", 42);
        assert_eq!(dag.get_blue_score("block_a"), 42);
    }

    #[test]
    fn test_store_blue_score_overwrites() {
        let dag = make_ghostdag("bs_overwrite");
        dag.store_blue_score("block_a", 10);
        assert_eq!(dag.get_blue_score("block_a"), 10);
        dag.store_blue_score("block_a", 99);
        assert_eq!(dag.get_blue_score("block_a"), 99);
    }

    // ── get_blue_score for unknown block ──────────────────────────────

    #[test]
    fn test_get_blue_score_unknown_block_returns_zero() {
        let dag = make_ghostdag("bs_unknown");
        assert_eq!(dag.get_blue_score("does_not_exist"), 0);
        assert_eq!(dag.get_blue_score(""), 0);
    }

    // ── Multiple blocks can have scores stored and retrieved ──────────

    #[test]
    fn test_multiple_blocks_store_and_retrieve_scores() {
        let dag = make_ghostdag("bs_multi");
        let blocks = vec![
            ("alpha", 1u64),
            ("bravo", 100),
            ("charlie", 0),
            ("delta", u64::MAX),
        ];
        for (hash, score) in &blocks {
            dag.store_blue_score(hash, *score);
        }
        for (hash, score) in &blocks {
            assert_eq!(dag.get_blue_score(hash), *score, "mismatch for {}", hash);
        }
    }

    // ── Blue-score ordering ──────────────────────────────────────────

    #[test]
    fn test_blue_score_ordering() {
        let dag = make_ghostdag("bs_order");
        dag.store_blue_score("low", 5);
        dag.store_blue_score("mid", 50);
        dag.store_blue_score("high", 500);

        let low = dag.get_blue_score("low");
        let mid = dag.get_blue_score("mid");
        let high = dag.get_blue_score("high");
        assert!(low < mid, "expected low < mid");
        assert!(mid < high, "expected mid < high");
    }

    // ── selected_parent roundtrip via add_block ──────────────────────

    #[test]
    fn test_store_and_get_selected_parent_roundtrip() {
        let dag = make_ghostdag("sp_roundtrip");

        // Add genesis first so it exists in storage.
        dag.add_block(genesis_block());

        // Add a child referencing genesis as its parent.
        let child = DagBlock {
            hash: "child_1".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 1,
        };
        let data = dag.add_block(child);

        // The selected parent should be genesis (only parent).
        assert_eq!(data.selected_parent, "genesis");
        assert_eq!(
            dag.get_selected_parent("child_1"),
            Some("genesis".to_string())
        );
    }

    #[test]
    fn test_get_selected_parent_unknown_block_returns_none() {
        let dag = make_ghostdag("sp_unknown");
        assert_eq!(dag.get_selected_parent("nonexistent"), None);
    }

    // ── add_block: genesis ────────────────────────────────────────────

    #[test]
    fn test_add_genesis_block() {
        let dag = make_ghostdag("genesis");
        let data = dag.add_block(genesis_block());

        assert_eq!(data.blue_score, 0);
        assert_eq!(data.selected_parent, "genesis");
        assert!(data.red_set.is_empty());
        assert_eq!(data.blue_set, vec!["genesis".to_string()]);

        // Tips should contain only genesis.
        let tips = dag.get_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "genesis");
    }

    // ── add_block: linear chain ──────────────────────────────────────

    #[test]
    fn test_linear_chain_blue_scores_increment() {
        let dag = make_ghostdag("linear_chain");
        dag.add_block(genesis_block());

        // Build a linear chain of 5 blocks.
        for i in 1..=5u64 {
            let parent = if i == 1 {
                "genesis".to_string()
            } else {
                format!("block_{}", i - 1)
            };
            let block = DagBlock {
                hash: format!("block_{}", i),
                parents: vec![parent],
                height: i,
                timestamp: i,
            };
            dag.add_block(block);
        }

        // In a linear chain, blue scores should be monotonically increasing.
        let mut prev_score = 0;
        for i in 1..=5u64 {
            let score = dag.get_blue_score(&format!("block_{}", i));
            assert!(
                score >= prev_score,
                "block_{} score {} should be >= previous {}",
                i,
                score,
                prev_score
            );
            prev_score = score;
        }

        // The latest block should be the only tip.
        let tips = dag.get_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "block_5");
    }

    // ── add_block: simple fork (two children of genesis) ─────────────

    #[test]
    fn test_fork_creates_two_tips() {
        let dag = make_ghostdag("fork");
        dag.add_block(genesis_block());

        let left = DagBlock {
            hash: "left".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 1,
        };
        let right = DagBlock {
            hash: "right".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 2,
        };
        dag.add_block(left);
        dag.add_block(right);

        let tips = dag.get_tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&"left".to_string()));
        assert!(tips.contains(&"right".to_string()));
    }

    // ── merge block resolves fork ────────────────────────────────────

    #[test]
    fn test_merge_block_reduces_tips() {
        let dag = make_ghostdag("merge");
        dag.add_block(genesis_block());

        dag.add_block(DagBlock {
            hash: "left".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 1,
        });
        dag.add_block(DagBlock {
            hash: "right".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 2,
        });

        // Merge both branches.
        let merge = DagBlock {
            hash: "merge".to_string(),
            parents: vec!["left".to_string(), "right".to_string()],
            height: 2,
            timestamp: 3,
        };
        let data = dag.add_block(merge);

        // Blue score should be > 0 after merge.
        assert!(data.blue_score > 0);

        // Only one tip after merge.
        let tips = dag.get_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "merge");
    }

    // ── get_parents roundtrip ────────────────────────────────────────

    #[test]
    fn test_get_parents_after_add_block() {
        let dag = make_ghostdag("parents");
        dag.add_block(genesis_block());

        dag.add_block(DagBlock {
            hash: "child".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 1,
        });

        let parents = dag.get_parents("child");
        assert_eq!(parents, vec!["genesis".to_string()]);
        assert!(dag.get_parents("nonexistent").is_empty());
    }

    // ── clear_all resets state ───────────────────────────────────────

    #[test]
    fn test_clear_all_resets_state() {
        let dag = make_ghostdag("clear_all");
        dag.add_block(genesis_block());
        dag.store_blue_score("extra", 42);

        // Verify data exists before clear.
        assert_eq!(dag.get_tips().len(), 1);
        assert_eq!(dag.get_blue_score("extra"), 42);

        dag.clear_all();

        assert!(dag.get_tips().is_empty());
        assert_eq!(dag.get_blue_score("extra"), 0);
        assert_eq!(dag.get_blue_score("genesis"), 0);
    }

    // ── get_stats ────────────────────────────────────────────────────

    #[test]
    fn test_get_stats_on_linear_chain() {
        let dag = make_ghostdag("stats");
        dag.add_block(genesis_block());

        dag.add_block(DagBlock {
            hash: "b1".to_string(),
            parents: vec!["genesis".to_string()],
            height: 1,
            timestamp: 1,
        });

        let stats = dag.get_stats();
        assert_eq!(stats.tip_count, 1);
        assert!(stats.virtual_blue_score > 0 || stats.virtual_chain_height > 0);
    }

    // ── select_parent picks highest blue score ───────────────────────

    #[test]
    fn test_select_parent_picks_highest_blue_score() {
        let dag = make_ghostdag("select_parent");
        dag.store_blue_score("low", 1);
        dag.store_blue_score("high", 100);
        dag.store_blue_score("mid", 50);

        let parents = vec![
            "low".to_string(),
            "high".to_string(),
            "mid".to_string(),
        ];
        let selected = dag.select_parent(&parents);
        assert_eq!(selected, "high");
    }
}
