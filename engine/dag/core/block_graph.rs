// ===============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// ===============================================================================
//
// BlockGraph -- RocksDB-backed DAG graph with bounded LRU cache.
//
// At 32 BPS for 1 year = ~1 billion blocks. Keeping all in RAM is impossible.
// Solution: RocksDB is the source of truth. An LRU-bounded in-memory cache
// keeps the hot working set for fast access. On node restart, the cache is
// rebuilt from RocksDB via `recover_from_db()`.
//
// Key prefixes in RocksDB:
//   "bg:block:<hash>"            -> bincode-serialized Block
//   "bg:parent:<child>:<parent>" -> b"1"
//   "bg:child:<parent>:<child>"  -> b"1"
//   "bg:tip:<hash>"              -> b"1"
//   "bg:meta:genesis"            -> b"1"
//   "bg:meta:total_added"        -> u64 LE bytes
//
// Capacity:
//   MAX_CACHED_BLOCKS  = 100,000 (~52 minutes at 32 BPS)
//   MAX_ORPHANS        = 10,000
//   MAX_PARENTS        = 16
//   MAX_CHILDREN       = 1,024
// ===============================================================================

use crate::domain::block::block::Block;
use crate::errors::{DagError, StorageError};
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::slog_info;
use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Maximum blocks kept in the in-memory LRU cache
const MAX_CACHED_BLOCKS: usize = 100_000;

const MAX_ORPHANS: usize = 10_000;
use crate::config::consensus::consensus_params::ConsensusParams;
const MAX_PARENTS: usize = ConsensusParams::MAX_PARENTS;
const MAX_CHILDREN: usize = 1024;

/// Eviction batch size (how many to remove from cache when hitting the cap)
const EVICT_BATCH: usize = 10_000;

// ── RocksDB key builders (no format! allocation) ─────────────────────────

#[inline]
fn key_block(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + hash.len());
    v.extend_from_slice(b"bg:block:");
    v.extend_from_slice(hash.as_bytes());
    v
}

#[inline]
fn key_parent(child: &str, parent: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(10 + child.len() + 1 + parent.len());
    v.extend_from_slice(b"bg:parent:");
    v.extend_from_slice(child.as_bytes());
    v.push(b':');
    v.extend_from_slice(parent.as_bytes());
    v
}

#[inline]
fn key_child(parent: &str, child: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + parent.len() + 1 + child.len());
    v.extend_from_slice(b"bg:child:");
    v.extend_from_slice(parent.as_bytes());
    v.push(b':');
    v.extend_from_slice(child.as_bytes());
    v
}

#[inline]
fn key_tip(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + hash.len());
    v.extend_from_slice(b"bg:tip:");
    v.extend_from_slice(hash.as_bytes());
    v
}

const META_GENESIS: &[u8] = b"bg:meta:genesis";
const META_TOTAL_ADDED: &[u8] = b"bg:meta:total_added";

// ── Orphan persistence keys ──────────────────────────────────────────
// Orphan blocks are persisted to RocksDB so they survive restarts.
// Without this, out-of-order blocks waiting for parents are silently
// dropped on crash — potentially causing missed transactions on mainnet.

#[inline]
fn key_orphan_block(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + hash.len());
    v.extend_from_slice(b"bg:orphan:block:");
    v.extend_from_slice(hash.as_bytes());
    v
}

#[inline]
fn key_orphan_parent(parent: &str, orphan: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(17 + parent.len() + 1 + orphan.len());
    v.extend_from_slice(b"bg:orphan:parent:");
    v.extend_from_slice(parent.as_bytes());
    v.push(b':');
    v.extend_from_slice(orphan.as_bytes());
    v
}

pub struct BlockGraph {
    /// RocksDB handle -- source of truth for all DAG state
    db: Arc<DB>,

    // ── In-memory LRU cache (NOT the source of truth) ──────────────────
    /// Block data cache (LRU-bounded)
    cache_blocks: HashMap<String, Block>,
    /// Parent->children cache
    cache_children: HashMap<String, HashSet<String>>,
    /// Child->parents cache
    cache_parents: HashMap<String, HashSet<String>>,
    /// Cached tip set
    cache_tips: HashSet<String>,
    /// Insertion order for LRU eviction of the cache
    insertion_order: VecDeque<String>,

    /// Orphan blocks (bounded, in-memory only -- orphans are transient)
    pub orphans: HashMap<String, Block>,
    pub orphan_index: HashMap<String, HashSet<String>>,
    orphan_queue: VecDeque<String>,

    genesis_added: bool,
    /// Total blocks ever added (persisted in RocksDB)
    total_added: u64,
    /// Total blocks evicted from cache (runtime stat only)
    total_evicted: u64,
}

impl BlockGraph {
    /// Create a new BlockGraph backed by the given RocksDB instance.
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, DagError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(32 * 1024 * 1024);

        let db = open_shared_db(source, &opts).map_err(|e| StorageError::OpenFailed {
            path: "BlockGraph".to_string(),
            reason: e.to_string(),
        })?;

        let mut graph = Self {
            db,
            cache_blocks: HashMap::with_capacity(MAX_CACHED_BLOCKS / 2),
            cache_children: HashMap::with_capacity(MAX_CACHED_BLOCKS / 2),
            cache_parents: HashMap::with_capacity(MAX_CACHED_BLOCKS / 2),
            cache_tips: HashSet::new(),
            insertion_order: VecDeque::with_capacity(MAX_CACHED_BLOCKS),
            orphans: HashMap::new(),
            orphan_index: HashMap::new(),
            orphan_queue: VecDeque::new(),
            genesis_added: false,
            total_added: 0,
            total_evicted: 0,
        };

        graph.recover_from_db();
        Ok(graph)
    }

    // ── Recovery from RocksDB on startup ─────────────────────────────────

    /// Rebuild the in-memory LRU cache from RocksDB.
    /// Called once at startup so the node can resume without data loss.
    pub fn recover_from_db(&mut self) {
        // Recover genesis flag
        self.genesis_added = self.db.get_pinned(META_GENESIS).ok().flatten().is_some();

        // Recover total_added counter
        self.total_added = self
            .db
            .get(META_TOTAL_ADDED)
            .ok()
            .flatten()
            .and_then(|v| v.as_slice().try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);

        // Recover tips from RocksDB into cache
        self.cache_tips.clear();
        let prefix = b"bg:tip:";
        for (k, _) in self
            .db
            .iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward))
            .flatten()
        {
            if !k.starts_with(prefix) {
                break;
            }
            let hash = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
            self.cache_tips.insert(hash);
        }

        // Recover the most recent blocks into the LRU cache.
        // We load up to MAX_CACHED_BLOCKS, prioritizing tips and their ancestors.
        self.cache_blocks.clear();
        self.cache_parents.clear();
        self.cache_children.clear();
        self.insertion_order.clear();

        // BFS from tips to load the most recent subgraph
        let mut queue: VecDeque<String> = self.cache_tips.iter().cloned().collect();
        let mut visited: HashSet<String> = HashSet::new();

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }
            if visited.len() >= MAX_CACHED_BLOCKS {
                break;
            }
            visited.insert(hash.clone());

            // Load block data from RocksDB
            if let Ok(Some(data)) = self.db.get(key_block(&hash)) {
                if let Ok(block) = bincode::deserialize::<Block>(&data) {
                    self.cache_blocks.insert(hash.clone(), block);
                    self.insertion_order.push_back(hash.clone());
                }
            }

            // Load parents from RocksDB
            let parents = self.db_get_parents(&hash);
            if !parents.is_empty() {
                for p in &parents {
                    self.cache_children
                        .entry(p.clone())
                        .or_default()
                        .insert(hash.clone());
                    if !visited.contains(p) {
                        queue.push_back(p.clone());
                    }
                }
                self.cache_parents
                    .insert(hash.clone(), parents.into_iter().collect());
            }

            // Load children from RocksDB
            let children = self.db_get_children(&hash);
            if !children.is_empty() {
                self.cache_children
                    .entry(hash.clone())
                    .or_default()
                    .extend(children);
            }
        }

        // ── Recover orphan blocks from RocksDB ─────────────────────────
        self.orphans.clear();
        self.orphan_index.clear();
        self.orphan_queue.clear();

        let orphan_prefix = b"bg:orphan:block:";
        let mut orphan_count = 0u64;
        for (k, v) in self
            .db
            .iterator(IteratorMode::From(
                orphan_prefix,
                rocksdb::Direction::Forward,
            ))
            .flatten()
        {
            if !k.starts_with(orphan_prefix) {
                break;
            }
            let hash = String::from_utf8_lossy(&k[orphan_prefix.len()..]).into_owned();
            if let Ok(block) = bincode::deserialize::<Block>(&v) {
                for parent in &block.header.parents {
                    self.orphan_index
                        .entry(parent.clone())
                        .or_default()
                        .insert(hash.clone());
                }
                self.orphan_queue.push_back(hash.clone());
                self.orphans.insert(hash, block);
                orphan_count += 1;
                if orphan_count as usize >= MAX_ORPHANS {
                    break;
                }
            }
        }

        if !visited.is_empty() || orphan_count > 0 {
            slog_info!("dag", "block_graph_recovered", blocks => visited.len(), tips => self.cache_tips.len(), orphans => orphan_count, total_added => self.total_added);
        }

        // Try to connect recovered orphans whose parents may now exist
        let orphan_parents: Vec<String> = self.orphan_index.keys().cloned().collect();
        for parent in orphan_parents {
            if self.cache_blocks.contains_key(&parent) || self.db_block_exists(&parent) {
                self.connect_orphans(&parent);
            }
        }
    }

    // ── RocksDB read helpers ─────────────────────────────────────────────

    fn db_block_exists(&self, hash: &str) -> bool {
        self.db
            .get_pinned(key_block(hash))
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    fn db_get_parents(&self, hash: &str) -> Vec<String> {
        let prefix = format!("bg:parent:{}:", hash);
        self.scan_prefix_suffix(prefix.as_bytes())
    }

    fn db_get_children(&self, hash: &str) -> Vec<String> {
        let prefix = format!("bg:child:{}:", hash);
        self.scan_prefix_suffix(prefix.as_bytes())
    }

    fn scan_prefix_suffix(&self, prefix: &[u8]) -> Vec<String> {
        let mut result = Vec::new();
        for (k, _) in self
            .db
            .iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward))
            .flatten()
        {
            if !k.starts_with(prefix) {
                break;
            }
            result.push(String::from_utf8_lossy(&k[prefix.len()..]).into_owned());
        }
        result
    }

    // ── Block addition (writes to RocksDB + updates cache) ───────────────

    pub fn add_block(&mut self, block: Block) -> Result<(), DagError> {
        let hash = block.header.hash.clone();
        let block_parents = block.header.parents.clone();

        if block_parents.is_empty() {
            if self.genesis_added {
                return Err(DagError::DuplicateBlock("Genesis already exists".into()));
            }
            self.genesis_added = true;
            self.insert_block(hash, block)?;
            return Ok(());
        }

        // Check both cache and RocksDB for existence
        if self.cache_blocks.contains_key(&hash) || self.db_block_exists(&hash) {
            return Err(DagError::DuplicateBlock(hash));
        }
        if self.orphans.contains_key(&hash) {
            return Ok(());
        }
        if block_parents.contains(&hash) {
            return Err(DagError::SelfParent(hash));
        }
        if block_parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents(block_parents.len(), MAX_PARENTS));
        }
        let unique: HashSet<_> = block_parents.iter().collect();
        if unique.len() != block_parents.len() {
            return Err(DagError::DuplicateParents(hash));
        }

        // Check if all parents are known (cache OR RocksDB)
        let all_parents_known = block_parents
            .iter()
            .all(|p| self.cache_blocks.contains_key(p) || self.db_block_exists(p));

        if all_parents_known {
            // Cycle detection: ensure none of the ancestors of this block
            // are the block itself. In a DAG, cycles are NEVER allowed.
            if self.has_cycle(&hash, &block_parents) {
                return Err(DagError::Other(
                    "Cycle detected: block would create a cycle in the DAG".into(),
                ));
            }
            self.insert_block(hash.clone(), block)?;
            self.connect_orphans(&hash);
            return Ok(());
        }

        // Not all parents known -> orphan
        self.store_orphan(hash, block);
        Ok(())
    }

    fn insert_block(&mut self, hash: String, block: Block) -> Result<(), DagError> {
        if self.cache_blocks.contains_key(&hash) || self.db_block_exists(&hash) {
            return Ok(());
        }

        let block_parents = block.header.parents.clone();

        // Check children limits
        for p in &block_parents {
            let child_count = self.cache_children.get(p).map(|s| s.len()).unwrap_or(0);
            if child_count >= MAX_CHILDREN {
                return Err(DagError::Other("Too many children for parent".into()));
            }
        }

        // ── Persist to RocksDB (source of truth) ────────────────────────
        let mut batch = WriteBatch::default();

        let serialized =
            bincode::serialize(&block).map_err(|e| DagError::Serialization(e.to_string()))?;
        batch.put(key_block(&hash), &serialized);

        for p in &block_parents {
            batch.put(key_parent(&hash, p), b"1");
            batch.put(key_child(p, &hash), b"1");
            batch.delete(key_tip(p));
        }
        batch.put(key_tip(&hash), b"1");

        if block_parents.is_empty() {
            // Genesis
            batch.put(META_GENESIS, b"1");
        }

        let new_total = self.total_added + 1;
        batch.put(META_TOTAL_ADDED, new_total.to_le_bytes());

        self.db.write(batch).map_err(StorageError::RocksDb)?;
        self.total_added = new_total;

        // ── Update in-memory LRU cache ──────────────────────────────────

        // Evict from cache if at capacity
        if self.cache_blocks.len() >= MAX_CACHED_BLOCKS {
            self.evict_oldest_blocks();
        }

        self.cache_blocks.insert(hash.clone(), block);
        self.insertion_order.push_back(hash.clone());

        let mut parent_set = HashSet::with_capacity(block_parents.len());
        for p in &block_parents {
            parent_set.insert(p.clone());
            self.cache_children
                .entry(p.clone())
                .or_default()
                .insert(hash.clone());
            self.cache_tips.remove(p);
        }

        self.cache_parents.insert(hash.clone(), parent_set);
        self.cache_tips.insert(hash);

        Ok(())
    }

    /// Evict oldest blocks from the in-memory cache.
    /// Tips and their immediate parents are NEVER evicted from cache.
    /// Data remains safely in RocksDB.
    fn evict_oldest_blocks(&mut self) {
        let mut evicted = 0;

        while evicted < EVICT_BATCH {
            let hash = match self.insertion_order.pop_front() {
                Some(h) => h,
                None => break,
            };

            // NEVER evict tips or parents of tips from cache
            if self.cache_tips.contains(&hash) {
                self.insertion_order.push_back(hash);
                continue;
            }
            let is_tip_parent = self
                .cache_children
                .get(&hash)
                .map(|kids| kids.iter().any(|k| self.cache_tips.contains(k)))
                .unwrap_or(false);
            if is_tip_parent {
                self.insertion_order.push_back(hash);
                continue;
            }

            // Evict from cache only -- data stays in RocksDB
            self.cache_blocks.remove(&hash);
            if let Some(parents) = self.cache_parents.remove(&hash) {
                for p in &parents {
                    if let Some(kids) = self.cache_children.get_mut(p) {
                        kids.remove(&hash);
                        if kids.is_empty() {
                            self.cache_children.remove(p);
                        }
                    }
                }
            }
            self.cache_children.remove(&hash);
            self.total_evicted += 1;
            evicted += 1;
        }
    }

    fn store_orphan(&mut self, hash: String, block: Block) {
        if self.orphans.contains_key(&hash) {
            return;
        }
        if self.orphans.len() >= MAX_ORPHANS {
            self.evict_orphan();
        }

        // Persist orphan to RocksDB so it survives restarts
        if let Ok(serialized) = bincode::serialize(&block) {
            let mut batch = WriteBatch::default();
            batch.put(key_orphan_block(&hash), &serialized);
            for parent in &block.header.parents {
                batch.put(key_orphan_parent(parent, &hash), b"1");
            }
            let _ = self.db.write(batch);
        }

        for parent in &block.header.parents {
            self.orphan_index
                .entry(parent.clone())
                .or_default()
                .insert(hash.clone());
        }
        self.orphan_queue.push_back(hash.clone());
        self.orphans.insert(hash, block);
    }

    fn evict_orphan(&mut self) {
        while let Some(old) = self.orphan_queue.pop_front() {
            if self.orphans.contains_key(&old) {
                self.remove_orphan(&old);
                return;
            }
        }
    }

    fn remove_orphan(&mut self, hash: &str) -> Option<Block> {
        if let Some(block) = self.orphans.remove(hash) {
            // Remove orphan from RocksDB
            let mut batch = WriteBatch::default();
            batch.delete(key_orphan_block(hash));
            for parent in &block.header.parents {
                batch.delete(key_orphan_parent(parent, hash));
                if let Some(set) = self.orphan_index.get_mut(parent) {
                    set.remove(hash);
                    if set.is_empty() {
                        self.orphan_index.remove(parent);
                    }
                }
            }
            let _ = self.db.write(batch);
            return Some(block);
        }
        None
    }

    fn connect_orphans(&mut self, root: &str) {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back(root.to_string());

        while let Some(parent) = queue.pop_front() {
            if !visited.insert(parent.clone()) {
                continue;
            }
            let children = match self.orphan_index.remove(&parent) {
                Some(c) => c,
                None => continue,
            };
            for orphan_hash in children {
                if let Some(block) = self.remove_orphan(&orphan_hash) {
                    let all_known = block
                        .header
                        .parents
                        .iter()
                        .all(|p| self.cache_blocks.contains_key(p) || self.db_block_exists(p));
                    if all_known {
                        let h = block.header.hash.clone();
                        if self.insert_block(h.clone(), block).is_ok() {
                            queue.push_back(h);
                        }
                    } else {
                        self.store_orphan(orphan_hash, block);
                    }
                }
            }
        }
    }

    // ── Cycle detection (full DFS with visited + recursion stack) ────────

    /// Check if adding a block with the given hash would create a cycle.
    /// Uses DFS with gray/black coloring (recursion_stack = gray, visited = black)
    /// to detect back-edges. A cycle exists if any ancestor of block_hash
    /// is block_hash itself. No depth limit -- traverses the entire ancestor chain.
    pub fn has_cycle(&self, block_hash: &str, parent_hashes: &[String]) -> bool {
        // visited = fully explored (black), rec_stack = currently being explored (gray)
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        rec_stack.insert(block_hash.to_string());

        for parent in parent_hashes {
            if self.dfs_has_cycle(parent, block_hash, &mut visited, &mut rec_stack) {
                return true;
            }
        }
        false
    }

    /// DFS helper: returns true if `current` can reach `target` through ancestors.
    /// `rec_stack` tracks nodes in the current DFS path (gray nodes).
    /// `visited` tracks fully explored nodes (black nodes) -- safe to skip.
    fn dfs_has_cycle(
        &self,
        current: &str,
        target: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> bool {
        if current == target {
            return true; // Back-edge found: ancestor is the block itself
        }
        if visited.contains(current) {
            return false; // Already fully explored, no cycle through here
        }
        if rec_stack.contains(current) {
            return false; // Already on the current path but not target, skip
        }

        rec_stack.insert(current.to_string());

        // Get parents from cache or RocksDB
        let parents = if let Some(p) = self.cache_parents.get(current) {
            p.iter().cloned().collect::<Vec<_>>()
        } else {
            self.db_get_parents(current)
        };

        for parent in &parents {
            if self.dfs_has_cycle(parent, target, visited, rec_stack) {
                return true;
            }
        }

        rec_stack.remove(current);
        visited.insert(current.to_string());
        false
    }

    // ── Getters (check cache first, fall back to RocksDB) ────────────────

    /// Get a block. Checks LRU cache first, then RocksDB.
    pub fn get_block(&self, hash: &str) -> Option<Block> {
        if let Some(b) = self.cache_blocks.get(hash) {
            return Some(b.clone());
        }
        // Fall back to RocksDB
        self.db
            .get(key_block(hash))
            .ok()
            .flatten()
            .and_then(|data| bincode::deserialize::<Block>(&data).ok())
    }

    /// Get parents. Checks cache first, then RocksDB.
    pub fn get_parents(&self, hash: &str) -> Option<HashSet<String>> {
        if let Some(p) = self.cache_parents.get(hash) {
            return Some(p.clone());
        }
        let parents = self.db_get_parents(hash);
        if parents.is_empty() {
            None
        } else {
            Some(parents.into_iter().collect())
        }
    }

    /// Get children. Checks cache first, then RocksDB.
    pub fn get_children(&self, hash: &str) -> Option<HashSet<String>> {
        if let Some(c) = self.cache_children.get(hash) {
            return Some(c.clone());
        }
        let children = self.db_get_children(hash);
        if children.is_empty() {
            None
        } else {
            Some(children.into_iter().collect())
        }
    }

    pub fn is_tip(&self, hash: &str) -> bool {
        self.cache_tips.contains(hash)
    }
    pub fn tips_iter(&self) -> impl Iterator<Item = &String> {
        self.cache_tips.iter()
    }
    pub fn blocks_iter(&self) -> impl Iterator<Item = (&String, &Block)> {
        self.cache_blocks.iter()
    }
    pub fn total_blocks(&self) -> usize {
        self.cache_blocks.len()
    }
    pub fn total_tips(&self) -> usize {
        self.cache_tips.len()
    }
    pub fn total_orphans(&self) -> usize {
        self.orphans.len()
    }

    /// Check if a block hash is known (cache OR RocksDB)
    pub fn is_known(&self, hash: &str) -> bool {
        self.cache_blocks.contains_key(hash)
            || self.cache_parents.contains_key(hash)
            || self.db_block_exists(hash)
    }

    /// Stats
    pub fn total_ever_added(&self) -> u64 {
        self.total_added
    }
    pub fn total_ever_evicted(&self) -> u64 {
        self.total_evicted
    }
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_added == 0 {
            return 100.0;
        }
        let cached = self.cache_blocks.len() as f64;
        let total = self.total_added as f64;
        (cached / total.max(1.0)) * 100.0
    }

    /// Get the underlying DB handle (for sharing with other components)
    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }

    pub fn clear(&mut self) {
        // Clear cache
        self.cache_blocks.clear();
        self.cache_children.clear();
        self.cache_parents.clear();
        self.cache_tips.clear();
        self.insertion_order.clear();
        self.orphans.clear();
        self.orphan_index.clear();
        self.orphan_queue.clear();
        self.genesis_added = false;
        // Note: RocksDB data is NOT cleared -- use a separate method if needed.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_blockgraph_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn make_block(hash: &str, parents: Vec<&str>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                hash: hash.to_string(),
                parents: parents.into_iter().map(|s| s.to_string()).collect(),
                merkle_root: "mr".into(),
                timestamp: 1000,
                nonce: 0,
                difficulty: 1,
                height: 0,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    fn add_genesis() {
        let mut g = BlockGraph::new(tmp_path().as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();
        assert_eq!(g.total_blocks(), 1);
        assert!(g.is_tip("genesis"));
    }

    #[test]
    fn add_child_moves_tip() {
        let mut g = BlockGraph::new(tmp_path().as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();
        g.add_block(make_block("b1", vec!["genesis"])).unwrap();
        assert!(!g.is_tip("genesis"));
        assert!(g.is_tip("b1"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut g = BlockGraph::new(tmp_path().as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();
        assert!(g.add_block(make_block("genesis", vec![])).is_err());
    }

    #[test]
    fn eviction_keeps_tips() {
        let mut g = BlockGraph::new(tmp_path().as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();

        let mut prev = "genesis".to_string();
        for i in 0..200 {
            let hash = format!("b{}", i);
            g.add_block(make_block(&hash, vec![&prev])).unwrap();
            prev = hash;
        }

        // Latest tip must still be in cache
        assert!(g.is_tip(&prev));
        assert!(g.get_block(&prev).is_some());
    }

    #[test]
    fn stats_tracking() {
        let mut g = BlockGraph::new(tmp_path().as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();
        assert_eq!(g.total_ever_added(), 1);
        assert_eq!(g.total_ever_evicted(), 0);
    }

    #[test]
    fn recover_from_db_restores_state() {
        let path = tmp_path();

        // Add some blocks
        {
            let mut g = BlockGraph::new(path.as_str()).unwrap();
            g.add_block(make_block("genesis", vec![])).unwrap();
            g.add_block(make_block("b1", vec!["genesis"])).unwrap();
            g.add_block(make_block("b2", vec!["b1"])).unwrap();
            assert!(g.is_tip("b2"));
            assert!(!g.is_tip("genesis"));
            assert_eq!(g.total_ever_added(), 3);
        }
        // Drop and re-open -- should recover from RocksDB
        {
            let g = BlockGraph::new(path.as_str()).unwrap();
            assert!(g.is_tip("b2"));
            assert!(!g.is_tip("genesis"));
            assert!(!g.is_tip("b1"));
            assert_eq!(g.total_ever_added(), 3);
            // Blocks should be loadable
            assert!(g.get_block("genesis").is_some());
            assert!(g.get_block("b1").is_some());
            assert!(g.get_block("b2").is_some());
        }
    }

    #[test]
    fn get_block_falls_back_to_rocksdb() {
        let path = tmp_path();
        let mut g = BlockGraph::new(path.as_str()).unwrap();
        g.add_block(make_block("genesis", vec![])).unwrap();

        // Manually remove from cache but leave in RocksDB
        g.cache_blocks.remove("genesis");
        assert!(
            g.get_block("genesis").is_some(),
            "Should fall back to RocksDB"
        );
    }
}
