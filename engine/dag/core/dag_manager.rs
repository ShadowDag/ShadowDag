// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::domain::block::block::Block;
use crate::engine::dag::security::dos_protection::MAX_DAG_PARENTS;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::errors::{DagError, StorageError};
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::{slog_error, slog_warn};

// Block data is stored in BlockStore (blk: prefix). DAG only stores topology:
//   - exists:{hash}   — lightweight marker for block existence checks
//   - parent:{hash}:{parent_hash} — parent relationships
//   - child:{parent_hash}:{hash}  — reverse (child) relationships
//   - tip:{hash}      — current tip status
//   - meta:block_count — running block counter

pub const MAX_ANCESTOR_WALK: usize = 50_000;

const META_BLOCK_COUNT: &[u8] = b"meta:block_count";

// KEY BUILDERS (NO format!)
#[inline]
fn key_exists(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + hash.len());
    v.extend_from_slice(b"exists:");
    v.extend_from_slice(hash.as_bytes());
    v
}

#[inline]
fn key_parent(child: &str, parent: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + child.len() + 1 + parent.len());
    v.extend_from_slice(b"parent:");
    v.extend_from_slice(child.as_bytes());
    v.push(b':');
    v.extend_from_slice(parent.as_bytes());
    v
}

#[inline]
fn key_child(parent: &str, child: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + parent.len() + 1 + child.len());
    v.extend_from_slice(b"child:");
    v.extend_from_slice(parent.as_bytes());
    v.push(b':');
    v.extend_from_slice(child.as_bytes());
    v
}

#[inline]
fn key_tip(hash: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + hash.len());
    v.extend_from_slice(b"tip:");
    v.extend_from_slice(hash.as_bytes());
    v
}

pub struct DagManager {
    pub(crate) db: Arc<DB>,
}

impl DagManager {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(32 * 1024 * 1024);

        match open_shared_db(source, &opts) {
            Ok(db) => Some(Self { db }),
            Err(e) => {
                slog_error!("dag", "dag_manager_open_failed", error => e);
                None
            }
        }
    }

    pub fn new_required(path: &str) -> Result<Self, crate::errors::StorageError> {
        Self::new(path).ok_or_else(|| crate::errors::StorageError::OpenFailed {
            path: path.to_string(),
            reason: "DagManager::new returned None".to_string(),
        })
    }

    /// Maximum allowed future timestamp drift (consensus: 120 seconds).
    /// Canonical value defined in block_validator::MAX_FUTURE_SECS.
    const MAX_FUTURE_TIMESTAMP: u64 = 120;

    /// Maximum children any single block can have in the DAG.
    /// Prevents any block from becoming a "hotspot" that slows traversal.
    /// At 10 BPS with MAX_PARENTS=80, realistic max is ~80-160 children.
    const MAX_CHILDREN_PER_BLOCK: usize = 256;

    #[inline]
    fn mark_block_rejected() {
        crate::telemetry::metrics::registry::global()
            .counter("dag.blocks_rejected")
            .inc();
    }

    #[inline]
    fn reject(err: DagError) -> Result<(), DagError> {
        Self::mark_block_rejected();
        Err(err)
    }

    // ADD BLOCK (delegates to add_block_validated with validated=false)
    pub fn add_block(&self, block: &Block) -> Result<(), DagError> {
        self.add_block_validated(block, false)
    }

    /// Add a block to the DAG with optional full consensus validation.
    ///
    /// Stores only topology (relationships, tips, existence marker).
    /// Full block data is persisted by BlockStore (blk: prefix); DAG does NOT
    /// duplicate it.
    ///
    /// If `validated == false`, performs full validation before inserting:
    ///   - PoW validation (hash matches difficulty target)
    ///   - Timestamp not too far in the future (max 120 seconds)
    ///
    /// If `validated == true`, skips these checks (block already validated by consensus).
    pub fn add_block_validated(&self, block: &Block, validated: bool) -> Result<(), DagError> {
        let hash = block.header.hash.as_str();

        if self.block_exists(hash) {
            return Self::reject(DagError::DuplicateBlock(hash.to_string()));
        }

        // ── Full consensus validation (when not pre-validated) ──────────
        if !validated {
            // 1. PoW validation — recompute hash and check difficulty target
            let pow_result = PowValidator::validate(block);
            if !pow_result.valid {
                return Self::reject(DagError::Other(format!(
                    "PoW validation failed: {}",
                    pow_result.reason.unwrap_or_else(|| "unknown".to_string())
                )));
            }

            // 2. Timestamp must not be too far in the future
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if block.header.timestamp > now + Self::MAX_FUTURE_TIMESTAMP {
                return Self::reject(DagError::Other(format!(
                    "block timestamp {} is too far in the future (now={}, max_drift={}s)",
                    block.header.timestamp,
                    now,
                    Self::MAX_FUTURE_TIMESTAMP
                )));
            }
        }

        // ── Structural / DAG checks (always performed) ──────────────────
        let mut batch = WriteBatch::default();

        // GENESIS
        if block.header.height == 0 {
            if !block.header.parents.is_empty() {
                return Self::reject(DagError::InvalidParent(
                    "genesis block must have no parents".into(),
                ));
            }

            batch.put(key_exists(hash), b"1");
            batch.put(key_tip(hash), b"1");

            self.db.write(batch).map_err(StorageError::RocksDb)?;
            let _ = self.increment_block_count();
            crate::telemetry::metrics::registry::global()
                .counter("dag.blocks_accepted")
                .inc();
            return Ok(());
        }

        let parents = &block.header.parents;

        if parents.is_empty() {
            return Self::reject(DagError::InvalidParent("missing parents".to_string()));
        }

        if parents.len() > MAX_DAG_PARENTS {
            return Self::reject(DagError::TooManyParents(parents.len(), MAX_DAG_PARENTS));
        }

        let mut seen: HashSet<&str> = HashSet::with_capacity(parents.len());

        for parent in parents {
            let p = parent.as_str();

            if p == hash {
                return Self::reject(DagError::SelfParent(hash.to_string()));
            }

            if !seen.insert(p) {
                return Self::reject(DagError::DuplicateParents(p.to_string()));
            }

            if !self.block_exists(p) {
                return Self::reject(DagError::OrphanBlock(hash.to_string(), p.to_string()));
            }

            // Conservative: if walk limit exceeded, treat as cycle (reject block)
            if self.would_create_cycle(hash, p).unwrap_or(true) {
                return Self::reject(DagError::Other(format!("cycle detected via {}", p)));
            }

            // Fanout limit: reject if parent already has too many children.
            // This prevents any block from becoming a traversal bottleneck.
            let child_count = self.get_children(p).len();
            if child_count >= Self::MAX_CHILDREN_PER_BLOCK {
                return Self::reject(DagError::Other(format!(
                    "parent {} already has {} children (max {})",
                    p,
                    child_count,
                    Self::MAX_CHILDREN_PER_BLOCK
                )));
            }
        }

        // Deterministic parent ordering: parents MUST be sorted in strictly ascending
        // lexicographic order. This ensures all nodes process the same block
        // identically, preventing ordering-dependent divergence in merkle roots or
        // hash computations.
        // See also: DagValidatorStore doc comment (engine/dag/validation/dag_validator.rs)
        // which documents that parent validation is handled here, not in the store.
        for i in 1..parents.len() {
            if parents[i] <= parents[i - 1] {
                return Self::reject(DagError::Other(
                    "parents must be sorted in strictly ascending lexicographic order".into(),
                ));
            }
        }

        // Store lightweight existence marker (NOT the full block — that's BlockStore's job)
        batch.put(key_exists(hash), b"1");

        for parent in parents {
            let p = parent.as_str();

            batch.put(key_parent(hash, p), b"1");
            batch.put(key_child(p, hash), b"1");
            batch.delete(key_tip(p));
        }

        batch.put(key_tip(hash), b"1");

        self.db.write(batch).map_err(StorageError::RocksDb)?;

        let _ = self.increment_block_count();

        // Metrics: track block acceptance
        crate::telemetry::metrics::registry::global()
            .counter("dag.blocks_accepted")
            .inc();

        Ok(())
    }

    /// Remove a block's topology entries from DAG storage.
    ///
    /// This is intended for rollback of a just-inserted block when a later
    /// pipeline stage (for example, GHOSTDAG insertion) fails.
    ///
    /// Safety rule: the block must be a tip (no children). Removing a block
    /// with children would orphan descendants and is rejected.
    pub fn remove_block_topology(&self, hash: &str) -> Result<(), DagError> {
        if !self.block_exists(hash) {
            return Ok(());
        }

        let parents = self.get_parents(hash);
        let children = self.get_children(hash);
        if !children.is_empty() {
            return Err(DagError::Other(format!(
                "cannot remove non-tip block {} ({} children)",
                hash,
                children.len()
            )));
        }

        // Determine which parents become tips after this child is removed.
        let mut restore_parent_tips: Vec<String> = Vec::new();
        for p in &parents {
            let has_other_children = self.get_children(p).iter().any(|c| c != hash);
            if !has_other_children {
                restore_parent_tips.push(p.clone());
            }
        }

        let mut batch = WriteBatch::default();
        batch.delete(key_exists(hash));
        batch.delete(key_tip(hash));

        for p in &parents {
            batch.delete(key_parent(hash, p));
            batch.delete(key_child(p, hash));
        }

        for p in &restore_parent_tips {
            batch.put(key_tip(p), b"1");
        }

        let current = self.read_block_count();
        batch.put(META_BLOCK_COUNT, current.saturating_sub(1).to_le_bytes());

        self.db.write(batch).map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // FAST EXISTS — uses lightweight exists: marker instead of full block data
    pub fn block_exists(&self, hash: &str) -> bool {
        self.db
            .get_pinned(key_exists(hash))
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    /// Retrieve the full block data.
    ///
    /// Block data is stored in BlockStore (blk: prefix), not in the DAG.
    /// Callers that need the full block should use BlockStore::get_block()
    /// directly. This method returns None because the DAG no longer stores
    /// serialized block data.
    #[deprecated(note = "DAG stores topology only — use BlockStore::get_block()")]
    pub fn get_block(&self, _hash: &str) -> Option<Block> {
        // DAG no longer stores full block data — delegate to BlockStore.
        None
    }

    pub fn get_parents(&self, hash: &str) -> Vec<String> {
        self.scan_prefix_suffix(&format!("parent:{}:", hash))
    }

    pub fn get_children(&self, hash: &str) -> Vec<String> {
        self.scan_prefix_suffix(&format!("child:{}:", hash))
    }

    pub fn get_tips(&self) -> Vec<String> {
        self.scan_prefix_suffix("tip:")
    }

    /// Walk parents recursively (BFS) to collect all ancestors of `hash`.
    pub fn get_ancestors(&self, hash: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        for p in self.get_parents(hash) {
            if visited.insert(p.clone()) {
                queue.push_back(p);
            }
        }
        while let Some(cur) = queue.pop_front() {
            for p in self.get_parents(&cur) {
                if visited.insert(p.clone()) {
                    queue.push_back(p);
                }
            }
        }
        visited
    }

    /// Simple select_parent: pick the lexicographically smallest tip.
    /// WARNING: This is a FALLBACK helper only — DO NOT use for mining/block
    /// building. Use TipManager::select_parents() which provides weighted
    /// random sampling with GHOSTDAG-aware blue score ordering.
    #[deprecated(note = "Use TipManager::select_parents() for mining")]
    pub fn select_parent_simple(&self, tips: &[String]) -> Option<String> {
        tips.iter().min().cloned()
    }

    // BFS cycle detection — returns Err when walk limit is exceeded
    // (conservative: callers should treat Err as "assume cycle")
    fn would_create_cycle(&self, target: &str, start: &str) -> Result<bool, DagError> {
        let mut visited: HashSet<String> = HashSet::with_capacity(64);
        let mut queue: VecDeque<String> = VecDeque::with_capacity(64);
        let mut cache: HashMap<String, Vec<String>> = HashMap::new();

        queue.push_back(start.to_string());

        let mut walked = 0;

        while let Some(current) = queue.pop_front() {
            if walked >= MAX_ANCESTOR_WALK {
                return Err(DagError::Other(format!(
                    "cycle detection walk limit {} exceeded",
                    MAX_ANCESTOR_WALK
                )));
            }
            walked += 1;

            if current == target {
                return Ok(true);
            }

            if !cache.contains_key(&current) {
                let parents = self.get_parents(&current);
                cache.insert(current.clone(), parents);
            }

            let parents = &cache[&current];

            for parent in parents {
                if visited.insert(parent.clone()) {
                    queue.push_back(parent.clone());
                }
            }
        }

        Ok(false)
    }

    // DAG SIZE
    pub fn dag_size(&self) -> usize {
        let count = self.read_block_count();

        if count == 0 {
            return self.scan_block_count_fallback();
        }

        count as usize
    }

    fn read_block_count(&self) -> u64 {
        match self.db.get(META_BLOCK_COUNT) {
            Ok(Some(v)) => {
                match <[u8; 8]>::try_from(v.as_slice()) {
                    Ok(bytes) => u64::from_le_bytes(bytes),
                    Err(_) => {
                        // Corrupted metadata — fall back to scan rather than
                        // returning 0, which would cause the DAG to think it's empty.
                        slog_warn!("dag", "block_count_metadata_corrupted", bytes => v.len(), expected => 8);
                        self.scan_block_count_fallback() as u64
                    }
                }
            }
            _ => 0,
        }
    }

    /// Atomically increment the block count using RocksDB WriteBatch.
    /// The read + write happen under the DagManager's Arc<DB>, which is
    /// effectively single-writer in the current architecture (all block
    /// acceptance goes through FullNode::process_block which is sequential).
    /// The WriteBatch ensures the increment is atomic at the DB level,
    /// protecting against future parallelization.
    fn increment_block_count(&self) -> Result<(), DagError> {
        let current = self.read_block_count();
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(META_BLOCK_COUNT, (current + 1).to_le_bytes());
        self.db.write(batch).map_err(StorageError::RocksDb)?;
        Ok(())
    }

    fn scan_block_count_fallback(&self) -> usize {
        let mut count = 0;

        for (k, _) in self.db.iterator(IteratorMode::Start).flatten() {
            if k.starts_with(b"exists:") {
                count += 1;
            }
        }

        count
    }

    pub fn get_all_blocks_map(&self) -> HashMap<String, Vec<String>> {
        let mut map = HashMap::new();

        for (k, _) in self.db.iterator(IteratorMode::Start).flatten() {
            if k.starts_with(b"exists:") {
                let hash = String::from_utf8_lossy(&k[7..]).into_owned();
                map.insert(hash.clone(), self.get_parents(&hash));
            }
        }

        map
    }

    pub fn select_parent(
        &self,
        parents: &[String],
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> Option<String> {
        let mut best: Option<(&String, u64)> = None;

        for p in parents {
            let score = ghostdag.get_blue_score(p);

            match best {
                None => best = Some((p, score)),
                Some((bp, bs)) => {
                    if score > bs || (score == bs && p < bp) {
                        best = Some((p, score));
                    }
                }
            }
        }

        best.map(|(p, _)| p.clone())
    }

    fn scan_prefix_suffix(&self, prefix: &str) -> Vec<String> {
        let mut result = Vec::new();
        let prefix_bytes = prefix.as_bytes();

        for (k, _) in self
            .db
            .iterator(IteratorMode::From(
                prefix_bytes,
                rocksdb::Direction::Forward,
            ))
            .flatten()
        {
            if !k.starts_with(prefix_bytes) {
                break;
            }

            result.push(String::from_utf8_lossy(&k[prefix_bytes.len()..]).into_owned());
        }

        result
    }
}
