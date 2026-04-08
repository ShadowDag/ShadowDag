// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Dynamic Finality Manager — k-cluster adaptive finality + auto-checkpoints.
//
// Static finality depth (200 blocks) is insufficient for mainnet because
// it doesn't adapt when hashrate drops or the DAG narrows (indicating
// potential selfish mining or network partition). This module provides:
//
//   1. Dynamic k-cluster finality: depth adapts based on DAG health metrics
//   2. Automatic periodic checkpoints: anchor history every N blocks
//   3. Finality window monitoring: detect and log degraded conditions
//
// The k-cluster algorithm scales finality depth in response to:
//   - Blue-to-total block ratio (attack indicator)
//   - DAG width relative to expected BPS (hashrate indicator)
//
// At normal conditions (blue_ratio ≥ 0.5, healthy DAG width), the depth
// stays at BASE_FINALITY_DEPTH (200). Under degraded conditions, it
// increases up to MAX_FINALITY_DEPTH (2000) for stronger guarantees.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use crate::{slog_info, slog_warn, slog_error};

// ── Constants ───────────────────────────────────────────────────────────

/// Default finality depth under normal network conditions.
pub const BASE_FINALITY_DEPTH: u64 = 200;

/// Minimum finality depth (never go below this, even under ideal conditions).
pub const MIN_FINALITY_DEPTH: u64 = 100;

/// Maximum finality depth (cap even under the worst conditions).
pub const MAX_FINALITY_DEPTH: u64 = 2_000;

/// Number of blocks per finality epoch. Metrics are recalculated every epoch.
pub const FINALITY_EPOCH: u64 = 1_000;

/// Create an automatic checkpoint every this many blocks.
pub const CHECKPOINT_INTERVAL: u64 = 10_000;

/// Blue ratio threshold — below this, the DAG has too many red blocks,
/// indicating a possible selfish mining attack or high-latency network.
pub const BLUE_RATIO_THRESHOLD: f64 = 0.50;

/// DAG width threshold as a fraction of expected BPS.
/// If observed width < BPS * this fraction, hashrate may be dangerously low.
pub const DAG_WIDTH_THRESHOLD_RATIO: f64 = 0.30;

/// Number of epochs to keep in the rolling history window.
const HISTORY_WINDOW: usize = 10;

/// RocksDB key prefix for auto-checkpoints.
const PFX_CHECKPOINT: &[u8] = b"chkpt:";

// ── Types ───────────────────────────────────────────────────────────────

/// A persisted checkpoint created automatically by the finality manager.
#[derive(Debug, Clone)]
pub struct AutoCheckpoint {
    pub height: u64,
    pub hash:   String,
}

/// Epoch-level DAG health metrics.
#[derive(Debug, Clone)]
pub struct EpochMetrics {
    /// Ratio of blue blocks to total blocks in the epoch (0.0–1.0).
    pub blue_ratio: f64,
    /// Average number of parallel blocks per height level in the epoch.
    pub dag_width: f64,
    /// The finality depth computed for this epoch.
    pub computed_depth: u64,
}

// ── FinalityManager ─────────────────────────────────────────────────────

pub struct FinalityManager {
    /// Base depth under normal conditions.
    base_depth: u64,
    /// Current dynamic finality depth (adjusted per epoch).
    current_depth: u64,
    /// Expected blocks per second from consensus params.
    expected_bps: u32,

    // ── Epoch tracking ──
    /// Height at which the current epoch started.
    _epoch_start_height: u64,
    /// Blue blocks seen in the current epoch.
    epoch_blue_count: u64,
    /// Total blocks seen in the current epoch.
    epoch_total_count: u64,
    /// Sum of DAG widths per height in the current epoch (for averaging).
    epoch_width_sum: u64,
    /// Number of distinct heights observed in the current epoch.
    epoch_height_count: u64,
    /// Set of heights already seen in the current epoch (for deduplication).
    epoch_seen_heights: HashSet<u64>,

    // ── History ──
    /// Rolling window of per-epoch metrics.
    epoch_history: VecDeque<EpochMetrics>,

    // ── Checkpoints ──
    /// Most recent auto-checkpoint.
    last_checkpoint: Option<AutoCheckpoint>,
    /// All auto-checkpoints loaded from DB.
    checkpoints: Vec<AutoCheckpoint>,
    /// Checkpoint interval in blocks.
    checkpoint_interval: u64,

    // ── DB ──
    db: Option<Arc<rocksdb::DB>>,
}

impl FinalityManager {
    /// Create a new FinalityManager with default parameters.
    pub fn new(expected_bps: u32) -> Self {
        Self {
            base_depth: BASE_FINALITY_DEPTH,
            current_depth: BASE_FINALITY_DEPTH,
            expected_bps,
            _epoch_start_height: 0,
            epoch_blue_count: 0,
            epoch_total_count: 0,
            epoch_width_sum: 0,
            epoch_height_count: 0,
            epoch_seen_heights: HashSet::new(),
            epoch_history: VecDeque::with_capacity(HISTORY_WINDOW + 1),
            last_checkpoint: None,
            checkpoints: Vec::new(),
            checkpoint_interval: CHECKPOINT_INTERVAL,
            db: None,
        }
    }

    /// Attach a RocksDB instance for checkpoint persistence.
    pub fn with_db(mut self, db: Arc<rocksdb::DB>) -> Self {
        self.db = Some(db);
        self
    }

    /// Load auto-checkpoints from RocksDB on startup.
    pub fn load_checkpoints(&mut self) {
        let db = match &self.db {
            Some(db) => db,
            None => return,
        };

        let prefix = PFX_CHECKPOINT;
        let iter = db.prefix_iterator(prefix);
        let mut loaded = Vec::new();

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };

            // Key format: "chkpt:{height_be8}"
            if key.len() < prefix.len() + 8 {
                continue;
            }
            if !key.starts_with(prefix) {
                break; // past prefix range
            }
            let height_bytes: [u8; 8] = match key[prefix.len()..prefix.len() + 8].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };
            let height = u64::from_be_bytes(height_bytes);
            let hash = String::from_utf8_lossy(&value).to_string();

            loaded.push(AutoCheckpoint { height, hash });
        }

        loaded.sort_by_key(|c| c.height);
        self.last_checkpoint = loaded.last().cloned();

        if !loaded.is_empty() {
            slog_info!("finality", "checkpoints_loaded", count => loaded.len());
        }

        self.checkpoints = loaded;
    }

    /// Get the current dynamic finality depth.
    #[inline]
    pub fn current_depth(&self) -> u64 {
        self.current_depth
    }

    /// Get the latest auto-checkpoint.
    pub fn latest_checkpoint(&self) -> Option<&AutoCheckpoint> {
        self.last_checkpoint.as_ref()
    }

    /// Get all auto-checkpoints.
    pub fn all_checkpoints(&self) -> &[AutoCheckpoint] {
        &self.checkpoints
    }

    /// Get the most recent epoch metrics (if any).
    pub fn last_epoch_metrics(&self) -> Option<&EpochMetrics> {
        self.epoch_history.back()
    }

    /// Check if finality conditions are currently threatened.
    /// Returns true if the last epoch had degraded blue ratio or DAG width.
    pub fn finality_threatened(&self) -> bool {
        match self.epoch_history.back() {
            Some(m) => m.computed_depth > self.base_depth,
            None => false,
        }
    }

    // ── Per-block update ────────────────────────────────────────────────

    /// Called after each block is added to the DAG.
    ///
    /// - `height`: block height
    /// - `hash`: block hash
    /// - `is_blue`: whether GHOSTDAG classified this block as blue
    /// - `dag_width_at_height`: number of blocks at this height level
    pub fn on_block(
        &mut self,
        height: u64,
        hash: &str,
        is_blue: bool,
        dag_width_at_height: u64,
    ) {
        // Accumulate epoch metrics
        self.epoch_total_count += 1;
        if is_blue {
            self.epoch_blue_count += 1;
        }
        if self.epoch_seen_heights.insert(height) {
            self.epoch_height_count += 1;
            self.epoch_width_sum += dag_width_at_height; // Only count width once per height
        }

        // Check if epoch boundary reached
        if self.epoch_total_count >= FINALITY_EPOCH {
            self.close_epoch();
        }

        // Only create checkpoints for blue (canonical) blocks
        if is_blue {
            self.maybe_create_checkpoint(height, hash);
        }
    }

    /// Close the current epoch, compute metrics, and adjust finality depth.
    fn close_epoch(&mut self) {
        let blue_ratio = if self.epoch_total_count > 0 {
            self.epoch_blue_count as f64 / self.epoch_total_count as f64
        } else {
            1.0
        };

        let dag_width = if self.epoch_height_count > 0 {
            self.epoch_width_sum as f64 / self.epoch_height_count as f64
        } else {
            self.expected_bps as f64
        };

        // ── k-cluster depth computation ─────────────────────────────
        let mut depth = self.base_depth as f64;

        // Factor 1: Blue ratio degradation
        // If blue_ratio < 0.5, many blocks are red → possible attack
        if blue_ratio < BLUE_RATIO_THRESHOLD {
            // Scale: at ratio 0.5 → 2×, at ratio 0.25 → 4×, at ratio 0.0 → 4×
            let factor = (BLUE_RATIO_THRESHOLD / blue_ratio.max(0.01)).min(4.0);
            depth *= factor;
            slog_warn!("finality", "low_blue_ratio",
                ratio => format!("{:.3}", blue_ratio),
                factor => format!("{:.1}", factor),
                new_depth => depth as u64
            );
        }

        // Factor 2: DAG width degradation
        // If DAG is too narrow relative to BPS, hashrate may be dropping
        let expected_width = self.expected_bps as f64;
        let width_ratio = dag_width / expected_width.max(1.0);
        if width_ratio < DAG_WIDTH_THRESHOLD_RATIO {
            let factor = (DAG_WIDTH_THRESHOLD_RATIO / width_ratio.max(0.01)).min(3.0);
            depth *= factor;
            slog_warn!("finality", "narrow_dag",
                width => format!("{:.1}", dag_width),
                expected => format!("{:.0}", expected_width),
                factor => format!("{:.1}", factor),
                new_depth => depth as u64
            );
        }

        // Clamp to bounds
        let computed_depth = (depth as u64).clamp(MIN_FINALITY_DEPTH, MAX_FINALITY_DEPTH);

        let metrics = EpochMetrics {
            blue_ratio,
            dag_width,
            computed_depth,
        };

        // Record in history
        self.epoch_history.push_back(metrics);
        if self.epoch_history.len() > HISTORY_WINDOW {
            self.epoch_history.pop_front();
        }

        // Apply new depth
        let old_depth = self.current_depth;
        self.current_depth = computed_depth;

        if computed_depth != old_depth {
            slog_info!("finality", "depth_adjusted",
                old => old_depth,
                new => computed_depth,
                blue_ratio => format!("{:.3}", blue_ratio),
                dag_width => format!("{:.1}", dag_width)
            );
        }

        // Reset epoch counters
        self.epoch_blue_count = 0;
        self.epoch_total_count = 0;
        self.epoch_width_sum = 0;
        self.epoch_height_count = 0;
        self.epoch_seen_heights.clear();
    }

    // ── Auto-checkpoints ────────────────────────────────────────────────

    /// Create an automatic checkpoint if the height is at a checkpoint boundary.
    fn maybe_create_checkpoint(&mut self, height: u64, hash: &str) {
        if height == 0 || !height.is_multiple_of(self.checkpoint_interval) {
            return;
        }

        // Don't re-checkpoint the same height
        if let Some(ref last) = self.last_checkpoint {
            if last.height >= height {
                return;
            }
        }

        let cp = AutoCheckpoint {
            height,
            hash: hash.to_string(),
        };

        // Persist to RocksDB
        if let Some(db) = &self.db {
            let mut key = PFX_CHECKPOINT.to_vec();
            key.extend_from_slice(&height.to_be_bytes());
            if let Err(e) = db.put(&key, hash.as_bytes()) {
                slog_error!("finality", "checkpoint_persist_failed", height => height, error => e);
                return; // Don't add to memory if not persisted
            }
        }

        slog_info!("finality", "auto_checkpoint_created",
            height => height,
            hash => &hash[..16.min(hash.len())]
        );

        self.checkpoints.push(cp.clone());
        self.last_checkpoint = Some(cp);
    }

    /// Check if a given height is below the latest auto-checkpoint
    /// (i.e., absolutely immutable).
    pub fn is_checkpointed(&self, height: u64) -> bool {
        match &self.last_checkpoint {
            Some(cp) => height <= cp.height,
            None => false,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_depth_is_base() {
        let fm = FinalityManager::new(10);
        assert_eq!(fm.current_depth(), BASE_FINALITY_DEPTH);
    }

    #[test]
    fn epoch_closes_after_threshold() {
        let mut fm = FinalityManager::new(10);

        // Simulate 1000 blocks, all blue, width=10
        for i in 0..FINALITY_EPOCH {
            fm.on_block(i, &format!("{:064x}", i), true, 10);
        }

        // Epoch should have closed, depth should remain at base (healthy DAG)
        assert_eq!(fm.current_depth(), BASE_FINALITY_DEPTH);
        assert_eq!(fm.epoch_history.len(), 1);
        let m = fm.epoch_history.back().unwrap();
        assert!((m.blue_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn low_blue_ratio_increases_depth() {
        let mut fm = FinalityManager::new(10);

        // Simulate epoch: only 25% blue
        for i in 0..FINALITY_EPOCH {
            let is_blue = i % 4 == 0; // 25% blue
            fm.on_block(i, &format!("{:064x}", i), is_blue, 10);
        }

        // Depth should have increased (blue_ratio=0.25 → factor ~2.0)
        assert!(fm.current_depth() > BASE_FINALITY_DEPTH);
        assert!(fm.current_depth() <= MAX_FINALITY_DEPTH);
    }

    #[test]
    fn narrow_dag_increases_depth() {
        let mut fm = FinalityManager::new(10);

        // Simulate epoch: all blue but very narrow DAG (width=1 vs expected 10)
        for i in 0..FINALITY_EPOCH {
            fm.on_block(i, &format!("{:064x}", i), true, 1);
        }

        // Depth should have increased due to narrow DAG
        assert!(fm.current_depth() > BASE_FINALITY_DEPTH);
    }

    #[test]
    fn depth_clamped_to_bounds() {
        let mut fm = FinalityManager::new(10);

        // Simulate worst case: 10% blue + very narrow DAG
        for i in 0..FINALITY_EPOCH {
            let is_blue = i % 10 == 0; // 10% blue
            fm.on_block(i, &format!("{:064x}", i), is_blue, 1);
        }

        assert!(fm.current_depth() <= MAX_FINALITY_DEPTH);
        assert!(fm.current_depth() >= MIN_FINALITY_DEPTH);
    }

    #[test]
    fn auto_checkpoint_created() {
        let mut fm = FinalityManager::new(10);
        fm.checkpoint_interval = 100; // lower for test

        for i in 0..101 {
            fm.on_block(i, &format!("{:064x}", i), true, 10);
        }

        assert!(fm.latest_checkpoint().is_some());
        assert_eq!(fm.latest_checkpoint().unwrap().height, 100);
        assert!(fm.is_checkpointed(50));
        assert!(fm.is_checkpointed(100));
        assert!(!fm.is_checkpointed(101));
    }

    #[test]
    fn finality_threatened_when_degraded() {
        let mut fm = FinalityManager::new(10);

        // Normal epoch → not threatened
        for i in 0..FINALITY_EPOCH {
            fm.on_block(i, &format!("{:064x}", i), true, 10);
        }
        assert!(!fm.finality_threatened());

        // Degraded epoch → threatened
        for i in FINALITY_EPOCH..FINALITY_EPOCH * 2 {
            let is_blue = i % 4 == 0;
            fm.on_block(i, &format!("{:064x}", i), is_blue, 1);
        }
        assert!(fm.finality_threatened());
    }

    #[test]
    fn history_window_bounded() {
        let mut fm = FinalityManager::new(10);

        // Run 15 epochs
        for epoch in 0..15 {
            for i in 0..FINALITY_EPOCH {
                let h = epoch * FINALITY_EPOCH + i;
                fm.on_block(h, &format!("{:064x}", h), true, 10);
            }
        }

        assert!(fm.epoch_history.len() <= HISTORY_WINDOW);
    }
}
