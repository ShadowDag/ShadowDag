// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// BPS Engine — Multi-Block Per Second processing engine.
//
// ShadowDAG supports configurable blocks-per-second (BPS) rates:
//   - 1 BPS  : Standard mode (conservative, low hardware requirement)
//   - 10 BPS : High-throughput mode (like Kaspa Crescendo)
//   - 32 BPS : Ultra mode (ShadowDAG exclusive — max throughput)
//
// Unlike Kaspa which required a hard fork for 10 BPS, ShadowDAG supports
// dynamic BPS adjustment via consensus parameters.
//
// At 32 BPS with 10,000 tx/block:
//   → 320,000 transactions per second theoretical throughput
//   → Confirmation time: ~100ms
//   → DAG width: up to 32 parallel blocks per level
//
// Design:
//   - Block interval = 1000ms / BPS
//   - GHOSTDAG K scales with BPS (K = 18 * BPS / 1)
//   - Max parents scales with BPS
//   - Difficulty adjusts per-second, not per-block
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};

/// BPS rate profiles
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpsProfile {
    /// 1 block per second — conservative, low requirements
    Standard,
    /// 10 blocks per second — high throughput (Kaspa Crescendo equivalent)
    HighThroughput,
    /// 32 blocks per second — ultra throughput (ShadowDAG exclusive)
    Ultra,
    /// Custom BPS rate (1-64)
    Custom(u32),
}

impl BpsProfile {
    pub fn bps(&self) -> u32 {
        match self {
            BpsProfile::Standard       => 1,
            BpsProfile::HighThroughput => 10,
            BpsProfile::Ultra          => 32,
            BpsProfile::Custom(n)      => (*n).clamp(1, 64),
        }
    }

    pub fn from_bps(bps: u32) -> Self {
        match bps {
            1  => BpsProfile::Standard,
            10 => BpsProfile::HighThroughput,
            32 => BpsProfile::Ultra,
            n  => BpsProfile::Custom(n),
        }
    }
}

/// BPS-scaled consensus parameters
#[derive(Debug, Clone)]
pub struct BpsParams {
    /// Blocks per second
    pub bps:                 u32,
    /// Target time between blocks in milliseconds
    pub block_interval_ms:   u64,
    /// GHOSTDAG K parameter (scales with BPS)
    pub ghostdag_k:          usize,
    /// Maximum parents per block (scales with BPS)
    pub max_parents:         usize,
    /// Difficulty adjustment window (in seconds, not blocks)
    pub difficulty_window_sec: u64,
    /// Maximum DAG width (parallel blocks at same height)
    pub max_dag_width:       usize,
    /// Merge depth (finality depth in seconds)
    pub merge_depth_sec:     u64,
    /// Pruning depth (in seconds)
    pub pruning_depth_sec:   u64,
    /// Median time window (number of blocks)
    pub median_time_window:  usize,
    /// Maximum block size (bytes) — smaller at higher BPS
    pub max_block_size:      usize,
    /// Maximum transactions per block — smaller at higher BPS
    pub max_block_txs:       usize,
    /// Theoretical max TPS
    pub max_tps:             u64,
}

impl BpsParams {
    /// Compute consensus parameters for a given BPS rate
    pub fn for_bps(bps: u32) -> Self {
        let bps = bps.clamp(1, 64);
        let bps_u64 = bps as u64;

        Self {
            bps,
            block_interval_ms:    1000 / bps_u64,
            ghostdag_k:           (18 * bps as usize).max(18),
            max_parents:          (8 * bps as usize).min(256),
            difficulty_window_sec: 60, // Always 60 seconds regardless of BPS
            max_dag_width:        bps as usize * 4,
            merge_depth_sec:      3600,      // 1 hour finality
            pruning_depth_sec:    86400 * 3, // 3 days
            median_time_window:   (263 * bps as usize).min(2048),
            max_block_size:       2 * 1024 * 1024, // 2 MB per block regardless of BPS
            max_block_txs:        10_000,          // Constant per-block capacity
            max_tps:              bps_u64 * 10_000, // BPS * txs_per_block
        }
    }

    pub fn standard()       -> Self { Self::for_bps(1) }
    pub fn high_throughput() -> Self { Self::for_bps(10) }
    pub fn ultra()          -> Self { Self::for_bps(32) }
}

/// BPS Engine — manages block production timing and DAG width
pub struct BpsEngine {
    /// Current BPS profile
    profile:         BpsProfile,
    /// Computed parameters
    params:          BpsParams,
    /// Blocks produced in current second
    blocks_this_sec: AtomicU32,
    /// Current second timestamp
    current_sec:     AtomicU64,
    /// Total blocks produced
    total_blocks:    AtomicU64,
    /// Total transactions processed
    total_txs:       AtomicU64,
    /// Start time for throughput measurement
    start_time:      Instant,
}

impl BpsEngine {
    pub fn new(profile: BpsProfile) -> Self {
        let params = BpsParams::for_bps(profile.bps());
        Self {
            profile,
            params,
            blocks_this_sec: AtomicU32::new(0),
            current_sec:     AtomicU64::new(Self::now_secs()),
            total_blocks:    AtomicU64::new(0),
            total_txs:       AtomicU64::new(0),
            start_time:      Instant::now(),
        }
    }

    /// Atomically check and claim a block production slot.
    /// Returns true if a slot was available and claimed.
    /// Uses CAS to prevent TOCTOU race between concurrent miners.
    pub fn can_produce_block(&self) -> bool {
        let now = Self::now_secs();
        let sec = self.current_sec.load(Ordering::SeqCst);

        if now != sec {
            // New second — try to reset (CAS prevents double-reset)
            if self.current_sec.compare_exchange(sec, now, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                self.blocks_this_sec.store(0, Ordering::SeqCst);
            }
        }

        // Atomically try to increment — only succeed if under limit
        loop {
            let count = self.blocks_this_sec.load(Ordering::SeqCst);
            if count >= self.params.bps {
                return false;
            }
            if self.blocks_this_sec.compare_exchange(count, count + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return true;
            }
            // CAS failed — another thread incremented, retry
        }
    }

    /// Register block production stats (call AFTER can_produce_block succeeds)
    pub fn on_block_produced(&self, tx_count: u32) {
        // blocks_this_sec already incremented by can_produce_block
        self.total_blocks.fetch_add(1, Ordering::Relaxed);
        self.total_txs.fetch_add(tx_count as u64, Ordering::Relaxed);
    }

    /// Get the minimum delay before next block can be produced
    pub fn next_block_delay(&self) -> Duration {
        if self.can_produce_block() {
            Duration::from_millis(self.params.block_interval_ms)
        } else {
            // Wait for next second
            let now_ms = Self::now_ms();
            let next_sec = ((now_ms / 1000) + 1) * 1000;
            Duration::from_millis(next_sec - now_ms)
        }
    }

    /// Current observed throughput (blocks per second)
    pub fn observed_bps(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 0.001 { return 0.0; }
        self.total_blocks.load(Ordering::Relaxed) as f64 / elapsed
    }

    /// Current observed TPS (transactions per second)
    pub fn observed_tps(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 0.001 { return 0.0; }
        self.total_txs.load(Ordering::Relaxed) as f64 / elapsed
    }

    /// Get current parameters
    pub fn params(&self) -> &BpsParams { &self.params }
    pub fn profile(&self) -> &BpsProfile { &self.profile }
    pub fn bps(&self) -> u32 { self.params.bps }

    /// Get total stats
    pub fn total_blocks(&self) -> u64 { self.total_blocks.load(Ordering::Relaxed) }
    pub fn total_txs(&self) -> u64 { self.total_txs.load(Ordering::Relaxed) }

    /// Maximum theoretical TPS for current profile
    pub fn max_tps(&self) -> u64 { self.params.max_tps }

    /// Human-readable status
    pub fn status(&self) -> String {
        format!(
            "BPS: {} | Blocks: {} | TPS: {:.1} | Observed BPS: {:.1} | Max TPS: {}",
            self.params.bps,
            self.total_blocks(),
            self.observed_tps(),
            self.observed_bps(),
            self.params.max_tps,
        )
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_bps_is_1() {
        let params = BpsParams::standard();
        assert_eq!(params.bps, 1);
        assert_eq!(params.block_interval_ms, 1000);
        assert_eq!(params.ghostdag_k, 18);
        assert_eq!(params.max_tps, 10_000);
    }

    #[test]
    fn high_throughput_bps_is_10() {
        let params = BpsParams::high_throughput();
        assert_eq!(params.bps, 10);
        assert_eq!(params.block_interval_ms, 100);
        assert_eq!(params.ghostdag_k, 180);
        assert_eq!(params.max_tps, 100_000);
    }

    #[test]
    fn ultra_bps_is_32() {
        let params = BpsParams::ultra();
        assert_eq!(params.bps, 32);
        assert_eq!(params.block_interval_ms, 31); // 1000/32 = 31.25
        assert_eq!(params.max_tps, 320_000);
    }

    #[test]
    fn bps_engine_can_produce() {
        let engine = BpsEngine::new(BpsProfile::Standard);
        assert!(engine.can_produce_block());
    }

    #[test]
    fn bps_engine_tracks_blocks() {
        let engine = BpsEngine::new(BpsProfile::HighThroughput);
        engine.on_block_produced(100);
        engine.on_block_produced(200);
        assert_eq!(engine.total_blocks(), 2);
        assert_eq!(engine.total_txs(), 300);
    }

    #[test]
    fn bps_params_scale_correctly() {
        let p1 = BpsParams::for_bps(1);
        let p10 = BpsParams::for_bps(10);
        assert!(p10.ghostdag_k > p1.ghostdag_k);
        assert!(p10.max_parents > p1.max_parents);
        assert!(p10.max_tps > p1.max_tps);
    }

    #[test]
    fn bps_clamped_to_valid_range() {
        let p0 = BpsParams::for_bps(0);
        assert_eq!(p0.bps, 1); // Minimum 1
        let p100 = BpsParams::for_bps(100);
        assert_eq!(p100.bps, 64); // Maximum 64
    }

    #[test]
    fn profile_roundtrip() {
        assert_eq!(BpsProfile::from_bps(1).bps(), 1);
        assert_eq!(BpsProfile::from_bps(10).bps(), 10);
        assert_eq!(BpsProfile::from_bps(32).bps(), 32);
        assert_eq!(BpsProfile::from_bps(7).bps(), 7);
    }

    #[test]
    fn status_contains_bps() {
        let engine = BpsEngine::new(BpsProfile::Ultra);
        let status = engine.status();
        assert!(status.contains("BPS: 32"));
        assert!(status.contains("Max TPS: 320000"));
    }
}
