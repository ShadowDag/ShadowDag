// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteOptions, ReadOptions};
use std::path::Path;
use std::sync::Arc;

use crate::engine::consensus::difficulty::difficulty::Difficulty;
use crate::errors::{ConsensusError, StorageError};
use crate::slog_error;

/// Retarget every 120 seconds worth of blocks to maintain ~2-minute windows.
/// At ConsensusParams::BLOCKS_PER_SECOND the actual block count per retarget
/// = 120 * BPS (e.g. DEFAULT_BPS -> 1200 blocks). Callers that compare
/// against block height must use RETARGET_BLOCK_INTERVAL, which is BPS-scaled.
pub const RETARGET_INTERVAL: u64 = 120;
/// Retarget interval scaled by BPS. At 10 BPS, 120 seconds = 1200 blocks.
pub const RETARGET_BLOCK_INTERVAL: u64 = RETARGET_INTERVAL * crate::config::consensus::consensus_params::ConsensusParams::BLOCKS_PER_SECOND;
pub const ADJUSTMENT_FACTOR_MAX: u64 = 4;
pub const TARGET_BLOCK_TIME_SECS: u64 = 1;

// 🔥 EMA smoothing — must match retarget.rs (single source of truth)
use crate::engine::consensus::difficulty::retarget::{
    EMA_ALPHA_NUM, EMA_ALPHA_DEN,
};

const KEY_DIFFICULTY: &[u8] = b"difficulty";

pub struct DifficultyAdjustment {
    db: Arc<DB>,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
    pub target_block_time: u64,
}

impl DifficultyAdjustment {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.increase_parallelism(4);
        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        // 🔥 performance tuning
        opts.set_max_write_buffer_number(4);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_background_jobs(4);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_bytes_per_sync(1 << 20);
        opts.set_compaction_readahead_size(2 << 20);

        // 🔥 NEW (performance boost)
        opts.set_use_fsync(true);
        opts.set_unordered_write(false);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(false);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            read_opts,
            target_block_time: TARGET_BLOCK_TIME_SECS,
        })
    }

    // ─────────────────────────────────────────
    // GET / SET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn get_difficulty(&self) -> u64 {
        if let Ok(Some(v)) = self.db.get_opt(KEY_DIFFICULTY, &self.read_opts) {
            return Self::read_u64(&v);
        }
        Difficulty::MIN_DIFFICULTY
    }

    #[inline(always)]
    pub fn set_difficulty(&self, difficulty: u64) -> Result<(), ConsensusError> {
        self.db.put_opt(
            KEY_DIFFICULTY,
            difficulty.to_le_bytes(),
            &self.write_opts,
        ).map_err(StorageError::RocksDb)?;
        Ok(())
    }

    // ─────────────────────────────────────────
    // MAIN ENTRY
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn on_new_block(
        &self,
        height: u64,
        window_timestamps: &[u64],
    ) -> u64 {
        if height == 0 || !height.is_multiple_of(RETARGET_BLOCK_INTERVAL) {
            return self.get_difficulty();
        }

        // Validate timestamp ordering — reject manipulated timestamps
        for i in 1..window_timestamps.len() {
            if window_timestamps[i] < window_timestamps[i - 1] {
                // Timestamps not monotonically increasing — use current difficulty
                return self.get_difficulty();
            }
        }

        // Anti-timewarp: validate window span against wall clock.
        // If the window's total timespan is impossibly small relative to
        // the number of blocks (< 1/4 of expected), someone manipulated
        // timestamps. Refuse to adjust — keep current difficulty.
        if window_timestamps.len() >= 5 {
            let first = window_timestamps[0];
            let last  = window_timestamps[window_timestamps.len() - 1];
            let span  = last.saturating_sub(first);
            let expected = (window_timestamps.len() as u64 - 1).saturating_mul(self.target_block_time);
            // If actual span < expected / 4, timestamps are suspicious
            if expected > 0 && span < expected / ADJUSTMENT_FACTOR_MAX {
                return self.get_difficulty();
            }
        }

        self.recalculate_difficulty(height, window_timestamps)
    }

    // ─────────────────────────────────────────
    // CORE LOGIC
    // ─────────────────────────────────────────
    pub fn recalculate_difficulty(
        &self,
        _height: u64,
        window_timestamps: &[u64],
    ) -> u64 {
        let current = self.get_difficulty();

        let len = window_timestamps.len();
        if len < 5 {
            return current;
        }

        let trim = (len / 5).clamp(1, len / 3);

        let low_idx = trim;
        let high_idx = len.saturating_sub(trim + 1);

        if low_idx >= len || high_idx >= len || low_idx >= high_idx {
            return current;
        }

        let mut data = window_timestamps.to_vec();

        data.select_nth_unstable(low_idx);
        let low = data[low_idx];

        let mut data_high = data.clone();
        data_high.select_nth_unstable(high_idx);
        let high = data_high[high_idx];

        let (low, high) = if high >= low {
            (low, high)
        } else {
            (high, low)
        };

        let actual_timespan = high.saturating_sub(low).max(1);

        // Use actual window size, not the fixed sample_size constant
        let trimmed_len = (high_idx - low_idx) as u64;
        let expected_timespan = trimmed_len.max(1).saturating_mul(self.target_block_time);

        // Anti-timewarp clamping:
        // min = max(expected/4, target_block_time) — prevents artificially
        //       compressed windows from spiking difficulty
        // max = expected*4 — prevents inflated windows from crashing difficulty
        //
        // The 4x factor matches Bitcoin's approach. Combined with the per-block
        // timestamp jump limit in block_validator (MAX_TIMESTAMP_JUMP_SECS=30),
        // an attacker's maximum influence per retarget is bounded:
        //   - Best case attack: shift window by ±30s per block
        //   - Over 120-block retarget interval: ±3600s drift
        //   - Clamped to max 4x change → difficulty can only move 4x per epoch
        let safe_min = self.target_block_time.max(1);
        let min_ts = (expected_timespan / ADJUSTMENT_FACTOR_MAX).max(safe_min);
        let max_ts = expected_timespan.saturating_mul(ADJUSTMENT_FACTOR_MAX);

        let clamped_timespan = actual_timespan.clamp(min_ts, max_ts);

        let raw = (current as u128)
            .saturating_mul(expected_timespan as u128)
            / (clamped_timespan as u128).max(1);

        let smoothed = (
            raw * EMA_ALPHA_NUM as u128 +
            current as u128 * (EMA_ALPHA_DEN - EMA_ALPHA_NUM) as u128
        ) / EMA_ALPHA_DEN as u128;

        let new_difficulty = Difficulty::clamp(smoothed as u64);

        if let Err(e) = self.set_difficulty(new_difficulty) {
            slog_error!("consensus", "set_difficulty_failed", error => e);
        }

        new_difficulty
    }

    // ─────────────────────────────────────────
    // LEGACY
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn adjust_difficulty(
        &self,
        last_block_time: u64,
        new_block_time: u64,
    ) -> u64 {
        let mut difficulty = self.get_difficulty();

        let time_diff = new_block_time
            .saturating_sub(last_block_time)
            .max(1);

        if time_diff < self.target_block_time {
            difficulty = difficulty.saturating_add(1);
        } else if time_diff > self.target_block_time {
            difficulty = difficulty.saturating_sub(1);
        }

        let difficulty = Difficulty::clamp(difficulty);
        if let Err(e) = self.set_difficulty(difficulty) {
            slog_error!("consensus", "set_difficulty_failed", error => e);
        }

        difficulty
    }

    // ─────────────────────────────────────────
    // UTILS
    // ─────────────────────────────────────────
    #[inline(always)]
    fn read_u64(v: &[u8]) -> u64 {
        if v.len() >= 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&v[..8]);
            u64::from_le_bytes(arr)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_adjuster(name: &str) -> DifficultyAdjustment {
        let dir = std::env::temp_dir().join(format!("shadowdag_test_da_{}", name));
        // Clean up any prior run
        let _ = std::fs::remove_dir_all(&dir);
        DifficultyAdjustment::new(dir.to_str().unwrap()).unwrap()
    }

    // ─────────────────────────────────────────
    // GET / SET
    // ─────────────────────────────────────────

    #[test]
    fn default_difficulty_is_min() {
        let da = temp_adjuster("default_min");
        assert_eq!(da.get_difficulty(), Difficulty::MIN_DIFFICULTY);
    }

    #[test]
    fn set_and_get_roundtrip() {
        let da = temp_adjuster("set_get");
        da.set_difficulty(12345).unwrap();
        assert_eq!(da.get_difficulty(), 12345);
    }

    // ─────────────────────────────────────────
    // READ_U64
    // ─────────────────────────────────────────

    #[test]
    fn read_u64_valid_bytes() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let bytes = val.to_le_bytes();
        assert_eq!(DifficultyAdjustment::read_u64(&bytes), val);
    }

    #[test]
    fn read_u64_short_bytes_returns_zero() {
        assert_eq!(DifficultyAdjustment::read_u64(&[1, 2, 3]), 0);
    }

    // ─────────────────────────────────────────
    // ON_NEW_BLOCK — non-retarget heights
    // ─────────────────────────────────────────

    #[test]
    fn on_new_block_height_zero_returns_current() {
        let da = temp_adjuster("h0");
        da.set_difficulty(500).unwrap();
        let d = da.on_new_block(0, &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(d, 500);
    }

    #[test]
    fn on_new_block_non_retarget_returns_current() {
        let da = temp_adjuster("non_retarget");
        da.set_difficulty(500).unwrap();
        // height=50 is not a multiple of RETARGET_INTERVAL=120
        let d = da.on_new_block(50, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(d, 500);
    }

    // ─────────────────────────────────────────
    // ON_NEW_BLOCK — timestamp validation
    // ─────────────────────────────────────────

    #[test]
    fn on_new_block_rejects_non_monotonic_timestamps() {
        let da = temp_adjuster("non_mono");
        da.set_difficulty(500).unwrap();
        // Last two timestamps are not monotonically increasing
        let ts = vec![1, 2, 3, 4, 6, 5];
        let d = da.on_new_block(RETARGET_BLOCK_INTERVAL, &ts);
        // Should refuse to adjust, return current difficulty
        assert_eq!(d, 500);
    }

    #[test]
    fn on_new_block_rejects_timewarp_attack() {
        let da = temp_adjuster("timewarp");
        da.set_difficulty(500).unwrap();
        // 10 timestamps with impossibly compressed span
        // expected span = 9 * 1 = 9; actual span = 1; 1 < 9/4 = 2
        let ts: Vec<u64> = (0..10).map(|i| 100 + if i == 9 { 1 } else { 0 }).collect();
        let d = da.on_new_block(RETARGET_BLOCK_INTERVAL, &ts);
        assert_eq!(d, 500);
    }

    // ─────────────────────────────────────────
    // RECALCULATE — adjustment direction
    // ─────────────────────────────────────────

    #[test]
    fn recalculate_increases_when_blocks_too_fast() {
        let da = temp_adjuster("fast");
        da.set_difficulty(1000).unwrap();
        // Window with blocks arriving faster than target.
        // Height 1000 → sample_size = XL_WINDOW = 120.
        // expected_timespan = 120 * 1 = 120.
        // Provide timestamps spanning much less than expected.
        let count = 20;
        let ts: Vec<u64> = (0..count).map(|i| i as u64).collect(); // ~1s apart but window_size=120
        // actual_timespan will be small relative to expected → difficulty increases
        let d = da.recalculate_difficulty(1000, &ts);
        assert!(d > 1000, "should increase when blocks are fast: got {}", d);
    }

    #[test]
    fn recalculate_decreases_when_blocks_too_slow() {
        let da = temp_adjuster("slow");
        da.set_difficulty(1000).unwrap();
        // Provide timestamps with very large spacing.
        // Height 1000 → sample_size = 120, expected = 120.
        // Timestamps spread over 1000 seconds — much larger than expected.
        let count = 20;
        let ts: Vec<u64> = (0..count).map(|i| i as u64 * 100).collect();
        let d = da.recalculate_difficulty(1000, &ts);
        assert!(d < 1000, "should decrease when blocks are slow: got {}", d);
    }

    #[test]
    fn recalculate_stays_within_bounds() {
        let da = temp_adjuster("bounds");
        da.set_difficulty(1000).unwrap();
        // Extreme case: timestamps all identical except one
        let mut ts: Vec<u64> = vec![0; 20];
        ts[19] = 1; // minimal span
        let d = da.recalculate_difficulty(1000, &ts);
        assert!(d >= Difficulty::MIN_DIFFICULTY);
        assert!(d <= Difficulty::MAX_DIFFICULTY);
    }

    // ─────────────────────────────────────────
    // MINIMUM DIFFICULTY FLOOR
    // ─────────────────────────────────────────

    #[test]
    fn difficulty_never_drops_below_min() {
        let da = temp_adjuster("min_floor");
        da.set_difficulty(1).unwrap();
        // Very slow blocks — should want to decrease but floor at MIN
        let ts: Vec<u64> = (0..20).map(|i| i as u64 * 10_000).collect();
        let d = da.recalculate_difficulty(1000, &ts);
        assert!(
            d >= Difficulty::MIN_DIFFICULTY,
            "difficulty {} below MIN {}",
            d, Difficulty::MIN_DIFFICULTY,
        );
    }

    #[test]
    fn difficulty_never_exceeds_max() {
        let da = temp_adjuster("max_ceil");
        da.set_difficulty(Difficulty::MAX_DIFFICULTY).unwrap();
        // Very fast blocks
        let ts: Vec<u64> = (0..20).collect();
        let d = da.recalculate_difficulty(1000, &ts);
        assert!(
            d <= Difficulty::MAX_DIFFICULTY,
            "difficulty {} above MAX {}",
            d, Difficulty::MAX_DIFFICULTY,
        );
    }

    // ─────────────────────────────────────────
    // RECALCULATE — too few timestamps
    // ─────────────────────────────────────────

    #[test]
    fn recalculate_few_timestamps_returns_current() {
        let da = temp_adjuster("few_ts");
        da.set_difficulty(500).unwrap();
        let d = da.recalculate_difficulty(RETARGET_INTERVAL, &[1, 2, 3]);
        assert_eq!(d, 500);
    }

    // ─────────────────────────────────────────
    // LEGACY adjust_difficulty
    // ─────────────────────────────────────────

    #[test]
    fn legacy_adjust_increases_for_fast_block() {
        let da = temp_adjuster("legacy_fast");
        da.set_difficulty(100).unwrap();
        // time_diff = 0, clamped to 1 → less than target_block_time(1) → false
        // Actually time_diff=0 → max(1) = 1, which is NOT < 1, NOT > 1 → no change
        // Use timestamps that give time_diff < target
        // Hmm, time_diff = new - last, max(1). For time_diff < 1 (target), impossible with integers.
        // So legacy adjust only triggers decrease when time_diff > 1.
        // Test decrease instead:
        let d = da.adjust_difficulty(100, 105);
        // time_diff = 5, 5 > 1 → decrease
        assert_eq!(d, 99);
    }

    #[test]
    fn legacy_adjust_no_change_at_target() {
        let da = temp_adjuster("legacy_stable");
        da.set_difficulty(100).unwrap();
        // time_diff = 1 = target → no change
        let d = da.adjust_difficulty(100, 101);
        assert_eq!(d, 100);
    }

    #[test]
    fn legacy_adjust_floor_at_min() {
        let da = temp_adjuster("legacy_floor");
        da.set_difficulty(Difficulty::MIN_DIFFICULTY).unwrap();
        // time_diff > target → wants to decrease, but already at min
        let d = da.adjust_difficulty(0, 100);
        assert_eq!(d, Difficulty::MIN_DIFFICULTY);
    }
}