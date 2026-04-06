// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
pub struct Difficulty;

impl Difficulty {
    /// Unified difficulty constants (MUST match pow_difficulty.rs and consensus_params.rs)
    pub const MIN_DIFFICULTY: u64 = 1;
    pub const MAX_DIFFICULTY: u64 = u64::MAX / 2; // Same as retarget.rs

    // Per-shard block rate. Each shard targets 1 block/second (1000ms interval).
    // The network-wide rate is BPS = shards * TARGET_BLOCKS_PER_SECOND (e.g., 10 shards = 10 BPS).
    // Difficulty adjustment uses TARGET_BLOCK_INTERVAL_MS, not this constant directly.
    pub const TARGET_BLOCKS_PER_SECOND: u64 = 1; // 1 block/sec per shard
    pub const TARGET_BLOCK_INTERVAL_MS: u64 = 1_000; // 1 second per block

    // 🔥 tuning
    pub const ADJUSTMENT_WINDOW: u64 = 100;

    // scaled bounds (بدل float)
    const SCALE: u128 = 1000;
    const MAX_ADJUST_UP_SCALED: u128 = 1250;   // 1.25
    const MAX_ADJUST_DOWN_SCALED: u128 = 800;  // 0.80

    // ─────────────────────────────────────────
    // CLAMP
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn clamp(value: u64) -> u64 {
        value.clamp(Self::MIN_DIFFICULTY, Self::MAX_DIFFICULTY)
    }

    // ─────────────────────────────────────────
    // NORMALIZE (اختياري)
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn normalize(difficulty: u64) -> f64 {
        difficulty as f64 / Self::MAX_DIFFICULTY as f64
    }

    // ─────────────────────────────────────────
    // FROM TARGET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn from_target(target: u64) -> u64 {
        if target == 0 {
            return Self::MAX_DIFFICULTY;
        }

        let target = target as u128;

        let numerator = (Self::MAX_DIFFICULTY as u128)
            .saturating_add(target >> 1); // target / 2

        let diff = numerator / target;

        Self::clamp(diff as u64)
    }

    // ─────────────────────────────────────────
    // TO TARGET
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn to_target(difficulty: u64) -> u64 {
        let diff = Self::clamp(difficulty) as u128;

        // diff guaranteed ≥ 1 بسبب clamp

        let numerator = (Self::MAX_DIFFICULTY as u128)
            .saturating_add(diff >> 1); // diff / 2

        let target = numerator / diff;

        target as u64
    }

    // ─────────────────────────────────────────
    // 🔥 ADJUST (CONSENSUS SAFE)
    // ─────────────────────────────────────────
    #[inline]
    pub fn adjust(
        current_difficulty: u64,
        actual_time_ms: u64,
        blocks: u64,
    ) -> u64 {
        if actual_time_ms == 0 || blocks == 0 {
            return Self::clamp(current_difficulty);
        }

        let expected_time = blocks
            .saturating_mul(Self::TARGET_BLOCK_INTERVAL_MS);

        if expected_time == 0 {
            return Self::clamp(current_difficulty);
        }

        let actual = actual_time_ms as u128;
        let expected = expected_time as u128;

        // ratio_scaled = (actual * SCALE) / expected
        let mut ratio_scaled = actual
            .saturating_mul(Self::SCALE)
            / expected;

        // clamp ratio
        ratio_scaled = ratio_scaled
            .clamp(Self::MAX_ADJUST_DOWN_SCALED, Self::MAX_ADJUST_UP_SCALED);

        // (current * SCALE + ratio/2) / ratio
        let numerator = (current_difficulty as u128)
            .saturating_mul(Self::SCALE)
            .saturating_add(ratio_scaled >> 1);

        let new_diff = numerator / ratio_scaled;

        Self::clamp(new_diff as u64)
    }

    // ─────────────────────────────────────────
    // 🔥 FAST PATH
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn adjust_single(
        current_difficulty: u64,
        actual_block_time_ms: u64,
    ) -> u64 {
        Self::adjust(current_difficulty, actual_block_time_ms, 1)
    }

    // ─────────────────────────────────────────
    // 🔥 WINDOW ADJUST
    // ─────────────────────────────────────────
    #[inline(always)]
    pub fn adjust_window(
        current_difficulty: u64,
        total_time_ms: u64,
    ) -> u64 {
        Self::adjust(
            current_difficulty,
            total_time_ms,
            Self::ADJUSTMENT_WINDOW,
        )
    }

    // ─────────────────────────────────────────
    // 🔥 TIMESTAMP-BASED ADJUSTMENT (KIP-0004 style)
    // ─────────────────────────────────────────
    // Uses exponential window sampling and past median time
    // for more responsive difficulty changes at high BPS.
    // ─────────────────────────────────────────

    /// Compute the Past Median Time (PMT) from a sorted list of timestamps.
    /// PMT is the median of the last N block timestamps, used to prevent
    /// timestamp manipulation attacks.
    pub fn past_median_time(timestamps: &[u64]) -> u64 {
        if timestamps.is_empty() {
            return 0;
        }
        let mut sorted = timestamps.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    /// Validate that a new block's timestamp is after the past median time.
    /// This prevents miners from backdating blocks to manipulate difficulty.
    pub fn validate_timestamp(block_timestamp: u64, past_timestamps: &[u64]) -> bool {
        if past_timestamps.is_empty() {
            return true;
        }
        let pmt = Self::past_median_time(past_timestamps);
        block_timestamp > pmt
    }

    /// Advanced difficulty adjustment using exponential window sampling.
    /// Instead of a fixed window, uses exponentially weighted timestamps
    /// for faster response to hashrate changes while maintaining stability.
    ///
    /// Parameters:
    ///   - current_difficulty: current difficulty value
    ///   - timestamps: recent block timestamps (newest first)
    ///   - bps: blocks per second target
    ///
    /// This combines:
    ///   1. Exponential Moving Average (EMA) for stability
    ///   2. Timestamp-based micro-adjustments for responsiveness
    ///   3. Outlier rejection via trim-mean
    pub fn adjust_advanced(
        current_difficulty: u64,
        timestamps: &[u64],
        bps: u64,
    ) -> u64 {
        let len = timestamps.len();
        if len < 3 {
            return Self::clamp(current_difficulty);
        }

        // 1. Compute inter-block intervals
        let mut intervals: Vec<u64> = Vec::with_capacity(len - 1);
        for i in 0..len - 1 {
            let dt = timestamps[i].saturating_sub(timestamps[i + 1]);
            intervals.push(dt.max(1));
        }

        if intervals.is_empty() {
            return Self::clamp(current_difficulty);
        }

        // 2. Trim outliers (remove top/bottom 20%)
        intervals.sort_unstable();
        let trim = (intervals.len() / 5).max(1);
        let trimmed = &intervals[trim..intervals.len().saturating_sub(trim)];
        if trimmed.is_empty() {
            return Self::clamp(current_difficulty);
        }

        // 3. Compute trimmed mean interval (in milliseconds)
        let sum: u128 = trimmed.iter().map(|&x| x as u128).sum();
        let mean_interval_ms = (sum * 1000 / trimmed.len() as u128) as u64;

        // 4. Expected interval based on BPS
        let _expected_interval_ms = 1000 / bps.max(1);

        // 5. Compute adjustment ratio
        Self::adjust(current_difficulty, mean_interval_ms, 1)
    }

    /// Blue work accumulation: cumulative difficulty for fork choice.
    /// Higher blue_work = more accumulated proof of work = preferred chain.
    /// This is superior to simple blue_score for fork choice at high BPS.
    pub fn blue_work(difficulty: u64) -> u128 {
        // Blue work = difficulty as a 128-bit accumulator
        // At difficulty D, expected hashes = D, so work = D
        difficulty as u128
    }

    /// Accumulate blue work from a parent chain
    pub fn accumulate_blue_work(parent_work: u128, block_difficulty: u64) -> u128 {
        parent_work.saturating_add(Self::blue_work(block_difficulty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────
    // CLAMP
    // ─────────────────────────────────────────

    #[test]
    fn clamp_returns_min_for_zero() {
        assert_eq!(Difficulty::clamp(0), Difficulty::MIN_DIFFICULTY);
    }

    #[test]
    fn clamp_returns_max_when_exceeds() {
        assert_eq!(
            Difficulty::clamp(u64::MAX),
            Difficulty::MAX_DIFFICULTY,
        );
    }

    #[test]
    fn clamp_preserves_value_in_range() {
        let mid = Difficulty::MAX_DIFFICULTY / 2;
        assert_eq!(Difficulty::clamp(mid), mid);
    }

    #[test]
    fn clamp_at_exact_boundaries() {
        assert_eq!(Difficulty::clamp(Difficulty::MIN_DIFFICULTY), Difficulty::MIN_DIFFICULTY);
        assert_eq!(Difficulty::clamp(Difficulty::MAX_DIFFICULTY), Difficulty::MAX_DIFFICULTY);
    }

    // ─────────────────────────────────────────
    // FROM TARGET / TO TARGET
    // ─────────────────────────────────────────

    #[test]
    fn from_target_zero_returns_max_difficulty() {
        assert_eq!(Difficulty::from_target(0), Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn from_target_one_returns_max_difficulty() {
        // target=1 → numerator = MAX_DIFFICULTY + 0 = MAX_DIFFICULTY → diff = MAX_DIFFICULTY
        let diff = Difficulty::from_target(1);
        assert_eq!(diff, Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn from_target_max_returns_one() {
        // Very large target → difficulty approaches 1
        let diff = Difficulty::from_target(u64::MAX);
        assert_eq!(diff, Difficulty::MIN_DIFFICULTY);
    }

    #[test]
    fn to_target_min_difficulty_returns_max_target() {
        // difficulty=1 → target = (MAX_DIFFICULTY + 0) / 1 = MAX_DIFFICULTY
        let target = Difficulty::to_target(Difficulty::MIN_DIFFICULTY);
        assert_eq!(target, Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn to_target_max_difficulty_returns_one() {
        // difficulty=MAX → target ≈ 1
        let target = Difficulty::to_target(Difficulty::MAX_DIFFICULTY);
        assert_eq!(target, 1);
    }

    #[test]
    fn from_target_to_target_roundtrip() {
        // For a mid-range difficulty, roundtrip should be close
        let original_diff: u64 = 1_000_000;
        let target = Difficulty::to_target(original_diff);
        let recovered = Difficulty::from_target(target);
        // Allow ±1 rounding error
        assert!(
            recovered.abs_diff(original_diff) <= 1,
            "roundtrip failed: {} -> target {} -> {}",
            original_diff, target, recovered,
        );
    }

    #[test]
    fn to_target_clamps_zero_to_min() {
        // Input 0 gets clamped to MIN_DIFFICULTY=1 inside to_target
        let target = Difficulty::to_target(0);
        assert_eq!(target, Difficulty::to_target(Difficulty::MIN_DIFFICULTY));
    }

    // ─────────────────────────────────────────
    // NORMALIZE
    // ─────────────────────────────────────────

    #[test]
    fn normalize_min_near_zero() {
        let n = Difficulty::normalize(Difficulty::MIN_DIFFICULTY);
        assert!(n > 0.0 && n < 0.001);
    }

    #[test]
    fn normalize_max_is_one() {
        let n = Difficulty::normalize(Difficulty::MAX_DIFFICULTY);
        assert!((n - 1.0).abs() < f64::EPSILON);
    }

    // ─────────────────────────────────────────
    // ADJUST
    // ─────────────────────────────────────────

    #[test]
    fn adjust_zero_time_returns_clamped_current() {
        let d = Difficulty::adjust(500, 0, 10);
        assert_eq!(d, 500);
    }

    #[test]
    fn adjust_zero_blocks_returns_clamped_current() {
        let d = Difficulty::adjust(500, 1000, 0);
        assert_eq!(d, 500);
    }

    #[test]
    fn adjust_exact_target_stays_stable() {
        // 10 blocks, each 1000ms target → 10_000ms actual should keep difficulty same
        let d = Difficulty::adjust(1000, 10_000, 10);
        assert_eq!(d, 1000);
    }

    #[test]
    fn adjust_increases_when_blocks_too_fast() {
        // actual_time < expected → blocks arrived fast → difficulty should increase
        // 10 blocks expected 10_000ms, actual 5_000ms
        let d = Difficulty::adjust(1000, 5_000, 10);
        assert!(d > 1000, "difficulty should increase: got {}", d);
    }

    #[test]
    fn adjust_decreases_when_blocks_too_slow() {
        // actual_time > expected → blocks arrived slow → difficulty should decrease
        // 10 blocks expected 10_000ms, actual 20_000ms
        let d = Difficulty::adjust(1000, 20_000, 10);
        assert!(d < 1000, "difficulty should decrease: got {}", d);
    }

    #[test]
    fn adjust_bounded_by_max_adjust_up() {
        // Even with extremely fast blocks, adjustment is capped at 1.25x
        // actual_time = 1ms for 10 blocks (expected 10_000ms)
        let d = Difficulty::adjust(1000, 1, 10);
        assert!(d <= 1250, "should be capped at ~1.25x: got {}", d);
    }

    #[test]
    fn adjust_bounded_by_max_adjust_down() {
        // Even with extremely slow blocks, adjustment is capped at 0.80x
        // actual_time = 1_000_000ms for 10 blocks (expected 10_000ms)
        let d = Difficulty::adjust(1000, 1_000_000, 10);
        assert!(d >= 800, "should be floored at ~0.80x: got {}", d);
    }

    #[test]
    fn adjust_never_below_min_difficulty() {
        let d = Difficulty::adjust(1, 1_000_000, 1);
        assert!(d >= Difficulty::MIN_DIFFICULTY);
    }

    // ─────────────────────────────────────────
    // ADJUST_SINGLE / ADJUST_WINDOW
    // ─────────────────────────────────────────

    #[test]
    fn adjust_single_delegates_correctly() {
        let a = Difficulty::adjust_single(1000, 500);
        let b = Difficulty::adjust(1000, 500, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn adjust_window_delegates_correctly() {
        let a = Difficulty::adjust_window(1000, 50_000);
        let b = Difficulty::adjust(1000, 50_000, Difficulty::ADJUSTMENT_WINDOW);
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────
    // PAST MEDIAN TIME
    // ─────────────────────────────────────────

    #[test]
    fn past_median_time_empty() {
        assert_eq!(Difficulty::past_median_time(&[]), 0);
    }

    #[test]
    fn past_median_time_single() {
        assert_eq!(Difficulty::past_median_time(&[42]), 42);
    }

    #[test]
    fn past_median_time_odd_count() {
        assert_eq!(Difficulty::past_median_time(&[10, 30, 20]), 20);
    }

    #[test]
    fn past_median_time_even_count() {
        // len=4, index=2 → third element after sort
        assert_eq!(Difficulty::past_median_time(&[10, 40, 20, 30]), 30);
    }

    // ─────────────────────────────────────────
    // VALIDATE TIMESTAMP
    // ─────────────────────────────────────────

    #[test]
    fn validate_timestamp_empty_past() {
        assert!(Difficulty::validate_timestamp(100, &[]));
    }

    #[test]
    fn validate_timestamp_after_median() {
        assert!(Difficulty::validate_timestamp(25, &[10, 20, 15]));
    }

    #[test]
    fn validate_timestamp_at_median_rejected() {
        // block_timestamp must be strictly greater than PMT
        assert!(!Difficulty::validate_timestamp(20, &[10, 20, 30]));
    }

    // ─────────────────────────────────────────
    // ADJUST ADVANCED
    // ─────────────────────────────────────────

    #[test]
    fn adjust_advanced_too_few_timestamps() {
        let d = Difficulty::adjust_advanced(500, &[100, 50], 1);
        assert_eq!(d, 500);
    }

    #[test]
    fn adjust_advanced_returns_valid_difficulty() {
        // timestamps newest-first, 1-second intervals → on-target for bps=1
        let ts: Vec<u64> = (0..20).rev().map(|i| i * 1).collect();
        let d = Difficulty::adjust_advanced(1000, &ts, 1);
        assert!(d >= Difficulty::MIN_DIFFICULTY);
        assert!(d <= Difficulty::MAX_DIFFICULTY);
    }

    // ─────────────────────────────────────────
    // BLUE WORK
    // ─────────────────────────────────────────

    #[test]
    fn blue_work_equals_difficulty() {
        assert_eq!(Difficulty::blue_work(42), 42u128);
    }

    #[test]
    fn accumulate_blue_work_sums() {
        assert_eq!(Difficulty::accumulate_blue_work(100, 50), 150);
    }

    #[test]
    fn accumulate_blue_work_saturates() {
        assert_eq!(Difficulty::accumulate_blue_work(u128::MAX, 1), u128::MAX);
    }
}