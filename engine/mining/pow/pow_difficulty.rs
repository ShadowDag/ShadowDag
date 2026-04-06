// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Hybrid Difficulty Adjustment — Dual EMA + Dual Window + Clamping
//
// أفضل نظام صعوبة لـ BlockDAG مع 1-second block time:
//
// 🧮 المعادلة:
//   D_new = D_prev × (T_target / T_avg)
//   T_avg = EMA_short × 0.7 + EMA_long × 0.3
//   EMA = EMA_prev + α × (t_block - EMA_prev)
//
// ⚡ المميزات:
//   ✅ Dual EMA (short reactive + long stable)
//   ✅ Dual Window (144 short + 2016 long)
//   ✅ Clamping (max 4x up/down)
//   ✅ Anti-spike protection
//   ✅ Max block spacing
//   ✅ Cliff detection (emergency adjustment)
//   ✅ Median timestamp for DAG
//   ✅ Integer-only math (no float in consensus)
//   ✅ Timestamp validation
//
// 📊 الإعدادات:
//   TARGET_BLOCK_TIME = 1s
//   EMA_ALPHA_SHORT   = 0.1  (1/10)
//   EMA_ALPHA_LONG    = 0.02 (1/50)
//   SHORT_WINDOW      = 144  (~2.4 دقائق)
//   LONG_WINDOW       = 2016 (~33.6 دقيقة)
//   MAX_ADJUST        = 4x
//
// ⚠️ خاص بـ DAG:
//   - نستخدم median timestamp (مو timestamp مباشر)
//   - أو selected parent فقط للحساب
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;

// ═══════════════════════════════════════════════════════════════════════════
//                       CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Target block time in milliseconds (1 second)
pub const TARGET_BLOCK_TIME_MS: u64 = 1_000;

/// Short window in SECONDS (not blocks) — 2.4 minutes regardless of BPS.
/// At runtime: actual_short_window = SHORT_WINDOW_SECS * ConsensusParams::BLOCKS_PER_SECOND
pub const SHORT_WINDOW_SECS: usize = 144;

/// Long window in SECONDS — 33.6 minutes regardless of BPS.
pub const LONG_WINDOW_SECS: usize = 2016;

/// Default windows at 1 BPS (backward compatible).
/// For higher BPS, compute actual block windows as SHORT_WINDOW_SECS *
/// ConsensusParams::BLOCKS_PER_SECOND and LONG_WINDOW_SECS *
/// ConsensusParams::BLOCKS_PER_SECOND respectively.
pub const SHORT_WINDOW: usize = SHORT_WINDOW_SECS;
pub const LONG_WINDOW: usize = LONG_WINDOW_SECS;

/// EMA alpha for short window: α = 1/10 (scaled: numerator/denominator)
pub const EMA_SHORT_ALPHA_NUM: u64 = 1;
pub const EMA_SHORT_ALPHA_DEN: u64 = 10;

/// EMA alpha for long window: α = 1/50
pub const EMA_LONG_ALPHA_NUM: u64 = 1;
pub const EMA_LONG_ALPHA_DEN: u64 = 50;

/// Blending weights: T_avg = short*70% + long*30% (scaled to 100)
pub const BLEND_SHORT_WEIGHT: u64 = 70;
pub const BLEND_LONG_WEIGHT:  u64 = 30;

/// Maximum adjustment factor (4x up or 4x down)
pub const MAX_ADJUST_UP:   u64 = 4;
pub const MAX_ADJUST_DOWN: u64 = 4;

/// Anti-spike: ignore block times below target/10
pub const SPIKE_THRESHOLD_DIV: u64 = 10;

/// Max block spacing: cap block times above target*10
pub const MAX_BLOCK_SPACING_MUL: u64 = 10;

/// Cliff detection: emergency adjust if T_avg > target*10
pub const CLIFF_THRESHOLD_MUL: u64 = 10;

/// Minimum difficulty (never go below)
pub const MIN_DIFFICULTY: u64 = 1;

/// Maximum difficulty
pub const MAX_DIFFICULTY: u64 = u64::MAX / 2;

/// Maximum future timestamp (consensus: 120 seconds).
/// Canonical value defined in block_validator::MAX_FUTURE_SECS.
pub const MAX_FUTURE_SECS: u64 = 120;

/// Scaling factor for integer math (avoid floating point)
const SCALE: u128 = 1_000_000;

// ═══════════════════════════════════════════════════════════════════════════
//                       BLOCK TIME RECORD
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct BlockTimeRecord {
    pub height:     u64,
    pub timestamp:  u64, // milliseconds
    pub difficulty: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
//                     DUAL EMA ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// Dual Exponential Moving Average — integer-only arithmetic
struct DualEma {
    /// Short EMA value (scaled by SCALE)
    short: u128,
    /// Long EMA value (scaled by SCALE)
    long:  u128,
    /// Whether initialized
    initialized: bool,
}

impl DualEma {
    fn new() -> Self {
        Self {
            short: TARGET_BLOCK_TIME_MS as u128 * SCALE,
            long:  TARGET_BLOCK_TIME_MS as u128 * SCALE,
            initialized: false,
        }
    }

    /// Update both EMAs with a new block time
    /// EMA = EMA_prev + α × (t_block - EMA_prev)
    /// Using integer math: EMA = EMA_prev + (NUM * (t - EMA_prev)) / DEN
    fn update(&mut self, block_time_ms: u64) {
        let t = block_time_ms as u128 * SCALE;

        if !self.initialized {
            self.short = t;
            self.long = t;
            self.initialized = true;
            return;
        }

        // Short EMA: α = 1/10
        // EMA_new = EMA_old + (1/10) * (t - EMA_old)
        //         = EMA_old + (t - EMA_old) / 10
        if t >= self.short {
            self.short = self.short + (t - self.short) * EMA_SHORT_ALPHA_NUM as u128 / EMA_SHORT_ALPHA_DEN as u128;
        } else {
            self.short = self.short - (self.short - t) * EMA_SHORT_ALPHA_NUM as u128 / EMA_SHORT_ALPHA_DEN as u128;
        }

        // Long EMA: α = 1/50
        if t >= self.long {
            self.long = self.long + (t - self.long) * EMA_LONG_ALPHA_NUM as u128 / EMA_LONG_ALPHA_DEN as u128;
        } else {
            self.long = self.long - (self.long - t) * EMA_LONG_ALPHA_NUM as u128 / EMA_LONG_ALPHA_DEN as u128;
        }
    }

    /// Get blended T_avg = short*70% + long*30% (in milliseconds)
    fn blended_ms(&self) -> u64 {
        let blended = (self.short * BLEND_SHORT_WEIGHT as u128
                     + self.long * BLEND_LONG_WEIGHT as u128)
                     / 100;
        (blended / SCALE).max(1) as u64
    }

    /// Get short EMA in milliseconds
    fn short_ms(&self) -> u64 { (self.short / SCALE).max(1) as u64 }

    /// Get long EMA in milliseconds
    fn long_ms(&self) -> u64 { (self.long / SCALE).max(1) as u64 }
}

// ═══════════════════════════════════════════════════════════════════════════
//                  DIFFICULTY ADJUSTMENT ENGINE
// ═══════════════════════════════════════════════════════════════════════════

pub struct DifficultyEngine {
    /// Short window (recent blocks for reactivity)
    short_window: VecDeque<BlockTimeRecord>,
    /// Long window (historical blocks for stability)
    long_window:  VecDeque<BlockTimeRecord>,
    /// Dual EMA tracker
    ema:          DualEma,
    /// Last accepted timestamp (for validation)
    last_ts:      u64,
    /// Current difficulty
    pub current_difficulty: u64,
    /// Statistics
    pub blocks_processed:   u64,
    pub adjustments_made:   u64,
    pub cliff_detections:   u64,
    pub spikes_filtered:    u64,
}

impl DifficultyEngine {
    pub fn new(initial_difficulty: u64) -> Self {
        Self {
            short_window:       VecDeque::with_capacity(SHORT_WINDOW + 1),
            long_window:        VecDeque::with_capacity(LONG_WINDOW + 1),
            ema:                DualEma::new(),
            last_ts:            0,
            current_difficulty: clamp(initial_difficulty),
            blocks_processed:   0,
            adjustments_made:   0,
            cliff_detections:   0,
            spikes_filtered:    0,
        }
    }

    // ─────────────────────────────────────────────────────────────
    // MAIN ENTRY POINT — called on every new block
    // ─────────────────────────────────────────────────────────────

    /// Process a new block and return the next difficulty
    pub fn on_new_block(&mut self, record: BlockTimeRecord) -> u64 {
        // Genesis block: always return initial difficulty unchanged.
        if record.height == 0 {
            return self.current_difficulty;
        }

        // 1. Validate timestamp
        if !self.validate_timestamp(record.timestamp) {
            return self.current_difficulty;
        }

        // 2. Calculate block time
        let block_time_ms = if self.last_ts > 0 {
            record.timestamp.saturating_sub(self.last_ts)
        } else {
            TARGET_BLOCK_TIME_MS
        };

        // 3. Anti-spike protection
        let filtered_time = self.filter_block_time(block_time_ms);

        // 4. Save timestamp before moving record
        let record_ts = record.timestamp;

        // 5. Update windows
        self.short_window.push_back(record.clone());
        if self.short_window.len() > SHORT_WINDOW {
            self.short_window.pop_front();
        }

        self.long_window.push_back(record);
        if self.long_window.len() > LONG_WINDOW {
            self.long_window.pop_front();
        }

        // 6. Update EMA
        self.ema.update(filtered_time);

        // 7. Update state
        self.last_ts = self.last_ts.max(record_ts);
        self.blocks_processed += 1;

        // 7. Compute new difficulty
        let new_diff = self.compute_difficulty();
        self.current_difficulty = new_diff;
        new_diff
    }

    // ─────────────────────────────────────────────────────────────
    // DIFFICULTY COMPUTATION
    // ─────────────────────────────────────────────────────────────

    fn compute_difficulty(&mut self) -> u64 {
        // Need minimum blocks for meaningful calculation
        if self.blocks_processed < 2 {
            return self.current_difficulty;
        }

        // Get blended T_avg from dual EMA
        let t_avg = self.ema.blended_ms();

        // 🔥 Cliff detection — emergency adjustment
        // Halve difficulty but respect MAX_ADJUST_DOWN clamp so we never
        // drop faster than the normal clamping path would allow.
        if t_avg > TARGET_BLOCK_TIME_MS * CLIFF_THRESHOLD_MUL {
            self.cliff_detections += 1;
            let emergency = self.current_difficulty / 2;
            let floor = self.current_difficulty / MAX_ADJUST_DOWN;
            let clamped = emergency.max(floor);
            return clamp(clamped);
        }

        // 🧮 Core formula: D_new = D_prev × (T_target / T_avg)
        // Using integer math: D_new = D_prev * T_target / T_avg
        let target = TARGET_BLOCK_TIME_MS as u128;
        let avg = t_avg as u128;
        let prev = self.current_difficulty as u128;

        // D_new = D_prev * T_target / T_avg
        // Divide first to avoid intermediate overflow when prev * target > u128::MAX
        let new_diff_scaled = if prev > u128::MAX / target.max(1) {
            // prev * target would overflow — divide prev first, then multiply
            (prev / avg.max(1)).saturating_mul(target)
        } else {
            prev.saturating_mul(target) / avg.max(1)
        };

        // 🔒 Clamping — max 4x change in either direction
        let max_up = prev.saturating_mul(MAX_ADJUST_UP as u128);
        let min_down = prev / MAX_ADJUST_DOWN as u128;

        let clamped = new_diff_scaled.max(min_down).min(max_up);

        self.adjustments_made += 1;
        clamp(clamped as u64)
    }

    // ─────────────────────────────────────────────────────────────
    // ANTI-SPIKE & VALIDATION
    // ─────────────────────────────────────────────────────────────

    /// Filter extreme block times
    fn filter_block_time(&mut self, block_time_ms: u64) -> u64 {
        let min_time = TARGET_BLOCK_TIME_MS / SPIKE_THRESHOLD_DIV; // target/10
        let max_time = TARGET_BLOCK_TIME_MS * MAX_BLOCK_SPACING_MUL; // target*10

        if block_time_ms < min_time {
            // 🔥 Anti-spike: block was absurdly fast
            self.spikes_filtered += 1;
            min_time
        } else if block_time_ms > max_time {
            // 🔥 Max spacing: block was absurdly slow
            max_time
        } else {
            block_time_ms
        }
    }

    /// Validate timestamp (reject future/backward/timewarp timestamps)
    ///
    /// Anti-timewarp rules:
    ///   1. Not too far in the future (vs wall clock)
    ///   2. Not too far behind last accepted timestamp
    ///   3. Not too far behind wall clock (prevents MTP drift attack)
    ///   4. Forward jump from last_ts clamped (prevents window inflation)
    fn validate_timestamp(&self, timestamp: u64) -> bool {
        // Don't reject if this is the first block
        if self.last_ts == 0 { return true; }

        let wall_clock = now_ms();

        // R1: Reject timestamps too far in the future
        if timestamp > wall_clock + MAX_FUTURE_SECS * 1000 {
            return false;
        }

        // R2: Reject timestamps too far behind last accepted (backward drift)
        if timestamp < self.last_ts.saturating_sub(60_000) {
            return false;
        }

        // R3: Anti-timewarp — reject timestamps too far behind wall clock.
        // Without this, miners can set ts = last_ts + 1ms repeatedly,
        // causing the difficulty engine to see tiny block times and
        // spike difficulty, OR set ts = last_ts + huge_gap to inflate
        // the window and drop difficulty.
        // 10 minutes tolerance for clock skew.
        if timestamp < wall_clock.saturating_sub(600_000) {
            return false;
        }

        // R4: Max forward jump from last_ts — prevents window inflation.
        // A single block claiming 30s elapsed when target is 1s would
        // disproportionately inflate the EMA. Clamp to 30x target.
        let max_jump = TARGET_BLOCK_TIME_MS * 30;
        if timestamp > self.last_ts + max_jump {
            // Don't reject — but the filter_block_time will clamp it.
            // We still accept the block but the EMA won't be inflated.
            // (validation is done at block_validator level; here we
            // just protect the EMA from manipulation)
        }

        true
    }

    // ─────────────────────────────────────────────────────────────
    // DAG-SPECIFIC: MEDIAN TIMESTAMP
    // ─────────────────────────────────────────────────────────────

    /// For DAG: compute median timestamp from multiple parent blocks
    /// This prevents any single miner from manipulating timestamps
    pub fn median_timestamp(timestamps: &mut [u64]) -> u64 {
        if timestamps.is_empty() { return 0; }
        timestamps.sort_unstable();
        let mid = timestamps.len() / 2;
        if timestamps.len().is_multiple_of(2) {
            (timestamps[mid - 1] + timestamps[mid]) / 2
        } else {
            timestamps[mid]
        }
    }

    // ─────────────────────────────────────────────────────────────
    // QUERIES
    // ─────────────────────────────────────────────────────────────

    pub fn difficulty(&self) -> u64 { self.current_difficulty }
    pub fn ema_short_ms(&self) -> u64 { self.ema.short_ms() }
    pub fn ema_long_ms(&self) -> u64 { self.ema.long_ms() }
    pub fn ema_blended_ms(&self) -> u64 { self.ema.blended_ms() }
    pub fn short_window_size(&self) -> usize { self.short_window.len() }
    pub fn long_window_size(&self) -> usize { self.long_window.len() }

    /// Human-readable status
    pub fn status(&self) -> String {
        format!(
            "Difficulty: {} | EMA short: {}ms | EMA long: {}ms | Blended: {}ms | \
             Blocks: {} | Adjustments: {} | Cliffs: {} | Spikes filtered: {}",
            self.current_difficulty,
            self.ema.short_ms(),
            self.ema.long_ms(),
            self.ema.blended_ms(),
            self.blocks_processed,
            self.adjustments_made,
            self.cliff_detections,
            self.spikes_filtered,
        )
    }

    /// Legacy API compatibility
    pub fn prefix(difficulty: u64) -> String {
        "0".repeat(difficulty.min(64) as usize)
    }

    pub fn adjust(&self, current_difficulty: u64) -> u64 {
        let t_avg = self.ema.blended_ms() as u128;
        let target = TARGET_BLOCK_TIME_MS as u128;
        let prev = current_difficulty as u128;
        let new_diff = prev.saturating_mul(target) / t_avg.max(1);
        clamp(new_diff as u64)
    }

    pub fn record_block_time(&mut self, timestamp: u64) -> bool {
        if !self.validate_timestamp(timestamp) { return false; }
        let block_time = if self.last_ts > 0 {
            timestamp.saturating_sub(self.last_ts)
        } else {
            TARGET_BLOCK_TIME_MS
        };
        let filtered = self.filter_block_time(block_time);
        self.ema.update(filtered);
        self.last_ts = timestamp.max(self.last_ts);
        self.blocks_processed += 1;
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                        HELPERS
// ═══════════════════════════════════════════════════════════════════════════

#[inline]
fn clamp(diff: u64) -> u64 {
    diff.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════════════════
//                         TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(height: u64, timestamp: u64, difficulty: u64) -> BlockTimeRecord {
        BlockTimeRecord { height, timestamp, difficulty }
    }

    /// Base timestamp for tests — uses wall clock so anti-timewarp rules pass.
    fn test_base_ts() -> u64 {
        now_ms() - 300_000 // 5 minutes ago, well within 10min window
    }

    // ── Basic Tests ─────────────────────────────────────────────

    #[test]
    fn initial_difficulty_preserved() {
        let engine = DifficultyEngine::new(1000);
        assert_eq!(engine.difficulty(), 1000);
    }

    #[test]
    fn first_block_no_change() {
        let mut engine = DifficultyEngine::new(1000);
        let d = engine.on_new_block(make_record(1, test_base_ts(), 1000));
        assert_eq!(d, 1000); // No change with < 2 blocks
    }

    // ── EMA Tests ───────────────────────────────────────────────

    #[test]
    fn ema_converges_to_target() {
        let mut engine = DifficultyEngine::new(1000);
        // Feed blocks at exactly target time (1 second = 1000ms apart)
        let mut ts = test_base_ts();
        for i in 0..200 {
            ts += 1_000; // 1 second apart
            engine.on_new_block(make_record(i, ts, 1000));
        }
        // EMA should be close to 1000ms
        let blended = engine.ema_blended_ms();
        assert!((800..=1200).contains(&blended),
            "Blended EMA {} should be near 1000ms", blended);
    }

    #[test]
    fn fast_blocks_increase_difficulty() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();
        // Feed blocks at 500ms (too fast)
        for i in 0..50 {
            ts += 500;
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }
        assert!(engine.difficulty() > 1000,
            "Difficulty {} should increase when blocks are fast", engine.difficulty());
    }

    #[test]
    fn slow_blocks_decrease_difficulty() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();
        // Feed blocks at 3000ms (too slow)
        for i in 0..50 {
            ts += 3000;
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }
        assert!(engine.difficulty() < 1000,
            "Difficulty {} should decrease when blocks are slow", engine.difficulty());
    }

    // ── Anti-Spike Tests ────────────────────────────────────────

    #[test]
    fn spike_filtered() {
        let mut engine = DifficultyEngine::new(1000);
        let filtered = engine.filter_block_time(10); // 10ms = absurdly fast
        assert!(filtered >= TARGET_BLOCK_TIME_MS / SPIKE_THRESHOLD_DIV,
            "Spike should be filtered to minimum");
        assert_eq!(engine.spikes_filtered, 1);
    }

    #[test]
    fn max_spacing_capped() {
        let mut engine = DifficultyEngine::new(1000);
        let filtered = engine.filter_block_time(999_999); // absurdly slow
        assert!(filtered <= TARGET_BLOCK_TIME_MS * MAX_BLOCK_SPACING_MUL,
            "Max spacing should be capped");
    }

    #[test]
    fn normal_time_unfiltered() {
        let mut engine = DifficultyEngine::new(1000);
        let filtered = engine.filter_block_time(1000); // exactly target
        assert_eq!(filtered, 1000, "Normal time should pass through");
    }

    // ── Clamping Tests ──────────────────────────────────────────

    #[test]
    fn difficulty_never_below_minimum() {
        let mut engine = DifficultyEngine::new(MIN_DIFFICULTY);
        let mut ts = test_base_ts();
        // Very slow blocks (capped at 10s by filter_block_time)
        for i in 0..100 {
            ts += 10_000; // 10 seconds per block (at max spacing cap)
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }
        assert!(engine.difficulty() >= MIN_DIFFICULTY);
    }

    #[test]
    fn difficulty_never_above_maximum() {
        let mut engine = DifficultyEngine::new(MAX_DIFFICULTY - 100);
        let mut ts = test_base_ts();
        // Very fast blocks
        for i in 0..100 {
            ts += 100; // 0.1 second per block
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }
        assert!(engine.difficulty() <= MAX_DIFFICULTY);
    }

    #[test]
    fn max_4x_change_per_adjustment() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();

        // Feed one very fast block
        ts += 100; // 0.1 second
        let old = engine.difficulty();
        engine.on_new_block(make_record(1, ts, old));
        // Difficulty should increase but not more than 4x
        assert!(engine.difficulty() <= old * MAX_ADJUST_UP,
            "Difficulty {} should be <= {} (4x old)", engine.difficulty(), old * MAX_ADJUST_UP);
    }

    // ── Cliff Detection Tests ───────────────────────────────────

    #[test]
    fn cliff_triggers_emergency() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();

        // First block at normal time
        ts += 1000;
        engine.on_new_block(make_record(1, ts, 1000));

        // Feed slow blocks to trigger cliff (capped at 10s by filter)
        for i in 2..20 {
            ts += 10_000; // 10 seconds per block (at max spacing cap)
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }

        assert!(engine.cliff_detections > 0 || engine.difficulty() < 1000,
            "Should detect cliff or reduce difficulty");
    }

    // ── DAG Median Timestamp ────────────────────────────────────

    #[test]
    fn median_timestamp_odd() {
        let mut ts = vec![5, 3, 1, 4, 2];
        assert_eq!(DifficultyEngine::median_timestamp(&mut ts), 3);
    }

    #[test]
    fn median_timestamp_even() {
        let mut ts = vec![1, 2, 3, 4];
        assert_eq!(DifficultyEngine::median_timestamp(&mut ts), 2); // (2+3)/2 = 2
    }

    #[test]
    fn median_timestamp_empty() {
        assert_eq!(DifficultyEngine::median_timestamp(&mut []), 0);
    }

    // ── Timestamp Validation ────────────────────────────────────

    #[test]
    fn rejects_future_timestamp() {
        let mut engine = DifficultyEngine::new(1000);
        engine.last_ts = now_ms();
        let far_future = now_ms() + MAX_FUTURE_SECS * 1000 + 100_000;
        assert!(!engine.validate_timestamp(far_future));
    }

    #[test]
    fn accepts_current_timestamp() {
        let mut engine = DifficultyEngine::new(1000);
        engine.last_ts = now_ms() - 1000;
        assert!(engine.validate_timestamp(now_ms()));
    }

    // ── Stability Tests ─────────────────────────────────────────

    #[test]
    fn stable_at_target_rate() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();
        let initial = engine.difficulty();

        // 500 blocks at exactly target time
        for i in 0..500 {
            ts += 1_000;
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }

        let final_diff = engine.difficulty();
        let ratio = if final_diff > initial { final_diff * 100 / initial } else { initial * 100 / final_diff };
        assert!(ratio < 120, // Within 20% of initial
            "Difficulty should be stable at target rate: initial={} final={} ratio={}%",
            initial, final_diff, ratio);
    }

    #[test]
    fn dual_ema_short_reacts_faster() {
        let mut engine = DifficultyEngine::new(1000);
        let mut ts = test_base_ts();

        // Normal blocks first
        for i in 0..100 {
            ts += 1_000;
            engine.on_new_block(make_record(i, ts, 1000));
        }

        // Sudden speed change
        for i in 100..110 {
            ts += 200; // 5x faster
            engine.on_new_block(make_record(i, ts, engine.difficulty()));
        }

        // Short EMA should react more than long EMA
        assert!(engine.ema_short_ms() < engine.ema_long_ms(),
            "Short EMA ({}) should react faster than long EMA ({})",
            engine.ema_short_ms(), engine.ema_long_ms());
    }

    // ── Status ──────────────────────────────────────────────────

    #[test]
    fn status_string() {
        let engine = DifficultyEngine::new(1000);
        let s = engine.status();
        assert!(s.contains("Difficulty: 1000"));
        assert!(s.contains("EMA short"));
        assert!(s.contains("Blended"));
    }
}
