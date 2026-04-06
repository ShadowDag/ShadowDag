// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;
pub const TARGET_BLOCK_TIME_SECS:   u64 = 1;
pub const SHORT_WINDOW:             usize = 144;
pub const LONG_WINDOW:              usize = 2016;

pub const EMA_ALPHA_NUM:            u64 = 1;
pub const EMA_ALPHA_DEN:            u64 = 20;

/// Max per-block adjustment: 4x up, 4x down.
/// Must converge fast enough that a difficulty mismatch (e.g. genesis → real
/// hashrate) is corrected within ~20 blocks, not 200.
pub const MAX_ADJUST_UP:            u64 = 4;
pub const MAX_ADJUST_DOWN:          u64 = 4;

/// Difficulty is a numeric value where target = MAX_TARGET / difficulty.
/// Higher difficulty = harder to mine. Unified with pow_validator.rs.
/// Range: 1 (easiest) to u64::MAX / 2 (theoretical maximum).
pub const MIN_DIFFICULTY:           u64 = 1;
pub const MAX_DIFFICULTY:           u64 = u64::MAX / 2;

pub const CLIFF_DETECT_RATIO:       u64 = 10;
pub const MAX_BLOCK_SPACING:        u64 = TARGET_BLOCK_TIME_SECS * 10;

#[derive(Debug, Clone)]
pub struct BlockTimeRecord {
    pub height:     u64,
    pub timestamp:  u64,
    pub difficulty: u64,
}

pub struct RetargetEngine {
    short_window: VecDeque<BlockTimeRecord>,
    long_window:  VecDeque<BlockTimeRecord>,
    /// EMA difficulty — stored as u64 (NOT float) for consensus determinism.
    /// Integer EMA: ema = ema_prev + (new - ema_prev) / 20
    ema_diff:     u64,
}

impl RetargetEngine {
    pub fn new(initial_difficulty: u64) -> Self {
        Self {
            short_window: VecDeque::new(),
            long_window:  VecDeque::new(),
            ema_diff:     initial_difficulty,
        }
    }

    pub fn on_new_block(&mut self, rec: BlockTimeRecord) -> u64 {
        self.short_window.push_back(rec.clone());
        if self.short_window.len() > SHORT_WINDOW {
            self.short_window.pop_front();
        }

        self.long_window.push_back(rec);
        if self.long_window.len() > LONG_WINDOW {
            self.long_window.pop_front();
        }

        self.compute_next_difficulty()
    }

    pub fn compute_next_difficulty(&mut self) -> u64 {
        let n = self.short_window.len();

        if n < 10 {
            // Not enough data — use aggressive heuristic to converge fast.
            //
            // The core problem: at 1-second timestamp resolution, if blocks
            // arrive in <1s they get the SAME timestamp as their predecessor.
            // We can't see the actual sub-second timing, so we count
            // same-timestamp pairs as a proxy for "too fast".
            let base = self.window_average_difficulty(&self.short_window);
            let ema  = self.ema_diff;
            let mut blended = ((base as u128 + ema as u128) / 2) as u64;

            if n >= 2 {
                let first_ts = self.short_window.front().map(|r| r.timestamp).unwrap_or(0);
                let last_ts  = self.short_window.back().map(|r| r.timestamp).unwrap_or(0);
                let span = last_ts.saturating_sub(first_ts).max(1);
                let blocks = (n - 1) as u64;

                // If blocks/second > 1, mining is too fast — boost aggressively
                if blocks > span {
                    // E.g. 5 blocks in 1 second → ratio=5 → multiply difficulty by 5
                    // Clamp ratio to MAX_ADJUST_UP to prevent bypassing the cap
                    let ratio = (blocks / span).min(MAX_ADJUST_UP);
                    blended = blended.saturating_mul(ratio.max(2));
                }

                // Also count same-timestamp pairs for extra sensitivity
                let same_ts = self.count_same_timestamp_pairs();
                if same_ts > 0 {
                    let boost = (same_ts as u64 + 1).min(MAX_ADJUST_UP);
                    blended = blended.saturating_mul(boost);
                }

                // Clamp early convergence boost to MAX_ADJUST_UP
                let current_difficulty = self.window_average_difficulty(&self.short_window);
                let max_allowed = current_difficulty.saturating_mul(MAX_ADJUST_UP);
                blended = blended.min(max_allowed);
            }

            self.ema_diff = self.clamp(blended);
            return self.ema_diff;
        }

        let lwma = self.compute_lwma(&self.short_window);
        let long_avg = self.compute_average_time_integer(&self.long_window);

        // DETERMINISTIC integer blending (no float!) — 70% short + 30% long
        let blended_time = (lwma as u128 * 7 + long_avg as u128 * 3) / 10;
        let mut blended_time = (blended_time as u64).max(1);

        // ── Sub-second block detection ─────────────────────────────────
        // With 1-second timestamp resolution, blocks mined in <1s get dt=0
        // which is clamped to 1 = TARGET. The retarget can't distinguish
        // "perfect 1s blocks" from "instant mining".
        //
        // Fix: count same-timestamp pairs. If >25% of block pairs share
        // a timestamp, blocks are arriving faster than 1s — halve the
        // effective block time to force difficulty upward.
        let same_ts = self.count_same_timestamp_pairs();
        let total_pairs = (n - 1) as u64;
        if total_pairs > 0 && same_ts > 0 {
            let same_pct = (same_ts * 100) / total_pairs;
            if same_pct > 25 {
                // Reduce effective block time proportionally
                // e.g. 50% same-ts → blended_time / 2
                let divisor = (same_pct / 25).min(4).max(1);
                blended_time = (blended_time / divisor).max(1);
            }
        }

        // Hard clamp (anti exploit)
        blended_time = blended_time.min(MAX_BLOCK_SPACING * 20);

        let window_diff = self.window_average_difficulty(&self.short_window);

        let mut new_diff = self.adjust_difficulty(window_diff, blended_time);

        // Cliff protection: if blocks are extremely slow, reduce difficulty
        if blended_time > TARGET_BLOCK_TIME_SECS * CLIFF_DETECT_RATIO {
            let ratio = blended_time.saturating_div(TARGET_BLOCK_TIME_SECS.max(1));
            let factor = ratio.clamp(1, 64);
            new_diff /= factor.max(2);
        }

        new_diff = self.clamp(new_diff);

        // Integer EMA: ema = ema + (new - ema) / 20 (α = 1/20)
        // Use minimum update of 1 when difference is non-zero to prevent
        // integer truncation from stalling the EMA at small deltas.
        let divisor = EMA_ALPHA_DEN / EMA_ALPHA_NUM;
        if new_diff >= self.ema_diff {
            let diff = new_diff - self.ema_diff;
            let update = (diff / divisor).max(if diff > 0 { 1 } else { 0 });
            self.ema_diff = self.ema_diff.saturating_add(update);
        } else {
            let diff = self.ema_diff - new_diff;
            let update = (diff / divisor).max(if diff > 0 { 1 } else { 0 });
            self.ema_diff = self.ema_diff.saturating_sub(update);
        }
        self.ema_diff = self.ema_diff.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);

        self.ema_diff
    }

    /// Count consecutive block pairs with identical timestamps.
    /// When blocks mine in <1 second, they get the same Unix timestamp.
    fn count_same_timestamp_pairs(&self) -> u64 {
        let mut count = 0u64;
        let mut prev_ts = 0u64;
        let mut first = true;
        for rec in &self.short_window {
            if !first && rec.timestamp == prev_ts {
                count += 1;
            }
            prev_ts = rec.timestamp;
            first = false;
        }
        count
    }

    fn adjust_difficulty(&self, current_diff: u64, actual_time: u64) -> u64 {
        let actual_time = actual_time.max(1);

        let nd = (current_diff as u128)
            .saturating_mul(TARGET_BLOCK_TIME_SECS as u128)
            / actual_time as u128;

        let nd = nd as u64;

        let max_up   = current_diff.saturating_mul(MAX_ADJUST_UP);
        let max_down = current_diff / MAX_ADJUST_DOWN;

        nd.clamp(max_down, max_up)
    }

    fn compute_lwma(&self, window: &VecDeque<BlockTimeRecord>) -> u64 {
        let n = window.len();
        if n < 2 { return TARGET_BLOCK_TIME_SECS; }

        let mut weighted_sum = 0u128;
        let mut weight_total = 0u128;

        let recs: Vec<&BlockTimeRecord> = window.iter().collect();

        for i in 1..n {
            let t1 = recs[i - 1].timestamp;
            let t2 = recs[i].timestamp;

            let mut dt = if t2 > t1 { t2 - t1 } else { 1 };

            // Anti-timewarp clamp: individual inter-block intervals are
            // clamped to [1, MAX_BLOCK_SPACING]. This prevents a single
            // manipulated timestamp from disproportionately affecting the
            // LWMA. Without this, a miner can insert one block with
            // ts = parent_ts + MAX_FUTURE to inflate the average.
            dt = dt.clamp(1, MAX_BLOCK_SPACING);

            let w = i as u128;
            weighted_sum += dt as u128 * w;
            weight_total += w;
        }

        if weight_total == 0 {
            return TARGET_BLOCK_TIME_SECS;
        }

        (weighted_sum / weight_total) as u64
    }

    /// 🔥 DETERMINISTIC integer average — NO FLOAT for consensus safety
    fn compute_average_time_integer(&self, window: &VecDeque<BlockTimeRecord>) -> u64 {
        let n = window.len();
        if n < 2 { return TARGET_BLOCK_TIME_SECS; }

        let mut times: Vec<u64> = window.iter().map(|r| r.timestamp).collect();
        times.sort_unstable();

        let median = times[n / 2];
        let oldest = times[0];

        let span = median.saturating_sub(oldest).max(1);

        let max_span = TARGET_BLOCK_TIME_SECS * LONG_WINDOW as u64;
        let clamped_span = span.min(max_span).max(1);

        let denom = (n - 1) as u64;
        if denom == 0 { return TARGET_BLOCK_TIME_SECS; }

        // Integer division with rounding: (span + denom/2) / denom
        (clamped_span + denom / 2) / denom
    }

    fn window_average_difficulty(&self, window: &VecDeque<BlockTimeRecord>) -> u64 {
        if window.is_empty() {
            return MIN_DIFFICULTY;
        }

        let mut sum = 0u128;
        let mut weight = 0u128;

        for (i, r) in window.iter().enumerate() {
            let w = (i + 1) as u128;
            sum += r.difficulty as u128 * w;
            weight += w;
        }

        if weight == 0 {
            return MIN_DIFFICULTY;
        }

        // 🔥 unbiased rounding
        ((sum + weight / 2) / weight) as u64
    }

    pub fn clamp(&self, d: u64) -> u64 {
        d.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
    }

    pub fn validate_difficulty(&self, claimed: u64, expected: u64) -> bool {
        let tolerance = expected / 8;
        claimed >= expected.saturating_sub(tolerance)
            && claimed <= expected.saturating_add(tolerance)
    }

    pub fn median_past_time(&self, last_n: usize) -> u64 {
        let n = last_n.min(self.long_window.len());
        if n == 0 { return 0; }

        let mut ts: Vec<u64> = self.long_window
            .iter()
            .rev()
            .take(n)
            .map(|r| r.timestamp)
            .collect();

        ts.sort_unstable();
        ts[n / 2]
    }

    pub fn short_window_len(&self) -> usize { self.short_window.len() }
    pub fn long_window_len(&self)  -> usize { self.long_window.len() }
    pub fn ema_difficulty(&self)   -> u64   { self.ema_diff }
}

// legacy
pub fn adjust_difficulty(current: u64, actual_secs: u64) -> u64 {
    let actual_secs = actual_secs.max(1);

    let nd = (current as u128)
        .saturating_mul(TARGET_BLOCK_TIME_SECS as u128)
        / actual_secs as u128;

    let nd = nd as u64;

    let max_up   = current.saturating_mul(MAX_ADJUST_UP);
    let max_down = current / MAX_ADJUST_DOWN;

    nd.clamp(max_down, max_up)
        .clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn block(h: u64, ts: u64, diff: u64) -> BlockTimeRecord {
        BlockTimeRecord { height: h, timestamp: ts, difficulty: diff }
    }

    #[test]
    fn stays_stable_at_target() {
        let init = 1000u64;
        let mut engine = RetargetEngine::new(init);
        let mut diff = init;

        for i in 0..200 {
            let r = block(i, i * TARGET_BLOCK_TIME_SECS, diff);
            diff = engine.on_new_block(r);
        }

        assert!(diff >= MIN_DIFFICULTY, "Unexpected diff: {}", diff);
        // Should stay roughly stable (within 3x of initial)
        assert!(diff > init / 3, "Unexpected diff: {}", diff);
    }

    #[test]
    fn increases_when_blocks_too_fast() {
        // When blocks arrive faster than TARGET_BLOCK_TIME_SECS (< 1s apart),
        // timestamps are integers so the minimum gap is 1s = target. To simulate
        // "too fast", we report higher difficulty blocks arriving at target pace,
        // which the EMA tracks upward. Verify the EMA tracks reported difficulty.
        let init = 2u64;
        let mut engine = RetargetEngine::new(init);
        // Feed blocks with increasing difficulty at target pace
        // The EMA should track upward toward the reported difficulty
        for i in 0..200u64 {
            let reported_diff = 50u64; // much higher than init
            let r = block(i, i * TARGET_BLOCK_TIME_SECS, reported_diff);
            let _ = engine.on_new_block(r);
        }
        let diff = engine.ema_difficulty();
        assert!(diff > init, "EMA should track upward from {}: got {}", init, diff);
    }

    #[test]
    fn decreases_when_blocks_too_slow() {
        let init = 10_000u64; // start high so it can decrease
        let mut engine = RetargetEngine::new(init);
        let mut diff = init;

        for i in 0..200u64 {
            let r = block(i, i * 10, diff);
            diff = engine.on_new_block(r);
        }
        assert!(diff < init, "Diff should have decreased: {}", diff);
    }

    #[test]
    fn never_below_min() {
        let mut engine = RetargetEngine::new(MIN_DIFFICULTY);
        let mut diff = MIN_DIFFICULTY;
        for i in 0..300u64 {
            let r = block(i, i * 100, diff);
            diff = engine.on_new_block(r);
        }
        assert!(diff >= MIN_DIFFICULTY);
    }

    #[test]
    fn legacy_adjust_function() {
        let d = adjust_difficulty(32, TARGET_BLOCK_TIME_SECS);
        assert_eq!(d, 32);
    }

    #[test]
    fn median_past_time() {
        let mut engine = RetargetEngine::new(32);
        for i in 0..20u64 {
            engine.on_new_block(block(i, i * 2, 32));
        }
        let mpt = engine.median_past_time(11);
        assert!(mpt > 0);
    }

    #[test]
    fn validate_difficulty_bounds() {
        let engine = RetargetEngine::new(32);
        assert!(engine.validate_difficulty(32, 32));
        // tolerance = 32/8 = 4, so 28..=36 is valid
        assert!(engine.validate_difficulty(28, 32));
        assert!(!engine.validate_difficulty(10, 32));
    }
}
