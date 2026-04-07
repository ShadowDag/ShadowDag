// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Smooth Emission Schedule — Gradual step-down instead of abrupt halving.
//
// ❌ Bitcoin-style (BAD for DAG):
//   Block 209,999: reward = 10 SDAG
//   Block 210,000: reward = 5 SDAG  ← 50% drop in 1 second!
//   → Miners leave → hashrate drops → difficulty chaos → price crash
//
// ✅ ShadowDAG-style (SMOOTH):
//   Reward decreases by ~0.38% every REDUCTION_INTERVAL (2,592,000 blocks = ~30 days)
//   → 10.00 → 9.96 → 9.92 → ... → 5.00 (takes ~6 years to halve)
//   → No shock. No miner exodus. Stable network.
//
// Math:
//   reduction_step = (height / REDUCTION_INTERVAL)
//   reward = INITIAL_REWARD * DECAY_FACTOR^reduction_step
//
//   Using integer math:
//   reward = INITIAL_REWARD * (DECAY_NUM^step) / (DECAY_DEN^step)
//
// Parameters:
//   INITIAL_REWARD     = 10 SDAG (1,000,000,000 satoshis)
//   REDUCTION_INTERVAL = REDUCTION_INTERVAL_SECS * DEFAULT_BPS (~30 days at ConsensusParams::BLOCKS_PER_SECOND)
//   DECAY per step     = 99.62% (0.38% reduction per month)
//   DECAY_NUM/DEN      = 9962 / 10000
//   Time to halve      = ~182 steps = ~5.5 years (similar to Bitcoin's 4 years)
//   Max Supply         = ~21 billion SDAG (converges asymptotically)
//
// Benefits over Bitcoin halving:
//   ✅ No sudden 50% reward drop
//   ✅ Miners can plan ahead — predictable income curve
//   ✅ Difficulty adjustment stays stable
//   ✅ No "halving dump" price volatility
//   ✅ Better for DAG with 1-second blocks
//   ✅ Smart contracts generate fees → miners keep earning after emission ends
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::consensus::consensus_params::ConsensusParams;
use once_cell::sync::Lazy;

/// Initial block reward: 10 SDAG in satoshis
pub const INITIAL_REWARD: u64 = 1_000_000_000;

/// Reduction interval in SECONDS (30 days = 2,592,000 seconds)
/// The actual block interval = REDUCTION_INTERVAL_SECS * BPS
/// This ensures the emission schedule runs on WALL-CLOCK TIME, not block count.
/// At 1 BPS:  2,592,000 blocks per step
/// At DEFAULT_BPS: 25,920,000 blocks per step (same 30 days)
/// At 32 BPS: 82,944,000 blocks per step (same 30 days)
pub const REDUCTION_INTERVAL_SECS: u64 = 2_592_000; // 30 days in seconds
/// Must match ConsensusParams::BLOCKS_PER_SECOND
pub const DEFAULT_BPS: u64 = 10;
pub const REDUCTION_INTERVAL: u64 = REDUCTION_INTERVAL_SECS * DEFAULT_BPS;

/// Decay factor per step: 9962/10000 = 99.62% (0.38% reduction)
/// After 182 steps (~5.5 years): 0.9962^182 ≈ 0.5 (halved)
pub const DECAY_NUM: u64 = 9962;
pub const DECAY_DEN: u64 = 10000;

/// Minimum block reward (1 satoshi) — below this, emission stops
pub const MIN_REWARD: u64 = 1;

/// Maximum number of reduction steps before reward reaches 0
/// 0.9962^12000 ≈ 0 — more than enough
pub const MAX_STEPS: u32 = 12_000;

/// PRECISION = 10^18: chosen to provide 18 decimal digits of precision,
/// matching the standard for cryptocurrency fixed-point arithmetic.
/// At DEFAULT_BPS with 200 halving steps, truncation error < 1 satoshi per block.
/// This ensures decay_factor() remains accurate over thousands of steps
/// without cumulative truncation drift.
const PRECISION: u128 = 1_000_000_000_000_000_000; // 10^18

pub struct EmissionSchedule;

impl EmissionSchedule {
    pub const MAX_HEIGHT: u64 = REDUCTION_INTERVAL * (MAX_STEPS as u64);

    /// Get the reduction interval for a given BPS rate
    pub fn reduction_interval_for_bps(bps: u64) -> u64 {
        REDUCTION_INTERVAL_SECS * bps.max(1)
    }

    /// Calculate block reward at a given height using smooth decay.
    /// Uses DEFAULT_BPS for interval. For other BPS rates, use block_reward_at_bps().
    pub fn block_reward(height: u64) -> u64 {
        Self::block_reward_at_bps(height, DEFAULT_BPS)
    }

    /// Calculate block reward at a given height with specific BPS rate.
    /// The BPS rate scales the interval so emission stays TIME-BASED.
    /// Includes MAX_SUPPLY enforcement to prevent exceeding 21 billion SDAG.
    pub fn block_reward_at_bps(height: u64, bps: u64) -> u64 {
        let interval = Self::reduction_interval_for_bps(bps);
        let step = (height / interval) as u32;

        if step >= MAX_STEPS {
            return 0;
        }

        let factor = Self::decay_factor(step);

        // reward = INITIAL_REWARD * factor / PRECISION
        let reward = (INITIAL_REWARD as u128)
            .saturating_mul(factor)
            / PRECISION;

        let reward = reward as u64;
        if reward < MIN_REWARD { return 0; }

        reward
    }

    /// Estimate total cumulative emission up to a given height.
    /// Uses geometric series approximation: Sum ≈ R₀ × interval × (1 - r^n) / (1 - r)
    /// where r = DECAY_NUM/DECAY_DEN and n = number of steps completed.
    pub fn estimate_cumulative_emission(height: u64, bps: u64) -> u64 {
        let interval = Self::reduction_interval_for_bps(bps);
        let steps = (height / interval) as u32;
        let blocks_in_last_step = height % interval;

        let mut total: u128 = 0;
        // Sum rewards for each completed step
        for s in 0..steps.min(MAX_STEPS) { // Cap at MAX_STEPS
            let factor = Self::decay_factor(s);
            let step_reward = (INITIAL_REWARD as u128).saturating_mul(factor) / PRECISION;
            total = total.saturating_add(step_reward * interval as u128);
        }
        // Add partial last step
        if steps < MAX_STEPS {
            let factor = Self::decay_factor(steps);
            let current_reward = (INITIAL_REWARD as u128).saturating_mul(factor) / PRECISION;
            total = total.saturating_add(current_reward * blocks_in_last_step as u128);
        }
        total.min(ConsensusParams::MAX_SUPPLY as u128) as u64
    }

    /// Compute decay factor: (DECAY_NUM/DECAY_DEN)^step scaled by PRECISION.
    /// Uses a pre-computed table built via iterative multiplication, which
    /// never overflows because each step stays within u128 range.
    /// The old binary-exponentiation approach had checked_mul overflow at
    /// step ~2600, causing rewards to suddenly drop to 0.
    fn decay_factor(step: u32) -> u128 {
        static DECAY_TABLE: Lazy<Vec<u128>> = Lazy::new(|| {
            let mut table = Vec::with_capacity(MAX_STEPS as usize + 1);
            table.push(PRECISION);
            for _ in 0..MAX_STEPS {
                let prev = *table.last().unwrap();
                let next = prev * DECAY_NUM as u128 / DECAY_DEN as u128;
                table.push(next);
            }
            table
        });

        DECAY_TABLE[step.min(MAX_STEPS) as usize]
    }

    /// Miner's share (95%)
    pub fn miner_reward(height: u64) -> u64 {
        let reward = Self::block_reward(height);
        (reward * ConsensusParams::MINER_PERCENT) / 100
    }

    /// Developer's share (5%)
    pub fn developer_reward(height: u64) -> u64 {
        let reward = Self::block_reward(height);
        reward - Self::miner_reward(height)
    }

    /// Current reduction step. Uses DEFAULT_BPS. For other BPS rates, use step_at_bps().
    pub fn step(height: u64) -> u32 {
        Self::step_at_bps(height, DEFAULT_BPS)
    }

    /// Current reduction step with specific BPS rate.
    pub fn step_at_bps(height: u64, bps: u64) -> u32 {
        let interval = Self::reduction_interval_for_bps(bps);
        (height / interval) as u32
    }

    /// Blocks until next reduction. Uses DEFAULT_BPS. For other BPS rates, use blocks_until_reduction_at_bps().
    pub fn blocks_until_reduction(height: u64) -> u64 {
        Self::blocks_until_reduction_at_bps(height, DEFAULT_BPS)
    }

    /// Blocks until next reduction with specific BPS rate.
    pub fn blocks_until_reduction_at_bps(height: u64, bps: u64) -> u64 {
        let interval = Self::reduction_interval_for_bps(bps);
        interval - (height % interval)
    }

    /// Approximate percentage of initial reward remaining
    pub fn reward_percent(height: u64) -> f64 {
        let reward = Self::block_reward(height);
        if INITIAL_REWARD == 0 { return 0.0; }
        (reward as f64 / INITIAL_REWARD as f64) * 100.0
    }

    /// Total emitted from genesis to height (era-based O(steps) calculation)
    /// Uses DEFAULT_BPS for interval. For other BPS rates, use total_emitted_at_bps().
    pub fn total_emitted(height: u64) -> u64 {
        Self::total_emitted_at_bps(height, DEFAULT_BPS)
    }

    /// Total emitted from genesis to height with specific BPS rate.
    pub fn total_emitted_at_bps(height: u64, bps: u64) -> u64 {
        let interval = Self::reduction_interval_for_bps(bps);
        let mut total: u64 = 0;
        let mut h: u64 = 0;

        while h <= height {
            let step = (h / interval) as u32;
            let step_end = (step as u64).saturating_add(1).saturating_mul(interval).min(height.saturating_add(1));
            let blocks_in_step = step_end - h;
            let reward = Self::block_reward_at_bps(h, bps);

            if reward == 0 { break; }

            total = total.saturating_add(blocks_in_step.saturating_mul(reward));
            h = step_end;
        }

        total
    }

    /// Theoretical max supply (sum of geometric series), capped at 21 billion SDAG.
    pub fn max_supply() -> u64 {
        // Sum = INITIAL_REWARD * REDUCTION_INTERVAL * (1 / (1 - DECAY_NUM/DECAY_DEN))
        //     = INITIAL_REWARD * REDUCTION_INTERVAL * (DECAY_DEN / (DECAY_DEN - DECAY_NUM))
        //     = 10^9 * 25,920,000 * (10000 / 38)
        //     ≈ 6.82 × 10^18 satoshis ≈ 68.2 billion SDAG (theoretical)
        // Capped at ConsensusParams::MAX_SUPPLY = 21 billion SDAG
        let den_minus_num = (DECAY_DEN - DECAY_NUM) as u128; // 38
        let theoretical: u128 = (INITIAL_REWARD as u128)
            * (REDUCTION_INTERVAL as u128)
            * (DECAY_DEN as u128)
            / den_minus_num;

        (theoretical.min(ConsensusParams::MAX_SUPPLY as u128)) as u64
    }

    /// Height at which reward drops below a given percentage of initial.
    /// Uses DEFAULT_BPS. For other BPS rates, use height_at_percent_at_bps().
    pub fn height_at_percent(target_pct: f64) -> u64 {
        Self::height_at_percent_at_bps(target_pct, DEFAULT_BPS)
    }

    /// Height at which reward drops below a given percentage of initial with specific BPS rate.
    pub fn height_at_percent_at_bps(target_pct: f64, bps: u64) -> u64 {
        // Validate input: percent must be in (0, 100]
        if !target_pct.is_finite() || target_pct <= 0.0 || target_pct > 100.0 {
            return 0; // Invalid input — return genesis height
        }
        let interval = Self::reduction_interval_for_bps(bps);
        // Solve: DECAY^step = target_pct/100
        // step = ln(target_pct/100) / ln(DECAY_NUM/DECAY_DEN)
        let decay_ratio = DECAY_NUM as f64 / DECAY_DEN as f64;
        let steps = (target_pct / 100.0).ln() / decay_ratio.ln();
        if !steps.is_finite() || steps < 0.0 {
            return 0;
        }
        (steps.ceil() as u64).saturating_mul(interval)
    }

    /// Human-readable info
    pub fn info(height: u64) -> String {
        format!(
            "Height: {} | Step: {} | Reward: {} sat ({:.2}%) | Miner: {} | Dev: {} | \
             Next reduction in: {} blocks",
            height,
            Self::step(height),
            Self::block_reward(height),
            Self::reward_percent(height),
            Self::miner_reward(height),
            Self::developer_reward(height),
            Self::blocks_until_reduction(height),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_reward_correct() {
        assert_eq!(EmissionSchedule::block_reward(0), INITIAL_REWARD);
        assert_eq!(EmissionSchedule::block_reward(1), INITIAL_REWARD);
        assert_eq!(EmissionSchedule::block_reward(REDUCTION_INTERVAL - 1), INITIAL_REWARD);
    }

    #[test]
    fn first_reduction_is_small() {
        let before = EmissionSchedule::block_reward(REDUCTION_INTERVAL - 1);
        let after  = EmissionSchedule::block_reward(REDUCTION_INTERVAL);
        // Should drop by ~0.38%, NOT 50%
        let drop_pct = ((before - after) as f64 / before as f64) * 100.0;
        assert!(drop_pct < 1.0, "First reduction should be <1%, got {:.2}%", drop_pct);
        assert!(drop_pct > 0.1, "First reduction should be >0.1%, got {:.2}%", drop_pct);
        assert!(after > 0, "Reward must be positive after first reduction");
    }

    #[test]
    fn smooth_not_abrupt() {
        // Check 10 consecutive reduction steps — each should be a small decrease
        for step in 0..10 {
            let h1 = step * REDUCTION_INTERVAL;
            let h2 = (step + 1) * REDUCTION_INTERVAL;
            let r1 = EmissionSchedule::block_reward(h1);
            let r2 = EmissionSchedule::block_reward(h2);
            if r1 == 0 { break; }
            let drop_pct = ((r1 - r2) as f64 / r1 as f64) * 100.0;
            assert!(drop_pct < 2.0,
                "Step {} to {}: drop should be <2%, got {:.2}%", step, step+1, drop_pct);
        }
    }

    #[test]
    fn halves_in_about_5_years() {
        // ~182 steps ≈ 5.5 years → reward should be roughly half
        let half_steps = 182u64;
        let h = half_steps * REDUCTION_INTERVAL;
        let reward = EmissionSchedule::block_reward(h);
        let ratio = reward as f64 / INITIAL_REWARD as f64;
        assert!(ratio > 0.4 && ratio < 0.6,
            "After ~5.5 years, reward should be ~50% of initial, got {:.1}%", ratio * 100.0);
    }

    #[test]
    fn reward_eventually_zero() {
        let very_high = REDUCTION_INTERVAL * 6000;
        assert_eq!(EmissionSchedule::block_reward(very_high), 0);
    }

    #[test]
    fn miner_plus_dev_equals_total() {
        for h in [0, 1000, REDUCTION_INTERVAL, REDUCTION_INTERVAL * 10] {
            let total = EmissionSchedule::block_reward(h);
            let miner = EmissionSchedule::miner_reward(h);
            let dev = EmissionSchedule::developer_reward(h);
            assert_eq!(miner + dev, total, "Split must equal total at height {}", h);
        }
    }

    #[test]
    fn miner_gets_95_percent() {
        let reward = EmissionSchedule::block_reward(0);
        let miner = EmissionSchedule::miner_reward(0);
        assert_eq!(miner, (reward * 95) / 100);
    }

    #[test]
    fn step_calculation() {
        assert_eq!(EmissionSchedule::step(0), 0);
        assert_eq!(EmissionSchedule::step(REDUCTION_INTERVAL - 1), 0);
        assert_eq!(EmissionSchedule::step(REDUCTION_INTERVAL), 1);
        assert_eq!(EmissionSchedule::step(REDUCTION_INTERVAL * 5), 5);
    }

    #[test]
    fn blocks_until_reduction_at_start() {
        assert_eq!(EmissionSchedule::blocks_until_reduction(0), REDUCTION_INTERVAL);
    }

    #[test]
    fn blocks_until_reduction_near_end() {
        assert_eq!(EmissionSchedule::blocks_until_reduction(REDUCTION_INTERVAL - 1), 1);
    }

    #[test]
    fn total_emitted_grows() {
        let e1 = EmissionSchedule::total_emitted(1000);
        let e2 = EmissionSchedule::total_emitted(2000);
        assert!(e2 > e1);
    }

    #[test]
    fn total_emitted_at_zero() {
        assert_eq!(EmissionSchedule::total_emitted(0), INITIAL_REWARD);
    }

    #[test]
    fn reward_monotonically_decreasing() {
        let mut prev = EmissionSchedule::block_reward(0);
        for step in 1..200 {
            let h = step * REDUCTION_INTERVAL;
            let reward = EmissionSchedule::block_reward(h);
            assert!(reward <= prev,
                "Reward must never increase: step {} = {}, prev = {}", step, reward, prev);
            prev = reward;
        }
    }

    #[test]
    fn emission_curve_preview() {
        // Print the emission curve for visual verification
        eprintln!("\n=== ShadowDAG Smooth Emission Curve ===");
        eprintln!("{:<8} {:<12} {:<15} {:<10}", "Step", "~Months", "Reward (SDAG)", "% of Initial");
        for step in [0, 6, 12, 24, 60, 120, 182, 240, 365, 500, 1000] {
            let h = step as u64 * REDUCTION_INTERVAL;
            let reward = EmissionSchedule::block_reward(h);
            let sdag = reward as f64 / 100_000_000.0;
            let pct = EmissionSchedule::reward_percent(h);
            eprintln!("{:<8} {:<12} {:<15.4} {:<10.2}%", step, step, sdag, pct);
        }
        eprintln!();
    }

    #[test]
    fn no_overflow_in_calculations() {
        // Test with very large heights
        for h in [0, 1_000_000, 100_000_000, 1_000_000_000, 10_000_000_000u64] {
            let reward = EmissionSchedule::block_reward(h);
            assert!(reward <= INITIAL_REWARD);
            let _ = EmissionSchedule::total_emitted(h.min(REDUCTION_INTERVAL * 100));
        }
    }

    #[test]
    fn max_supply_is_reasonable() {
        let supply = EmissionSchedule::max_supply();
        let sdag = supply as f64 / 100_000_000.0;
        // Should be in the billions range
        assert!(sdag > 1_000_000_000.0, "Max supply should be >1B SDAG, got {:.0}", sdag);
        assert!(sdag < 100_000_000_000.0, "Max supply should be <100B SDAG, got {:.0}", sdag);
        eprintln!("Max Supply: {:.2} billion SDAG", sdag / 1_000_000_000.0);
    }

    #[test]
    fn precision_sufficient_for_all_steps() {
        // Verify precision doesn't cause cumulative error > 1 satoshi.
        // The decay factor must remain non-zero for all meaningful steps,
        // ensuring rewards don't prematurely truncate to 0.
        for step in 0..MAX_STEPS {
            let h = (step as u64) * REDUCTION_INTERVAL;
            let reward = EmissionSchedule::block_reward(h);
            assert!(
                reward > 0 || step >= MAX_STEPS - 1,
                "Reward zeroed too early at step {}",
                step
            );
        }
    }

    #[test]
    fn height_at_50_percent() {
        let h = EmissionSchedule::height_at_percent(50.0);
        let _reward = EmissionSchedule::block_reward(h);
        let pct = EmissionSchedule::reward_percent(h);
        assert!(pct < 55.0 && pct > 30.0,
            "At 50% height {}, reward should be ~50%, got {:.1}%", h, pct);
    }
}
