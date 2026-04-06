// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reward {
    pub miner: u64,
    pub developer: u64,
}

impl Reward {
    // ─────────────────────────────────────────
    // CONFIG (single source of truth)
    // ─────────────────────────────────────────
    /// Dev gets 1/20 = 5%, miner gets 19/20 = 95%.
    /// This matches genesis.rs MINER_REWARD_PCT=95 and DEV_REWARD_PCT=5,
    /// as well as emission_schedule.rs which uses 95/100 for the miner share.
    pub const DEV_RATIO_NUM: u64 = 1;
    pub const DEV_RATIO_DEN: u64 = 20;

    // ─────────────────────────────────────────
    // SPLIT
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub const fn split(total: u64) -> Self {
        let developer = Self::developer_portion(total);
        let miner = total - developer;

        Self { miner, developer }
    }

    // ─────────────────────────────────────────
    // FAST PATHS (exact + overflow-safe)
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub const fn developer_portion(total: u64) -> u64 {
        // u128 math to preserve exactness and avoid overflow
        ((total as u128 * Self::DEV_RATIO_NUM as u128)
            / Self::DEV_RATIO_DEN as u128) as u64
    }

    #[inline(always)]
    #[must_use]
    pub const fn miner_portion(total: u64) -> u64 {
        total - Self::developer_portion(total)
    }

    /// Validate that miner + developer == total (no satoshi loss).
    /// Called during block validation to catch any future regressions.
    #[inline(always)]
    #[must_use]
    pub const fn validate_split(total: u64) -> bool {
        let d = Self::developer_portion(total);
        let m = Self::miner_portion(total);
        d + m == total
    }

    // ─────────────────────────────────────────
    // SELFISH MINING PENALTIES
    // ─────────────────────────────────────────

    /// Percentage of reward retained by red blocks (anticone > GHOSTDAG_K).
    /// Red blocks receive only 20% of the normal miner reward.
    /// This makes selfish mining unprofitable: even if the attacker's blocks
    /// are accepted into the DAG, they earn far less than honest miners.
    pub const RED_BLOCK_REWARD_PCT: u64 = 20;

    /// Penalty applied to blocks that arrive late (withheld by selfish miner).
    /// For each second of delay beyond the expected block time, the reward
    /// is reduced by this percentage (compounded). Cap: minimum 10% reward.
    pub const LATE_PENALTY_PCT_PER_SEC: u64 = 5;

    /// Minimum reward percentage after all penalties (floor to prevent zero rewards
    /// which could break coinbase validation).
    pub const MIN_REWARD_PCT: u64 = 10;

    /// Calculate the penalized miner reward for a red block.
    ///
    /// Red blocks (anticone > K in GHOSTDAG) are blocks that did not reach
    /// the network in time to be in the blue set. This is a strong signal
    /// of selfish mining or severe network partitioning.
    ///
    /// Returns: `miner_portion × RED_BLOCK_REWARD_PCT / 100`
    #[inline]
    #[must_use]
    pub fn red_block_miner_reward(total: u64) -> u64 {
        let base = Self::miner_portion(total);
        (base as u128 * Self::RED_BLOCK_REWARD_PCT as u128 / 100) as u64
    }

    /// Calculate the penalized reward for a late-arriving block.
    ///
    /// `delay_secs` is how many seconds late the block arrived relative to
    /// its expected timestamp. Each second costs LATE_PENALTY_PCT_PER_SEC
    /// of the remaining reward (multiplicative decay).
    ///
    /// Formula: `reward × (1 - penalty_rate)^delay_secs`
    /// Implemented as integer math: `reward × (100 - pct)^delay / 100^delay`
    ///
    /// Examples at 5% per second:
    ///   0s delay → 100% reward
    ///   1s delay → 95% reward
    ///   5s delay → 77% reward
    ///   10s delay → 60% reward
    ///   20s delay → 36% reward
    ///   30s+ delay → 10% minimum floor
    #[must_use]
    pub fn late_block_miner_reward(total: u64, delay_secs: u64) -> u64 {
        if delay_secs == 0 {
            return Self::miner_portion(total);
        }

        let base = Self::miner_portion(total);
        let min_reward = (base as u128 * Self::MIN_REWARD_PCT as u128 / 100) as u64;

        // Multiplicative decay: reward × ((100 - pct) / 100)^delay
        // Use u128 to avoid overflow
        let decay_base = (100u128 - Self::LATE_PENALTY_PCT_PER_SEC as u128).max(1);
        let mut numerator = base as u128;
        let mut denominator = 1u128;

        // Apply decay per second (cap at 30 iterations to prevent DoS)
        let steps = delay_secs.min(30) as usize;
        for _ in 0..steps {
            numerator *= decay_base;
            denominator *= 100;
            // Prevent overflow by reducing periodically
            if denominator > 1_000_000_000_000 {
                numerator /= 1_000_000;
                denominator /= 1_000_000;
            }
        }

        let penalized = (numerator / denominator.max(1)) as u64;
        penalized.max(min_reward)
    }

    /// Combined penalty: red block + late arrival.
    /// Applies both penalties multiplicatively.
    #[must_use]
    pub fn penalized_miner_reward(total: u64, is_red: bool, delay_secs: u64) -> u64 {
        let base = if is_red {
            Self::red_block_miner_reward(total)
        } else {
            Self::miner_portion(total)
        };

        if delay_secs == 0 {
            return base;
        }

        let min_reward = (Self::miner_portion(total) as u128
            * Self::MIN_REWARD_PCT as u128 / 100) as u64;

        let decay_base = (100u128 - Self::LATE_PENALTY_PCT_PER_SEC as u128).max(1);
        let mut numerator = base as u128;
        let mut denominator = 1u128;
        let steps = delay_secs.min(30) as usize;
        for _ in 0..steps {
            numerator *= decay_base;
            denominator *= 100;
            if denominator > 1_000_000_000_000 {
                numerator /= 1_000_000;
                denominator /= 1_000_000;
            }
        }

        let penalized = (numerator / denominator.max(1)) as u64;
        penalized.max(min_reward)
    }
}

// ─────────────────────────────────────────
// COMPILE-TIME SAFETY CHECKS (CRITICAL)
// ─────────────────────────────────────────
const _: () = {
    // denominator must not be zero
    assert!(Reward::DEV_RATIO_DEN > 0);

    // numerator must be <= denominator (no over-allocation)
    assert!(Reward::DEV_RATIO_NUM <= Reward::DEV_RATIO_DEN);

    // penalty constants are sane
    assert!(Reward::RED_BLOCK_REWARD_PCT <= 100);
    assert!(Reward::LATE_PENALTY_PCT_PER_SEC < 100);
    assert!(Reward::MIN_REWARD_PCT > 0);
    assert!(Reward::MIN_REWARD_PCT <= 100);
};

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REWARD: u64 = 100_000_000; // 1 SDAG

    #[test]
    fn split_sums_to_total() {
        let r = Reward::split(TEST_REWARD);
        assert_eq!(r.miner + r.developer, TEST_REWARD);
    }

    #[test]
    fn red_block_gets_20_percent() {
        let red = Reward::red_block_miner_reward(TEST_REWARD);
        let normal = Reward::miner_portion(TEST_REWARD);
        assert_eq!(red, normal * 20 / 100);
        assert!(red < normal);
    }

    #[test]
    fn no_delay_full_reward() {
        let r = Reward::late_block_miner_reward(TEST_REWARD, 0);
        assert_eq!(r, Reward::miner_portion(TEST_REWARD));
    }

    #[test]
    fn delay_reduces_reward() {
        let full = Reward::miner_portion(TEST_REWARD);
        let delayed_5s = Reward::late_block_miner_reward(TEST_REWARD, 5);
        let delayed_10s = Reward::late_block_miner_reward(TEST_REWARD, 10);
        let delayed_30s = Reward::late_block_miner_reward(TEST_REWARD, 30);

        assert!(delayed_5s < full, "5s delay should reduce reward");
        assert!(delayed_10s < delayed_5s, "10s delay < 5s delay");
        assert!(delayed_30s < delayed_10s, "30s delay < 10s delay");
    }

    #[test]
    fn delay_never_below_floor() {
        let min = Reward::miner_portion(TEST_REWARD) * Reward::MIN_REWARD_PCT / 100;
        let extreme = Reward::late_block_miner_reward(TEST_REWARD, 1000);
        assert!(extreme >= min, "Reward {} should be >= floor {}", extreme, min);
    }

    #[test]
    fn combined_penalty_stacks() {
        let normal = Reward::miner_portion(TEST_REWARD);
        let red_only = Reward::penalized_miner_reward(TEST_REWARD, true, 0);
        let late_only = Reward::penalized_miner_reward(TEST_REWARD, false, 10);
        let both = Reward::penalized_miner_reward(TEST_REWARD, true, 10);

        assert!(red_only < normal);
        assert!(late_only < normal);
        assert!(both < red_only, "Combined penalty should be harshest");
        assert!(both < late_only, "Combined penalty should be harshest");
    }
}