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
}

// ─────────────────────────────────────────
// COMPILE-TIME SAFETY CHECKS (CRITICAL)
// ─────────────────────────────────────────
const _: () = {
    // denominator must not be zero
    assert!(Reward::DEV_RATIO_DEN > 0);

    // numerator must be <= denominator (no over-allocation)
    assert!(Reward::DEV_RATIO_NUM <= Reward::DEV_RATIO_DEN);
};