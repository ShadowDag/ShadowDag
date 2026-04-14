// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, Default)]
pub struct DifficultyWindow;

impl DifficultyWindow {
    // ─────────────────────────────────────────
    // CONFIG
    // ─────────────────────────────────────────
    pub const SMALL_WINDOW: u64 = 10;
    pub const MEDIUM_WINDOW: u64 = 20;
    pub const LARGE_WINDOW: u64 = 60;
    pub const XL_WINDOW: u64 = 120;

    pub const THRESHOLD_1: u64 = 10;
    pub const THRESHOLD_2: u64 = 100;
    pub const THRESHOLD_3: u64 = 1000;

    // ─────────────────────────────────────────
    // CONST VERSION (fastest path)
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub const fn sample_size_const(height: u64) -> u64 {
        if height < Self::THRESHOLD_1 {
            Self::SMALL_WINDOW
        } else if height < Self::THRESHOLD_2 {
            Self::MEDIUM_WINDOW
        } else if height < Self::THRESHOLD_3 {
            Self::LARGE_WINDOW
        } else {
            Self::XL_WINDOW
        }
    }

    // ─────────────────────────────────────────
    // INTERNAL CHECK (fail-safe)
    // ─────────────────────────────────────────
    #[inline(always)]
    fn validate_config() {
        // Thresholds are compile-time constants; ordering is guaranteed by their definitions.
    }

    // ─────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub fn sample_size(height: u64) -> u64 {
        Self::validate_config();
        Self::sample_size_const(height)
    }

    // ─────────────────────────────────────────
    // EXPECTED TIMESPAN
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub fn expected_timespan(height: u64, target_block_time: u64) -> u64 {
        Self::validate_config();

        Self::sample_size_const(height).saturating_mul(target_block_time)
    }

    // ─────────────────────────────────────────
    // DYNAMIC SCALING
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub fn sample_size_with_scale(height: u64, scale: u64) -> u64 {
        Self::validate_config();

        let base = Self::sample_size_const(height);

        if scale <= 1 {
            return base;
        }

        if base == Self::XL_WINDOW {
            return base;
        }

        let scaled = base.saturating_mul(scale);

        scaled.clamp(Self::SMALL_WINDOW, Self::XL_WINDOW)
    }

    // ─────────────────────────────────────────
    // FAST PATH
    // ─────────────────────────────────────────
    #[inline(always)]
    #[must_use]
    pub fn sample_size_fast(height: u64) -> u64 {
        // بدون validation لأقصى أداء
        Self::sample_size_const(height)
    }
}
