// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};

pub type Timestamp = u64;

/// Maximum allowed future drift for block timestamps (120 seconds in milliseconds).
/// Canonical value: 120s (see block_validator::MAX_FUTURE_SECS).
pub const MAX_FUTURE_DRIFT_MS: u64 = 120_000;

/// Maximum allowed past drift (2 hours in milliseconds)
pub const MAX_PAST_DRIFT_MS: u64 = 7_200_000;

/// Target block interval in milliseconds (1 second)
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 1_000;

pub struct TimestampHelper;

impl TimestampHelper {
    /// Returns current UNIX timestamp in milliseconds
    #[inline]
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Returns current UNIX timestamp in seconds
    #[inline]
    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Validates that a timestamp is not too far in the future
    pub fn is_valid(ts: u64, current: u64) -> bool {
        ts <= current.saturating_add(MAX_FUTURE_DRIFT_MS)
    }

    /// Validates within acceptable range (not too far in future or past)
    pub fn is_valid_range(ts: u64, current: u64) -> bool {
        let min = current.saturating_sub(MAX_PAST_DRIFT_MS);
        let max = current.saturating_add(MAX_FUTURE_DRIFT_MS);
        ts >= min && ts <= max
    }

    /// Returns the median timestamp from a list
    pub fn median(timestamps: &mut [u64]) -> u64 {
        if timestamps.is_empty() {
            return 0;
        }
        timestamps.sort_unstable();
        let mid = timestamps.len() / 2;
        if timestamps.len().is_multiple_of(2) {
            (timestamps[mid - 1] + timestamps[mid]) / 2
        } else {
            timestamps[mid]
        }
    }

    /// Calculate elapsed time between two timestamps
    #[inline]
    pub fn elapsed(start: u64, end: u64) -> u64 {
        end.saturating_sub(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_nonzero() {
        assert!(TimestampHelper::now() > 0);
    }

    #[test]
    fn now_secs_returns_reasonable_value() {
        let ts = TimestampHelper::now_secs();
        assert!(ts > 1_577_836_800);
    }

    #[test]
    fn is_valid_accepts_current() {
        let now = TimestampHelper::now();
        assert!(TimestampHelper::is_valid(now, now));
    }

    #[test]
    fn is_valid_rejects_far_future() {
        let now = TimestampHelper::now();
        assert!(!TimestampHelper::is_valid(
            now + MAX_FUTURE_DRIFT_MS + 1,
            now
        ));
    }

    #[test]
    fn median_works() {
        let mut ts = vec![5, 3, 1, 4, 2];
        assert_eq!(TimestampHelper::median(&mut ts), 3);
    }
}
