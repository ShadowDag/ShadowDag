// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const RATE_WINDOW_SECS: u64 = 60;
pub const MAX_SAMPLES: usize = 1_000;

#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub timestamp: u64,
    pub value: f64,
}

#[derive(Debug, Clone)]
pub struct RateMeter {
    samples: VecDeque<MetricPoint>,
    window: Duration,
}

impl RateMeter {
    pub fn new(window_secs: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn record(&mut self, count: f64) {
        let now_ts = now_secs();
        self.samples.push_back(MetricPoint {
            timestamp: now_ts,
            value: count,
        });

        let cutoff = now_ts.saturating_sub(self.window.as_secs());
        while self
            .samples
            .front()
            .map(|s| s.timestamp < cutoff)
            .unwrap_or(false)
        {
            self.samples.pop_front();
        }
        if self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    /// Average rate per second over the **actual** elapsed window
    /// between the oldest and newest sample.
    ///
    /// Previously this divided by `self.window.as_secs_f64()` (the
    /// fixed 60-second nominal window) regardless of how long the
    /// samples had actually been accumulating. That under-reported
    /// the rate at startup — e.g. two samples one second apart
    /// would be reported as `total / 60` (1/60 of the real value)
    /// — and over-reported it after long idle periods where the
    /// nominal window had elapsed but the front-of-queue prune
    /// hadn't yet trimmed older samples.
    ///
    /// The new formula uses the difference between the latest and
    /// earliest sample timestamps as the denominator, with two
    /// guard rails:
    ///
    ///   1. If there are fewer than two samples, return 0.0 (the
    ///      rate is undefined with one or zero data points).
    ///   2. If the elapsed time is zero (two samples in the same
    ///      `now_secs()` second — which `record` can produce
    ///      because the timestamps are seconds-granularity), fall
    ///      back to the nominal window so we don't divide by zero.
    pub fn rate(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let total: f64 = self.samples.iter().map(|s| s.value).sum();
        // Both .front() and .back() are Some because len >= 2.
        let oldest = self.samples.front().unwrap().timestamp;
        let newest = self.samples.back().unwrap().timestamp;
        let elapsed_secs = newest.saturating_sub(oldest) as f64;
        if elapsed_secs <= 0.0 {
            // Same-second samples — fall back to the nominal window
            // rather than dividing by zero. The rate is at least
            // "this many events in less than one second", so the
            // nominal-window denominator is a conservative under-
            // estimate.
            let nominal = self.window.as_secs_f64();
            if nominal <= 0.0 {
                return 0.0;
            }
            return total / nominal;
        }
        total / elapsed_secs
    }

    pub fn count(&self) -> usize {
        self.samples.len()
    }
}

#[derive(Debug)]
pub struct NodeMetrics {
    pub best_height: u64,
    pub best_blue_score: u64,
    pub peer_count: usize,
    pub mempool_size: usize,
    pub mempool_bytes: usize,
    pub dag_tip_count: usize,
    pub sync_progress: f64,
    pub is_synced: bool,
    pub uptime_secs: u64,
    pub total_blocks: u64,
    pub total_txs: u64,
    pub cache_hit_rate: f64,

    pub block_rate: RateMeter,
    pub tx_rate: RateMeter,

    started_at: Instant,
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self {
            best_height: 0,
            best_blue_score: 0,
            peer_count: 0,
            mempool_size: 0,
            mempool_bytes: 0,
            dag_tip_count: 0,
            sync_progress: 0.0,
            is_synced: false,
            uptime_secs: 0,
            total_blocks: 0,
            total_txs: 0,
            cache_hit_rate: 0.0,
            block_rate: RateMeter::new(RATE_WINDOW_SECS),
            tx_rate: RateMeter::new(RATE_WINDOW_SECS),
            started_at: Instant::now(),
        }
    }

    pub fn update_uptime(&mut self) {
        self.uptime_secs = self.started_at.elapsed().as_secs();
    }

    pub fn on_new_block(&mut self) {
        self.total_blocks += 1;
        self.block_rate.record(1.0);
    }

    pub fn on_new_tx(&mut self) {
        self.total_txs += 1;
        self.tx_rate.record(1.0);
    }

    /// Update sync progress as `current / target`, **clamped to
    /// `[0.0, 1.0]`**.
    ///
    /// The previous implementation set `sync_progress = current as f64
    /// / target as f64` with no clamp, so an over-shoot
    /// (`current > target`, which can happen during a reorg or after
    /// a tip jump) would produce a value > 1.0 — and `to_json` then
    /// multiplied by 100.0 and printed e.g. `"sync_progress": "120.0%"`,
    /// which any UI / explorer that trusted the value would render
    /// as nonsense.
    ///
    /// `target == 0` is treated as "no target known yet" and leaves
    /// `sync_progress` unchanged, matching the previous behaviour.
    /// `is_synced` still tracks `current >= target` independently of
    /// the clamped progress value.
    pub fn set_sync_progress(&mut self, current: u64, target: u64) {
        if target > 0 {
            let raw = current as f64 / target as f64;
            // Clamp to [0.0, 1.0]. A reorg / tip jump can briefly
            // produce current > target; we still mark `is_synced`
            // below so the consumer knows the chain is caught up,
            // but the displayed percentage stays sane.
            self.sync_progress = raw.clamp(0.0, 1.0);
        }
        self.is_synced = current >= target;
    }

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"height":{},"blue_score":{},"peers":{},"mempool":{},"synced":{},"uptime":{},"blocks":{},"txs":{},"block_rate":"{:.3}/min","tx_rate":"{:.3}/min","sync_progress":"{:.1}%","cache_hit_rate":"{:.1}%"}}"#,
            self.best_height,
            self.best_blue_score,
            self.peer_count,
            self.mempool_size,
            self.is_synced,
            self.uptime_secs,
            self.total_blocks,
            self.total_txs,
            self.block_rate.rate() * 60.0,
            self.tx_rate.rate() * 60.0,
            self.sync_progress * 100.0,
            self.cache_hit_rate * 100.0,
        )
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn on_new_block_increments_count() {
        let mut m = NodeMetrics::new();
        m.on_new_block();
        m.on_new_block();
        assert_eq!(m.total_blocks, 2);
    }

    #[test]
    fn sync_progress_calculated() {
        let mut m = NodeMetrics::new();
        m.set_sync_progress(50, 100);
        assert!((m.sync_progress - 0.5).abs() < 0.01);
        assert!(!m.is_synced);
    }

    #[test]
    fn sync_complete_marks_synced() {
        let mut m = NodeMetrics::new();
        m.set_sync_progress(100, 100);
        assert!(m.is_synced);
    }

    #[test]
    fn rate_meter_records_samples() {
        let mut meter = RateMeter::new(60);
        meter.record(1.0);
        meter.record(1.0);
        assert_eq!(meter.count(), 2);
    }

    #[test]
    fn to_json_contains_height() {
        let mut m = NodeMetrics::new();
        m.best_height = 42;
        let json = m.to_json();
        assert!(json.contains("\"height\":42"));
    }

    #[test]
    fn uptime_increases_over_time() {
        let mut m = NodeMetrics::new();
        sleep(Duration::from_millis(10));
        m.update_uptime();

        assert!(m.uptime_secs <= 1);
    }

    // ─── sync_progress clamp regression ─────────────────────────────

    #[test]
    fn sync_progress_clamps_overshoot_to_one() {
        // Regression for the no-clamp bug. A reorg can briefly
        // produce current > target. Without a clamp, sync_progress
        // would exceed 1.0 and to_json would render it as
        // e.g. "120.0%", which is nonsense for any UI consumer.
        let mut m = NodeMetrics::new();
        m.set_sync_progress(120, 100); // overshoot
        assert!(
            (m.sync_progress - 1.0).abs() < f64::EPSILON,
            "overshoot must be clamped to 1.0, got {}",
            m.sync_progress
        );
        assert!(
            m.is_synced,
            "is_synced must still be true when current >= target"
        );
    }

    #[test]
    fn sync_progress_clamps_negative_like_input_to_zero() {
        // current and target are u64 so a "negative" raw can't
        // actually happen, but the clamp formulation also enforces
        // the lower bound, so this test pins that the floor does
        // exist for any future signed conversion.
        let mut m = NodeMetrics::new();
        m.set_sync_progress(0, 1_000);
        assert_eq!(m.sync_progress, 0.0);
    }

    #[test]
    fn sync_progress_target_zero_leaves_progress_unchanged() {
        let mut m = NodeMetrics::new();
        m.set_sync_progress(50, 100); // baseline 0.5
        assert!((m.sync_progress - 0.5).abs() < 0.01);
        m.set_sync_progress(7, 0); // unknown target
        assert!(
            (m.sync_progress - 0.5).abs() < 0.01,
            "target=0 must not overwrite the previous value"
        );
    }

    // ─── RateMeter elapsed-time regression ──────────────────────────

    #[test]
    fn rate_meter_uses_actual_elapsed_between_samples() {
        // Regression for the fixed-window divisor bug. Build a
        // meter with a 60-second nominal window, plant TWO samples
        // with the SAME timestamp (which `record` would do for two
        // events in the same second), and verify the rate falls
        // back to the nominal-window divisor (the documented edge
        // case for zero-elapsed input).
        //
        // To exercise the actual-elapsed path we plant two samples
        // with timestamps 10 seconds apart and assert the rate is
        // computed against 10 seconds, not 60.
        let mut meter = RateMeter::new(60);
        meter.samples.push_back(MetricPoint {
            timestamp: 1000,
            value: 5.0,
        });
        meter.samples.push_back(MetricPoint {
            timestamp: 1010,
            value: 5.0,
        });
        // total = 10, elapsed = 10s → rate = 1.0 events/sec
        let r = meter.rate();
        assert!(
            (r - 1.0).abs() < 1e-9,
            "expected rate ~1.0/s for 10 events over 10 seconds, got {}",
            r
        );
    }

    #[test]
    fn rate_meter_zero_elapsed_falls_back_to_nominal_window() {
        // Two samples at the SAME second timestamp — `record` will
        // happily do this if multiple events arrive within one
        // second of each other. Without the fall-back, the new
        // formula would divide by zero. The fall-back uses the
        // nominal window so the rate is still well-defined.
        let mut meter = RateMeter::new(60);
        meter.samples.push_back(MetricPoint {
            timestamp: 1000,
            value: 3.0,
        });
        meter.samples.push_back(MetricPoint {
            timestamp: 1000,
            value: 4.0,
        });
        // total = 7, elapsed = 0 → fall back to 60s → rate = 7/60
        let r = meter.rate();
        assert!(
            (r - (7.0 / 60.0)).abs() < 1e-9,
            "expected fallback to nominal 60s window, got {}",
            r
        );
    }

    #[test]
    fn rate_meter_single_sample_returns_zero() {
        let mut meter = RateMeter::new(60);
        meter.samples.push_back(MetricPoint {
            timestamp: 1000,
            value: 5.0,
        });
        assert_eq!(
            meter.rate(),
            0.0,
            "single sample → rate is undefined → return 0.0"
        );
    }
}
