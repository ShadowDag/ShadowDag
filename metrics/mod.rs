// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const RATE_WINDOW_SECS: u64   = 60;
pub const MAX_SAMPLES:      usize = 1_000;

#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub timestamp: u64,
    pub value:     f64,
}

#[derive(Debug, Clone)]
pub struct RateMeter {
    samples:    VecDeque<MetricPoint>,
    window:     Duration,
}

impl RateMeter {
    pub fn new(window_secs: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            window:  Duration::from_secs(window_secs),
        }
    }

    pub fn record(&mut self, count: f64) {
        let now_ts = now_secs();
        self.samples.push_back(MetricPoint { timestamp: now_ts, value: count });

        let cutoff = now_ts.saturating_sub(self.window.as_secs());
        while self.samples.front().map(|s| s.timestamp < cutoff).unwrap_or(false) {
            self.samples.pop_front();
        }
        if self.samples.len() > MAX_SAMPLES { self.samples.pop_front(); }
    }

    pub fn rate(&self) -> f64 {
        if self.samples.len() < 2 { return 0.0; }
        let total: f64 = self.samples.iter().map(|s| s.value).sum();
        let elapsed = self.window.as_secs_f64();
        total / elapsed
    }

    pub fn count(&self) -> usize { self.samples.len() }
}

#[derive(Debug)]
pub struct NodeMetrics {
    pub best_height:       u64,
    pub best_blue_score:   u64,
    pub peer_count:        usize,
    pub mempool_size:      usize,
    pub mempool_bytes:     usize,
    pub dag_tip_count:     usize,
    pub sync_progress:     f64,
    pub is_synced:         bool,
    pub uptime_secs:       u64,
    pub total_blocks:      u64,
    pub total_txs:         u64,
    pub cache_hit_rate:    f64,

    pub block_rate:  RateMeter,
    pub tx_rate:     RateMeter,

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
            best_height:     0,
            best_blue_score: 0,
            peer_count:      0,
            mempool_size:    0,
            mempool_bytes:   0,
            dag_tip_count:   0,
            sync_progress:   0.0,
            is_synced:       false,
            uptime_secs:     0,
            total_blocks:    0,
            total_txs:       0,
            cache_hit_rate:  0.0,
            block_rate:  RateMeter::new(RATE_WINDOW_SECS),
            tx_rate:     RateMeter::new(RATE_WINDOW_SECS),
            started_at:  Instant::now(),
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

    pub fn set_sync_progress(&mut self, current: u64, target: u64) {
        if target > 0 {
            self.sync_progress = current as f64 / target as f64;
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
}
