// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Unified Metrics Registry — single source of truth for all node metrics.
//
// Replaces the 9 fragmented stats structs with one global registry that:
//   1. All subsystems report to (dag, mempool, p2p, mining, etc.)
//   2. Exports to Prometheus text format (pull-based scraping)
//   3. Exports to JSON (for RPC and health endpoints)
//   4. Tracks histograms for latency measurements
//
// Thread-safe: all operations use atomics or interior mutability.
// Zero-allocation hot path: counter increments are AtomicU64::fetch_add.
//
// Usage:
//   METRICS.counter("dag.blocks_accepted").inc();
//   METRICS.counter("mempool.txs_added").inc_by(5);
//   METRICS.gauge("mempool.size").set(42);
//   METRICS.gauge("p2p.peers").inc();
//   METRICS.histogram("dag.block_validation_ms").observe(12.5);
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Instant;

// ── Global singleton ────────────────────────────────────────────────────

static METRICS: OnceLock<MetricsRegistry> = OnceLock::new();

/// Access the global metrics registry.
pub fn global() -> &'static MetricsRegistry {
    METRICS.get_or_init(MetricsRegistry::new)
}

// ── Counter (monotonically increasing) ──────────────────────────────────

pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

// ── Gauge (arbitrary value, can go up and down) ─────────────────────────

pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    fn new() -> Self {
        Self {
            value: AtomicI64::new(0),
        }
    }

    #[inline]
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

// ── Histogram (latency / distribution tracking) ─────────────────────────

/// A simple histogram with fixed buckets for latency tracking.
/// Buckets: 0.1ms, 0.5ms, 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s, +Inf
pub struct Histogram {
    buckets: [AtomicU64; 12],
    sum: AtomicU64, // sum of observations × 1000 (microseconds)
    count: AtomicU64,
}

const BUCKET_BOUNDS: [f64; 11] = [
    0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0,
];

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation in milliseconds.
    #[inline]
    pub fn observe(&self, value_ms: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum
            .fetch_add((value_ms * 1000.0) as u64, Ordering::Relaxed);

        for (i, &bound) in BUCKET_BOUNDS.iter().enumerate() {
            if value_ms <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // +Inf bucket (last)
        self.buckets[11].fetch_add(1, Ordering::Relaxed);
    }

    /// Start a timer that auto-records when dropped.
    pub fn start_timer(&self) -> HistogramTimer<'_> {
        HistogramTimer {
            histogram: self,
            start: Instant::now(),
        }
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    pub fn get_sum_ms(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1000.0
    }
}

/// RAII timer — records elapsed time on drop.
pub struct HistogramTimer<'a> {
    histogram: &'a Histogram,
    start: Instant,
}

impl<'a> Drop for HistogramTimer<'a> {
    fn drop(&mut self) {
        let elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        self.histogram.observe(elapsed_ms);
    }
}

// ── Registry ────────────────────────────────────────────────────────────

pub struct MetricsRegistry {
    // Metrics are boxed to ensure stable heap addresses even when the
    // HashMap rehashes. The HashMap moves its entries; Box<T> does not.
    // We leak the &'static reference via Box::leak, which is safe because
    // the registry is a OnceLock global with 'static lifetime.
    counters: RwLock<HashMap<&'static str, &'static Counter>>,
    gauges: RwLock<HashMap<&'static str, &'static Gauge>>,
    histograms: RwLock<HashMap<&'static str, &'static Histogram>>,
    start_time: Instant,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    // ── Counter access ──────────────────────────────────────────────────

    /// Get or create a counter. The first call allocates a boxed Counter
    /// (leaked to 'static) and subsequent calls return the same reference.
    /// The 'static reference is safe because the MetricsRegistry is a
    /// OnceLock global with 'static lifetime.
    pub fn counter(&self, name: &'static str) -> &'static Counter {
        // Fast path: read lock
        {
            let map = self.counters.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&c) = map.get(name) {
                return c;
            }
        }
        // Slow path: write lock + insert
        let mut map = self.counters.write().unwrap_or_else(|e| e.into_inner());
        // Double-check after acquiring write lock (another thread may have inserted)
        if let Some(&c) = map.get(name) {
            return c;
        }
        let boxed: &'static Counter = Box::leak(Box::new(Counter::new()));
        map.insert(name, boxed);
        boxed
    }

    // ── Gauge access ────────────────────────────────────────────────────

    pub fn gauge(&self, name: &'static str) -> &'static Gauge {
        {
            let map = self.gauges.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&g) = map.get(name) {
                return g;
            }
        }
        let mut map = self.gauges.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&g) = map.get(name) {
            return g;
        }
        let boxed: &'static Gauge = Box::leak(Box::new(Gauge::new()));
        map.insert(name, boxed);
        boxed
    }

    // ── Histogram access ────────────────────────────────────────────────

    pub fn histogram(&self, name: &'static str) -> &'static Histogram {
        {
            let map = self.histograms.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&h) = map.get(name) {
                return h;
            }
        }
        let mut map = self.histograms.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&h) = map.get(name) {
            return h;
        }
        let boxed: &'static Histogram = Box::leak(Box::new(Histogram::new()));
        map.insert(name, boxed);
        boxed
    }

    // ── Uptime ──────────────────────────────────────────────────────────

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    // ── Export: Prometheus text format ───────────────────────────────────

    /// Export all metrics in Prometheus exposition format.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Uptime
        out.push_str("# HELP shadowdag_uptime_seconds Node uptime\n");
        out.push_str("# TYPE shadowdag_uptime_seconds gauge\n");
        out.push_str(&format!(
            "shadowdag_uptime_seconds {}\n\n",
            self.uptime_secs()
        ));

        // Counters
        if let Ok(map) = self.counters.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                let prom_name = prom_name(name);
                let val = map[*name].get();
                out.push_str(&format!(
                    "# HELP shadowdag_{} ShadowDAG counter\n",
                    prom_name
                ));
                out.push_str(&format!("# TYPE shadowdag_{} counter\n", prom_name));
                out.push_str(&format!("shadowdag_{} {}\n\n", prom_name, val));
            }
        }

        // Gauges
        if let Ok(map) = self.gauges.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                let prom_name = prom_name(name);
                let val = map[*name].get();
                out.push_str(&format!("# HELP shadowdag_{} ShadowDAG gauge\n", prom_name));
                out.push_str(&format!("# TYPE shadowdag_{} gauge\n", prom_name));
                out.push_str(&format!("shadowdag_{} {}\n\n", prom_name, val));
            }
        }

        // Histograms
        if let Ok(map) = self.histograms.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                let prom_name = prom_name(name);
                let h = &map[*name];
                out.push_str(&format!(
                    "# HELP shadowdag_{} ShadowDAG histogram (ms)\n",
                    prom_name
                ));
                out.push_str(&format!("# TYPE shadowdag_{} histogram\n", prom_name));

                let mut cumulative = 0u64;
                for (i, &bound) in BUCKET_BOUNDS.iter().enumerate() {
                    cumulative += h.buckets[i].load(Ordering::Relaxed);
                    out.push_str(&format!(
                        "shadowdag_{}_bucket{{le=\"{}\"}} {}\n",
                        prom_name, bound, cumulative
                    ));
                }
                cumulative += h.buckets[11].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "shadowdag_{}_bucket{{le=\"+Inf\"}} {}\n",
                    prom_name, cumulative
                ));
                out.push_str(&format!(
                    "shadowdag_{}_sum {:.3}\n",
                    prom_name,
                    h.get_sum_ms()
                ));
                out.push_str(&format!(
                    "shadowdag_{}_count {}\n\n",
                    prom_name,
                    h.get_count()
                ));
            }
        }

        out
    }

    // ── Export: JSON ────────────────────────────────────────────────────

    /// Export all metrics as a JSON object.
    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("\"uptime_secs\":{}", self.uptime_secs()));

        if let Ok(map) = self.counters.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                parts.push(format!("\"{}\":{}", name, map[*name].get()));
            }
        }

        if let Ok(map) = self.gauges.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                parts.push(format!("\"{}\":{}", name, map[*name].get()));
            }
        }

        if let Ok(map) = self.histograms.read() {
            let mut names: Vec<&&str> = map.keys().collect();
            names.sort();
            for name in names {
                let h = &map[*name];
                parts.push(format!(
                    "\"{}_count\":{},\"{}_sum_ms\":{:.3}",
                    name,
                    h.get_count(),
                    name,
                    h.get_sum_ms()
                ));
            }
        }

        format!("{{{}}}", parts.join(","))
    }

    // ── Snapshot ────────────────────────────────────────────────────────

    /// Get a point-in-time snapshot of all metrics (for diagnostics).
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut counters = Vec::new();
        let mut gauges = Vec::new();
        let mut histograms = Vec::new();

        if let Ok(map) = self.counters.read() {
            for (name, c) in map.iter() {
                counters.push((*name, c.get()));
            }
        }
        if let Ok(map) = self.gauges.read() {
            for (name, g) in map.iter() {
                gauges.push((*name, g.get()));
            }
        }
        if let Ok(map) = self.histograms.read() {
            for (name, h) in map.iter() {
                histograms.push((*name, h.get_count(), h.get_sum_ms()));
            }
        }

        counters.sort_by_key(|(n, _)| *n);
        gauges.sort_by_key(|(n, _)| *n);
        histograms.sort_by_key(|(n, _, _)| *n);

        MetricsSnapshot {
            uptime_secs: self.uptime_secs(),
            counters,
            gauges,
            histograms,
        }
    }
}

/// Point-in-time snapshot of all metrics.
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub counters: Vec<(&'static str, u64)>,
    pub gauges: Vec<(&'static str, i64)>,
    pub histograms: Vec<(&'static str, u64, f64)>, // (name, count, sum_ms)
}

/// Convert dotted metric name to Prometheus-compatible underscore format.
fn prom_name(name: &str) -> String {
    name.replace('.', "_")
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> MetricsRegistry {
        MetricsRegistry::new()
    }

    #[test]
    fn counter_basic() {
        let r = test_registry();
        r.counter("test.blocks").inc();
        r.counter("test.blocks").inc();
        r.counter("test.blocks").inc_by(3);
        assert_eq!(r.counter("test.blocks").get(), 5);
    }

    #[test]
    fn gauge_basic() {
        let r = test_registry();
        r.gauge("test.peers").set(10);
        assert_eq!(r.gauge("test.peers").get(), 10);
        r.gauge("test.peers").dec();
        assert_eq!(r.gauge("test.peers").get(), 9);
    }

    #[test]
    fn histogram_basic() {
        let r = test_registry();
        r.histogram("test.latency").observe(5.0);
        r.histogram("test.latency").observe(50.0);
        r.histogram("test.latency").observe(500.0);
        assert_eq!(r.histogram("test.latency").get_count(), 3);
        assert!((r.histogram("test.latency").get_sum_ms() - 555.0).abs() < 1.0);
    }

    #[test]
    fn histogram_timer() {
        let r = test_registry();
        {
            let _timer = r.histogram("test.timer").start_timer();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(r.histogram("test.timer").get_count() >= 1);
    }

    #[test]
    fn prometheus_export() {
        let r = test_registry();
        r.counter("dag.blocks").inc_by(100);
        r.gauge("mempool.size").set(42);
        let prom = r.to_prometheus();
        assert!(prom.contains("shadowdag_dag_blocks 100"));
        assert!(prom.contains("shadowdag_mempool_size 42"));
        assert!(prom.contains("shadowdag_uptime_seconds"));
    }

    #[test]
    fn json_export() {
        let r = test_registry();
        r.counter("dag.blocks").inc_by(10);
        r.gauge("p2p.peers").set(5);
        let json = r.to_json();
        assert!(json.contains("\"dag.blocks\":10"));
        assert!(json.contains("\"p2p.peers\":5"));
    }

    #[test]
    fn snapshot_captures_all() {
        let r = test_registry();
        r.counter("a.b").inc();
        r.gauge("c.d").set(7);
        r.histogram("e.f").observe(1.0);
        let snap = r.snapshot();
        assert_eq!(snap.counters.len(), 1);
        assert_eq!(snap.gauges.len(), 1);
        assert_eq!(snap.histograms.len(), 1);
    }

    #[test]
    fn global_registry_accessible() {
        global().counter("test.global").inc();
        assert!(global().counter("test.global").get() >= 1);
    }
}
