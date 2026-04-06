// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Debug Diagnostics — subsystem introspection for operators and developers.
//
// Provides a single entry point to dump the complete internal state of the
// node for troubleshooting. Used by:
//   - `getdiagnostics` RPC method
//   - `--dump-diagnostics` CLI flag
//   - Crash recovery logging
//
// Each subsystem registers a diagnostic hook. On demand, all hooks are
// called and their outputs are collected into a single JSON report.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Type alias for diagnostic hook functions.
/// Each hook returns a JSON-serializable string for its subsystem.
type DiagnosticHook = Box<dyn Fn() -> String + Send + Sync>;

static HOOKS: OnceLock<Mutex<BTreeMap<&'static str, DiagnosticHook>>> = OnceLock::new();

fn hooks() -> &'static Mutex<BTreeMap<&'static str, DiagnosticHook>> {
    HOOKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Register a diagnostic hook for a subsystem.
///
/// ```ignore
/// diagnostics::register("mempool", || {
///     format!("{{\"size\":{},\"bytes\":{}}}", pool.count(), pool.total_bytes())
/// });
/// ```
pub fn register(name: &'static str, hook: impl Fn() -> String + Send + Sync + 'static) {
    if let Ok(mut map) = hooks().lock() {
        map.insert(name, Box::new(hook));
    }
}

/// Collect diagnostics from all registered subsystems.
///
/// Returns a JSON object:
/// ```json
/// {
///   "timestamp": 1712345678,
///   "version": "1.0.0",
///   "subsystems": {
///     "dag": { ... },
///     "mempool": { ... },
///     "p2p": { ... },
///     ...
///   },
///   "metrics": { ... },
///   "log_stats": { "emitted": 1234, "dropped": 56 }
/// }
/// ```
pub fn collect() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut subsystems = Vec::new();

    if let Ok(map) = hooks().lock() {
        for (name, hook) in map.iter() {
            let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook()))
                .unwrap_or_else(|_| format!("\"<panic in {} diagnostic hook>\"", name));
            subsystems.push(format!("\"{}\":{}", name, output));
        }
    }

    // Metrics snapshot
    let metrics_json = crate::telemetry::metrics::registry::global().to_json();

    // Log stats
    let (emitted, dropped) = crate::telemetry::logging::structured::log_stats();

    format!(
        "{{\"timestamp\":{},\"version\":\"1.0.0\",\"subsystems\":{{{}}},\"metrics\":{},\"log_stats\":{{\"emitted\":{},\"dropped\":{}}}}}",
        now,
        subsystems.join(","),
        metrics_json,
        emitted,
        dropped
    )
}

/// Collect diagnostics and format as human-readable text.
pub fn dump_pretty() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut lines = Vec::new();
    lines.push(format!("═══ ShadowDAG Diagnostics ═══  timestamp={}", now));
    lines.push(String::new());

    if let Ok(map) = hooks().lock() {
        for (name, hook) in map.iter() {
            lines.push(format!("── {} ──", name));
            let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook()))
                .unwrap_or_else(|_| format!("<panic in {} hook>", name));
            lines.push(output);
            lines.push(String::new());
        }
    }

    // Metrics
    lines.push("── metrics ──".to_string());
    let snap = crate::telemetry::metrics::registry::global().snapshot();
    lines.push(format!("  uptime: {}s", snap.uptime_secs));
    for (name, val) in &snap.counters {
        lines.push(format!("  [counter] {}: {}", name, val));
    }
    for (name, val) in &snap.gauges {
        lines.push(format!("  [gauge]   {}: {}", name, val));
    }
    for (name, count, sum) in &snap.histograms {
        let avg = if *count > 0 { sum / *count as f64 } else { 0.0 };
        lines.push(format!("  [hist]    {}: count={} sum={:.1}ms avg={:.2}ms", name, count, sum, avg));
    }
    lines.push(String::new());

    // Log stats
    let (emitted, dropped) = crate::telemetry::logging::structured::log_stats();
    lines.push("── logging ──".to_string());
    lines.push(format!("  emitted: {}  dropped: {}", emitted, dropped));

    lines.join("\n")
}

/// Number of registered diagnostic hooks.
pub fn hook_count() -> usize {
    hooks().lock().map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_collect() {
        register("test_sub", || "{\"status\":\"ok\"}".to_string());
        let json = collect();
        assert!(json.contains("\"test_sub\":{\"status\":\"ok\"}"));
        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"log_stats\""));
    }

    #[test]
    fn panic_safe() {
        register("panicky", || panic!("boom"));
        let json = collect();
        // Should contain error message, not crash
        assert!(json.contains("panicky"));
    }

    #[test]
    fn pretty_dump() {
        register("test_pretty", || "count=42".to_string());
        let text = dump_pretty();
        assert!(text.contains("ShadowDAG Diagnostics"));
        assert!(text.contains("test_pretty"));
    }

    #[test]
    fn hook_count_tracks() {
        let before = hook_count();
        register("count_test", || "ok".to_string());
        assert!(hook_count() >= before);
    }
}
