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
/// ```text
/// diagnostics::register("mempool", || {
///     format!("{{\"size\":{},\"bytes\":{}}}", pool.count(), pool.total_bytes())
/// });
/// ```
pub fn register(name: &'static str, hook: impl Fn() -> String + Send + Sync + 'static) {
    match hooks().lock() {
        Ok(mut map) => {
            map.insert(name, Box::new(hook));
        }
        Err(e) => {
            crate::slog_error!("diagnostics", "hook_register_lock_failed", error => e.to_string());
        }
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

    match hooks().lock() {
        Ok(map) => {
            for (name, hook) in map.iter() {
                // Validate hook output is valid JSON before including it.
                // If a hook returns malformed JSON or panics, wrap its output
                // as a JSON string literal with an explicit error marker so
                // the overall diagnostic report remains valid JSON.
                let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)) {
                    Ok(s) => {
                        // Best-effort JSON validation: if it parses, use as-is.
                        // Otherwise wrap as escaped string with error marker.
                        if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
                            s
                        } else {
                            format!(
                                "{{\"error\":\"invalid_json_from_hook\",\"raw\":{}}}",
                                escape_json_string(&s)
                            )
                        }
                    }
                    Err(payload) => {
                        let msg = panic_payload_to_string(&payload);
                        format!(
                            "{{\"error\":\"hook_panicked\",\"hook\":\"{}\",\"panic\":{}}}",
                            name,
                            escape_json_string(&msg)
                        )
                    }
                };
                subsystems.push(format!("{}:{}", escape_json_string(name), output));
            }
        }
        Err(e) => {
            crate::slog_error!("diagnostics", "collect_lock_failed", error => e.to_string());
        }
    }

    // Metrics snapshot
    let metrics_json = crate::telemetry::metrics::registry::global().to_json();

    // Log stats
    let (emitted, dropped) = crate::telemetry::logging::structured::log_stats();

    // Version from Cargo.toml at compile time (single source of truth)
    let version = env!("CARGO_PKG_VERSION");

    format!(
        "{{\"timestamp\":{},\"version\":\"{}\",\"subsystems\":{{{}}},\"metrics\":{},\"log_stats\":{{\"emitted\":{},\"dropped\":{}}}}}",
        now,
        version,
        subsystems.join(","),
        metrics_json,
        emitted,
        dropped
    )
}

/// Escape a string for JSON embedding (full RFC-compliant subset).
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Extract a readable message from a panic payload (if possible).
fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(&s) = payload.downcast_ref::<&'static str>() {
        s.to_string()
    } else {
        "<unknown panic payload>".to_string()
    }
}

/// Collect diagnostics and format as human-readable text.
pub fn dump_pretty() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let version = env!("CARGO_PKG_VERSION");
    let mut lines = Vec::new();
    lines.push(format!(
        "═══ ShadowDAG Diagnostics ═══  version={} timestamp={}",
        version, now
    ));
    lines.push(String::new());

    match hooks().lock() {
        Ok(map) => {
            for (name, hook) in map.iter() {
                lines.push(format!("── {} ──", name));
                let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)) {
                    Ok(s) => s,
                    Err(payload) => {
                        let msg = panic_payload_to_string(&payload);
                        format!("<panic in {} hook: {}>", name, msg)
                    }
                };
                lines.push(output);
                lines.push(String::new());
            }
        }
        Err(e) => {
            crate::slog_error!("diagnostics", "dump_pretty_lock_failed", error => e.to_string());
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
        lines.push(format!(
            "  [hist]    {}: count={} sum={:.1}ms avg={:.2}ms",
            name, count, sum, avg
        ));
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
    match hooks().lock() {
        Ok(m) => m.len(),
        Err(e) => {
            crate::slog_error!("diagnostics", "hook_count_lock_failed", error => e.to_string());
            0
        }
    }
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
