// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::{Arc, Mutex};
use std::io::Write;
use crate::{slog_info, slog_error, slog_warn};

pub struct PrometheusExporter {
    metrics: Arc<Mutex<Vec<(String, u64)>>>,
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Prometheus metric name validation ──────────────────────────────────
//
// The Prometheus exposition format requires metric names to match the
// regex `[a-zA-Z_:][a-zA-Z0-9_:]*`. Anything outside that alphabet — and
// in particular ASCII control characters, newlines, spaces, `#`, `{`,
// or `}` — can produce invalid exposition output OR allow an attacker
// who controls a metric name to inject arbitrary `# HELP` / `# TYPE`
// lines and forge metrics. We sanitize aggressively at the boundary.

/// True if `name` is already a valid Prometheus metric name.
pub(crate) fn is_valid_metric_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_' || first == ':') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// Return a Prometheus-safe version of `name`.
///
/// - Any character outside `[a-zA-Z0-9_:]` is replaced with `_`.
/// - If the first character would be a digit, a leading `_` is prepended.
/// - An empty input becomes `_invalid`.
///
/// The result is always a legal Prometheus metric name, which means
/// downstream exposition text cannot be broken or spoofed by the input.
pub(crate) fn sanitize_metric_name(name: &str) -> String {
    if name.is_empty() {
        return "_invalid".to_string();
    }
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_' || c == ':'
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == ':'
        };
        if ok {
            out.push(c);
        } else if i == 0 && c.is_ascii_digit() {
            // Digit first: keep it but prepend an underscore.
            out.push('_');
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

impl PrometheusExporter {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Export metrics in Prometheus text format.
    ///
    /// Metric names are sanitized via [`sanitize_metric_name`] before being
    /// interpolated into `# HELP`, `# TYPE`, and the sample line. Any
    /// non-conforming character (including newline, `#`, `{`, space,
    /// control chars) is replaced with `_`, so untrusted input cannot
    /// forge exposition output or inject fake metric lines.
    pub fn export(metrics: &[(&str, u64)]) -> String {
        let mut output = String::with_capacity(metrics.len() * 80);
        for (name, value) in metrics {
            let safe = sanitize_metric_name(name);
            output.push_str(&format!("# HELP shadowdag_{} ShadowDAG metric\n", safe));
            output.push_str(&format!("# TYPE shadowdag_{} gauge\n", safe));
            output.push_str(&format!("shadowdag_{} {}\n", safe, value));
        }
        output
    }

    /// Record a metric value.
    ///
    /// If `name` is not a valid Prometheus metric name (control chars,
    /// spaces, `#`, newlines, etc.), the call is rejected and a warning
    /// is logged. This prevents garbage — and, in particular, anything
    /// that looks like an exposition-format control line — from being
    /// retained in the in-memory store where `export()` will later
    /// serialize it. `export()` also sanitizes as defense-in-depth, so
    /// even if the store is populated by another code path, the final
    /// exposition output stays well-formed.
    pub fn record(&self, name: &str, value: u64) {
        if !is_valid_metric_name(name) {
            slog_warn!("metrics", "prometheus_record_invalid_name_rejected",
                name => name,
                note => "metric name must match [a-zA-Z_:][a-zA-Z0-9_:]*");
            return;
        }
        if let Ok(mut m) = self.metrics.lock() {
            if let Some(entry) = m.iter_mut().find(|(n, _)| n == name) {
                entry.1 = value;
            } else {
                m.push((name.to_string(), value));
            }
        }
    }

    /// Get all recorded metrics as Prometheus text
    pub fn scrape(&self) -> String {
        let m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        let refs: Vec<(&str, u64)> = m.iter().map(|(n, v)| (n.as_str(), *v)).collect();
        Self::export(&refs)
    }

    /// Start a simple HTTP metrics server on the given port.
    ///
    /// Serves two endpoints:
    ///   GET /metrics   → Prometheus text format (all counters, gauges, histograms)
    ///   GET /health    → JSON health status
    ///   GET /debug     → Full diagnostic dump (JSON)
    ///
    /// Pulls live metrics from the global MetricsRegistry on every scrape.
    pub fn start_server(port: u16) {
        let addr = format!("0.0.0.0:{}", port);

        std::thread::spawn(move || {
            let listener = match std::net::TcpListener::bind(&addr) {
                Ok(l) => l,
                Err(e) => {
                    slog_error!("metrics", "prometheus_bind_failed", addr => &addr, error => &e.to_string());
                    return;
                }
            };

            slog_info!("metrics", "prometheus_server_started", addr => &addr);
            slog_info!("metrics", "prometheus_endpoints", routes => "/metrics, /health, /debug");

            for stream_result in listener.incoming() {
                let stream = match stream_result {
                    Ok(s) => s,
                    Err(e) => {
                        slog_error!("metrics", "prometheus_accept_failed", error => e.to_string());
                        continue;
                    }
                };

                let mut buf = [0u8; 2048];
                let n = match std::io::Read::read(&mut &stream, &mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        slog_error!("metrics", "prometheus_read_failed", error => e.to_string());
                        continue;
                    }
                };
                let request = String::from_utf8_lossy(&buf[..n]);

                let (content_type, body) = if request.contains("GET /debug") {
                    ("application/json", crate::telemetry::diagnostics::collect())
                } else if request.contains("GET /health") {
                    ("application/json", format!(
                        "{{\"status\":\"up\",\"uptime_secs\":{}}}",
                        crate::telemetry::metrics::registry::global().uptime_secs()
                    ))
                } else {
                    // Default: /metrics → Prometheus text
                    let registry = crate::telemetry::metrics::registry::global();
                    let mut body = registry.to_prometheus();

                    // Also include any manually-recorded metrics from this exporter
                    if let Ok(m) = self_metrics_guard() {
                        let refs: Vec<(&str, u64)> = m.iter().map(|(n, v)| (n.as_str(), *v)).collect();
                        body.push_str(&Self::export(&refs));
                    }

                    ("text/plain; charset=utf-8", body)
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: {}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    content_type, body.len(), body
                );

                let mut writer = std::io::BufWriter::new(&stream);
                if let Err(e) = writer.write_all(response.as_bytes()) {
                    slog_error!("metrics", "prometheus_write_failed", error => e.to_string());
                    continue;
                }
                if let Err(e) = writer.flush() {
                    slog_error!("metrics", "prometheus_flush_failed", error => e.to_string());
                }
            }
        });
    }
}

/// Helper to access the self-recorded metrics (for backward compatibility).
fn self_metrics_guard() -> Result<std::sync::MutexGuard<'static, Vec<(String, u64)>>, ()> {
    // This is a convenience for metrics recorded via PrometheusExporter::record()
    // rather than the global registry. New code should use the registry directly.
    static SELF_METRICS: std::sync::OnceLock<std::sync::Mutex<Vec<(String, u64)>>> = std::sync::OnceLock::new();
    SELF_METRICS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_are_accepted() {
        assert!(is_valid_metric_name("blocks_total"));
        assert!(is_valid_metric_name("_underscore_first"));
        assert!(is_valid_metric_name(":colon_first"));
        assert!(is_valid_metric_name("mixed:name_42"));
        assert!(is_valid_metric_name("a"));
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert!(!is_valid_metric_name(""));
        assert!(!is_valid_metric_name("1starts_with_digit"));
        assert!(!is_valid_metric_name("has space"));
        assert!(!is_valid_metric_name("has\nnewline"));
        assert!(!is_valid_metric_name("has#hash"));
        assert!(!is_valid_metric_name("has{brace"));
        assert!(!is_valid_metric_name("has-dash"));
        assert!(!is_valid_metric_name("has.dot"));
        // Control characters and non-ASCII
        assert!(!is_valid_metric_name("tab\there"));
        assert!(!is_valid_metric_name("ctrl\x01here"));
    }

    #[test]
    fn sanitize_replaces_forbidden_chars() {
        assert_eq!(sanitize_metric_name("blocks total"), "blocks_total");
        assert_eq!(sanitize_metric_name("has-dash"),      "has_dash");
        assert_eq!(sanitize_metric_name("has.dot"),       "has_dot");
        assert_eq!(sanitize_metric_name("has#hash"),      "has_hash");
        assert_eq!(sanitize_metric_name("has\nnewline"),  "has_newline");
        assert_eq!(sanitize_metric_name(""),              "_invalid");
        // Digit first → prepend underscore
        assert_eq!(sanitize_metric_name("1start"),        "_1start");
        // Multiple bad chars in a row
        assert_eq!(sanitize_metric_name("a b-c.d"),       "a_b_c_d");
    }

    #[test]
    fn export_sanitizes_malicious_names() {
        // An attacker-controlled name with a newline + fake exposition
        // lines must NOT produce multi-line output that includes a
        // forged `# HELP` / `# TYPE` block.
        let evil = "legit\n# HELP shadowdag_fake_metric injected\n# TYPE shadowdag_fake_metric gauge\nshadowdag_fake_metric 1337";
        let out = PrometheusExporter::export(&[(evil, 0)]);

        // The sanitized name should have underscores where the newlines
        // and spaces were, so there is exactly ONE HELP + ONE TYPE + ONE
        // sample line (three '\n' characters) in the output.
        assert_eq!(out.matches('\n').count(), 3, "sanitized export must be 3 lines, got:\n{}", out);
        assert!(!out.contains("fake_metric 1337"));
        assert!(!out.contains("# HELP shadowdag_fake_metric injected"));
    }

    #[test]
    fn record_rejects_invalid_names() {
        let exporter = PrometheusExporter::new();
        exporter.record("good_name", 42);
        exporter.record("bad name with space", 99);     // rejected
        exporter.record("forge\n# TYPE foo gauge", 100); // rejected
        exporter.record("another_good", 7);

        let text = exporter.scrape();
        assert!(text.contains("shadowdag_good_name 42"));
        assert!(text.contains("shadowdag_another_good 7"));
        // The rejected names must not appear at all, sanitized or otherwise,
        // because record() filtered them out before storing.
        assert!(!text.contains("99"));
        assert!(!text.contains("100"));
        assert!(!text.contains("bad"));
        assert!(!text.contains("forge"));
    }

    #[test]
    fn export_output_is_always_valid_prometheus_format() {
        // Feed a mix of legal and illegal names into the static export API
        // (the record() path rejects, but export() sanitizes as
        // defense-in-depth). Every line must match the Prometheus grammar
        // after the `shadowdag_` prefix.
        let names = [
            "normal",
            "name with space",
            "with\ttab",
            "with\nnewline",
            "with#hash",
            "",
            "123digit",
        ];
        let samples: Vec<(&str, u64)> = names.iter().map(|n| (*n, 1)).collect();
        let out = PrometheusExporter::export(&samples);

        // Every sample line (not starting with '#') must match
        // `shadowdag_[A-Za-z_:][A-Za-z0-9_:]* <value>`.
        for line in out.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Split the value off
            let name_part = line.split_whitespace().next().expect("non-empty line");
            let stripped = name_part.strip_prefix("shadowdag_").expect("prefix present");
            assert!(
                is_valid_metric_name(stripped),
                "exported sample line has illegal metric name '{}': {}",
                stripped, line
            );
        }
    }
}
