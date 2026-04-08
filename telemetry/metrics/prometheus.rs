// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::{Arc, Mutex};
use std::io::Write;
use crate::{slog_info, slog_error};

pub struct PrometheusExporter {
    metrics: Arc<Mutex<Vec<(String, u64)>>>,
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusExporter {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Export metrics in Prometheus text format
    pub fn export(metrics: &[(&str, u64)]) -> String {
        let mut output = String::with_capacity(metrics.len() * 80);
        for (name, value) in metrics {
            output.push_str(&format!("# HELP shadowdag_{} ShadowDAG metric\n", name));
            output.push_str(&format!("# TYPE shadowdag_{} gauge\n", name));
            output.push_str(&format!("shadowdag_{} {}\n", name, value));
        }
        output
    }

    /// Record a metric value
    pub fn record(&self, name: &str, value: u64) {
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
