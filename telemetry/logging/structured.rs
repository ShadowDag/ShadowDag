// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Structured logging layer — replaces eprintln!/eprintln! with typed,
// JSON-serializable log events.
//
// Usage:
//   slog!(Level::Info, "dag", "block_accepted", { hash: hash, height: h });
//   slog_info!("p2p", "peer_connected", { addr: peer, version: v });
//   slog_warn!("mempool", "eviction_triggered", { count: n, reason: "full" });
//
// Output modes (controlled by SHADOWDAG_LOG_FORMAT env var):
//   - "json"   → one JSON object per line (for log aggregators)
//   - "pretty" → human-readable colored output (default for dev)
//   - "compact"→ single-line structured text (default for daemon)
// ═══════════════════════════════════════════════════════════════════════════

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Log levels ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4,
    Fatal = 5,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info  => "INFO",
            Level::Warn  => "WARN",
            Level::Error => "ERROR",
            Level::Fatal => "FATAL",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TRACE" => Level::Trace,
            "DEBUG" => Level::Debug,
            "INFO"  => Level::Info,
            "WARN"  => Level::Warn,
            "ERROR" => Level::Error,
            "FATAL" => Level::Fatal,
            _       => Level::Info,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Output format ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFormat {
    /// One JSON object per line: {"ts":..., "level":"INFO", "subsystem":"dag", ...}
    Json,
    /// Human-readable: [2026-04-05 12:34:56.789] INFO  [dag] block_accepted hash=abc height=100
    Pretty,
    /// Single-line compact: ts=1712345678 level=INFO sub=dag event=block_accepted hash=abc
    Compact,
}

impl LogFormat {
    pub fn from_env() -> Self {
        match std::env::var("SHADOWDAG_LOG_FORMAT").as_deref() {
            Ok("json")    => LogFormat::Json,
            Ok("pretty")  => LogFormat::Pretty,
            Ok("compact") => LogFormat::Compact,
            _             => LogFormat::Pretty,
        }
    }
}

// ── Log event ───────────────────────────────────────────────────────────

/// A structured log event with typed fields.
pub struct LogEvent {
    pub timestamp: u64,
    pub level:     Level,
    pub subsystem: &'static str,
    pub event:     &'static str,
    pub fields:    Vec<(&'static str, String)>,
}

impl LogEvent {
    pub fn new(level: Level, subsystem: &'static str, event: &'static str) -> Self {
        Self {
            timestamp: unix_now_ms(),
            level,
            subsystem,
            event,
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, key: &'static str, value: impl fmt::Display) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }

    /// Format as JSON line.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push_str("{\"ts\":");
        s.push_str(&self.timestamp.to_string());
        s.push_str(",\"level\":\"");
        s.push_str(self.level.as_str());
        s.push_str("\",\"sub\":\"");
        s.push_str(self.subsystem);
        s.push_str("\",\"event\":\"");
        s.push_str(self.event);
        s.push('"');
        for (k, v) in &self.fields {
            s.push_str(",\"");
            s.push_str(k);
            s.push_str("\":\"");
            // Escape quotes in value
            for c in v.chars() {
                if c == '"' { s.push('\\'); }
                s.push(c);
            }
            s.push('"');
        }
        s.push('}');
        s
    }

    /// Format as human-readable line.
    pub fn to_pretty(&self) -> String {
        let secs = self.timestamp / 1000;
        let ms   = self.timestamp % 1000;

        let mut s = String::with_capacity(256);
        s.push_str(&format!("[{}.{:03}] ", secs, ms));
        s.push_str(&format!("{:<5} ", self.level.as_str()));
        s.push_str(&format!("[{}] ", self.subsystem));
        s.push_str(self.event);

        for (k, v) in &self.fields {
            s.push(' ');
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        s
    }

    /// Format as compact key=value line.
    pub fn to_compact(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push_str("ts=");
        s.push_str(&(self.timestamp / 1000).to_string());
        s.push_str(" level=");
        s.push_str(self.level.as_str());
        s.push_str(" sub=");
        s.push_str(self.subsystem);
        s.push_str(" event=");
        s.push_str(self.event);
        for (k, v) in &self.fields {
            s.push(' ');
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        s
    }
}

// ── Global logger state ─────────────────────────────────────────────────

static LOG_FORMAT: OnceLock<LogFormat> = OnceLock::new();
static MIN_LEVEL:  OnceLock<Level>     = OnceLock::new();

/// Total log events emitted (for metrics).
static LOG_COUNT: AtomicU64 = AtomicU64::new(0);
/// Total log events dropped by level filter.
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Initialize the structured logger. Safe to call multiple times (first wins).
pub fn init() {
    let _ = LOG_FORMAT.set(LogFormat::from_env());
    let level_str = std::env::var("SHADOWDAG_LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
    let _ = MIN_LEVEL.set(Level::from_str(&level_str));
}

/// Get current format.
pub fn format() -> LogFormat {
    LOG_FORMAT.get().copied().unwrap_or(LogFormat::Pretty)
}

/// Get minimum log level.
pub fn min_level() -> Level {
    MIN_LEVEL.get().copied().unwrap_or(Level::Info)
}

/// Emit a log event. This is the core function called by all macros.
pub fn emit(event: LogEvent) {
    if event.level < min_level() {
        LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }

    LOG_COUNT.fetch_add(1, Ordering::Relaxed);

    let line = match format() {
        LogFormat::Json    => event.to_json(),
        LogFormat::Pretty  => event.to_pretty(),
        LogFormat::Compact => event.to_compact(),
    };

    // All log output goes to stderr (stdout reserved for structured data/RPC).
    eprintln!("{}", line);
}

/// Log event counters (for metrics/diagnostics).
pub fn log_stats() -> (u64, u64) {
    (
        LOG_COUNT.load(Ordering::Relaxed),
        LOG_DROPPED.load(Ordering::Relaxed),
    )
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Macros ──────────────────────────────────────────────────────────────

/// Core structured logging macro.
///
/// Usage:
///   slog!(Level::Info, "dag", "block_accepted", hash => &hash, height => h);
#[macro_export]
macro_rules! slog {
    ($level:expr, $sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {{
        let ev = $crate::telemetry::logging::structured::LogEvent::new($level, $sub, $event)
            $(.field(stringify!($key), &$val))*;
        $crate::telemetry::logging::structured::emit(ev);
    }};
}

/// Convenience macros for each level.
#[macro_export]
macro_rules! slog_trace {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Trace, $sub, $event $(, $key => $val)*)
    };
}

#[macro_export]
macro_rules! slog_debug {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Debug, $sub, $event $(, $key => $val)*)
    };
}

#[macro_export]
macro_rules! slog_info {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Info, $sub, $event $(, $key => $val)*)
    };
}

#[macro_export]
macro_rules! slog_warn {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Warn, $sub, $event $(, $key => $val)*)
    };
}

#[macro_export]
macro_rules! slog_error {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Error, $sub, $event $(, $key => $val)*)
    };
}

#[macro_export]
macro_rules! slog_fatal {
    ($sub:expr, $event:expr $(, $key:ident => $val:expr)* $(,)?) => {
        $crate::slog!($crate::telemetry::logging::structured::Level::Fatal, $sub, $event $(, $key => $val)*)
    };
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_format() {
        let ev = LogEvent::new(Level::Info, "dag", "block_accepted")
            .field("hash", "abc123")
            .field("height", 42);
        let json = ev.to_json();
        assert!(json.contains("\"sub\":\"dag\""));
        assert!(json.contains("\"event\":\"block_accepted\""));
        assert!(json.contains("\"hash\":\"abc123\""));
        assert!(json.contains("\"height\":\"42\""));
    }

    #[test]
    fn pretty_format() {
        let ev = LogEvent::new(Level::Warn, "p2p", "peer_banned")
            .field("addr", "1.2.3.4")
            .field("reason", "spam");
        let pretty = ev.to_pretty();
        assert!(pretty.contains("WARN"));
        assert!(pretty.contains("[p2p]"));
        assert!(pretty.contains("peer_banned"));
        assert!(pretty.contains("addr=1.2.3.4"));
    }

    #[test]
    fn compact_format() {
        let ev = LogEvent::new(Level::Debug, "mempool", "tx_added")
            .field("hash", "ff00");
        let compact = ev.to_compact();
        assert!(compact.contains("level=DEBUG"));
        assert!(compact.contains("sub=mempool"));
        assert!(compact.contains("hash=ff00"));
    }

    #[test]
    fn level_ordering() {
        assert!(Level::Trace < Level::Debug);
        assert!(Level::Debug < Level::Info);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
        assert!(Level::Error < Level::Fatal);
    }

    #[test]
    fn level_from_str() {
        assert_eq!(Level::from_str("trace"), Level::Trace);
        assert_eq!(Level::from_str("WARN"), Level::Warn);
        assert_eq!(Level::from_str("garbage"), Level::Info); // default
    }

    #[test]
    fn macro_works() {
        // Just verify the macro compiles and doesn't panic
        init();
        slog!(Level::Info, "test", "macro_test", key => "val", num => 42);
        slog_info!("test", "convenience_test", x => 1);
    }
}
