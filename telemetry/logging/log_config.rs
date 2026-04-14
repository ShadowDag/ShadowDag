// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::Once;

static INIT: Once = Once::new();

pub struct LogConfig;

impl LogConfig {
    pub const LOG_LEVEL: &'static str = "INFO";
    /// Log path — resolved at runtime via base_data_dir().
    /// This constant is a fallback only; use log_dir() for the actual path.
    pub const LOG_PATH: &'static str = "logs";

    pub fn log_dir() -> std::path::PathBuf {
        crate::config::node::node_config::NetworkMode::base_data_dir().join("logs")
    }
    pub const MAX_LOG_SIZE_MB: u64 = 100;

    /// Initialize the logging system. Safe to call multiple times (only runs once).
    ///
    /// Initializes both:
    ///   1. Legacy `env_logger` (for `log::info!` etc. backward compat)
    ///   2. Structured logger (for `slog_info!` etc. — new code)
    ///
    /// Both layers are pinned to the same level (INFO) so that messages
    /// above/below the threshold behave consistently across the process.
    ///
    /// Control structured output format via SHADOWDAG_LOG_FORMAT env var:
    ///   "json"   → one JSON object per line (log aggregators)
    ///   "pretty" → human-readable (default)
    ///   "compact"→ single-line key=value
    pub fn init() {
        INIT.call_once(|| {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Info)
                .format_timestamp_millis()
                .format_module_path(true)
                .init();

            // Initialize structured logging layer at the SAME level. We must
            // use init_with_level() rather than init() here, because init()
            // only reads SHADOWDAG_LOG_LEVEL from the environment and would
            // silently diverge from env_logger's filter (e.g. env_logger at
            // INFO but structured at DEBUG because SHADOWDAG_LOG_LEVEL=debug
            // was exported by the shell). See structured::init_with_level.
            crate::telemetry::logging::structured::init_with_level(
                crate::telemetry::logging::structured::Level::Info,
            );

            log::info!(
                "[ShadowDAG] Logging initialized at level {}",
                Self::LOG_LEVEL
            );
        });
    }

    /// Initialize with a custom log level.
    ///
    /// The same level is applied to both the `env_logger` filter AND the
    /// structured logger so that the two stay in sync. Previously,
    /// `structured::init()` was called here without a level argument, which
    /// made it fall back to `SHADOWDAG_LOG_LEVEL`/INFO and diverge from
    /// whatever `env_logger` was configured with.
    pub fn init_with_level(level: &str) {
        INIT.call_once(|| {
            let filter = match level.to_uppercase().as_str() {
                "TRACE" => log::LevelFilter::Trace,
                "DEBUG" => log::LevelFilter::Debug,
                "INFO" => log::LevelFilter::Info,
                "WARN" => log::LevelFilter::Warn,
                "ERROR" => log::LevelFilter::Error,
                _ => log::LevelFilter::Info,
            };

            env_logger::Builder::new()
                .filter_level(filter)
                .format_timestamp_millis()
                .init();

            // Convert the CLI/config level string into a structured::Level
            // and pass it through, so env_logger and structured agree.
            // `Level::from_str` defaults to Info on unknown input, matching
            // the `_ => LevelFilter::Info` fallback above.
            let structured_level = crate::telemetry::logging::structured::Level::from_str(level);
            crate::telemetry::logging::structured::init_with_level(structured_level);

            log::info!("[ShadowDAG] Logging initialized at level {}", level);
        });
    }
}
