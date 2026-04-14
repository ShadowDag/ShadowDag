// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Persistent log store — id→message records kept in RocksDB.
//
// Error-handling invariants (mirror `telemetry::tracing::tracing::Tracing`):
//   - `log()` returns `Result<(), StorageError>` so callers can decide
//     whether a dropped log event is fatal, retryable, or ignorable.
//     The previous implementation swallowed the error with `eprintln!` and
//     returned `()`, which is indistinguishable from success.
//   - `get_log()` still returns `Option<String>` for ergonomic reads, but
//     every error or UTF-8 corruption path is logged through the
//     structured logger with a `may_be_false_negative` marker so operators
//     can tell a genuine miss apart from a masked failure.
//   - `get_log_strict()` is available for callers that MUST distinguish
//     the three states explicitly.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{Options, DB};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

pub struct Logger {
    db: DB,
}

impl Logger {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { db })
    }

    /// Persist a log record.
    ///
    /// Returns `Err(StorageError::WriteFailed)` on RocksDB failure so the
    /// caller can react to dropped logs. The previous API returned `()`
    /// and printed to stderr, making write failures invisible to the
    /// control flow.
    pub fn log(&self, id: &str, message: &str) -> Result<(), StorageError> {
        self.db.put(id, message).map_err(|e| {
            slog_error!("telemetry", "log_write_failed",
                id => id, error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    /// Look up a log record by id.
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid UTF-8, or when RocksDB itself reports a read error. The two
    /// failure cases are logged via `slog_error!` with a
    /// `may_be_false_negative` marker so log aggregators can distinguish
    /// them from a genuine miss.
    ///
    /// Use [`Self::get_log_strict`] when corruption must NOT be treated as
    /// absence (for example from audit or crash-recovery code).
    pub fn get_log(&self, id: &str) -> Option<String> {
        match self.db.get(id) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("telemetry", "log_corrupt_utf8_may_be_false_negative",
                        id => id, error => e,
                        note => "returning None but key exists with invalid UTF-8 payload");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("telemetry", "log_read_failed_may_be_false_negative",
                    id => id, error => e,
                    note => "returning None but key may exist — this is a false negative");
                None
            }
        }
    }

    /// Strict read that distinguishes the three possible states:
    ///   - `Ok(None)`         → key is genuinely absent
    ///   - `Ok(Some(s))`      → key exists and value is valid UTF-8
    ///   - `Err(StorageError)` → read failed OR stored value is not UTF-8
    ///
    /// Use this from code paths where "not found" and "corrupt / unreadable"
    /// must be handled differently.
    pub fn get_log_strict(&self, id: &str) -> Result<Option<String>, StorageError> {
        match self.db.get(id) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("telemetry", "log_corrupt_utf8_strict",
                        id => id, error => e);
                    Err(StorageError::ReadFailed(format!(
                        "log '{}' has non-UTF8 payload: {}",
                        id, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("telemetry", "log_read_failed_strict",
                    id => id, error => e);
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_logger_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    #[test]
    fn log_and_read_roundtrip() {
        let l = Logger::new(&tmp_path()).expect("open logger");
        l.log("id:1", "message-one").expect("write ok");
        assert_eq!(l.get_log("id:1").as_deref(), Some("message-one"));
    }

    #[test]
    fn missing_key_returns_none_and_ok_none() {
        let l = Logger::new(&tmp_path()).expect("open logger");
        assert!(l.get_log("nonexistent").is_none());
        assert!(matches!(l.get_log_strict("nonexistent"), Ok(None)));
    }

    #[test]
    fn corrupt_utf8_is_err_in_strict_mode() {
        let l = Logger::new(&tmp_path()).expect("open logger");
        // Plant raw non-UTF8 bytes under a real key.
        l.db.put("id:bad", [0xff, 0xfe, 0xfd]).expect("raw put");

        // Non-strict returns None (logs may_be_false_negative)
        assert!(l.get_log("id:bad").is_none());
        // Strict surfaces corruption as Err
        assert!(l.get_log_strict("id:bad").is_err());
    }
}
