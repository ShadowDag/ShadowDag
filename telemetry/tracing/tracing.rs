// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Persistent trace store — key→payload records for post-mortem inspection.
//
// Error-handling invariants:
//   - `trace()` returns `Result<(), StorageError>` so callers can react to
//     write failures instead of silently losing the trace.
//   - `get_trace()` still returns `Option<String>` for ergonomic use in
//     read paths, but now logs every error/corruption case via the
//     structured logger with a clear `may_be_false_negative` marker so
//     operators know a `None` here can mean "key exists but unreadable"
//     rather than "key genuinely absent".
//   - `get_trace_strict()` is provided for callers that must distinguish
//     these three states explicitly (`Ok(None)` vs `Err(_)`).
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

pub struct Tracing {
    db: DB,
}

impl Tracing {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { db })
    }

    /// Persist a trace record.
    ///
    /// Returns `Err(StorageError::WriteFailed)` on RocksDB failure so that
    /// the caller can decide whether to retry, abort, or continue. The
    /// previous implementation swallowed the error with `eprintln!` and
    /// returned `()`, which meant trace writes could silently drop.
    pub fn trace(&self, event_id: &str, payload: &str) -> Result<(), StorageError> {
        self.db.put(event_id, payload).map_err(|e| {
            slog_error!("telemetry", "trace_write_failed",
                event_id => event_id, error => e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    /// Look up a trace by id.
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid UTF-8, or when RocksDB itself reports a read error. The two
    /// failure cases are logged via `slog_error!` with
    /// `may_be_false_negative` so operators can distinguish them from a
    /// genuine miss in log aggregators.
    ///
    /// Callers that must NOT treat corruption as absence should use
    /// [`Self::get_trace_strict`] instead.
    pub fn get_trace(&self, event_id: &str) -> Option<String> {
        match self.db.get(event_id) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("telemetry", "trace_corrupt_utf8_may_be_false_negative",
                        event_id => event_id, error => e,
                        note => "returning None but key exists with invalid UTF-8 payload");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("telemetry", "trace_read_failed_may_be_false_negative",
                    event_id => event_id, error => e,
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
    /// must be handled differently (for example, crash recovery or audit
    /// tooling that must flag data corruption rather than silently skip it).
    pub fn get_trace_strict(&self, event_id: &str) -> Result<Option<String>, StorageError> {
        match self.db.get(event_id) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("telemetry", "trace_corrupt_utf8_strict",
                        event_id => event_id, error => e);
                    Err(StorageError::ReadFailed(format!(
                        "trace '{}' has non-UTF8 payload: {}",
                        event_id, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("telemetry", "trace_read_failed_strict",
                    event_id => event_id, error => e);
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
            "/tmp/test_tracing_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    #[test]
    fn trace_and_read_roundtrip() {
        let t = Tracing::new(&tmp_path()).expect("open tracing");
        t.trace("evt:1", "payload-one").expect("write ok");
        assert_eq!(t.get_trace("evt:1").as_deref(), Some("payload-one"));
    }

    #[test]
    fn missing_key_is_none_but_strict_is_ok_none() {
        let t = Tracing::new(&tmp_path()).expect("open tracing");
        assert!(t.get_trace("nonexistent").is_none());
        assert!(matches!(t.get_trace_strict("nonexistent"), Ok(None)));
    }

    #[test]
    fn corrupt_utf8_is_err_in_strict_mode() {
        let t = Tracing::new(&tmp_path()).expect("open tracing");
        // Bypass the typed API to plant invalid UTF-8 bytes.
        t.db.put("evt:bad", &[0xff, 0xfe, 0xfd]).expect("raw put");

        // Non-strict returns None (but logs the corruption)
        assert!(t.get_trace("evt:bad").is_none());
        // Strict surfaces the corruption as Err
        assert!(t.get_trace_strict("evt:bad").is_err());
    }
}
