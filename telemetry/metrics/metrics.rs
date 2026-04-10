// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Persistent metrics store — name→u64 values kept in RocksDB for external
// tooling (dashboards, forensic analysis, etc.).
//
// Error-handling invariants:
//   - `set_metric()` returns `Result<(), StorageError>` so callers can
//     notice dropped writes (the previous version swallowed errors in an
//     `if let Err` and returned `()`).
//   - `get_metric()` still returns `Option<u64>` for ergonomic reads, but
//     every failure path is now routed through `slog_error!` with a clear
//     `may_be_false_negative` marker. The old code printed corruption to
//     stderr via `eprintln!`, which both bypassed structured logging and
//     collapsed three distinct states — "missing", "read failed", and
//     "data corrupt" — into the same `None`.
//   - `get_metric_strict()` is available for callers that must distinguish
//     the three states explicitly.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

pub struct Metrics {
    db: DB,
}

impl Metrics {
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

    /// Persist a metric value as an 8-byte big-endian integer.
    ///
    /// Returns `Err(StorageError::WriteFailed)` on RocksDB failure so the
    /// caller can react to dropped writes. The previous signature was
    /// `fn set_metric(&self, name: &str, value: u64)` which silently
    /// swallowed errors.
    pub fn set_metric(&self, name: &str, value: u64) -> Result<(), StorageError> {
        self.db.put(name, value.to_be_bytes()).map_err(|e| {
            slog_error!("metrics", "db_put_error",
                name => name, error => &e.to_string());
            StorageError::WriteFailed(e.to_string())
        })
    }

    /// Look up a metric by name.
    ///
    /// Returns `None` when the key is absent, when the stored value has
    /// an unexpected length (data corruption), or when RocksDB itself
    /// reports a read error. Failure cases are logged via `slog_error!`
    /// with `may_be_false_negative`. Use [`Self::get_metric_strict`] if
    /// you need to distinguish the three states.
    pub fn get_metric(&self, name: &str) -> Option<u64> {
        let bytes = match self.db.get(name) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => {
                slog_error!("metrics", "get_metric_read_failed_may_be_false_negative",
                    name => name, error => e.to_string(),
                    note => "returning None but key may exist — this is a false negative");
                return None;
            }
        };
        if bytes.len() != 8 {
            slog_error!("metrics", "get_metric_corrupt_length_may_be_false_negative",
                name => name, got => bytes.len(), expected => 8usize,
                note => "returning None but key exists with corrupt payload length");
            return None;
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Some(u64::from_be_bytes(arr))
    }

    /// Strict read that distinguishes the three possible states:
    ///   - `Ok(None)`         → key is genuinely absent
    ///   - `Ok(Some(v))`      → key exists and payload is a valid 8-byte BE u64
    ///   - `Err(StorageError)` → read failed OR payload length is corrupt
    pub fn get_metric_strict(&self, name: &str) -> Result<Option<u64>, StorageError> {
        let bytes = match self.db.get(name) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => {
                slog_error!("metrics", "get_metric_read_failed_strict",
                    name => name, error => e.to_string());
                return Err(StorageError::ReadFailed(e.to_string()));
            }
        };
        if bytes.len() != 8 {
            slog_error!("metrics", "get_metric_corrupt_length_strict",
                name => name, got => bytes.len(), expected => 8usize);
            return Err(StorageError::ReadFailed(format!(
                "metric '{}': expected 8 bytes, got {} — data corruption",
                name, bytes.len()
            )));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(Some(u64::from_be_bytes(arr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_metrics_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    #[test]
    fn set_and_get_roundtrip() {
        let m = Metrics::new(&tmp_path()).expect("open metrics");
        m.set_metric("blocks", 42).expect("write ok");
        assert_eq!(m.get_metric("blocks"), Some(42));
        assert_eq!(m.get_metric_strict("blocks").unwrap(), Some(42));
    }

    #[test]
    fn missing_key_returns_none_and_ok_none() {
        let m = Metrics::new(&tmp_path()).expect("open metrics");
        assert!(m.get_metric("absent").is_none());
        assert!(matches!(m.get_metric_strict("absent"), Ok(None)));
    }

    #[test]
    fn corrupt_length_is_err_in_strict_mode() {
        let m = Metrics::new(&tmp_path()).expect("open metrics");
        // Plant a value of the wrong length (not 8 bytes).
        m.db.put("bad", &[0x01, 0x02, 0x03]).expect("raw put");

        // Non-strict collapses corruption into None
        assert!(m.get_metric("bad").is_none());
        // Strict surfaces corruption as Err
        assert!(m.get_metric_strict("bad").is_err());
    }

    #[test]
    fn big_endian_encoding_is_stable() {
        let m = Metrics::new(&tmp_path()).expect("open metrics");
        m.set_metric("v", 0x0123_4567_89ab_cdef).expect("ok");
        assert_eq!(m.get_metric("v"), Some(0x0123_4567_89ab_cdef));
    }
}
