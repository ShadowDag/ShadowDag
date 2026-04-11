// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::DB;
use std::sync::Arc;
use crate::errors::StorageError;
use crate::slog_error;

pub struct RuntimeManager {
    db: Arc<DB>,
}

impl RuntimeManager {
    /// ياخذ DB جاهز من النظام (NodeDB)
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// تشغيل runtime
    ///
    /// Persists `runtime:status = "running"` and
    /// `runtime:version = CARGO_PKG_VERSION` atomically (well —
    /// sequentially via RocksDB's own ordering). Returns
    /// `Err(StorageError::WriteFailed)` if either write fails so
    /// the boot path can refuse to claim the runtime is up when
    /// the persisted markers actually didn't land.
    pub fn start(&self) -> Result<(), StorageError> {
        self.set_state("runtime:status", "running")?;
        self.set_state("runtime:version", env!("CARGO_PKG_VERSION"))?;
        Ok(())
    }

    /// ايقاف runtime
    pub fn stop(&self) -> Result<(), StorageError> {
        self.set_state("runtime:status", "stopped")
    }

    /// كتابة state
    ///
    /// Returns `Err(StorageError::WriteFailed)` if the underlying
    /// RocksDB write fails. The previous implementation used
    /// `if let Err(e) = … { slog_error!(…) }` and returned `()`,
    /// so any caller that needed to know "did this state actually
    /// land?" had to read it back — and the read path
    /// (`get_state`) collapsed three failure modes into `None`
    /// (see its doc), so even the read-back was unreliable.
    pub fn set_state(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.db.put(key.as_bytes(), value.as_bytes()).map_err(|e| {
            slog_error!("runtime", "runtime_manager_db_put_error",
                key => key, error => &e.to_string());
            StorageError::WriteFailed(e.to_string())
        })
    }

    /// قراءة state — non-strict variant (backward-compatible).
    ///
    /// Returns `None` for genuine absence, AND for read failures
    /// AND for non-UTF-8 stored bytes. Logged via `slog_error!`
    /// with `_may_be_false_negative` markers so an operator chasing
    /// a silent miss can find the corrupt record via audit tooling.
    /// Use [`Self::get_state_strict`] when you need to tell the
    /// three apart — for example in audit / boot-health code that
    /// must NOT confuse "key absent" with "DB corruption".
    pub fn get_state(&self, key: &str) -> Option<String> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("runtime", "runtime_manager_state_utf8_corruption_may_be_false_negative",
                        key => key, error => &e.to_string(),
                        note => "returning None but the raw stored bytes are not valid UTF-8 — use get_state_strict to surface this");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "runtime_manager_db_get_error_may_be_false_negative",
                    key => key, error => &e.to_string(),
                    note => "returning None but the read failed — use get_state_strict to surface this");
                None
            }
        }
    }

    /// قراءة state — strict variant.
    ///
    /// Distinguishes the three possible states:
    ///
    ///   - `Ok(None)`          → key is genuinely absent
    ///   - `Ok(Some(value))`   → key exists with valid UTF-8
    ///   - `Err(StorageError)` → read failed OR stored bytes are
    ///     not valid UTF-8 (corrupt record)
    ///
    /// Use this from any code path that must NOT silently treat a
    /// damaged record as missing — boot health checks, audit
    /// tooling, anything that branches on the DB's contents. The
    /// non-strict [`Self::get_state`] is preserved for callers that
    /// historically treat all three as "no value" and would break
    /// if they suddenly started seeing errors on read failures.
    pub fn get_state_strict(&self, key: &str) -> Result<Option<String>, StorageError> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("runtime", "runtime_manager_state_utf8_corruption_strict",
                        key => key, error => &e.to_string());
                    Err(StorageError::Serialization(format!(
                        "runtime state for key '{}' is not valid UTF-8: {}",
                        key, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("runtime", "runtime_manager_db_get_error_strict",
                    key => key, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }
}
