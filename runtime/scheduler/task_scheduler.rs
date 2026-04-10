// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// TaskScheduler — RocksDB-backed persistent task queue.
//
// Error-handling invariants (mirror `telemetry::logging::logger::Logger`
// and `runtime::event_bus::event_bus::EventBus`):
//   - `schedule()` already returns `Result<(), rocksdb::Error>` and we
//     keep that surface.
//   - `get_task()` still returns `Option<String>` for ergonomic reads,
//     but every failure path is now routed through `slog_error!` with a
//     `may_be_false_negative` marker so "absent", "read failed", and
//     "UTF-8 corruption" can be distinguished in log aggregators.
//   - `get_task_strict()` is provided for callers (crash recovery,
//     audit, scheduler lease reclamation) that MUST distinguish the
//     three states explicitly.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::DB;
use std::sync::Arc;

use crate::errors::StorageError;
use crate::slog_error;

pub struct TaskScheduler {
    db: Arc<DB>,
}

impl TaskScheduler {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    pub fn schedule(&self, task_id: &str, payload: &str) -> Result<(), rocksdb::Error> {
        let key = format!("task:{}", task_id);
        self.db.put(key.as_bytes(), payload.as_bytes())
    }

    /// Look up a task by id.
    ///
    /// Returns `None` when the key is absent, when the stored payload is
    /// not valid UTF-8, or when RocksDB itself reports a read error. The
    /// two failure cases are logged via `slog_error!` with a
    /// `may_be_false_negative` marker so operators can distinguish them
    /// from a genuine miss in log aggregators.
    ///
    /// Callers that must NOT treat corruption as absence should use
    /// [`Self::get_task_strict`] instead.
    pub fn get_task(&self, task_id: &str) -> Option<String> {
        let key = format!("task:{}", task_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("runtime", "get_task_corrupt_utf8_may_be_false_negative",
                        task_id => task_id, error => &e.to_string(),
                        note => "returning None but key exists with invalid UTF-8 payload");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "get_task_read_failed_may_be_false_negative",
                    task_id => task_id, error => &e.to_string(),
                    note => "returning None but key may exist — this is a false negative");
                None
            }
        }
    }

    /// Strict read that distinguishes the three possible states:
    ///   - `Ok(None)`         → key is genuinely absent
    ///   - `Ok(Some(s))`      → key exists and payload is valid UTF-8
    ///   - `Err(StorageError)` → read failed OR payload is not UTF-8
    pub fn get_task_strict(&self, task_id: &str) -> Result<Option<String>, StorageError> {
        let key = format!("task:{}", task_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("runtime", "get_task_corrupt_utf8_strict",
                        task_id => task_id, error => &e.to_string());
                    Err(StorageError::ReadFailed(format!(
                        "task '{}' has non-UTF8 payload: {}",
                        task_id, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("runtime", "get_task_read_failed_strict",
                    task_id => task_id, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }
}
