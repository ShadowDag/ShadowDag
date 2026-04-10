// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// EventBus — RocksDB-backed persistent event log + in-process broadcast
// channel for real-time subscribers.
//
// Error-handling invariants (mirror `telemetry::logging::logger::Logger`):
//   - `get_event()` still returns `Option<String>` for ergonomic reads,
//     but every failure path is now routed through `slog_error!` with a
//     `may_be_false_negative` marker so "absent", "read failed", and
//     "UTF-8 corruption" can be distinguished in log aggregators.
//   - `get_event_strict()` is provided for callers (crash recovery,
//     audit) that MUST distinguish the three states explicitly.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::errors::StorageError;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::slog_error;

/// Event payload for the broadcast channel
#[derive(Debug, Clone)]
pub struct BusEvent {
    pub event_id: String,
    pub payload:  String,
}

pub struct EventBus {
    db: Arc<DB>,
    /// Broadcast channel for real-time event delivery to subscribers
    broadcast_tx: broadcast::Sender<BusEvent>,
}

impl EventBus {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = open_shared_db(source, &opts)
            .inspect_err(|e| {
                slog_error!("runtime", "event_bus_db_init_failed", error => &e.to_string());
            })?;
        let (broadcast_tx, _) = broadcast::channel(4096);
        Ok(Self { db, broadcast_tx })
    }

    /// Publish an event — persists to DB and broadcasts to all subscribers
    pub fn publish(&self, event_id: &str, payload: &str) {
        let key = format!("event:{}", event_id);
        if let Err(e) = self.db.put(key.as_bytes(), payload.as_bytes()) {
            slog_error!("runtime", "event_persist_failed_but_broadcast",
                error => &e.to_string(),
                note => "event delivered to real-time subscribers but NOT persisted to history");
        }
        // Broadcast to real-time subscribers (ignore send errors — no subscribers is OK)
        let _ = self.broadcast_tx.send(BusEvent {
            event_id: event_id.to_string(),
            payload:  payload.to_string(),
        });
    }

    /// Subscribe to real-time events
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.broadcast_tx.receiver_count()
    }

    /// Look up a persisted event by id.
    ///
    /// Returns `None` when the key is absent, when the stored payload is
    /// not valid UTF-8, or when RocksDB itself reports a read error. The
    /// two failure cases are logged via `slog_error!` with a
    /// `may_be_false_negative` marker so operators can distinguish them
    /// from a genuine miss in log aggregators.
    ///
    /// Callers that must NOT treat corruption as absence should use
    /// [`Self::get_event_strict`] instead.
    pub fn get_event(&self, event_id: &str) -> Option<String> {
        let key = format!("event:{}", event_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("runtime", "get_event_corrupt_utf8_may_be_false_negative",
                        event_id => event_id, error => &e.to_string(),
                        note => "returning None but key exists with invalid UTF-8 payload");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "get_event_read_failed_may_be_false_negative",
                    event_id => event_id, error => &e.to_string(),
                    note => "returning None but key may exist — this is a false negative");
                None
            }
        }
    }

    /// Strict read that distinguishes the three possible states:
    ///   - `Ok(None)`         → key is genuinely absent
    ///   - `Ok(Some(s))`      → key exists and payload is valid UTF-8
    ///   - `Err(StorageError)` → read failed OR payload is not UTF-8
    pub fn get_event_strict(&self, event_id: &str) -> Result<Option<String>, StorageError> {
        let key = format!("event:{}", event_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("runtime", "get_event_corrupt_utf8_strict",
                        event_id => event_id, error => &e.to_string());
                    Err(StorageError::ReadFailed(format!(
                        "event '{}' has non-UTF8 payload: {}",
                        event_id, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("runtime", "get_event_read_failed_strict",
                    event_id => event_id, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }
}
