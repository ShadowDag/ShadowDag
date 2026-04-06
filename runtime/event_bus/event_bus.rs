// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::sync::Arc;
use tokio::sync::broadcast;

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
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = open_shared_db(source, &opts)
            .map_err(|e| {
                slog_error!("runtime", "event_bus_db_init_failed", error => &e.to_string());
                e
            })?;
        let (broadcast_tx, _) = broadcast::channel(4096);
        Ok(Self { db, broadcast_tx })
    }

    /// Publish an event — persists to DB and broadcasts to all subscribers
    pub fn publish(&self, event_id: &str, payload: &str) {
        let key = format!("event:{}", event_id);
        if let Err(_e) = self.db.put(key.as_bytes(), payload.as_bytes()) {
            slog_error!("runtime", "event_bus_db_put_error", error => &_e.to_string());
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

    pub fn get_event(&self, event_id: &str) -> Option<String> {
        let key = format!("event:{}", event_id);
        match self.db.get(key.as_bytes()).unwrap_or(None) {
            Some(data) => Some(String::from_utf8(data.to_vec()).ok()?),
            None => None,
        }
    }
}
