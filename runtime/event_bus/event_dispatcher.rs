// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// EventDispatcher — thin wrapper over EventBus that assigns a stable,
// bounded, collision-free event id on every dispatch.
//
// The previous implementation built the event id with
//     format!("{:?}_{}", event, payload)
// which had three serious problems:
//
//   1. **Payload leakage into the key.** The raw payload — which can be
//      arbitrary caller-controlled data, including transaction hashes,
//      user-facing strings, or secrets — was embedded verbatim in the
//      RocksDB key. Keys are visible in iterators, backups, and crash
//      dumps, which turned the event store into an accidental PII sink.
//
//   2. **Unbounded key length.** A multi-megabyte payload produced a
//      multi-megabyte key, blowing up the block index and slowing every
//      range scan. RocksDB imposes no key-size limit so this would not
//      have errored — it would just silently degrade performance.
//
//   3. **Duplicate collisions.** Two identical `(event_type, payload)`
//      pairs mapped to the same key, so the second dispatch overwrote
//      the first. That made the store useless as an append-only log.
//
// The new id has the shape
//     `{event_type}:{unix_nanos}:{monotonic_counter}`
// which is:
//   - bounded (length depends only on the enum name),
//   - payload-free (the payload goes into the VALUE, not the key),
//   - strictly monotonic (the counter breaks ties when multiple events
//     arrive within the same nanosecond),
//   - prefix-scannable by event type (operators can `prefix_iterator`
//     all `BlockAdded:…` events without touching the rest).
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::StorageError;
use crate::runtime::event_bus::event_bus::EventBus;
use crate::runtime::event_bus::event_types::EventType;

/// Monotonic tiebreaker used when two events arrive in the same nanosecond.
///
/// Relaxed ordering is sufficient: we only need uniqueness across the life
/// of the process, not cross-thread happens-before.
static DISPATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct EventDispatcher {
    bus: EventBus,
}

impl EventDispatcher {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        Ok(Self { bus: EventBus::new(path)? })
    }

    /// Dispatch an event. The payload is stored as the value under an
    /// auto-generated id. The id is returned so the caller can later
    /// retrieve the event via [`Self::get`].
    ///
    /// See the module header for the rationale behind the id shape.
    pub fn dispatch(&self, event: EventType, payload: &str) -> String {
        let event_id = Self::make_event_id(&event);
        self.bus.publish(&event_id, payload);
        event_id
    }

    /// Look up an event by id. Delegates to [`EventBus::get_event`] and
    /// inherits its logging semantics (three states collapsed into
    /// `Option<String>` with `may_be_false_negative` markers on error).
    pub fn get(&self, event_id: &str) -> Option<String> {
        self.bus.get_event(event_id)
    }

    /// Strict lookup that distinguishes `Ok(None)` from `Err(_)`. Use from
    /// audit / crash-recovery code where corruption must not be masked.
    pub fn get_strict(&self, event_id: &str) -> Result<Option<String>, StorageError> {
        self.bus.get_event_strict(event_id)
    }

    /// Build a bounded, collision-free id: `{EventType}:{nanos}:{counter}`.
    ///
    /// The event-type prefix makes it cheap to scan all events of a given
    /// kind. The nanosecond timestamp gives coarse ordering for humans.
    /// The counter breaks ties when the clock has insufficient resolution
    /// or when two threads publish in the same instant.
    fn make_event_id(event: &EventType) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let counter = DISPATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{:?}:{}:{}", event, nanos, counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> String {
        format!(
            "/tmp/test_event_dispatcher_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    #[test]
    fn dispatch_returns_retrievable_id() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        let id = d.dispatch(EventType::BlockAdded, "block-hash-abc");
        assert_eq!(d.get(&id).as_deref(), Some("block-hash-abc"));
    }

    #[test]
    fn dispatch_ids_are_unique_even_for_same_input() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        let id1 = d.dispatch(EventType::BlockAdded, "same-payload");
        let id2 = d.dispatch(EventType::BlockAdded, "same-payload");
        assert_ne!(id1, id2, "duplicate (event, payload) must produce distinct ids");
        // Both must be independently retrievable
        assert_eq!(d.get(&id1).as_deref(), Some("same-payload"));
        assert_eq!(d.get(&id2).as_deref(), Some("same-payload"));
    }

    #[test]
    fn dispatch_id_does_not_leak_payload_into_key() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        let secret = "SECRET_PAYLOAD_SHOULD_NOT_APPEAR_IN_KEY";
        let id = d.dispatch(EventType::BlockAdded, secret);
        assert!(
            !id.contains(secret),
            "event id must not embed the payload: got '{}'",
            id
        );
    }

    #[test]
    fn dispatch_id_length_is_bounded_regardless_of_payload_size() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        let huge = "x".repeat(1_000_000);
        let id = d.dispatch(EventType::BlockAdded, &huge);
        // With the new format the id is <prefix>:{u128}:{u64} which is
        // well under a few hundred bytes no matter how big the payload.
        assert!(id.len() < 256, "id length exploded with big payload: {}", id.len());
    }

    #[test]
    fn dispatch_id_starts_with_event_type() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        let id = d.dispatch(EventType::PeerConnected, "peer-1.2.3.4");
        assert!(id.starts_with("PeerConnected:"), "got: {}", id);
    }

    #[test]
    fn get_strict_distinguishes_missing_from_error() {
        let d = EventDispatcher::new(&tmp_path()).expect("open dispatcher");
        assert!(matches!(d.get_strict("nonexistent-id"), Ok(None)));
    }
}
