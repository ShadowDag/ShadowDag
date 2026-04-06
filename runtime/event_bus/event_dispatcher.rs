// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::runtime::event_bus::event_types::EventType;
use crate::runtime::event_bus::event_bus::EventBus;

pub struct EventDispatcher {
    bus: EventBus,
}

impl EventDispatcher {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        Ok(Self { bus: EventBus::new(path)? })
    }

    pub fn dispatch(&self, event: EventType, payload: &str) {
        let event_id = format!("{:?}_{}", event, payload);
        self.bus.publish(&event_id, payload);
    }

    pub fn get(&self, event_id: &str) -> Option<String> {
        self.bus.get_event(event_id)
    }
}
