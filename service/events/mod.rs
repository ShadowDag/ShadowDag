// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub mod pubsub;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub enum NodeEvent {
    NewBlock {
        hash:   String,
        height: u64,
    },
    NewTransaction {
        hash: String,
        fee:  u64,
    },
    BlockMined {
        hash:   String,
        height: u64,
        miner:  String,
        reward: u64,
    },
    DagTipChanged {
        new_tips: Vec<String>,
    },
    PeerConnected {
        address: String,
    },
    PeerDisconnected {
        address: String,
        reason:  String,
    },
    SyncProgress {
        current: u64,
        target:  u64,
    },
    SyncComplete {
        height: u64,
    },
    MempoolFull,
    ChainReorg {
        old_tip: String,
        new_tip: String,
        depth:   u64,
    },
}

impl NodeEvent {
    pub fn name(&self) -> &'static str {
        match self {
            NodeEvent::NewBlock { .. }         => "new_block",
            NodeEvent::NewTransaction { .. }   => "new_transaction",
            NodeEvent::BlockMined { .. }       => "block_mined",
            NodeEvent::DagTipChanged { .. }    => "dag_tip_changed",
            NodeEvent::PeerConnected { .. }    => "peer_connected",
            NodeEvent::PeerDisconnected { .. } => "peer_disconnected",
            NodeEvent::SyncProgress { .. }     => "sync_progress",
            NodeEvent::SyncComplete { .. }     => "sync_complete",
            NodeEvent::MempoolFull             => "mempool_full",
            NodeEvent::ChainReorg { .. }       => "chain_reorg",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventEntry {
    pub event:     NodeEvent,
    pub timestamp: u64,
}

impl EventEntry {
    pub fn new(event: NodeEvent) -> Self {
        Self {
            event,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

pub type EventCallback = Box<dyn Fn(&NodeEvent) + Send + Sync>;

pub struct EventBus {
    subscribers: HashMap<String, Vec<EventCallback>>,
    history:     Vec<EventEntry>,
    max_history: usize,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            history:     Vec::new(),
            max_history: 1_000,
        }
    }

    pub fn subscribe(&mut self, event_name: &str, cb: EventCallback) {
        self.subscribers
            .entry(event_name.to_string())
            .or_default()
            .push(cb);
    }

    pub fn publish(&mut self, event: NodeEvent) {
        let name = event.name();

        self.history.push(EventEntry::new(event.clone()));
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }

        if let Some(callbacks) = self.subscribers.get(name) {
            for cb in callbacks {
                cb(&event);
            }
        }

        if let Some(callbacks) = self.subscribers.get("all") {
            for cb in callbacks {
                cb(&event);
            }
        }
    }

    pub fn emit_new_block(&mut self, hash: &str, height: u64) {
        self.publish(NodeEvent::NewBlock { hash: hash.to_string(), height });
    }

    pub fn emit_new_tx(&mut self, hash: &str, fee: u64) {
        self.publish(NodeEvent::NewTransaction { hash: hash.to_string(), fee });
    }

    pub fn emit_block_mined(&mut self, hash: &str, height: u64, miner: &str, reward: u64) {
        self.publish(NodeEvent::BlockMined {
            hash:   hash.to_string(),
            height,
            miner:  miner.to_string(),
            reward,
        });
    }

    pub fn emit_dag_tip_changed(&mut self, tips: Vec<String>) {
        self.publish(NodeEvent::DagTipChanged { new_tips: tips });
    }

    pub fn emit_sync_progress(&mut self, current: u64, target: u64) {
        self.publish(NodeEvent::SyncProgress { current, target });
    }

    pub fn emit_sync_complete(&mut self, height: u64) {
        self.publish(NodeEvent::SyncComplete { height });
    }

    pub fn emit_reorg(&mut self, old_tip: &str, new_tip: &str, depth: u64) {
        self.publish(NodeEvent::ChainReorg {
            old_tip: old_tip.to_string(),
            new_tip: new_tip.to_string(),
            depth,
        });
    }

    pub fn emit_peer_connected(&mut self, address: &str) {
        self.publish(NodeEvent::PeerConnected { address: address.to_string() });
    }

    pub fn emit_peer_disconnected(&mut self, address: &str, reason: &str) {
        self.publish(NodeEvent::PeerDisconnected {
            address: address.to_string(),
            reason:  reason.to_string(),
        });
    }

    pub fn last_events(&self, count: usize) -> &[EventEntry] {
        let start = self.history.len().saturating_sub(count);
        &self.history[start..]
    }

    pub fn event_count(&self) -> usize { self.history.len() }

    pub fn subscriber_count(&self, event_name: &str) -> usize {
        self.subscribers.get(event_name).map(|v| v.len()).unwrap_or(0)
    }
}

pub type SharedEventBus = Arc<Mutex<EventBus>>;

pub fn create_shared_bus() -> SharedEventBus {
    Arc::new(Mutex::new(EventBus::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn publish_triggers_subscriber() {
        let mut bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&counter);
        bus.subscribe("new_block", Box::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        bus.emit_new_block("hash1", 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn all_subscriber_receives_every_event() {
        let mut bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&counter);
        bus.subscribe("all", Box::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        bus.emit_new_block("h1", 1);
        bus.emit_new_tx("t1", 100);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn history_is_recorded() {
        let mut bus = EventBus::new();
        bus.emit_new_block("h1", 1);
        bus.emit_new_block("h2", 2);
        assert_eq!(bus.event_count(), 2);
    }

    #[test]
    fn history_max_not_exceeded() {
        let mut bus = EventBus::new();
        bus.max_history = 3;
        for i in 0..10 {
            bus.emit_new_block(&format!("h{}", i), i);
        }
        assert!(bus.event_count() <= 3);
    }

    #[test]
    fn sync_event_roundtrip() {
        let mut bus = EventBus::new();
        bus.emit_sync_complete(500);
        let last = bus.last_events(1);
        assert_eq!(last[0].event.name(), "sync_complete");
    }
}
