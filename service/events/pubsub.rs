// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Pub-Sub Notification System — Real-time event streaming for clients.
//
// Clients subscribe to topics and receive push notifications when events
// occur (new blocks, transactions, DAG changes, etc.).
//
// Topics:
//   - blocks          : New block added to DAG
//   - transactions    : New transaction in mempool
//   - dag_tips        : DAG tip set changed
//   - finality        : Block reached finality
//   - mining          : New block template available
//   - privacy         : Shadow pool activity (anonymized)
//   - contracts       : Contract state change
//   - chain_reorg     : Chain reorganization detected
//
// Delivery: via WebSocket or long-polling HTTP connections
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::errors::NetworkError;

/// Maximum events per topic buffer
pub const MAX_BUFFER_SIZE: usize = 1_000;

/// Maximum subscriptions per client
pub const MAX_SUBS_PER_CLIENT: usize = 16;

/// Maximum total subscriptions
pub const MAX_TOTAL_SUBS: usize = 10_000;

/// Event topics
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Topic {
    Blocks,
    Transactions,
    DagTips,
    Finality,
    Mining,
    Privacy,
    Contracts,
    ChainReorg,
    Custom(String),
}

impl Topic {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "blocks"       => Topic::Blocks,
            "transactions" | "tx" => Topic::Transactions,
            "dag_tips"     => Topic::DagTips,
            "finality"     => Topic::Finality,
            "mining"       => Topic::Mining,
            "privacy"      => Topic::Privacy,
            "contracts"    => Topic::Contracts,
            "chain_reorg"  => Topic::ChainReorg,
            other          => Topic::Custom(other.to_string()),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Topic::Blocks       => "blocks",
            Topic::Transactions => "transactions",
            Topic::DagTips      => "dag_tips",
            Topic::Finality     => "finality",
            Topic::Mining       => "mining",
            Topic::Privacy      => "privacy",
            Topic::Contracts    => "contracts",
            Topic::ChainReorg   => "chain_reorg",
            Topic::Custom(s)    => s,
        }
    }
}

/// A published event
#[derive(Debug, Clone)]
pub struct Event {
    pub id:        u64,
    pub topic:     Topic,
    pub payload:   String,
    pub timestamp: u64,
}

/// A subscription
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id:         u64,
    pub client_id:  String,
    pub topic:      Topic,
    pub created_at: u64,
    /// Filter: only deliver events matching this prefix (optional)
    pub filter:     Option<String>,
}

/// Client notification queue
struct ClientQueue {
    events:    VecDeque<Event>,
    max_size:  usize,
}

impl ClientQueue {
    fn new() -> Self {
        Self { events: VecDeque::with_capacity(64), max_size: MAX_BUFFER_SIZE }
    }

    fn push(&mut self, event: Event) {
        if self.events.len() >= self.max_size {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn drain(&mut self, limit: usize) -> Vec<Event> {
        let count = limit.min(self.events.len());
        self.events.drain(..count).collect()
    }

    fn len(&self) -> usize { self.events.len() }
}

/// Pub-Sub Manager
pub struct PubSub {
    /// Topic → list of subscriptions
    subscriptions:    RwLock<HashMap<Topic, Vec<Subscription>>>,
    /// Client → notification queue
    client_queues:    RwLock<HashMap<String, ClientQueue>>,
    /// Next event ID
    next_event_id:    AtomicU64,
    /// Next subscription ID
    next_sub_id:      AtomicU64,
    /// Total events published
    total_published:  AtomicU64,
    /// Total events delivered
    total_delivered:  AtomicU64,
}

impl Default for PubSub {
    fn default() -> Self {
        Self::new()
    }
}

impl PubSub {
    pub fn new() -> Self {
        Self {
            subscriptions:   RwLock::new(HashMap::new()),
            client_queues:   RwLock::new(HashMap::new()),
            next_event_id:   AtomicU64::new(1),
            next_sub_id:     AtomicU64::new(1),
            total_published: AtomicU64::new(0),
            total_delivered: AtomicU64::new(0),
        }
    }

    /// Subscribe a client to a topic
    pub fn subscribe(&self, client_id: &str, topic: Topic, filter: Option<String>) -> Result<u64, NetworkError> {
        let mut subs = self.subscriptions.write().unwrap_or_else(|e| e.into_inner());

        // Check per-client limit
        let client_count = subs.values()
            .flat_map(|v| v.iter())
            .filter(|s| s.client_id == client_id)
            .count();

        if client_count >= MAX_SUBS_PER_CLIENT {
            return Err(NetworkError::RateLimited(format!("Max {} subscriptions per client", MAX_SUBS_PER_CLIENT)));
        }

        // Check total limit
        let total: usize = subs.values().map(|v| v.len()).sum();
        if total >= MAX_TOTAL_SUBS {
            return Err(NetworkError::RateLimited("Max subscriptions reached".to_string()));
        }

        let sub_id = self.next_sub_id.fetch_add(1, Ordering::Relaxed);
        let sub = Subscription {
            id:         sub_id,
            client_id:  client_id.to_string(),
            topic:      topic.clone(),
            created_at: now_secs(),
            filter,
        };

        subs.entry(topic).or_default().push(sub);

        // Create client queue if needed
        self.client_queues.write().unwrap_or_else(|e| e.into_inner())
            .entry(client_id.to_string())
            .or_insert_with(ClientQueue::new);

        Ok(sub_id)
    }

    /// Unsubscribe from a topic
    pub fn unsubscribe(&self, client_id: &str, sub_id: u64) -> bool {
        let mut subs = self.subscriptions.write().unwrap_or_else(|e| e.into_inner());
        let mut found = false;
        for topic_subs in subs.values_mut() {
            let before = topic_subs.len();
            topic_subs.retain(|s| !(s.id == sub_id && s.client_id == client_id));
            if topic_subs.len() < before { found = true; }
        }
        found
    }

    /// Unsubscribe a client from everything
    pub fn unsubscribe_all(&self, client_id: &str) -> usize {
        let mut subs = self.subscriptions.write().unwrap_or_else(|e| e.into_inner());
        let mut removed = 0;
        for topic_subs in subs.values_mut() {
            let before = topic_subs.len();
            topic_subs.retain(|s| s.client_id != client_id);
            removed += before - topic_subs.len();
        }
        self.client_queues.write().unwrap_or_else(|e| e.into_inner()).remove(client_id);
        removed
    }

    /// Publish an event to a topic — delivers to all subscribers
    pub fn publish(&self, topic: Topic, payload: String) -> u64 {
        let event_id = self.next_event_id.fetch_add(1, Ordering::Relaxed);
        self.total_published.fetch_add(1, Ordering::Relaxed);

        let event = Event {
            id:        event_id,
            topic:     topic.clone(),
            payload,
            timestamp: now_secs(),
        };

        // Find all subscribers for this topic
        let subs = self.subscriptions.read().unwrap_or_else(|e| e.into_inner());
        if let Some(topic_subs) = subs.get(&topic) {
            let mut queues = self.client_queues.write().unwrap_or_else(|e| e.into_inner());

            for sub in topic_subs {
                // Apply filter if set
                if let Some(ref filter) = sub.filter {
                    if !event.payload.contains(filter) { continue; }
                }

                if let Some(queue) = queues.get_mut(&sub.client_id) {
                    queue.push(event.clone());
                    self.total_delivered.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        event_id
    }

    /// Convenience: publish a new block event
    pub fn publish_block(&self, hash: &str, height: u64, tx_count: usize) -> u64 {
        let payload = serde_json::json!({
            "hash": hash, "height": height, "tx_count": tx_count
        }).to_string();
        self.publish(Topic::Blocks, payload)
    }

    /// Convenience: publish a new transaction event
    pub fn publish_tx(&self, hash: &str, fee: u64) -> u64 {
        let payload = serde_json::json!({
            "hash": hash, "fee": fee
        }).to_string();
        self.publish(Topic::Transactions, payload)
    }

    /// Convenience: publish chain reorg
    pub fn publish_reorg(&self, old_tip: &str, new_tip: &str, depth: u64) -> u64 {
        let payload = serde_json::json!({
            "old_tip": old_tip, "new_tip": new_tip, "depth": depth
        }).to_string();
        self.publish(Topic::ChainReorg, payload)
    }

    /// Poll: get pending events for a client
    pub fn poll(&self, client_id: &str, limit: usize) -> Vec<Event> {
        let mut queues = self.client_queues.write().unwrap_or_else(|e| e.into_inner());
        match queues.get_mut(client_id) {
            Some(queue) => queue.drain(limit),
            None => vec![],
        }
    }

    /// Get pending event count for a client
    pub fn pending_count(&self, client_id: &str) -> usize {
        let queues = self.client_queues.read().unwrap_or_else(|e| e.into_inner());
        queues.get(client_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Stats
    pub fn total_subscriptions(&self) -> usize {
        self.subscriptions.read().unwrap_or_else(|e| e.into_inner()).values().map(|v| v.len()).sum()
    }
    pub fn total_clients(&self) -> usize {
        self.client_queues.read().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn total_published(&self) -> u64 { self.total_published.load(Ordering::Relaxed) }
    pub fn total_delivered(&self) -> u64 { self.total_delivered.load(Ordering::Relaxed) }

    pub fn status(&self) -> String {
        format!(
            "PubSub: {} subs | {} clients | {} published | {} delivered",
            self.total_subscriptions(), self.total_clients(),
            self.total_published(), self.total_delivered()
        )
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_publish() {
        let ps = PubSub::new();
        ps.subscribe("client1", Topic::Blocks, None).unwrap();
        ps.publish_block("hash123", 1, 10);

        let events = ps.poll("client1", 10);
        assert_eq!(events.len(), 1);
        assert!(events[0].payload.contains("hash123"));
    }

    #[test]
    fn multiple_subscribers() {
        let ps = PubSub::new();
        ps.subscribe("a", Topic::Blocks, None).unwrap();
        ps.subscribe("b", Topic::Blocks, None).unwrap();
        ps.publish_block("blk", 1, 5);

        assert_eq!(ps.poll("a", 10).len(), 1);
        assert_eq!(ps.poll("b", 10).len(), 1);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let ps = PubSub::new();
        let sub_id = ps.subscribe("c", Topic::Transactions, None).unwrap();
        ps.unsubscribe("c", sub_id);
        ps.publish_tx("tx1", 100);

        assert_eq!(ps.poll("c", 10).len(), 0);
    }

    #[test]
    fn filter_works() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::Blocks, Some("important".to_string())).unwrap();

        ps.publish(Topic::Blocks, "regular block".to_string());
        ps.publish(Topic::Blocks, "important block event".to_string());

        let events = ps.poll("c", 10);
        assert_eq!(events.len(), 1);
        assert!(events[0].payload.contains("important"));
    }

    #[test]
    fn topic_isolation() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::Blocks, None).unwrap();
        ps.publish_tx("tx1", 50); // Different topic

        assert_eq!(ps.poll("c", 10).len(), 0);
    }

    #[test]
    fn unsubscribe_all() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::Blocks, None).unwrap();
        ps.subscribe("c", Topic::Transactions, None).unwrap();
        let removed = ps.unsubscribe_all("c");
        assert_eq!(removed, 2);
        assert_eq!(ps.total_subscriptions(), 0);
    }

    #[test]
    fn per_client_limit() {
        let ps = PubSub::new();
        for i in 0..MAX_SUBS_PER_CLIENT {
            ps.subscribe("c", Topic::Custom(format!("t{}", i)), None).unwrap();
        }
        assert!(ps.subscribe("c", Topic::Blocks, None).is_err());
    }

    #[test]
    fn poll_drains_events() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::Blocks, None).unwrap();
        ps.publish_block("b1", 1, 1);
        ps.publish_block("b2", 2, 2);

        let first = ps.poll("c", 1);
        assert_eq!(first.len(), 1);
        let second = ps.poll("c", 10);
        assert_eq!(second.len(), 1);
        let empty = ps.poll("c", 10);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn stats_tracking() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::Blocks, None).unwrap();
        ps.publish_block("b", 1, 1);

        assert_eq!(ps.total_published(), 1);
        assert_eq!(ps.total_delivered(), 1);
        assert_eq!(ps.total_subscriptions(), 1);
        assert_eq!(ps.total_clients(), 1);
    }

    #[test]
    fn reorg_event() {
        let ps = PubSub::new();
        ps.subscribe("c", Topic::ChainReorg, None).unwrap();
        ps.publish_reorg("old", "new", 3);

        let events = ps.poll("c", 10);
        assert_eq!(events.len(), 1);
        assert!(events[0].payload.contains("old"));
        assert!(events[0].payload.contains("depth"));
    }
}
