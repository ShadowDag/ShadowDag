// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// WebSocket RPC Server — Real-time event subscriptions over WebSocket.
//
// Supports:
//   - All JSON-RPC methods (same as HTTP RPC)
//   - subscribe/unsubscribe for real-time events
//   - Block notifications, TX notifications, DAG tip changes
//
// Port: 18787 (configurable)
// ═══════════════════════════════════════════════════════════════════════════

use crate::slog_warn;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::broadcast;

/// Subscription types for real-time event streaming
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionType {
    NewBlock,
    NewTransaction,
    DagTipsChanged,
    UtxoChanged,
    VirtualChainChanged,
    PruningCompleted,
}

impl SubscriptionType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "new_block" | "newBlock" => Some(Self::NewBlock),
            "new_transaction" | "newTx" => Some(Self::NewTransaction),
            "dag_tips" | "dagTips" => Some(Self::DagTipsChanged),
            "utxo_changed" | "utxoChanged" => Some(Self::UtxoChanged),
            "virtual_chain" | "virtualChain" => Some(Self::VirtualChainChanged),
            "pruning" | "pruningCompleted" => Some(Self::PruningCompleted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewBlock => "new_block",
            Self::NewTransaction => "new_transaction",
            Self::DagTipsChanged => "dag_tips",
            Self::UtxoChanged => "utxo_changed",
            Self::VirtualChainChanged => "virtual_chain",
            Self::PruningCompleted => "pruning",
        }
    }
}

/// WebSocket event payload
#[derive(Debug, Clone)]
pub struct WsEvent {
    pub event_type: SubscriptionType,
    pub payload: String, // JSON string
}

/// Subscription tracking
pub struct WsSubscription {
    pub id: u64,
    pub sub_type: SubscriptionType,
}

/// WebSocket RPC server configuration and event bus
pub struct WsServer {
    pub port: u16,
    next_sub_id: AtomicU64,
    subscriptions: Arc<Mutex<HashMap<u64, Vec<WsSubscription>>>>,
    event_tx: broadcast::Sender<WsEvent>,
    _event_rx: broadcast::Receiver<WsEvent>,
    pub max_subscriptions_per_conn: usize,
}

impl WsServer {
    pub fn new(port: u16) -> Self {
        let (tx, rx) = broadcast::channel(1024);
        Self {
            port,
            next_sub_id: AtomicU64::new(1),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            event_tx: tx,
            _event_rx: rx,
            max_subscriptions_per_conn: 10,
        }
    }

    /// Get a new broadcast receiver for events.
    ///
    /// **Important:** The broadcast channel delivers ALL events to every
    /// receiver. Callers MUST use [`should_deliver`] to filter events
    /// according to the connection's registered subscriptions before
    /// forwarding them to the client.
    pub fn subscribe_events(&self) -> broadcast::Receiver<WsEvent> {
        self.event_tx.subscribe()
    }

    /// Check whether an event should be delivered to a specific connection,
    /// based on that connection's registered subscription types.
    ///
    /// Connection handlers should call this for every event received from
    /// the broadcast channel and drop events that return `false`.
    pub fn should_deliver(&self, conn_id: u64, event_type: SubscriptionType) -> bool {
        self.subscriptions
            .lock()
            .map(|subs| {
                subs.get(&conn_id)
                    .map(|conn_subs| conn_subs.iter().any(|s| s.sub_type == event_type))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Publish an event to subscribers of the given type.
    ///
    /// Because `broadcast::Sender` delivers to ALL receivers, per-connection
    /// filtering must be done on the receive side using [`should_deliver`].
    /// This method short-circuits when **no** connection has subscribed to
    /// `event_type` at all, avoiding unnecessary broadcast traffic.
    pub fn publish(&self, event_type: SubscriptionType, payload: String) {
        // Only send if at least one connection has subscribed to this event type
        let has_subscribers = self
            .subscriptions
            .lock()
            .map(|subs| {
                subs.values()
                    .any(|conn_subs| conn_subs.iter().any(|s| s.sub_type == event_type))
            })
            .unwrap_or(false);

        if !has_subscribers {
            return; // No subscribers for this event type — skip broadcast
        }

        let event = WsEvent {
            event_type,
            payload,
        };
        if let Err(_e) = self.event_tx.send(event) {
            slog_warn!("rpc", "ws_event_dropped", event_type => format!("{:?}", event_type));
        }
    }

    /// Register a subscription for a connection
    pub fn add_subscription(&self, conn_id: u64, sub_type: SubscriptionType) -> Option<u64> {
        let mut subs = self.subscriptions.lock().ok()?;
        let conn_subs = subs.entry(conn_id).or_default();
        if conn_subs.len() >= self.max_subscriptions_per_conn {
            return None; // Limit reached — don't allocate sub_id
        }
        let sub_id = self.next_sub_id.fetch_add(1, Ordering::SeqCst);
        conn_subs.push(WsSubscription {
            id: sub_id,
            sub_type,
        });
        Some(sub_id)
    }

    /// Remove a subscription
    pub fn remove_subscription(&self, conn_id: u64, sub_id: u64) -> bool {
        if let Ok(mut subs) = self.subscriptions.lock() {
            if let Some(conn_subs) = subs.get_mut(&conn_id) {
                let before = conn_subs.len();
                conn_subs.retain(|s| s.id != sub_id);
                let removed = conn_subs.len() < before;
                // Clean up empty entry so connection_count() stays accurate
                if conn_subs.is_empty() {
                    subs.remove(&conn_id);
                }
                return removed;
            }
        }
        false
    }

    /// Remove all subscriptions for a connection (on disconnect)
    pub fn remove_connection(&self, conn_id: u64) {
        if let Ok(mut subs) = self.subscriptions.lock() {
            subs.remove(&conn_id);
        }
    }

    /// Get active subscription count
    pub fn subscription_count(&self) -> usize {
        if let Ok(subs) = self.subscriptions.lock() {
            subs.values().map(|v| v.len()).sum()
        } else {
            0
        }
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        if let Ok(subs) = self.subscriptions.lock() {
            subs.len()
        } else {
            0
        }
    }

    /// Notify: new block accepted
    pub fn notify_new_block(&self, hash: &str, height: u64, tx_count: usize) {
        let payload = serde_json::json!({
            "hash": hash,
            "height": height,
            "tx_count": tx_count,
        })
        .to_string();
        self.publish(SubscriptionType::NewBlock, payload);
    }

    /// Notify: new transaction in mempool
    pub fn notify_new_transaction(&self, txid: &str, fee: u64) {
        let payload = serde_json::json!({
            "txid": txid,
            "fee": fee,
        })
        .to_string();
        self.publish(SubscriptionType::NewTransaction, payload);
    }

    /// Notify: DAG tips changed
    pub fn notify_tips_changed(&self, tip_count: usize, best_hash: &str) {
        let payload = serde_json::json!({
            "tip_count": tip_count,
            "best_hash": best_hash,
        })
        .to_string();
        self.publish(SubscriptionType::DagTipsChanged, payload);
    }

    /// Notify: pruning completed
    pub fn notify_pruning(&self, pruned_count: u64, lowest_height: u64) {
        let payload = serde_json::json!({
            "pruned_count": pruned_count,
            "lowest_height": lowest_height,
        })
        .to_string();
        self.publish(SubscriptionType::PruningCompleted, payload);
    }

    /// Available subscription types
    pub fn available_subscriptions() -> Vec<&'static str> {
        vec![
            "new_block",
            "new_transaction",
            "dag_tips",
            "utxo_changed",
            "virtual_chain",
            "pruning",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_lifecycle() {
        let server = WsServer::new(18787);
        let sub_id = server
            .add_subscription(1, SubscriptionType::NewBlock)
            .expect("subscription should succeed");
        assert!(sub_id > 0);
        assert_eq!(server.subscription_count(), 1);
        assert_eq!(server.connection_count(), 1);

        server.remove_subscription(1, sub_id);
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn connection_cleanup() {
        let server = WsServer::new(18787);
        server.add_subscription(1, SubscriptionType::NewBlock);
        server.add_subscription(1, SubscriptionType::NewTransaction);
        server.add_subscription(2, SubscriptionType::DagTipsChanged);
        assert_eq!(server.subscription_count(), 3);

        server.remove_connection(1);
        assert_eq!(server.subscription_count(), 1);
        assert_eq!(server.connection_count(), 1);
    }

    #[test]
    fn max_subscriptions_per_connection() {
        let server = WsServer::new(18787);
        let mut accepted = 0;
        for _ in 0..15 {
            if server
                .add_subscription(1, SubscriptionType::NewBlock)
                .is_some()
            {
                accepted += 1;
            }
        }
        assert_eq!(accepted, server.max_subscriptions_per_conn);
        assert_eq!(
            server.subscription_count(),
            server.max_subscriptions_per_conn
        );
    }

    #[test]
    fn event_broadcast() {
        let server = WsServer::new(18787);
        let mut rx = server.subscribe_events();

        // Register a subscription so publish() doesn't short-circuit
        server.add_subscription(1, SubscriptionType::NewBlock);

        server.notify_new_block("abc123", 100, 5);

        match rx.try_recv() {
            Ok(event) => {
                assert_eq!(event.event_type, SubscriptionType::NewBlock);
                assert!(event.payload.contains("abc123"));
            }
            Err(_) => panic!("Should have received event"),
        }
    }

    #[test]
    fn should_deliver_filters_by_subscription() {
        let server = WsServer::new(18787);
        // conn 1 subscribes only to NewBlock
        server.add_subscription(1, SubscriptionType::NewBlock);
        // conn 2 subscribes only to NewTransaction
        server.add_subscription(2, SubscriptionType::NewTransaction);

        // conn 1 should receive NewBlock but NOT NewTransaction
        assert!(server.should_deliver(1, SubscriptionType::NewBlock));
        assert!(!server.should_deliver(1, SubscriptionType::NewTransaction));

        // conn 2 should receive NewTransaction but NOT NewBlock
        assert!(server.should_deliver(2, SubscriptionType::NewTransaction));
        assert!(!server.should_deliver(2, SubscriptionType::NewBlock));

        // Unknown conn should not receive anything
        assert!(!server.should_deliver(99, SubscriptionType::NewBlock));
    }

    #[test]
    fn subscription_type_parsing() {
        assert_eq!(
            SubscriptionType::from_str("new_block"),
            Some(SubscriptionType::NewBlock)
        );
        assert_eq!(
            SubscriptionType::from_str("newTx"),
            Some(SubscriptionType::NewTransaction)
        );
        assert_eq!(SubscriptionType::from_str("invalid"), None);
    }
}
