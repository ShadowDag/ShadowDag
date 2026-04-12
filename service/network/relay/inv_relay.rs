// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Inventory Relay — Broadcasts inventory announcements (block hashes,
// tx hashes) to connected peers so they can request the full data.
//
// Pushes P2PMessage::Inv to the global outbound queue; each peer
// connection thread drains the queue and writes to its TCP socket.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::service::network::p2p::peer_manager::PeerManager;
use crate::service::network::p2p::p2p::{
    push_outbound, P2PMessage,
    InvItem as P2PInvItem,
};

/// Maximum inventory items per broadcast message.
/// Must match protocol::MAX_INV_PER_MSG (5,000) — exceeding the wire
/// limit causes peers to reject the entire Inv message.
pub const MAX_INV_PER_MSG: usize = 5_000;

/// Seen inventory hashes — prevent re-broadcasting items we've already sent.
/// Capped at 100K entries; cleared when full.
static SEEN_INV: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::with_capacity(4096)));

/// Inventory item types
#[derive(Debug, Clone, PartialEq)]
pub enum InvType {
    Block,
    Transaction,
}

/// A single inventory item
#[derive(Debug, Clone)]
pub struct InvItem {
    pub inv_type: InvType,
    pub hash:     String,
}

pub struct InvRelay;

impl InvRelay {
    /// Broadcast **transaction** inventory items to all connected peers.
    /// Each peer receives a list of hashes they can then request via GetData.
    ///
    /// **TX-only**: all items are tagged `kind: "tx"`. For mixed block+tx
    /// inventory, use [`broadcast_typed`] with explicit [`InvItem`] entries.
    ///
    /// Items are pushed to the P2P outbound queue; peer threads drain and
    /// write to their sockets — no direct socket access needed here.
    pub fn broadcast(items: &[String], _peers: &PeerManager) {
        if items.is_empty() {
            return;
        }

        // Deduplicate: skip items we've already broadcast recently
        let new_items: Vec<String> = if let Ok(mut seen) = SEEN_INV.lock() {
            if seen.len() > 100_000 { seen.clear(); }
            items.iter()
                .filter(|h| seen.insert((*h).clone()))
                .cloned()
                .collect()
        } else {
            items.to_vec()
        };

        if new_items.is_empty() {
            return;
        }

        // Chunk into batches and push to outbound queue
        for chunk in new_items.chunks(MAX_INV_PER_MSG) {
            let inv_items: Vec<P2PInvItem> = chunk.iter().map(|hash| P2PInvItem {
                kind: "tx".to_string(),
                hash: hash.clone(),
            }).collect();

            push_outbound(P2PMessage::Inv { items: inv_items });
        }
    }

    /// Broadcast typed inventory items (with explicit Block/Transaction type).
    pub fn broadcast_typed(items: &[InvItem], _peers: &PeerManager) {
        if items.is_empty() {
            return;
        }

        // Deduplicate
        let new_items: Vec<&InvItem> = if let Ok(mut seen) = SEEN_INV.lock() {
            if seen.len() > 100_000 { seen.clear(); }
            items.iter()
                .filter(|i| seen.insert(i.hash.clone()))
                .collect()
        } else {
            items.iter().collect()
        };

        if new_items.is_empty() {
            return;
        }

        let inv_items: Vec<P2PInvItem> = new_items.iter().map(|item| {
            let kind = match item.inv_type {
                InvType::Block       => "block",
                InvType::Transaction => "tx",
            };
            P2PInvItem {
                kind: kind.to_string(),
                hash: item.hash.clone(),
            }
        }).collect();

        for chunk in inv_items.chunks(MAX_INV_PER_MSG) {
            push_outbound(P2PMessage::Inv { items: chunk.to_vec() });
        }
    }

    /// Receive an inventory announcement from a peer.
    /// Returns true if this is a new item we haven't seen before.
    pub fn receive(item: &str, from_peer: &str) -> bool {
        if item.is_empty() || from_peer.is_empty() {
            return false;
        }
        // Check seen set — only request data for items we haven't seen
        if let Ok(mut seen) = SEEN_INV.lock() {
            if seen.len() > 100_000 { seen.clear(); }
            seen.insert(item.to_string())
        } else {
            true
        }
    }
}
