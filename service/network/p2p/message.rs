// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

// PeerAddress is defined in domain/types/peer_address.rs and re-exported here
// for backward compatibility.
pub use crate::domain::types::peer_address::PeerAddress;

/// DEPRECATED: Use P2PMessage from p2p.rs for wire protocol.
/// NetworkMessage is retained for JSON-based APIs only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum NetworkMessage {
    Version {
        version:    u32,
        height:     u64,
        timestamp:  u64,
        user_agent: String,
        chain_id:   u32,
    },

    VerAck,

    GetPeers,

    PeerList(Vec<PeerAddress>),

    Inv { items: Vec<InvItem> },

    GetData { items: Vec<InvItem> },

    GetHeaders { from_hash: String, count: u32 },

    Headers { hashes: Vec<String> },

    GetBlock { hash: String },

    Block { data: String },

    Tx { data: String },

    Ping { nonce: u64 },

    Pong { nonce: u64 },

    Reject { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InvItem {
    pub kind: String,

    pub hash: String,
}

impl InvItem {
    pub fn block(hash: impl Into<String>) -> Self {
        Self { kind: "block".into(), hash: hash.into() }
    }
    pub fn tx(hash: impl Into<String>) -> Self {
        Self { kind: "tx".into(), hash: hash.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn peer_address_valid_ipv4() {
        let pa = PeerAddress::new("192.168.1.1:9333", 1);
        assert!(pa.is_valid());
    }

    #[test]
    fn peer_address_valid_ipv6() {
        let pa = PeerAddress::new("[::1]:9333", 1);
        assert!(pa.is_valid());
    }

    #[test]
    fn peer_address_invalid_empty() {
        let pa = PeerAddress::new("", 0);
        assert!(!pa.is_valid());
    }

    #[test]
    fn get_peers_round_trips_json() {
        let msg = NetworkMessage::GetPeers;
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: NetworkMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(msg, back);
    }

    #[test]
    fn peer_list_round_trips_json() {
        let peers = vec![
            PeerAddress::new("10.0.0.1:9333", 1),
            PeerAddress::new("10.0.0.2:9333", 1),
        ];
        let msg = NetworkMessage::PeerList(peers.clone());
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: NetworkMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(msg, back);
    }

    #[test]
    fn inv_item_constructors() {
        let b = InvItem::block("abc123");
        assert_eq!(b.kind, "block");
        let t = InvItem::tx("def456");
        assert_eq!(t.kind, "tx");
    }
}
