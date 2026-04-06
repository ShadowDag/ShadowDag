// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use crate::errors::NetworkError;

pub const PROTOCOL_VERSION: u32     = 1;
pub const NETWORK_MAGIC:    [u8; 4] = [0x53, 0x44, 0x41, 0x47];
pub const MAX_INV_ITEMS:    usize   = 50_000;
pub const MAX_HEADERS_ITEMS: usize  = 2_000;
pub const MAX_ADDR_ITEMS:   usize   = 1_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvType {
    Transaction,
    Block,
    FilteredBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvItem {
    pub kind: InvType,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrEntry {
    pub address:  String,
    pub services: u64,
    pub time:     u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderMsg {
    pub hash:       String,
    pub height:     u64,
    pub parents:    Vec<String>,
    pub timestamp:  u64,
    pub difficulty: u64,
    pub nonce:      u64,
    pub blue_score: u64,
    pub merkle:     String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "data")]
pub enum NetworkMessage {
    Version {
        version:      u32,
        user_agent:   String,
        best_height:  u64,
        timestamp:    u64,
        services:     u64,
        relay:        bool,
    },
    VerAck,

    GetAddr,
    Addr { entries: Vec<AddrEntry> },

    Inv     { items: Vec<InvItem> },
    GetData { items: Vec<InvItem> },
    NotFound { items: Vec<InvItem> },

    GetHeaders { locator: Vec<String>, stop_hash: String },
    Headers    { headers: Vec<BlockHeaderMsg> },
    GetBlocks  { locator: Vec<String>, stop_hash: String },
    Block      { raw: String },

    Tx { raw: String },

    Ping { nonce: u64 },
    Pong { nonce: u64 },

    Reject { hash: String, code: u8, reason: String },

    MemPool,
}

impl NetworkMessage {
    pub fn name(&self) -> &'static str {
        match self {
            NetworkMessage::Version { .. } => "version",
            NetworkMessage::VerAck         => "verack",
            NetworkMessage::GetAddr        => "getaddr",
            NetworkMessage::Addr { .. }    => "addr",
            NetworkMessage::Inv { .. }     => "inv",
            NetworkMessage::GetData { .. } => "getdata",
            NetworkMessage::NotFound { .. }=> "notfound",
            NetworkMessage::GetHeaders { .. } => "getheaders",
            NetworkMessage::Headers { .. } => "headers",
            NetworkMessage::GetBlocks { .. }  => "getblocks",
            NetworkMessage::Block { .. }   => "block",
            NetworkMessage::Tx { .. }      => "tx",
            NetworkMessage::Ping { .. }    => "ping",
            NetworkMessage::Pong { .. }    => "pong",
            NetworkMessage::Reject { .. }  => "reject",
            NetworkMessage::MemPool        => "mempool",
        }
    }

    pub fn is_data_message(&self) -> bool {
        matches!(self,
            NetworkMessage::Block { .. } | NetworkMessage::Tx { .. } |
            NetworkMessage::Headers { .. }
        )
    }

    pub fn ping(nonce: u64) -> Self { NetworkMessage::Ping { nonce } }
    pub fn pong(nonce: u64) -> Self { NetworkMessage::Pong { nonce } }
    pub fn get_addr()       -> Self { NetworkMessage::GetAddr }
    pub fn verack()         -> Self { NetworkMessage::VerAck }
    pub fn mempool()        -> Self { NetworkMessage::MemPool }

    pub fn version(height: u64, agent: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        NetworkMessage::Version {
            version:     PROTOCOL_VERSION,
            user_agent:  agent.to_string(),
            best_height: height,
            timestamp:   SystemTime::now()
                             .duration_since(UNIX_EPOCH)
                             .map(|d| d.as_secs())
                             .unwrap_or(0),
            services:    1,
            relay:       true,
        }
    }

    pub fn inv_block(hash: &str) -> Self {
        NetworkMessage::Inv {
            items: vec![InvItem { kind: InvType::Block, hash: hash.to_string() }],
        }
    }

    pub fn inv_tx(hash: &str) -> Self {
        NetworkMessage::Inv {
            items: vec![InvItem { kind: InvType::Transaction, hash: hash.to_string() }],
        }
    }

    pub fn get_data(items: Vec<InvItem>) -> Self {
        NetworkMessage::GetData { items }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, NetworkError> {
        serde_json::to_vec(self).map_err(|e| NetworkError::Serialization(e.to_string()))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        serde_json::from_slice(data).map_err(|e| NetworkError::Serialization(e.to_string()))
    }

    pub fn to_wire_frame(&self) -> Result<Vec<u8>, NetworkError> {
        let payload = self.serialize()?;
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&NETWORK_MAGIC);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    pub fn from_wire_frame(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < 8 {
            return Err(NetworkError::Serialization("Frame too short".to_string()));
        }
        if data[..4] != NETWORK_MAGIC {
            return Err(NetworkError::Serialization("Invalid network magic".to_string()));
        }
        let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() < 8 + len {
            return Err(NetworkError::Serialization(
                format!("Incomplete frame: need {} got {}", 8 + len, data.len())
            ));
        }
        Self::deserialize(&data[8..8 + len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong_roundtrip() {
        let ping = NetworkMessage::ping(42);
        let data = ping.to_wire_frame().unwrap();
        let out  = NetworkMessage::from_wire_frame(&data).unwrap();
        assert_eq!(out.name(), "ping");
    }

    #[test]
    fn version_message_has_name() {
        let v = NetworkMessage::version(100, "ShadowDAG/0.1");
        assert_eq!(v.name(), "version");
    }

    #[test]
    fn inv_block_creates_block_inv() {
        let inv = NetworkMessage::inv_block("abc123");
        if let NetworkMessage::Inv { items } = inv {
            assert_eq!(items[0].kind, InvType::Block);
            assert_eq!(items[0].hash, "abc123");
        } else {
            panic!("expected Inv");
        }
    }

    #[test]
    fn invalid_magic_returns_error() {
        let bad = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'{', b'}'];
        assert!(NetworkMessage::from_wire_frame(&bad).is_err());
    }

    #[test]
    fn data_message_detection() {
        assert!(NetworkMessage::Block { raw: "x".into() }.is_data_message());
        assert!(!NetworkMessage::VerAck.is_data_message());
    }
}
