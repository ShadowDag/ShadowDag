// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    pub address:  String,

    pub services: u64,

    pub last_seen: u64,
}

impl PeerAddress {
    pub fn new(address: impl Into<String>, services: u64) -> Self {
        Self {
            address:  address.into(),
            services,
            last_seen: 0,
        }
    }

    pub fn new_now(address: impl Into<String>, services: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            address: address.into(),
            services,
            last_seen: now,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.address.is_empty() {
            return false;
        }

        let colon_count = self.address.chars().filter(|&c| c == ':').count();
        if self.address.starts_with('[') {
            colon_count >= 2
        } else {
            colon_count == 1
        }
    }
}
