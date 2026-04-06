// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch, IteratorMode};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::types::peer_address::PeerAddress;
use crate::slog_error;

pub const MAX_STORED_PEERS: usize = 2_048;

pub const MAX_GETPEERS_RESPONSE: usize = 200;

const PFX_PEER: &str = "peer:";
const PFX_BAN:  &str = "ban:";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn encode_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn decode_u64(b: &[u8]) -> u64 {
    if b.len() < 8 { return 0; }
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub struct PeerStore {
    db: DB,
}

impl PeerStore {
    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(8 * 1024 * 1024);
        match DB::open(&opts, Path::new(path)) {
            Ok(db) => {
                Some(Self { db })
            }
            Err(_e) => {
                None
            }
        }
    }

    pub fn new_default() -> Result<Self, crate::errors::StorageError> {
        let path = crate::config::node::node_config::NetworkMode::base_data_dir()
            .join("peers_store");
        Self::new(&path.to_string_lossy()).ok_or_else(|| {
            slog_error!("storage", "peer_store_open_failed");
            crate::errors::StorageError::OpenFailed {
                path: path.to_string_lossy().to_string(),
                reason: "PeerStore::new returned None".to_string(),
            }
        })
    }

    pub fn add_peer(&self, addr: &PeerAddress) {
        if self.is_banned(&addr.address) {
            return;
        }
        if addr.address.is_empty() {
            return;
        }
        let key   = format!("{}{}", PFX_PEER, addr.address);
        let value = encode_u64(addr.last_seen.max(now_secs()));
        if let Err(_e) = self.db.put(key.as_bytes(), value) {
        }
    }

    pub fn add_raw(&self, address: &str) {
        let pa = PeerAddress::new_now(address, 0);
        self.add_peer(&pa);
    }

    pub fn remove_peer(&self, address: &str) {
        let key = format!("{}{}", PFX_PEER, address);
        if let Err(_e) = self.db.delete(key.as_bytes()) {
        }
    }

    pub fn get_all_peers(&self, max: usize) -> Vec<PeerAddress> {
        let prefix = PFX_PEER.as_bytes();
        let mut peers = Vec::new();

        let iter = self.db.iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward));
        for item in iter {
            if peers.len() >= max { break; }
            match item {
                Ok((k, v)) => {
                    if !k.starts_with(prefix) { break; }
                    let addr_str = match std::str::from_utf8(&k[prefix.len()..]) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    };
                    if self.is_banned(&addr_str) { continue; }
                    let last_seen = decode_u64(&v);
                    peers.push(PeerAddress {
                        address:  addr_str,
                        services: 0,
                        last_seen,
                    });
                }
                Err(_) => break,
            }
        }
        peers
    }

    pub fn get_peers_for_relay(&self) -> Vec<PeerAddress> {
        self.get_all_peers(MAX_GETPEERS_RESPONSE)
    }

    pub fn peer_count(&self) -> usize {
        self.get_all_peers(MAX_STORED_PEERS).len()
    }

    pub fn ban_peer(&self, address: &str, duration_secs: u64) {
        let expiry = now_secs() + duration_secs;
        let key    = format!("{}{}", PFX_BAN, address);
        let value  = encode_u64(expiry);
        if let Err(_e) = self.db.put(key.as_bytes(), value) {
        }

        self.remove_peer(address);
    }

    pub fn is_banned(&self, address: &str) -> bool {
        let key = format!("{}{}", PFX_BAN, address);
        match self.db.get(key.as_bytes()) {
            Ok(Some(v)) => {
                let expiry = decode_u64(&v);
                now_secs() < expiry
            }
            _ => false,
        }
    }

    pub fn prune_banned(&self) {
        let prefix = PFX_BAN.as_bytes();
        let now    = now_secs();
        let mut batch = WriteBatch::default();
        let mut pruned = 0usize;

        let iter = self.db.iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward));
        for item in iter {
            match item {
                Ok((k, v)) => {
                    if !k.starts_with(prefix) { break; }
                    let expiry = decode_u64(&v);
                    if now >= expiry {
                        batch.delete(&k);
                        pruned += 1;
                    }
                }
                Err(_) => break,
            }
        }

        if pruned > 0 {
            if let Err(_e) = self.db.write(batch) {
            } 
        }
    }

    pub fn add_peer_batch(&self, peers: &[PeerAddress]) {
        let current_count = self.peer_count();
        let space = MAX_STORED_PEERS.saturating_sub(current_count);
        if space == 0 {
            return;
        }

        let mut batch = WriteBatch::default();
        let mut added = 0usize;

        for pa in peers.iter().take(space) {
            if pa.address.is_empty() || self.is_banned(&pa.address) {
                continue;
            }
            let key   = format!("{}{}", PFX_PEER, pa.address);
            let value = encode_u64(pa.last_seen.max(now_secs()));
            batch.put(key.as_bytes(), value);
            added += 1;
        }

        if added > 0 {
            if let Err(_e) = self.db.write(batch) {
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> PeerStore {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        PeerStore::new(&format!("/tmp/test_peerstore_{}", ts))
            .expect("open test peer store")
    }

    #[test]
    fn add_and_retrieve_peer() {
        let store = make_store();
        let pa = PeerAddress::new("10.0.0.1:9333", 1);
        store.add_peer(&pa);
        let peers = store.get_all_peers(100);
        assert!(peers.iter().any(|p| p.address == "10.0.0.1:9333"),
            "Stored peer must appear in get_all_peers");
    }

    #[test]
    fn remove_peer_disappears() {
        let store = make_store();
        store.add_raw("10.0.0.2:9333");
        store.remove_peer("10.0.0.2:9333");
        let peers = store.get_all_peers(100);
        assert!(!peers.iter().any(|p| p.address == "10.0.0.2:9333"),
            "Removed peer must not appear");
    }

    #[test]
    fn banned_peer_excluded_from_list() {
        let store = make_store();
        store.add_raw("10.0.0.3:9333");
        store.ban_peer("10.0.0.3:9333", 3600);
        let peers = store.get_all_peers(100);
        assert!(!peers.iter().any(|p| p.address == "10.0.0.3:9333"),
            "Banned peer must not appear in peer list");
    }

    #[test]
    fn is_banned_works() {
        let store = make_store();
        store.ban_peer("10.0.0.4:9333", 3600);
        assert!(store.is_banned("10.0.0.4:9333"));
        assert!(!store.is_banned("10.0.0.5:9333"));
    }

    #[test]
    fn expired_ban_not_active() {
        let store = make_store();

        let key = "ban:10.0.0.6:9333".to_string();
        let expiry: u64 = 0;
        store.db.put(key.as_bytes(), expiry.to_le_bytes()).ok();
        assert!(!store.is_banned("10.0.0.6:9333"),
            "Expired ban must not count as active");
    }

    #[test]
    fn prune_removes_expired_bans() {
        let store = make_store();

        let key = "ban:stale_peer:9333".to_string();
        store.db.put(key.as_bytes(), 0u64.to_le_bytes()).ok();
        store.prune_banned();
        assert!(!store.is_banned("stale_peer:9333"),
            "Pruned ban must not exist");
    }

    #[test]
    fn add_peer_batch_respects_cap() {
        let store = make_store();
        let peers: Vec<PeerAddress> = (0..300)
            .map(|i| PeerAddress::new(format!("11.0.{}.1:9333", i), 0))
            .collect();
        store.add_peer_batch(&peers);
        let count = store.peer_count();
        assert!(count <= MAX_STORED_PEERS, "Peer count must not exceed MAX_STORED_PEERS");
    }
}
