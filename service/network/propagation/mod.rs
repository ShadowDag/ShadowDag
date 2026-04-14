// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub mod dandelion;

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const SEEN_CACHE_MAX: usize = 100_000;
pub const SEEN_CACHE_TTL_SEC: u64 = 300;
pub const MAX_RELAY_PEERS: usize = 8;
pub const COMPACT_BLOCK_THRESHOLD: u64 = 512_000;

#[derive(Debug, Clone, PartialEq)]
pub enum PropagationPriority {
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone)]
pub struct PropEntry {
    pub hash: String,
    pub is_block: bool,
    pub added_at: Instant,
}

pub struct PropagationManager {
    peer_seen: HashMap<String, HashSet<String>>,

    global_seen: HashSet<String>,

    queue_high: VecDeque<PropEntry>,
    queue_normal: VecDeque<PropEntry>,
    queue_low: VecDeque<PropEntry>,
    pub stats_relayed_blocks: u64,
    pub stats_relayed_txs: u64,
}

impl Default for PropagationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PropagationManager {
    pub fn new() -> Self {
        Self {
            peer_seen: HashMap::new(),
            global_seen: HashSet::new(),
            queue_high: VecDeque::new(),
            queue_normal: VecDeque::new(),
            queue_low: VecDeque::new(),
            stats_relayed_blocks: 0,
            stats_relayed_txs: 0,
        }
    }

    pub fn announce_block(&mut self, hash: &str) {
        if self.global_seen.contains(hash) {
            return;
        }
        self.global_seen.insert(hash.to_string());
        self.queue_high.push_back(PropEntry {
            hash: hash.to_string(),
            is_block: true,
            added_at: Instant::now(),
        });
    }

    pub fn announce_tx(&mut self, hash: &str) {
        if self.global_seen.contains(hash) {
            return;
        }
        self.global_seen.insert(hash.to_string());
        self.queue_normal.push_back(PropEntry {
            hash: hash.to_string(),
            is_block: false,
            added_at: Instant::now(),
        });
    }

    pub fn mark_seen_by_peer(&mut self, peer: &str, hash: &str) {
        self.peer_seen
            .entry(peer.to_string())
            .or_default()
            .insert(hash.to_string());
    }

    pub fn peer_has_seen(&self, peer: &str, hash: &str) -> bool {
        self.peer_seen
            .get(peer)
            .map(|s| s.contains(hash))
            .unwrap_or(false)
    }

    pub fn get_items_for_peer(&mut self, peer: &str) -> Vec<PropEntry> {
        let mut result = Vec::new();

        for entry in &self.queue_high {
            if !self.peer_has_seen(peer, &entry.hash) {
                result.push(entry.clone());
            }
        }
        for entry in &self.queue_normal {
            if !self.peer_has_seen(peer, &entry.hash) {
                result.push(entry.clone());
            }
        }

        result
    }

    pub fn relay_block(&mut self, hash: &str, peers: &[String]) -> usize {
        let mut count = 0;
        for peer in peers.iter().take(MAX_RELAY_PEERS) {
            if !self.peer_has_seen(peer, hash) {
                self.mark_seen_by_peer(peer, hash);
                count += 1;
            }
        }
        self.stats_relayed_blocks += count as u64;
        count
    }

    pub fn relay_tx(&mut self, hash: &str, peers: &[String]) -> usize {
        let mut count = 0;
        for peer in peers.iter().take(MAX_RELAY_PEERS) {
            if !self.peer_has_seen(peer, hash) {
                self.mark_seen_by_peer(peer, hash);
                count += 1;
            }
        }
        self.stats_relayed_txs += count as u64;
        count
    }

    pub fn remove_peer(&mut self, peer: &str) {
        self.peer_seen.remove(peer);
    }

    pub fn prune_old_entries(&mut self, max_age_secs: u64) {
        let max_age = Duration::from_secs(max_age_secs);
        self.queue_high.retain(|e| e.added_at.elapsed() < max_age);
        self.queue_normal.retain(|e| e.added_at.elapsed() < max_age);
        self.queue_low.retain(|e| e.added_at.elapsed() < max_age);

        if self.global_seen.len() > SEEN_CACHE_MAX {
            self.global_seen.clear();
        }
    }

    pub fn queue_size(&self) -> usize {
        self.queue_high.len() + self.queue_normal.len() + self.queue_low.len()
    }

    pub fn peer_count(&self) -> usize {
        self.peer_seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_block_once() {
        let mut mgr = PropagationManager::new();
        mgr.announce_block("hash1");
        mgr.announce_block("hash1");
        assert_eq!(mgr.queue_size(), 1);
    }

    #[test]
    fn relay_block_skips_seen_peers() {
        let mut mgr = PropagationManager::new();
        mgr.mark_seen_by_peer("peer1", "hash1");
        let count = mgr.relay_block("hash1", &["peer1".to_string(), "peer2".to_string()]);
        assert_eq!(count, 1);
    }

    #[test]
    fn relay_tx_counts_relayed() {
        let mut mgr = PropagationManager::new();
        let peers: Vec<String> = (0..5).map(|i| format!("peer{}", i)).collect();
        mgr.relay_tx("tx1", &peers);
        assert_eq!(mgr.stats_relayed_txs, 5);
    }

    #[test]
    fn get_items_for_peer_excludes_seen() {
        let mut mgr = PropagationManager::new();
        mgr.announce_block("block1");
        mgr.mark_seen_by_peer("peer1", "block1");
        let items = mgr.get_items_for_peer("peer1");
        assert!(items.is_empty());
    }

    #[test]
    fn remove_peer_clears_seen_set() {
        let mut mgr = PropagationManager::new();
        mgr.mark_seen_by_peer("peer1", "h1");
        mgr.remove_peer("peer1");
        assert_eq!(mgr.peer_count(), 0);
    }
}
