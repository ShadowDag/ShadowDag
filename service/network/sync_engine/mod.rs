// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_PENDING_HEADERS:  usize = 4_096;
pub const MAX_PENDING_BLOCKS:   usize = 512;
pub const HEADER_BATCH_SIZE:    usize = 2_000;
pub const BLOCK_BATCH_SIZE:     usize = 64;
pub const SYNC_TIMEOUT_SECS:    u64   = 30;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncPhase {
    Idle,
    HeaderSync,
    BlockDownload,
    Verification,
    Complete,
}

#[derive(Debug, Clone)]
pub struct BlockRequest {
    pub hash:    String,
    pub peer:    String,
    pub queued:  Instant,
    pub retries: u32,
}

pub struct DagSyncEngine {
    pub phase:            SyncPhase,
    pub local_dag_tips:   HashSet<String>,
    pub remote_tips:      HashMap<String, String>,
    pending_headers:      HashMap<String, BlockRequest>,
    pending_blocks:       HashMap<String, BlockRequest>,
    _header_queue:         VecDeque<String>,
    block_queue:          VecDeque<String>,
    verified_blocks:      HashSet<String>,
    failed_peers:         HashSet<String>,
    pub synced_count:     u64,
}

impl Default for DagSyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DagSyncEngine {
    pub fn new() -> Self {
        Self {
            phase:           SyncPhase::Idle,
            local_dag_tips:  HashSet::new(),
            remote_tips:     HashMap::new(),
            pending_headers: HashMap::new(),
            pending_blocks:  HashMap::new(),
            _header_queue:    VecDeque::new(),
            block_queue:     VecDeque::new(),
            verified_blocks: HashSet::new(),
            failed_peers:    HashSet::new(),
            synced_count:    0,
        }
    }

    pub fn set_local_tips(&mut self, tips: Vec<String>) {
        self.local_dag_tips = tips.into_iter().collect();
    }

    pub fn on_peer_tip(&mut self, peer: &str, tip: &str) {
        if !self.local_dag_tips.contains(tip) {
            self.remote_tips.insert(peer.to_string(), tip.to_string());
            if self.phase == SyncPhase::Idle {
                self.phase = SyncPhase::HeaderSync;
            }
        }
    }

    pub fn build_locator(&self) -> Vec<String> {
        self.local_dag_tips.iter().cloned().collect()
    }

    pub fn request_header(&mut self, hash: &str, peer: &str) -> bool {
        if self.pending_headers.len() >= MAX_PENDING_HEADERS { return false; }
        if self.verified_blocks.contains(hash) { return false; }
        self.pending_headers.insert(hash.to_string(), BlockRequest {
            hash:    hash.to_string(),
            peer:    peer.to_string(),
            queued:  Instant::now(),
            retries: 0,
        });
        true
    }

    pub fn on_headers(&mut self, hashes: Vec<String>, _peer: &str) {
        let new_count = hashes.iter()
            .filter(|h| !self.verified_blocks.contains(*h) && !self.block_queue.contains(h))
            .count();
        for hash in hashes {
            if !self.verified_blocks.contains(&hash) {
                self.block_queue.push_back(hash.clone());
            }
            self.pending_headers.remove(&hash);
        }
        if new_count > 0 {
            self.phase = SyncPhase::BlockDownload;
        }
    }

    pub fn next_block_request(&mut self, peer: &str) -> Option<String> {
        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS { return None; }
        let hash = self.block_queue.pop_front()?;
        self.pending_blocks.insert(hash.clone(), BlockRequest {
            hash:    hash.clone(),
            peer:    peer.to_string(),
            queued:  Instant::now(),
            retries: 0,
        });
        Some(hash)
    }

    pub fn on_block_received(&mut self, hash: &str) {
        self.pending_blocks.remove(hash);
        self.verified_blocks.insert(hash.to_string());
        // Prune verified_blocks to prevent unbounded memory growth
        if self.verified_blocks.len() > 100_000 {
            // Keep only the most recent entries (clear and rebuild would be better with LRU)
            let excess = self.verified_blocks.len() - 50_000;
            let to_remove: Vec<String> = self.verified_blocks.iter().take(excess).cloned().collect();
            for h in to_remove { self.verified_blocks.remove(&h); }
        }
        self.local_dag_tips.insert(hash.to_string());
        self.synced_count += 1;

        if self.pending_blocks.is_empty() && self.block_queue.is_empty() {
            self.phase = SyncPhase::Complete;
        }
    }

    pub fn handle_timeouts(&mut self) -> Vec<String> {
        let timeout = Duration::from_secs(SYNC_TIMEOUT_SECS);
        let mut requeue = Vec::new();

        let stale: Vec<String> = self.pending_blocks.iter()
            .filter(|(_, r)| r.queued.elapsed() > timeout)
            .map(|(h, _)| h.clone())
            .collect();

        for hash in stale {
            if let Some(mut req) = self.pending_blocks.remove(&hash) {
                if req.retries < 3 {
                    req.retries += 1;
                    self.block_queue.push_front(hash.clone());
                    requeue.push(hash);
                } else {
                    self.failed_peers.insert(req.peer.clone());
                    self.block_queue.push_back(hash);
                }
            }
        }

        requeue
    }

    pub fn is_synced(&self)         -> bool  { self.phase == SyncPhase::Complete }
    pub fn pending_count(&self)     -> usize { self.pending_blocks.len() }
    pub fn queue_count(&self)       -> usize { self.block_queue.len() }
    pub fn is_failed_peer(&self, p: &str) -> bool { self.failed_peers.contains(p) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_phase_is_idle() {
        let engine = DagSyncEngine::new();
        assert_eq!(engine.phase, SyncPhase::Idle);
    }

    #[test]
    fn on_peer_tip_starts_header_sync() {
        let mut engine = DagSyncEngine::new();
        engine.on_peer_tip("peer1", "newhash");
        assert_eq!(engine.phase, SyncPhase::HeaderSync);
    }

    #[test]
    fn known_tip_does_not_start_sync() {
        let mut engine = DagSyncEngine::new();
        engine.set_local_tips(vec!["known".into()]);
        engine.on_peer_tip("peer1", "known");
        assert_eq!(engine.phase, SyncPhase::Idle);
    }

    #[test]
    fn on_headers_queues_blocks() {
        let mut engine = DagSyncEngine::new();
        engine.on_headers(vec!["b1".into(), "b2".into()], "p1");
        assert_eq!(engine.queue_count(), 2);
    }

    #[test]
    fn on_block_received_marks_complete_when_done() {
        let mut engine = DagSyncEngine::new();
        engine.on_headers(vec!["b1".into()], "p1");
        let hash = engine.next_block_request("p1").unwrap();
        engine.on_block_received(&hash);
        assert!(engine.is_synced());
    }
}
