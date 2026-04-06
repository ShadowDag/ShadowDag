// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub mod chain_verifier;

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_IN_FLIGHT:        usize    = 128;
pub const PEER_TIMEOUT_SECS:    u64      = 15;
pub const MAX_RETRIES:          u32      = 3;
pub const HEADERS_BATCH_SIZE:   usize    = 2_000;
pub const BLOCKS_BATCH_SIZE:    usize    = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    Idle,
    FetchingHeaders,
    FetchingBlocks,
    Synced,
}

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub hash:        String,
    pub peer:        String,
    pub sent_at:     Instant,
    pub retries:     u32,
}

pub struct SyncManager {
    pub state:          SyncState,
    pub local_height:   u64,
    pub best_height:    u64,
    pending_headers:    HashMap<String, PendingRequest>,
    pending_blocks:     HashMap<String, PendingRequest>,
    header_queue:       VecDeque<String>,
    block_queue:        VecDeque<String>,
    downloaded_headers: HashSet<String>,
    downloaded_blocks:  HashSet<String>,
    slow_peers:         HashSet<String>,
}

impl SyncManager {
    pub fn new(local_height: u64) -> Self {
        Self {
            state:              SyncState::Idle,
            local_height,
            best_height:        0,
            pending_headers:    HashMap::new(),
            pending_blocks:     HashMap::new(),
            header_queue:       VecDeque::new(),
            block_queue:        VecDeque::new(),
            downloaded_headers: HashSet::new(),
            downloaded_blocks:  HashSet::new(),
            slow_peers:         HashSet::new(),
        }
    }

    pub fn start_sync(&mut self, best_height: u64) {
        if self.local_height >= best_height {
            self.state = SyncState::Synced;
            return;
        }
        self.best_height = best_height;
        self.state = SyncState::FetchingHeaders;
    }

    pub fn request_headers(&mut self, from_hash: &str, peer: &str) -> bool {
        if self.pending_headers.len() >= MAX_IN_FLIGHT { return false; }
        if self.downloaded_headers.contains(from_hash) { return false; }
        self.pending_headers.insert(from_hash.to_string(), PendingRequest {
            hash:    from_hash.to_string(),
            peer:    peer.to_string(),
            sent_at: Instant::now(),
            retries: 0,
        });
        true
    }

    pub fn on_headers_received(&mut self, hashes: Vec<String>, _peer: &str) {
        for hash in &hashes {
            if !self.downloaded_blocks.contains(hash) {
                self.block_queue.push_back(hash.clone());
            }
            self.downloaded_headers.insert(hash.clone());
        }
        if !hashes.is_empty() {
            self.state = SyncState::FetchingBlocks;
        }
    }

    pub fn request_next_block(&mut self, peer: &str) -> Option<String> {
        if self.pending_blocks.len() >= MAX_IN_FLIGHT { return None; }
        let hash = self.block_queue.pop_front()?;
        self.pending_blocks.insert(hash.clone(), PendingRequest {
            hash:    hash.clone(),
            peer:    peer.to_string(),
            sent_at: Instant::now(),
            retries: 0,
        });
        Some(hash)
    }

    pub fn on_block_received(&mut self, hash: &str) {
        self.pending_blocks.remove(hash);
        self.downloaded_blocks.insert(hash.to_string());
        if self.pending_blocks.is_empty() && self.block_queue.is_empty() {
            self.local_height = self.best_height;
            self.state = SyncState::Synced;
        }
    }

    pub fn handle_timeouts(&mut self) -> Vec<(String, String)> {
        let timeout = Duration::from_secs(PEER_TIMEOUT_SECS);
        let mut retry_list = Vec::new();

        let stale_h: Vec<String> = self.pending_headers.iter()
            .filter(|(_, r)| r.sent_at.elapsed() > timeout)
            .map(|(h, _)| h.clone())
            .collect();
        for hash in stale_h {
            if let Some(mut req) = self.pending_headers.remove(&hash) {
                if req.retries < MAX_RETRIES {
                    req.retries += 1;
                    retry_list.push((hash.clone(), req.peer.clone()));
                    self.pending_headers.insert(hash, req);
                } else {
                    self.slow_peers.insert(req.peer.clone());
                    self.header_queue.push_front(hash);
                }
            }
        }

        let stale_b: Vec<String> = self.pending_blocks.iter()
            .filter(|(_, r)| r.sent_at.elapsed() > timeout)
            .map(|(h, _)| h.clone())
            .collect();
        for hash in stale_b {
            if let Some(mut req) = self.pending_blocks.remove(&hash) {
                if req.retries < MAX_RETRIES {
                    req.retries += 1;
                    retry_list.push((hash.clone(), req.peer.clone()));
                    self.pending_blocks.insert(hash, req);
                } else {
                    self.slow_peers.insert(req.peer.clone());
                    self.block_queue.push_front(hash);
                }
            }
        }

        retry_list
    }

    pub fn is_synced(&self)               -> bool    { self.state == SyncState::Synced }
    pub fn pending_block_count(&self)     -> usize   { self.pending_blocks.len() }
    pub fn queued_block_count(&self)      -> usize   { self.block_queue.len() }
    pub fn downloaded_block_count(&self)  -> usize   { self.downloaded_blocks.len() }
    pub fn is_slow_peer(&self, p: &str)   -> bool    { self.slow_peers.contains(p) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_idle() {
        let mgr = SyncManager::new(0);
        assert_eq!(mgr.state, SyncState::Idle);
    }

    #[test]
    fn start_sync_sets_fetching() {
        let mut mgr = SyncManager::new(0);
        mgr.start_sync(100);
        assert_eq!(mgr.state, SyncState::FetchingHeaders);
    }

    #[test]
    fn already_synced_if_at_best() {
        let mut mgr = SyncManager::new(100);
        mgr.start_sync(50);
        assert!(mgr.is_synced());
    }

    #[test]
    fn on_headers_received_queues_blocks() {
        let mut mgr = SyncManager::new(0);
        mgr.start_sync(10);
        mgr.on_headers_received(vec!["h1".into(), "h2".into()], "peer1");
        assert_eq!(mgr.queued_block_count(), 2);
        assert_eq!(mgr.state, SyncState::FetchingBlocks);
    }

    #[test]
    fn on_block_received_marks_synced_when_done() {
        let mut mgr = SyncManager::new(0);
        mgr.start_sync(1);
        mgr.on_headers_received(vec!["block1".into()], "peer1");
        let hash = mgr.request_next_block("peer1").unwrap();
        mgr.on_block_received(&hash);
        assert!(mgr.is_synced());
    }
}
