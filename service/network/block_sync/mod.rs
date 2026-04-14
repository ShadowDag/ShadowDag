// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::genesis::genesis::genesis_hash;
use crate::service::network::p2p::peer_manager::PeerManager;

pub const MAX_CONCURRENT_DOWNLOADS: usize = 32;
pub const MAX_HEADER_BATCH: usize = 2_000;
pub const MAX_BLOCK_BATCH: usize = 64;
pub const SYNC_STALL_TIMEOUT_SECS: u64 = 60;
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 30;
pub const MAX_RETRIES: u32 = 5;
pub const BACKOFF_BASE_MS: u64 = 200;
pub const SNAPSHOT_CHUNK_SIZE: usize = 65_536;
pub const IBD_BATCH_VERIFY_WORKERS: usize = 4;
pub const PEER_SCORE_BONUS: i64 = 10;
pub const PEER_SCORE_PENALTY: i64 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    Idle,
    SnapshotDiscovery,
    SnapshotDownload,
    HeaderSync,
    BlockSync,
    TailSync,
    Synced,
}

impl SyncPhase {
    pub fn is_syncing(&self) -> bool {
        !matches!(self, SyncPhase::Idle | SyncPhase::Synced)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHeader {
    pub hash: String,
    pub prev_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub parents: Vec<String>,
    pub blue_score: u64,
}

#[derive(Debug, Clone)]
struct DownloadJob {
    hash: String,
    _height: u64,
    assigned_to: String,
    started_at: u64,
    retries: u32,
    _is_snapshot: bool,
}

impl DownloadJob {
    fn is_stalled(&self) -> bool {
        unix_now().saturating_sub(self.started_at) > DOWNLOAD_TIMEOUT_SECS
    }
}

#[derive(Debug, Clone)]
struct PeerSyncState {
    _addr: String,
    _best_height: u64,
    score: i64,
    in_flight: usize,
    last_response: u64,
    failed: u32,
}

impl PeerSyncState {
    fn new(addr: &str, height: u64) -> Self {
        Self {
            _addr: addr.to_string(),
            _best_height: height,
            score: 100,
            in_flight: 0,
            last_response: unix_now(),
            failed: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSnapshot {
    pub block_hash: String,
    pub height: u64,
    pub utxo_count: u64,
    pub root_hash: String,
    pub size_bytes: u64,
    pub created_at: u64,
}

/// LOCK ORDERING: To prevent deadlocks, always acquire locks in this order:
///   1. phase
///   2. headers
///   3. peer_states
///   4. best_snapshot
///   5. pending
///   6. in_flight
///   7. completed
///
/// Never acquire a lower-numbered lock while holding a higher-numbered one.
pub struct BlockSyncManager {
    _peers: Arc<PeerManager>,
    phase: Arc<RwLock<SyncPhase>>, // Lock order: 1
    local_height: Arc<AtomicU64>,
    best_height: Arc<AtomicU64>,
    is_running: Arc<AtomicBool>,

    headers: Arc<RwLock<HashMap<String, SyncHeader>>>, // Lock order: 2 — hash -> header
    headers_by_height: Arc<RwLock<HashMap<u64, Vec<String>>>>, // Lock order: 2b — height -> [hashes]

    pending: Arc<Mutex<VecDeque<DownloadJob>>>, // Lock order: 5
    pending_set: Arc<Mutex<HashSet<String>>>,   // Lock order: 5b — dedup

    in_flight: Arc<Mutex<HashMap<String, DownloadJob>>>, // Lock order: 6

    completed: Arc<Mutex<HashSet<String>>>, // Lock order: 7

    peer_states: Arc<RwLock<HashMap<String, PeerSyncState>>>, // Lock order: 3

    best_snapshot: Arc<RwLock<Option<UtxoSnapshot>>>, // Lock order: 4
}

impl BlockSyncManager {
    pub fn new(peers: Arc<PeerManager>) -> Self {
        Self {
            _peers: peers,
            phase: Arc::new(RwLock::new(SyncPhase::Idle)),
            local_height: Arc::new(AtomicU64::new(0)),
            best_height: Arc::new(AtomicU64::new(0)),
            is_running: Arc::new(AtomicBool::new(false)),
            headers: Arc::new(RwLock::new(HashMap::new())),
            headers_by_height: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(VecDeque::new())),
            pending_set: Arc::new(Mutex::new(HashSet::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(HashSet::new())),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            best_snapshot: Arc::new(RwLock::new(None)),
        }
    }

    pub fn start_ibd(&self, local_height: u64) {
        self.local_height.store(local_height, Ordering::SeqCst);
        self.is_running.store(true, Ordering::SeqCst);
        self.set_phase(SyncPhase::SnapshotDiscovery);
    }

    pub fn mark_synced(&self) {
        self.set_phase(SyncPhase::Synced);
        self.is_running.store(false, Ordering::SeqCst);
    }

    fn set_phase(&self, p: SyncPhase) {
        *self.phase.write().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn phase(&self) -> SyncPhase {
        self.phase.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn register_peer(&self, addr: &str, height: u64) {
        let mut states = self.peer_states.write().unwrap_or_else(|e| e.into_inner());
        states.insert(addr.to_string(), PeerSyncState::new(addr, height));
        let bh = self.best_height.load(Ordering::SeqCst);
        if height > bh {
            self.best_height.store(height, Ordering::SeqCst);
        }
    }

    pub fn drop_peer(&self, addr: &str) {
        let mut states = self.peer_states.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ps) = states.get_mut(addr) {
            ps.score -= PEER_SCORE_PENALTY;
        }

        let mut inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending_set = self.pending_set.lock().unwrap_or_else(|e| e.into_inner());
        let re_queue: Vec<DownloadJob> = inflight
            .values()
            .filter(|j| j.assigned_to == addr)
            .cloned()
            .collect();
        for job in re_queue {
            inflight.remove(&job.hash);
            pending_set.insert(job.hash.clone());
            pending.push_front(job);
        }
    }

    // WARNING: Snapshot discovery selects the peer offering the highest
    // height. This is vulnerable to a malicious peer advertising a fake
    // snapshot at an inflated height. Production deployments should:
    //   1. Require snapshot commitments signed by a quorum of known peers
    //   2. Verify the UTXO commitment against a known checkpoint
    //   3. Validate a subset of the snapshot data against the header chain
    // Currently, snapshot sync is UNSAFE and should only be used with
    // trusted peers or on trusted networks.
    pub fn on_snapshot_offered(&self, _peer: &str, snap: UtxoSnapshot) {
        // Basic sanity checks — these do NOT replace cryptographic verification
        if snap.block_hash.is_empty() || snap.root_hash.is_empty() {
            log::warn!("snapshot_discovery_untrusted: rejecting snapshot with empty hash fields");
            return;
        }
        if snap.height == 0 || snap.utxo_count == 0 {
            log::warn!(
                "snapshot_discovery_untrusted: rejecting snapshot with zero height or utxo_count"
            );
            return;
        }

        let mut best = self
            .best_snapshot
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let should_replace = best
            .as_ref()
            .map(|b| snap.height > b.height)
            .unwrap_or(true);
        if should_replace {
            log::warn!(
                "snapshot_discovery_untrusted: selected snapshot is NOT cryptographically verified \
                 — vulnerable to forgery (height={}, block_hash={})",
                snap.height, snap.block_hash
            );
            *best = Some(snap);
        }
    }

    pub fn select_snapshot(&self) -> Option<UtxoSnapshot> {
        let local = self.local_height.load(Ordering::SeqCst);
        let snap = self
            .best_snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;

        if snap.height > local + 10_000 {
            log::warn!(
                "snapshot_discovery_untrusted: proceeding with unverified snapshot at height {}",
                snap.height
            );
            Some(snap)
        } else {
            None
        }
    }

    pub fn begin_snapshot_download(&self) {
        self.set_phase(SyncPhase::SnapshotDownload);
    }

    pub fn on_snapshot_chunk_received(&self, chunk_index: u64, total_chunks: u64, _data: &[u8]) {
        let pct = (chunk_index * 100) / total_chunks.max(1);
        if chunk_index.is_multiple_of(100) {
            log::info!(
                "Snapshot chunk received: chunk_index={}, total_chunks={}, pct={}%",
                chunk_index,
                total_chunks,
                pct
            );
        }
        if chunk_index + 1 >= total_chunks {
            // NOTE: Snapshot content integrity is NOT verified here.
            // The chunk count alone does not guarantee data correctness.
            // A full UTXO commitment verification should be performed
            // before trusting the snapshot data.
            log::warn!(
                "snapshot_complete_unverified: proceeding to HeaderSync without content verification \
                 (total_chunks={})",
                total_chunks
            );
            self.set_phase(SyncPhase::HeaderSync);
        }
    }

    pub fn on_headers_received(&self, headers: Vec<SyncHeader>) {
        // Enforce MAX_HEADER_BATCH to prevent memory abuse from a peer
        // sending an oversized header batch.
        let headers: Vec<SyncHeader> = if headers.len() > MAX_HEADER_BATCH {
            log::warn!(
                "header_batch_truncated: received={}, max={}",
                headers.len(),
                MAX_HEADER_BATCH
            );
            headers.into_iter().take(MAX_HEADER_BATCH).collect()
        } else {
            headers
        };

        if headers.is_empty() {
            // Peer has no more headers. Only transition to BlockSync
            // if we actually have headers to download blocks for.
            let has_pending = !self
                .headers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty();
            if has_pending {
                self.set_phase(SyncPhase::BlockSync);
                self.enqueue_block_downloads();
            } else {
                log::warn!(
                    "on_headers_received: peer sent empty headers but we have nothing to download"
                );
            }
            return;
        }

        // Validate headers before accepting them into the sync pipeline.
        // Without this, a malicious peer can inject fake headers that
        // cause invalid block downloads.
        let headers: Vec<SyncHeader> = headers
            .into_iter()
            .filter(|h| {
                // Basic sanity: hash must be 64 hex chars
                if h.hash.len() != 64 || !h.hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    log::warn!(
                        "header_invalid_hash: rejecting header with bad hash '{}'",
                        h.hash
                    );
                    return false;
                }
                // Height must be positive (genesis is not synced via headers)
                if h.height == 0 {
                    log::warn!("header_zero_height: rejecting header hash={}", h.hash);
                    return false;
                }
                // Difficulty must be non-zero
                if h.difficulty == 0 {
                    log::warn!("header_zero_difficulty: rejecting header hash={}", h.hash);
                    return false;
                }
                true
            })
            .collect();

        if headers.is_empty() {
            log::warn!("on_headers_received: all headers rejected by validation");
            return;
        }

        // Verify headers are in ascending height order (basic continuity)
        let mut prev_h = 0u64;
        for h in &headers {
            if h.height > 0 && h.height <= prev_h {
                log::warn!(
                    "on_headers_received: header height not ascending (height={}, prev={})",
                    h.height,
                    prev_h
                );
                return; // Reject entire batch
            }
            prev_h = h.height;
        }

        // Verify prev_hash continuity between consecutive headers
        for window in headers.windows(2) {
            if !window[1].parents.contains(&window[0].hash) && window[1].prev_hash != window[0].hash
            {
                log::warn!(
                    "header_chain_break: height={}, expected_parent={}",
                    window[1].height,
                    &window[0].hash[..window[0].hash.len().min(16)]
                );
                return; // Reject entire batch — broken chain
            }
        }

        let mut map = self.headers.write().unwrap_or_else(|e| e.into_inner());
        let mut by_height = self
            .headers_by_height
            .write()
            .unwrap_or_else(|e| e.into_inner());
        for h in &headers {
            map.insert(h.hash.clone(), h.clone());
            let entry = by_height.entry(h.height).or_default();
            if !entry.contains(&h.hash) {
                entry.push(h.hash.clone());
            }
        }
        let _max_h = headers.iter().map(|h| h.height).max().unwrap_or(0);
    }

    pub fn build_header_locator(&self) -> Vec<String> {
        let by_height = self
            .headers_by_height
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let local_h = self.local_height.load(Ordering::SeqCst);
        let mut locator = Vec::new();
        let mut step = 1u64;
        let mut h = local_h;
        loop {
            if let Some(hashes) = by_height.get(&h) {
                if let Some(first) = hashes.first() {
                    locator.push(first.clone());
                }
            }
            if h < step {
                break;
            }
            h -= step;
            step *= 2;
        }
        locator.push(genesis_hash());
        locator
    }

    fn enqueue_block_downloads(&self) {
        let headers = self.headers.read().unwrap_or_else(|e| e.into_inner());
        let local_h = self.local_height.load(Ordering::SeqCst);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending_set = self.pending_set.lock().unwrap_or_else(|e| e.into_inner());
        let inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let completed = self.completed.lock().unwrap_or_else(|e| e.into_inner());

        for (hash, hdr) in headers.iter() {
            if hdr.height <= local_h {
                continue;
            }
            if inflight.contains_key(hash) {
                continue;
            }
            if completed.contains(hash) {
                continue;
            }
            if pending_set.contains(hash) {
                continue;
            }
            pending_set.insert(hash.clone());
            pending.push_back(DownloadJob {
                hash: hash.clone(),
                _height: hdr.height,
                assigned_to: String::new(),
                started_at: 0,
                retries: 0,
                _is_snapshot: false,
            });
        }
    }

    pub fn next_download_batch(&self, peer: &str) -> Vec<String> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending_set = self.pending_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let mut batch = Vec::new();

        let inflight_count = inflight.len();
        while batch.len() < MAX_BLOCK_BATCH
            && (inflight_count + batch.len()) < MAX_CONCURRENT_DOWNLOADS
        {
            match pending.pop_front() {
                Some(mut job) => {
                    job.assigned_to = peer.to_string();
                    job.started_at = unix_now();
                    let hash = job.hash.clone();
                    pending_set.remove(&hash);
                    inflight.insert(hash.clone(), job);
                    batch.push(hash);
                }
                None => break,
            }
        }

        // Increment peer in_flight count
        if !batch.is_empty() {
            let mut states = self.peer_states.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ps) = states.get_mut(peer) {
                ps.in_flight += batch.len();
            }
        }

        batch
    }

    pub fn on_block_received(&self, hash: &str, peer: &str) {
        let mut inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let mut completed = self.completed.lock().unwrap_or_else(|e| e.into_inner());

        if inflight.remove(hash).is_some() {
            completed.insert(hash.to_string());

            if let Some(hdr) = self
                .headers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(hash)
                .cloned()
            {
                let cur = self.local_height.load(Ordering::SeqCst);
                // NOTE: In a DAG, height gaps are expected. This update
                // does NOT guarantee all blocks below this height exist.
                // The Synced check uses a 5-block tolerance (local >= best-5).
                if hdr.height > cur {
                    self.local_height.store(hdr.height, Ordering::SeqCst);
                }
            }

            let mut states = self.peer_states.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ps) = states.get_mut(peer) {
                ps.score += PEER_SCORE_BONUS;
                ps.last_response = unix_now();
                ps.in_flight = ps.in_flight.saturating_sub(1);
            }
        }

        if inflight.is_empty()
            && self
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        {
            let best = self.best_height.load(Ordering::SeqCst);
            let local = self.local_height.load(Ordering::SeqCst);
            if local >= best.saturating_sub(5) {
                self.mark_synced();
            } else {
                self.set_phase(SyncPhase::TailSync);
            }
        }

        // Prune completed set to prevent unbounded memory growth.
        // Once synced, old entries are no longer needed.
        if completed.len() > 50_000 {
            let excess = completed.len() - 25_000;
            let to_remove: Vec<String> = completed.iter().take(excess).cloned().collect();
            for h in &to_remove {
                completed.remove(h);
            }
        }

        // Prune headers map to prevent unbounded memory growth.
        {
            let mut map = self.headers.write().unwrap_or_else(|e| e.into_inner());
            if map.len() > 50_000 {
                let excess = map.len() - 25_000;
                let to_remove: Vec<String> = map.keys().take(excess).cloned().collect();
                for h in &to_remove {
                    map.remove(h);
                }
            }
        }
    }

    pub fn on_block_failed(&self, hash: &str, peer: &str) {
        let mut inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending_set = self.pending_set.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(mut job) = inflight.remove(hash) {
            job.retries += 1;
            if job.retries < MAX_RETRIES {
                // Check pending_set before re-adding to avoid duplicate entries
                if !pending_set.contains(&job.hash) {
                    pending_set.insert(job.hash.clone());
                    pending.push_back(job);
                }
            }
        }

        let mut states = self.peer_states.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ps) = states.get_mut(peer) {
            ps.score -= PEER_SCORE_PENALTY;
            ps.failed += 1;
            ps.in_flight = ps.in_flight.saturating_sub(1);
        }
    }

    pub fn check_stalled_downloads(&self) {
        let stalled: Vec<(String, String)> = {
            let inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            inflight
                .values()
                .filter(|j| j.is_stalled())
                .map(|j| (j.hash.clone(), j.assigned_to.clone()))
                .collect()
        };
        for (hash, peer) in stalled {
            self.on_block_failed(&hash, &peer);
        }
    }

    pub fn stats(&self) -> SyncStats {
        SyncStats {
            phase: format!("{:?}", self.phase()),
            local_height: self.local_height.load(Ordering::SeqCst),
            best_height: self.best_height.load(Ordering::SeqCst),
            pending_blocks: self.pending.lock().unwrap_or_else(|e| e.into_inner()).len(),
            in_flight: self
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            completed: self
                .completed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
        }
    }

    pub fn needs_ibd(&self, local: u64, best: u64) -> bool {
        best > local + 144
    }

    pub fn local_height(&self) -> u64 {
        self.local_height.load(Ordering::SeqCst)
    }

    pub fn best_height(&self) -> u64 {
        self.best_height.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct SyncStats {
    pub phase: String,
    pub local_height: u64,
    pub best_height: u64,
    pub pending_blocks: usize,
    pub in_flight: usize,
    pub completed: usize,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_sync(label: &str) -> BlockSyncManager {
        let path = format!("/tmp/sync_{}", label);
        let _ = fs::remove_dir_all(&path);
        let pm =
            Arc::new(crate::service::network::p2p::peer_manager::PeerManager::open(&path).unwrap());
        BlockSyncManager::new(pm)
    }

    #[test]
    fn ibd_phase_transitions() {
        let sync = make_sync("phase");
        assert_eq!(sync.phase(), SyncPhase::Idle);
        sync.start_ibd(0);
        assert_eq!(sync.phase(), SyncPhase::SnapshotDiscovery);
        sync.mark_synced();
        assert_eq!(sync.phase(), SyncPhase::Synced);
    }

    #[test]
    fn peer_registration() {
        let sync = make_sync("peer");
        sync.register_peer("10.0.0.1:9333", 5000);
        assert_eq!(sync.best_height(), 5000);
    }

    #[test]
    fn snapshot_selection() {
        let sync = make_sync("snap");
        sync.local_height.store(100, Ordering::SeqCst);
        let snap = UtxoSnapshot {
            block_hash: "abc".to_string(),
            height: 15000,
            utxo_count: 1_000_000,
            root_hash: "root".to_string(),
            size_bytes: 1_000_000_000,
            created_at: unix_now(),
        };
        sync.on_snapshot_offered("peer1", snap);
        assert!(sync.select_snapshot().is_some());
    }

    #[test]
    fn needs_ibd_logic() {
        let sync = make_sync("ibd");
        assert!(sync.needs_ibd(0, 1000));
        assert!(!sync.needs_ibd(999, 1000));
    }
}
