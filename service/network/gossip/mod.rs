// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque, BinaryHeap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

use crate::service::network::p2p::peer_manager::PeerManager;

pub const GOSSIP_FANOUT:         usize = 8;
pub const SEEN_SET_MAX:          usize = 65_536;
pub const GLOBAL_SEEN_MAX:       usize = 262_144;
pub const INV_TTL_SECS:          u64   = 600;
pub const MAX_INV_BATCH:         usize = 512;
pub const BCAST_RETRY_MAX:       u32   = 3;
pub const BCAST_RETRY_DELAY_MS:  u64   = 500;
pub const TRICKLE_INTERVAL_SECS: u64   = 1;
pub const PEER_QUEUE_DEPTH:      usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MsgPriority {
    Low    = 0,
    Normal = 1,
    High   = 2,
    Critical = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvType {
    Tx,
    Block,
    DagBlock,
    CompactBlock,
    FilteredBlock,
    Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvEntry {
    pub kind:  InvType,
    pub hash:  String,
    pub seen:  u64,
}

impl InvEntry {
    pub fn new_tx(hash: &str)    -> Self { Self::new(InvType::Tx,       hash) }
    pub fn new_block(hash: &str) -> Self { Self::new(InvType::Block,    hash) }
    pub fn new_dag(hash: &str)   -> Self { Self::new(InvType::DagBlock, hash) }

    fn new(kind: InvType, hash: &str) -> Self {
        Self { kind, hash: hash.to_string(), seen: unix_now() }
    }

    pub fn is_expired(&self) -> bool {
        unix_now().saturating_sub(self.seen) > INV_TTL_SECS
    }
}

#[derive(Debug, Clone)]
struct QueueEntry {
    priority:  MsgPriority,
    entry:     InvEntry,
    _retries:   u32,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool { self.priority == other.priority }
}
impl Eq for QueueEntry {}
impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

struct SeenRing {
    set:   HashSet<String>,
    queue: VecDeque<String>,
    cap:   usize,
}

impl SeenRing {
    fn new(cap: usize) -> Self {
        Self { set: HashSet::new(), queue: VecDeque::new(), cap }
    }

    fn contains(&self, hash: &str) -> bool {
        self.set.contains(hash)
    }

    fn insert(&mut self, hash: String) -> bool {
        if self.set.contains(&hash) { return false; }
        if self.set.len() >= self.cap {
            if let Some(old) = self.queue.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(hash.clone());
        self.queue.push_back(hash);
        true
    }
}

struct PeerGossipState {
    seen:       SeenRing,
    queue:      BinaryHeap<QueueEntry>,
    last_trickle: u64,
}

impl PeerGossipState {
    fn new() -> Self {
        Self {
            seen: SeenRing::new(SEEN_SET_MAX),
            queue: BinaryHeap::new(),
            last_trickle: 0,
        }
    }
}

pub struct GossipManager {
    peers:       Arc<PeerManager>,
    global_seen: Arc<Mutex<SeenRing>>,
    peer_state:  Arc<RwLock<HashMap<String, PeerGossipState>>>,

    pending_blocks: Arc<Mutex<HashMap<String, InvEntry>>>,
    pending_txs:    Arc<Mutex<HashMap<String, InvEntry>>>,
}

impl GossipManager {
    pub fn new(peers: Arc<PeerManager>) -> Self {
        Self {
            peers,
            global_seen:    Arc::new(Mutex::new(SeenRing::new(GLOBAL_SEEN_MAX))),
            peer_state:     Arc::new(RwLock::new(HashMap::new())),
            pending_blocks: Arc::new(Mutex::new(HashMap::new())),
            pending_txs:    Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_peer(&self, addr: &str) {
        let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
        states.insert(addr.to_string(), PeerGossipState::new());
    }

    pub fn unregister_peer(&self, addr: &str) {
        let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
        states.remove(addr);
    }

    pub fn announce_block(&self, hash: &str) {
        let entry = InvEntry::new_block(hash);
        if !self.global_seen.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.to_string()) {
            return;
        }
        self.pending_blocks.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.to_string(), entry.clone());
        self.fan_out_inv(entry, MsgPriority::Critical);
    }

    pub fn announce_dag_block(&self, hash: &str) {
        let entry = InvEntry::new_dag(hash);
        if !self.global_seen.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.to_string()) {
            return;
        }
        self.fan_out_inv(entry, MsgPriority::Critical);
    }

    pub fn announce_tx(&self, hash: &str) {
        let entry = InvEntry::new_tx(hash);
        if !self.global_seen.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.to_string()) {
            return;
        }
        self.pending_txs.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.to_string(), entry.clone());
        self.trickle_inv(entry);
    }

    pub fn relay_block(&self, hash: &str, from_peer: &str) {
        {
            let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ps) = states.get_mut(from_peer) {
                ps.seen.insert(hash.to_string());
            }
        }

        self.announce_block(hash);
    }

    pub fn relay_tx(&self, hash: &str, from_peer: &str) {
        {
            let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ps) = states.get_mut(from_peer) {
                ps.seen.insert(hash.to_string());
            }
        }
        self.announce_tx(hash);
    }

    pub fn already_seen(&self, hash: &str) -> bool {
        self.global_seen.lock().unwrap_or_else(|e| e.into_inner()).contains(hash)
    }

    fn fan_out_inv(&self, entry: InvEntry, priority: MsgPriority) {
        let peer_list = self.peers.get_best_peers(GOSSIP_FANOUT * 2);
        let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
        let mut sent = 0usize;

        for peer in &peer_list {
            if sent >= GOSSIP_FANOUT { break; }
            let ps = states.entry(peer.addr.clone()).or_insert_with(PeerGossipState::new);
            if ps.seen.contains(&entry.hash) { continue; }
            if ps.queue.len() >= PEER_QUEUE_DEPTH { continue; }
            ps.seen.insert(entry.hash.clone());
            ps.queue.push(QueueEntry {
                priority: priority.clone(),
                entry:    entry.clone(),
                _retries:  0,
            });
            sent += 1;
        }
    }

    fn trickle_inv(&self, entry: InvEntry) {
        let peer_list = self.peers.get_best_peers(GOSSIP_FANOUT * 3);
        let now = unix_now();
        let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());

        for peer in peer_list.iter().take(GOSSIP_FANOUT) {
            let ps = states.entry(peer.addr.clone()).or_insert_with(PeerGossipState::new);

            if now - ps.last_trickle < TRICKLE_INTERVAL_SECS { continue; }
            if ps.seen.contains(&entry.hash) { continue; }
            ps.seen.insert(entry.hash.clone());
            ps.queue.push(QueueEntry {
                priority: MsgPriority::Normal,
                entry:    entry.clone(),
                _retries:  0,
            });
            ps.last_trickle = now;
        }
    }

    pub fn drain_queue(&self, addr: &str, limit: usize) -> Vec<InvEntry> {
        let mut states = self.peer_state.write().unwrap_or_else(|e| e.into_inner());
        let ps = match states.get_mut(addr) {
            Some(ps) => ps,
            None     => return vec![],
        };
        let mut out = Vec::new();
        while out.len() < limit {
            match ps.queue.pop() {
                Some(qe) if !qe.entry.is_expired() => out.push(qe.entry),
                Some(_)  => {  }
                None     => break,
            }
        }
        out
    }

    pub fn tick_evict_expired(&self) {
        let mut blocks = self.pending_blocks.lock().unwrap_or_else(|e| e.into_inner());
        blocks.retain(|_, v| !v.is_expired());
        let mut txs = self.pending_txs.lock().unwrap_or_else(|e| e.into_inner());
        txs.retain(|_, v| !v.is_expired());
    }

    pub fn stats(&self) -> GossipStats {
        let states = self.peer_state.read().unwrap_or_else(|e| e.into_inner());
        let total_queued: usize = states.values().map(|ps| ps.queue.len()).sum();
        GossipStats {
            registered_peers: states.len(),
            total_queued_inv: total_queued,
            pending_blocks:   self.pending_blocks.lock().unwrap_or_else(|e| e.into_inner()).len(),
            pending_txs:      self.pending_txs.lock().unwrap_or_else(|e| e.into_inner()).len(),
        }
    }
}

#[derive(Debug)]
pub struct GossipStats {
    pub registered_peers: usize,
    pub total_queued_inv: usize,
    pub pending_blocks:   usize,
    pub pending_txs:      usize,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::service::network::p2p::peer_manager::PeerManager;

    fn make_gossip(label: &str) -> GossipManager {
        let path = format!("/tmp/gossip_{}", label);
        let _ = fs::remove_dir_all(&path);
        let pm = Arc::new(PeerManager::open(&path).unwrap());
        GossipManager::new(pm)
    }

    #[test]
    fn block_deduplicated() {
        let g = make_gossip("dedup");
        g.announce_block("abc123");
        g.announce_block("abc123");
        let stats = g.stats();
        assert_eq!(stats.pending_blocks, 1);
    }

    #[test]
    fn register_and_drain() {
        let g = make_gossip("drain");

        g.register_peer("10.0.0.1:9333");
        g.announce_block("deadbeef");
        let items = g.drain_queue("10.0.0.1:9333", 100);

        assert!(items.len() <= 1);
    }

    #[test]
    fn tx_announce() {
        let g = make_gossip("tx");
        g.announce_tx("txhash1");
        let stats = g.stats();
        assert_eq!(stats.pending_txs, 1);
    }
}
