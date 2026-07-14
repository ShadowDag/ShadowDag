// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::network::network_params::NetworkParams;
use crate::config::node::node_config::{NetworkMode, NodeConfig};
use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::Transaction;
use crate::engine::dag::security::dag_shield::DagShield;
use crate::errors::NetworkError;
use crate::service::network::dos_guard::{BanCategory, DosGuard, DosVerdict, MsgType};
use crate::service::network::p2p::connection_puzzle::{ChallengeSolution, ConnectionPuzzle};
use crate::service::network::p2p::peer_diversity::PeerIdentity;
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::service::network::p2p::protocol::{
    build_version_payload, validate_addr_list, validate_hash_hex, validate_header,
    validate_headers_list, validate_inv_items, validate_payload_checksum, validate_payload_size,
    validate_reject, CommandId, ProtocolSession, VersionPayload, WireHeader, DEFAULT_BPS,
    MAX_MESSAGE_SIZE, WIRE_HEADER_SIZE,
};
use crate::{slog_debug, slog_error, slog_info, slog_warn};

/// Global DoS guard — shared across all peer threads.
static DOS_GUARD: Lazy<DosGuard> = Lazy::new(DosGuard::new);

/// Inbound connection throttle: max new connections per second.
const MAX_INBOUND_PER_SEC: u32 = 10;
/// Max pending (not-yet-handshaked) connections.
const MAX_PENDING_CONNECTIONS: usize = 64;

pub const MAX_PEERS: usize = NetworkParams::MAX_PEERS;
pub const MIN_PEERS: usize = NetworkParams::MIN_PEERS;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
pub const MSG_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const RATE_LIMIT_MS: u64 = 50;

pub const DEFAULT_PORT: u16 = NetworkParams::DEFAULT_PORT;
pub const PROTOCOL_VERSION: u32 = 1;

// Cross-thread pending queues: P2P handler threads push here, node main loop drains.
// Uses Arc<Mutex<>> so ANY thread can push and ANY thread can drain.
// Each item is tagged with the peer_id that sent it, so the event loop
// can ban_score on rejection (closing the feedback gap).
use once_cell::sync::Lazy;
use parking_lot::Mutex as PlMutex;

/// (peer_id, transaction) — peer attribution for ban feedback on rejection.
#[allow(clippy::type_complexity)]
static PENDING_TXS: Lazy<Arc<PlMutex<Vec<(String, Transaction)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(1024))));
/// (peer_id, block) — peer attribution for ban feedback on rejection.
#[allow(clippy::type_complexity)]
static PENDING_BLOCKS: Lazy<Arc<PlMutex<Vec<(String, Block)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(128))));

/// Per-peer pending counts: prevents one peer from monopolizing the queue.
/// Key: peer_id, Value: (pending_tx_count, pending_block_count)
#[allow(clippy::type_complexity)]
static PEER_PENDING: Lazy<Arc<PlMutex<HashMap<String, (u32, u32)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Max pending TXs allowed from a single peer before dropping.
const MAX_PENDING_TXS_PER_PEER: u32 = 500;
/// Max pending blocks allowed from a single peer before dropping. Sized to hold
/// a full served header range (512) so a catching-up node can buffer a whole
/// GetBlock burst from its sync peer without dropping (and re-requesting) most
/// of it — the drop-and-refetch churn was the dominant IBD throughput limiter.
const MAX_PENDING_BLOCKS_PER_PEER: u32 = 512;
/// Global hard caps for pending inbound queues (all peers combined).
const MAX_PENDING_TX_QUEUE: usize = 10_000;
const MAX_PENDING_BLOCK_QUEUE: usize = 4_096;
const MAX_OUTBOUND_LAG_SEQS: u64 = 5_000;
/// Bytes per peer per minute — disconnect abusive peers (100MB/min).
const MAX_BYTES_PER_PEER_PER_MIN: u64 = 100 * 1024 * 1024;
/// Interval for bandwidth check (seconds)
const BANDWIDTH_CHECK_INTERVAL_SECS: u64 = 60;
/// Keepalive ping interval (seconds) — detect dead connections.
const KEEPALIVE_INTERVAL_SECS: u64 = 60;
/// Max time without pong before disconnecting (seconds).
const PONG_TIMEOUT_SECS: u64 = 120;

/// Broadcast outbound queue: (sequence_number, message).
/// Each peer tracks `last_outbound_seq` so every peer gets every message.
#[allow(clippy::type_complexity)]
static OUTBOUND_MSGS: Lazy<Arc<PlMutex<(u64, Vec<(u64, P2PMessage)>)>>> =
    Lazy::new(|| Arc::new(PlMutex::new((0, Vec::with_capacity(256)))));

/// Targeted outbound messages: (target_peer_id, message).
/// Used by Dandelion++ stem phase to send to exactly one peer.
#[allow(clippy::type_complexity)]
static TARGETED_MSGS: Lazy<Arc<PlMutex<Vec<(String, P2PMessage)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(64))));

/// Block-serve requests from peers: (requesting_peer_id, block_hash). Filled by
/// the GetBlock/GetData handlers (which lack block_store access) and drained by
/// the daemon event loop, which looks the block up and replies to that peer.
/// Without this, GetBlock is a no-op and peers can never download missing
/// ancestors — so forked nodes never converge.
#[allow(clippy::type_complexity)]
static PENDING_BLOCK_REQUESTS: Lazy<Arc<PlMutex<Vec<(String, String)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(256))));
const MAX_BLOCK_REQUEST_QUEUE: usize = 5_000;

/// Orphan blocks: received blocks whose parent is not yet known, buffered for
/// reprocessing once the missing ancestor arrives. (peer_id, block). Bounded.
#[allow(clippy::type_complexity)]
static ORPHAN_BLOCKS: Lazy<Arc<PlMutex<Vec<(String, Block)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(256))));
const MAX_ORPHAN_BLOCKS: usize = 5_000;

/// Header-serve requests: (peer_id, from_hash, count). The GetHeaders handler
/// queues these; the daemon walks the chain FORWARD from from_hash and returns
/// a batch of block hashes so a behind/forked peer can bulk-download and catch
/// up (the sequential orphan-walk alone is too slow for a fast chain).
#[allow(clippy::type_complexity)]
static PENDING_HEADER_REQUESTS: Lazy<Arc<PlMutex<Vec<(String, String, u32)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(64))));
const MAX_HEADER_REQUEST_QUEUE: usize = 2_000;

/// Target addresses (host:p2p_port) with a live OUTBOUND connection. Prevents
/// duplicate dials and drives auto-reconnect: the maintenance loop re-dials any
/// known peer not in this set, so a node recovers from restarts, timeouts, and
/// network blips instead of staying isolated until its own restart.
static CONNECTED_OUTBOUND: Lazy<Arc<PlMutex<HashSet<String>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashSet::new())));

/// Last outbound dial time per target addr. The reconnect loop uses it to
/// enforce a minimum interval between dials of the same peer, so a peer that
/// keeps dropping (a banned peer, or the node's own IP self-connecting) is not
/// hammered — which otherwise trips the DoS guard and bans everyone.
static LAST_DIAL: Lazy<Arc<PlMutex<HashMap<String, Instant>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));
const MIN_REDIAL_INTERVAL_SECS: u64 = 30;

/// IPs discovered to be OURSELVES (a Version echoing our identity nonce). Once
/// an address is here, the dial loop never targets it again — this stops a node
/// from endlessly re-connecting to its own IP (which is in the seed list) and
/// frees those attempts to reach real peers.
static SELF_ADDRS: Lazy<Arc<PlMutex<HashSet<String>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashSet::new())));

/// Record a peer address whose IP is ourselves, so we stop dialing it.
fn mark_self_addr(addr: &str) {
    SELF_ADDRS.lock().insert(extract_ban_ip(addr));
}

/// True if this address's IP was previously identified as our own.
fn is_self_addr(addr: &str) -> bool {
    SELF_ADDRS.lock().contains(&extract_ban_ip(addr))
}

/// Per-peer last acknowledged outbound broadcast sequence.
/// Used to safely prune only messages that all currently connected peers
/// have already consumed.
static PEER_LAST_OUTBOUND: Lazy<Arc<PlMutex<HashMap<String, u64>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Received peer addresses from Addr messages — drained by daemon event loop
/// and fed to PeerManager.
static RECEIVED_ADDRS: Lazy<Arc<PlMutex<Vec<String>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::new())));

/// Live inbound connection count per remote IP (anti-eclipse).
///
/// `PeerManager::conn_count_for_ip` only counts *stored* peer records, so it
/// does not bound how many live inbound sockets a single host may open — a
/// single IP/subnet could otherwise monopolize all inbound slots and eclipse
/// the node. This map tracks currently-open inbound connections per IP and is
/// enforced in `accept_loop` (reject over the cap) + released when the
/// connection ends.
static INBOUND_CONN_PER_IP: Lazy<Arc<PlMutex<HashMap<String, u32>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Try to register one more live inbound connection for `ip`. Returns `false`
/// (without incrementing) if `ip` already has `MAX_PEERS_PER_IP` live inbound
/// connections.
fn try_register_inbound_ip(ip: &str) -> bool {
    use crate::service::network::p2p::peer_manager::MAX_PEERS_PER_IP;
    let mut map = INBOUND_CONN_PER_IP.lock();
    let entry = map.entry(ip.to_string()).or_insert(0);
    if *entry >= MAX_PEERS_PER_IP {
        return false;
    }
    *entry += 1;
    true
}

/// True if `addr` is a routable `host:port` SocketAddr suitable for the peer
/// store. Rejects unparseable/garbage strings (which would otherwise bloat the
/// peer DB unbounded) and loopback/unspecified/multicast addresses.
fn is_routable_peer_addr(addr: &str) -> bool {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => {
            let ip = sa.ip();
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
        }
        Err(_) => false,
    }
}

/// Release one live inbound connection for `ip` (call exactly once per
/// successful `try_register_inbound_ip`).
fn release_inbound_ip(ip: &str) {
    let mut map = INBOUND_CONN_PER_IP.lock();
    if let Some(c) = map.get_mut(ip) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            map.remove(ip);
        }
    }
}

/// Max concurrent inbound connections from a single /16 subnet (anti-eclipse).
///
/// The per-IP cap (MAX_PEERS_PER_IP) is bypassed by an attacker who controls a
/// whole /16 range: each distinct IP passes the per-IP check, so one subnet can
/// still fill every inbound slot and eclipse the node. Capping per /16 closes
/// that while leaving room for a handful of honest hosts behind one ISP block.
const MAX_INBOUND_PER_SUBNET: u32 = 8;

/// Live inbound connection count per /16 subnet (anti-eclipse). Parallel to
/// INBOUND_CONN_PER_IP but keyed on `subnet_16` so a single subnet cannot
/// monopolize inbound slots using many distinct IPs.
static INBOUND_CONN_PER_SUBNET: Lazy<Arc<PlMutex<HashMap<String, u32>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Register one inbound connection for `ip`'s /16 subnet and report whether the
/// subnet is still WITHIN `MAX_INBOUND_PER_SUBNET`. ALWAYS increments (pair with
/// exactly one `release_inbound_subnet`), so a caller that rejects on `false`
/// can release immediately without desyncing the counter — and a whitelisted
/// peer that bypasses the cap is still tracked and released symmetrically.
fn register_inbound_subnet(ip: &str) -> bool {
    use crate::service::network::p2p::peer_diversity::subnet_16;
    let subnet = subnet_16(ip);
    let mut map = INBOUND_CONN_PER_SUBNET.lock();
    let entry = map.entry(subnet).or_insert(0);
    *entry += 1;
    *entry <= MAX_INBOUND_PER_SUBNET
}

/// Release one live inbound connection for `ip`'s /16 subnet (call exactly once
/// per successful `try_register_inbound_subnet`).
fn release_inbound_subnet(ip: &str) {
    use crate::service::network::p2p::peer_diversity::subnet_16;
    let subnet = subnet_16(ip);
    let mut map = INBOUND_CONN_PER_SUBNET.lock();
    if let Some(c) = map.get_mut(&subnet) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            map.remove(&subnet);
        }
    }
}

/// Whether dialing `addr` would exceed the outbound /16-subnet diversity limit
/// (MAX_PEERS_PER_SUBNET) among currently-connected OUTBOUND peers. Stateless:
/// derived from the live CONNECTED_OUTBOUND set, so it needs no register/release
/// bookkeeping. Anti-eclipse: outbound links must span distinct subnets, or an
/// attacker owning one /16 can occupy every outbound slot and control the
/// node's view of the chain.
fn outbound_subnet_would_saturate(addr: &str) -> bool {
    let set = CONNECTED_OUTBOUND.lock();
    subnet_saturated_among(addr, set.iter())
}

/// Pure core of `outbound_subnet_would_saturate`: whether `addr`'s /16 already
/// holds `MAX_PEERS_PER_SUBNET` of the given connected addresses.
fn subnet_saturated_among<'a>(addr: &str, connected: impl Iterator<Item = &'a String>) -> bool {
    use crate::service::network::p2p::peer_diversity::{subnet_16, MAX_PEERS_PER_SUBNET};
    let subnet = subnet_16(addr);
    let count = connected.filter(|a| subnet_16(a) == subnet).count();
    count >= MAX_PEERS_PER_SUBNET
}

/// Deserialize untrusted wire bytes with a byte limit equal to the input
/// length. Plain `bincode::deserialize` reads an inner collection's length
/// prefix and may pre-allocate `Vec::with_capacity(len)` from it — a single
/// (already size-capped) message could declare a huge inner length and trigger
/// an OOM abort. Capping the limit at the buffer's own size makes any inner
/// length larger than the buffer fail cleanly, and is wire-compatible with
/// `bincode::serialize` (fixint encoding, reject trailing) — proven by the
/// `bounded_deserialize_wire_compatible` test.
fn bounded_deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)
}

/// Drain all pending transactions received by P2P (call from node main loop).
/// Returns (peer_id, transaction) tuples for ban attribution.
/// Thread-safe: works from ANY thread, not just the one that pushed.
pub fn drain_pending_txs() -> Vec<(String, Transaction)> {
    let items = std::mem::take(&mut *PENDING_TXS.lock());
    // Decrement per-peer pending counts
    if !items.is_empty() {
        let mut counts = PEER_PENDING.lock();
        for (peer, _) in &items {
            if let Some(entry) = counts.get_mut(peer) {
                entry.0 = entry.0.saturating_sub(1);
            }
        }
    }
    items
}

/// Drain all pending blocks received by P2P (call from node main loop).
/// Returns (peer_id, block) tuples for ban attribution.
/// Thread-safe: works from ANY thread, not just the one that pushed.
pub fn drain_pending_blocks() -> Vec<(String, Block)> {
    let items = std::mem::take(&mut *PENDING_BLOCKS.lock());
    // Decrement per-peer pending counts
    if !items.is_empty() {
        let mut counts = PEER_PENDING.lock();
        for (peer, _) in &items {
            if let Some(entry) = counts.get_mut(peer) {
                entry.1 = entry.1.saturating_sub(1);
            }
        }
    }
    items
}

/// Clean up global state for a disconnected peer.
/// Removes targeted messages and pending counts to prevent resource leaks.
pub fn cleanup_peer_state(peer_id: &str) {
    // Remove pending inbound work attributed to this peer so disconnected
    // peers cannot keep stale queue pressure.
    {
        let mut q = PENDING_TXS.lock();
        let before = q.len();
        q.retain(|(peer, _)| peer != peer_id);
        let dropped = before.saturating_sub(q.len());
        if dropped > 0 {
            slog_warn!("p2p", "cleanup_dropped_pending_txs", peer => peer_id, dropped => dropped);
        }
    }
    {
        let mut q = PENDING_BLOCKS.lock();
        let before = q.len();
        q.retain(|(peer, _)| peer != peer_id);
        let dropped = before.saturating_sub(q.len());
        if dropped > 0 {
            slog_warn!("p2p", "cleanup_dropped_pending_blocks", peer => peer_id, dropped => dropped);
        }
    }
    {
        let mut q = TARGETED_MSGS.lock();
        q.retain(|(target, _)| target != peer_id);
    }
    {
        let mut q = PENDING_BLOCK_REQUESTS.lock();
        q.retain(|(target, _)| target != peer_id);
    }
    {
        let mut q = ORPHAN_BLOCKS.lock();
        q.retain(|(source, _)| source != peer_id);
    }
    {
        let mut q = PENDING_HEADER_REQUESTS.lock();
        q.retain(|(target, _, _)| target != peer_id);
    }
    {
        let mut p = PEER_PENDING.lock();
        p.remove(peer_id);
    }
    {
        let mut acks = PEER_LAST_OUTBOUND.lock();
        acks.remove(peer_id);
    }
}

/// Drain all received peer addresses from Addr messages (call from node main loop).
/// Thread-safe: works from ANY thread.
pub fn drain_received_addrs() -> Vec<String> {
    std::mem::take(&mut *RECEIVED_ADDRS.lock())
}

/// Queue a peer's block-serve request. The GetBlock/GetData handlers call this;
/// the daemon event loop drains it and serves the block from the BlockStore.
pub fn push_block_request(peer_id: &str, hash: &str) {
    let mut q = PENDING_BLOCK_REQUESTS.lock();
    if q.len() < MAX_BLOCK_REQUEST_QUEUE {
        q.push((peer_id.to_string(), hash.to_string()));
    }
}

/// Drain queued block-serve requests (call from the node main loop).
pub fn drain_block_requests() -> Vec<(String, String)> {
    std::mem::take(&mut *PENDING_BLOCK_REQUESTS.lock())
}

/// Buffer an orphan block (parent not yet known) for reprocessing once the
/// missing ancestor arrives. Deduplicated by hash; bounded (drops oldest).
pub fn buffer_orphan(peer_id: &str, block: Block) {
    let mut q = ORPHAN_BLOCKS.lock();
    if q.iter().any(|(_, b)| b.header.hash == block.header.hash) {
        return;
    }
    if q.len() >= MAX_ORPHAN_BLOCKS {
        q.remove(0);
    }
    q.push((peer_id.to_string(), block));
}

/// Remove and return buffered orphans that list `parent_hash` among their
/// parents. Called after a block is accepted: those orphans may now be
/// processable (re-queue them; still-missing parents re-buffer + re-request).
pub fn take_orphans_for_parent(parent_hash: &str) -> Vec<(String, Block)> {
    let mut q = ORPHAN_BLOCKS.lock();
    let mut ready = Vec::new();
    q.retain(|(peer, b)| {
        if b.header.parents.iter().any(|p| p == parent_hash) {
            ready.push((peer.clone(), b.clone()));
            false
        } else {
            true
        }
    });
    ready
}

/// Queue a peer's GetHeaders request. The daemon walks the chain forward from
/// `from_hash` and replies with a batch of block hashes for bulk catch-up.
pub fn push_header_request(peer_id: &str, from_hash: &str, count: u32) {
    let mut q = PENDING_HEADER_REQUESTS.lock();
    if q.len() < MAX_HEADER_REQUEST_QUEUE {
        q.push((peer_id.to_string(), from_hash.to_string(), count));
    }
}

/// Drain queued header-serve requests (call from the node main loop).
pub fn drain_header_requests() -> Vec<(String, String, u32)> {
    std::mem::take(&mut *PENDING_HEADER_REQUESTS.lock())
}

/// Requeue excess blocks that couldn't be processed in this tick.
/// Prepends them to the front of the queue so they're processed first next tick.
/// Re-increments PEER_PENDING block counts that were decremented during drain.
///
/// LOCK ORDER: PENDING_BLOCKS first, then PEER_PENDING.
pub fn requeue_pending_blocks(items: Vec<(String, Block)>) {
    if items.is_empty() {
        return;
    }
    let mut q = PENDING_BLOCKS.lock();
    let mut counts = PEER_PENDING.lock();

    // Keep queue bounded even during requeue. Under load, new incoming items
    // can arrive between drain and requeue; without this cap, requeue could
    // temporarily exceed the global queue limit.
    let available = MAX_PENDING_BLOCK_QUEUE.saturating_sub(q.len());
    let mut dropped = 0usize;
    let mut requeued: Vec<(String, Block)> = Vec::with_capacity(items.len().min(available));
    for (peer_id, block) in items {
        if requeued.len() >= available {
            dropped = dropped.saturating_add(1);
            continue;
        }
        let entry = counts.entry(peer_id.clone()).or_insert((0, 0));
        if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
            dropped = dropped.saturating_add(1);
            continue;
        }
        entry.1 = entry.1.saturating_add(1);
        requeued.push((peer_id, block));
    }
    if dropped > 0 {
        slog_warn!("p2p", "pending_block_requeue_dropped", dropped => dropped);
    }

    let mut combined = requeued;
    combined.extend(q.drain(..));
    *q = combined;
}

/// Requeue excess transactions that couldn't be processed in this tick.
/// Re-increments PEER_PENDING tx counts that were decremented during drain.
///
/// LOCK ORDER: PENDING_TXS first, then PEER_PENDING.
pub fn requeue_pending_txs(items: Vec<(String, Transaction)>) {
    if items.is_empty() {
        return;
    }
    let mut q = PENDING_TXS.lock();
    let mut counts = PEER_PENDING.lock();

    // Keep queue bounded even during requeue.
    let available = MAX_PENDING_TX_QUEUE.saturating_sub(q.len());
    let mut dropped = 0usize;
    let mut requeued: Vec<(String, Transaction)> = Vec::with_capacity(items.len().min(available));
    for (peer_id, tx) in items {
        if requeued.len() >= available {
            dropped = dropped.saturating_add(1);
            continue;
        }
        let entry = counts.entry(peer_id.clone()).or_insert((0, 0));
        if entry.0 >= MAX_PENDING_TXS_PER_PEER {
            dropped = dropped.saturating_add(1);
            continue;
        }
        entry.0 = entry.0.saturating_add(1);
        requeued.push((peer_id, tx));
    }
    if dropped > 0 {
        slog_warn!("p2p", "pending_tx_requeue_dropped", dropped => dropped);
    }

    let mut combined = requeued;
    combined.extend(q.drain(..));
    *q = combined;
}

/// Push a block into the pending queue for consensus validation.
/// Thread-safe: can be called from RPC or any thread.
/// The daemon event loop drains this queue and processes each block
/// through FullNode::process_block() (full validation pipeline).
///
/// LOCK ORDER: PENDING_BLOCKS first, then PEER_PENDING.
/// This matches the lock order in dispatch_message to prevent deadlocks.
pub fn push_pending_block(peer_id: &str, block: Block) -> bool {
    // Lock queue FIRST to match lock order in dispatch_message
    // (queue → PEER_PENDING), preventing deadlocks.
    let mut q = PENDING_BLOCKS.lock();
    if q.len() >= MAX_PENDING_BLOCK_QUEUE {
        slog_warn!("p2p", "pending_block_queue_full");
        return false;
    }
    // Drop duplicate block hashes already waiting in queue.
    if q.iter().any(|(_, b)| b.header.hash == block.header.hash) {
        return true;
    }

    let mut pending = PEER_PENDING.lock();
    let entry = pending.entry(peer_id.to_string()).or_insert((0, 0));
    if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
        slog_warn!("p2p", "per_peer_block_limit_reached", peer => peer_id);
        return false;
    }
    entry.1 += 1;
    q.push((peer_id.to_string(), block));
    true
}

/// Push a transaction into the pending queue for mempool validation.
/// Thread-safe: can be called from RPC or any thread.
///
/// LOCK ORDER: PENDING_TXS first, then PEER_PENDING.
/// This matches the lock order in dispatch_message to prevent deadlocks.
pub fn push_pending_tx(peer_id: &str, tx: Transaction) -> bool {
    // Lock queue FIRST to match lock order in dispatch_message
    // (queue → PEER_PENDING), preventing deadlocks.
    let mut q = PENDING_TXS.lock();
    if q.len() >= MAX_PENDING_TX_QUEUE {
        slog_warn!("p2p", "pending_tx_queue_full");
        return false;
    }
    // Drop duplicate tx hashes already waiting in queue.
    if q.iter().any(|(_, t)| t.hash == tx.hash) {
        return true;
    }

    let mut pending = PEER_PENDING.lock();
    let entry = pending.entry(peer_id.to_string()).or_insert((0, 0));
    if entry.0 >= MAX_PENDING_TXS_PER_PEER {
        slog_warn!("p2p", "per_peer_tx_limit_reached", peer => peer_id);
        return false;
    }
    entry.0 += 1;
    q.push((peer_id.to_string(), tx));
    true
}

/// Extract IP from a peer address string (ip:port), handling IPv4 and IPv6.
/// Formats: "1.2.3.4:9333", "[::1]:9333", "::1"
fn extract_ban_ip(addr: &str) -> String {
    // Try parsing as SocketAddr (handles all formats correctly)
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return sa.ip().to_string();
    }
    // Bracketed IPv6: [::1]:9333
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            return addr[1..end].to_string();
        }
    }
    // IPv4: 1.2.3.4:9333 — split on last ':'
    if let Some(pos) = addr.rfind(':') {
        if addr[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            return addr[..pos].to_string();
        }
    }
    addr.to_string()
}

/// One round of DoS-guard maintenance: decay every peer's ban score toward 0,
/// then evict records that are fully cleared (score 0 and not banned). Composed
/// (decay THEN evict) so a peer that has served out its penalty is dropped from
/// the table the same tick. Takes the guard explicitly so it is unit-testable
/// without the process-global `DOS_GUARD`.
fn maintain_dos_guard(dos: &DosGuard) {
    dos.tick_decay();
    dos.evict_inactive();
}

/// Report a bad TX/block to the DoS guard (called by event loop on rejection).
/// Closes the feedback loop: event_loop → ban_score → P2P disconnects peer.
/// Bans both the full ip:port key AND the IP-only key so reconnecting with a
/// new ephemeral port does not bypass the ban.
pub fn report_bad_peer(peer_id: &str, score: u64, reason: &str) {
    DOS_GUARD.add_ban_score(peer_id, score, reason);
    let ip_key = extract_ban_ip(peer_id);
    if ip_key != peer_id {
        DOS_GUARD.add_ban_score(&ip_key, score, reason);
    }
}

/// Categorized version of report_bad_peer for callers that know the offense type.
pub fn report_bad_peer_cat(peer_id: &str, score: u64, reason: &str, category: BanCategory) {
    DOS_GUARD.add_ban_score_cat(peer_id, score, reason, category);
    let ip_key = extract_ban_ip(peer_id);
    if ip_key != peer_id {
        DOS_GUARD.add_ban_score_cat(&ip_key, score, reason, category);
    }
}

/// Push a message to be broadcast to all connected peers.
/// Thread-safe: can be called from any thread (e.g. TxRelay, mempool).
pub fn push_outbound(msg: P2PMessage) {
    let mut q = OUTBOUND_MSGS.lock();
    if q.1.len() >= 10_000 {
        // Newest-wins: drop the OLDEST queued message, never the new one.
        // Stale gossip is worthless to live peers (laggards backfill via
        // header-sync/IBD), while the new message may be a critical sync
        // request (GetHeaders) — dropping those wedged IBD entirely.
        q.1.remove(0);
        slog_warn!("p2p", "outbound_queue_full");
    }
    let seq = q.0 + 1;
    q.0 = seq;
    q.1.push((seq, msg));
}

/// The current global broadcast sequence number. A freshly-connected peer must
/// start its outbound cursor HERE (not at 0) so it only receives FUTURE
/// broadcasts — the historical backlog is delivered via header-sync / IBD, never
/// replayed through the broadcast queue. Without this, a new peer's cursor of 0
/// against a high global counter is misread as thousands of seqs of "outbound
/// lag" and the peer is wrongly disconnected as slow the instant it connects,
/// which prevents a lagging node from ever catching up (chain never converges).
fn current_outbound_seq() -> u64 {
    OUTBOUND_MSGS.lock().0
}

/// Push a message targeted at a specific peer (Dandelion++ stem phase).
/// Thread-safe: can be called from any thread.
pub fn push_outbound_to_peer(peer_id: &str, msg: P2PMessage) {
    let mut q = TARGETED_MSGS.lock();
    if q.len() < 10_000 {
        q.push((peer_id.to_string(), msg));
    } else {
        slog_warn!("p2p", "targeted_queue_full");
    }
}

/// Drain targeted messages for a specific peer_id.
/// Each peer connection thread calls this with its own ID.
fn drain_targeted_for(peer_id: &str) -> Vec<P2PMessage> {
    let mut q = TARGETED_MSGS.lock();
    let mut mine = Vec::new();
    q.retain(|(target, msg)| {
        if target == peer_id {
            mine.push(msg.clone());
            false // remove from queue
        } else {
            true // keep for other peers
        }
    });
    mine
}

/// Get outbound messages that this peer hasn't sent yet.
/// Each peer tracks its own `last_outbound_seq` to ensure ALL peers
/// receive ALL broadcast messages (not just the first to drain).
/// Also prunes old messages that all peers have had time to read.
fn drain_outbound_since(since: u64) -> (Vec<(u64, P2PMessage)>, u64) {
    // Oldest messages a flush hands one peer in one call. Bounds the per-flush
    // clone cost (the cursor advances incrementally; the next flush continues),
    // so one slow peer's flush can no longer scan-and-clone a huge backlog.
    const OUTBOUND_FLUSH_BATCH: usize = 512;
    let mut q = OUTBOUND_MSGS.lock();
    let new_msgs: Vec<(u64, P2PMessage)> =
        q.1.iter()
            .filter(|(seq, _)| *seq > since)
            .take(OUTBOUND_FLUSH_BATCH)
            .map(|(seq, msg)| (*seq, msg.clone()))
            .collect();
    let max_seq = q.0;
    // Ack-based pruning: remove messages every connected peer has consumed.
    let min_ack = {
        let acks = PEER_LAST_OUTBOUND.lock();
        acks.values().copied().min()
    };
    if let Some(min_seq) = min_ack {
        if min_seq > 0 {
            let before = q.1.len();
            q.1.retain(|(seq, _)| *seq > min_seq);
            let dropped = before.saturating_sub(q.1.len());
            if dropped > 0 {
                slog_debug!("p2p", "outbound_queue_pruned",
                    dropped => dropped,
                    min_ack_seq => min_seq);
            }
        }
    }
    // Hard-cap retention INDEPENDENT of acks: a pinned or stale ack cursor
    // (a leaked entry after a peer-thread panic, or a retained whitelisted
    // laggard) must never freeze pruning — the growing queue first slows
    // every flush and finally wedges sync when it fills. Broadcast messages
    // older than the newest HARD_RETAIN are stale gossip by definition;
    // a peer that far behind backfills via header-sync/IBD instead.
    const OUTBOUND_HARD_RETAIN: u64 = 4_096;
    let cutoff = max_seq.saturating_sub(OUTBOUND_HARD_RETAIN);
    if cutoff > 0 {
        q.1.retain(|(seq, _)| *seq > cutoff);
    }
    (new_msgs, max_seq)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Connection puzzle challenge (anti-Sybil, sent by inbound acceptor).
    PuzzleChallenge {
        challenge: String,
    },
    /// Connection puzzle solution (sent by connector in response).
    PuzzleSolution {
        challenge: String,
        nonce: u64,
        hash: String,
    },

    Version {
        version: u32,
        height: u64,
        timestamp: u64,
        user_agent: String,
        /// Blocks per second — must match for same-chain peers.
        #[serde(default)]
        bps: u32,
        /// Chain identifier — prevents cross-chain connections.
        #[serde(default)]
        chain_id: u32,
        /// Service flags (capabilities bitmap).
        #[serde(default)]
        services: u64,
        /// Random nonce for self-connection detection.
        #[serde(default)]
        nonce: u64,
    },
    VerAck,

    GetAddr,
    Addr {
        peers: Vec<String>,
    },

    GetHeaders {
        from_hash: String,
        count: u32,
    },
    Headers {
        hashes: Vec<String>,
    },
    GetBlock {
        hash: String,
    },
    Block {
        data: Vec<u8>,
    },

    Tx {
        data: Vec<u8>,
    },
    Inv {
        items: Vec<InvItem>,
    },
    GetData {
        items: Vec<InvItem>,
    },

    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Reject {
        reason: String,
    },

    /// Privacy-layer shadow transaction (CommandId::ShadowTx = 0x20).
    ShadowTx {
        data: Vec<u8>,
    },
    /// Privacy-layer onion-routed transaction (CommandId::OnionTx = 0x21).
    OnionTx {
        data: Vec<u8>,
    },
    /// Request mempool contents (CommandId::GetMempool = 0x30).
    GetMempool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvItem {
    pub kind: String,
    pub hash: String,
}

/// Per-connection session state wrapping ProtocolSession with connection-level fields.
///
/// ProtocolSession handles: state machine, version negotiation, nonce tracking.
/// ConnectionSession adds: addr, keepalive timers, bandwidth tracking.
struct ConnectionSession {
    /// Protocol state machine (handshake, lifecycle, version, nonces).
    protocol: ProtocolSession,
    /// Peer's socket address.
    _addr: SocketAddr,
    /// Last time we received a Pong (keepalive monitoring).
    last_pong: Instant,
    /// Last time we sent a Ping (keepalive interval).
    last_ping_sent: Instant,
    /// Bandwidth tracking: bytes received since last reset.
    bytes_this_window: u64,
    /// When the current bandwidth window started.
    bandwidth_window_start: Instant,
    /// Last time we received any message (for stale detection).
    last_message_at: u64,
    /// Count of lifecycle violations (restricted peer sending forbidden commands).
    /// Escalates ban score and disconnects after threshold.
    lifecycle_violations: u32,
    /// Whether this peer connected without solving the connection puzzle.
    /// Legacy peers are monitored more aggressively.
    legacy_peer: bool,
    /// Count of unsupported-message violations (unimplemented protocol commands).
    /// Repeated abuse is treated as malformed/malicious behavior and disconnects.
    unsupported_msg_violations: u32,
    /// Last outbound broadcast sequence number sent to this peer.
    /// Used to ensure every peer gets every broadcast message.
    last_outbound_seq: u64,
}

// dos_type_name removed — CommandId::name() used directly now

impl ConnectionSession {
    fn new(addr: SocketAddr, outbound: bool) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            protocol: ProtocolSession::new(outbound, DEFAULT_BPS),
            _addr: addr,
            last_pong: Instant::now(),
            last_ping_sent: Instant::now(),
            bytes_this_window: 0,
            bandwidth_window_start: Instant::now(),
            last_message_at: now,
            lifecycle_violations: 0,
            legacy_peer: false,
            unsupported_msg_violations: 0,
            // Start at the CURRENT global seq, not 0: a new peer only needs
            // future broadcasts (backlog comes via sync). Starting at 0 makes
            // the outbound-lag check see the whole global counter as "lag" and
            // disconnect the peer as slow on its first flush — which stalled
            // convergence for any node behind the broadcast counter.
            last_outbound_seq: current_outbound_seq(),
        }
    }

    fn touch(&mut self) {
        self.last_message_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    /// Track bandwidth and check if the peer exceeds MAX_BYTES_PER_PEER_PER_MIN.
    /// Returns true if the peer should be disconnected for bandwidth abuse.
    fn check_bandwidth(&mut self, bytes_read: u64) -> bool {
        self.bytes_this_window += bytes_read;

        // Immediate check: reject if we've already exceeded the limit
        // within the current window (don't wait for window expiry).
        if self.bytes_this_window > MAX_BYTES_PER_PEER_PER_MIN {
            return true; // disconnect immediately
        }

        // Reset window after interval
        if self.bandwidth_window_start.elapsed()
            >= Duration::from_secs(BANDWIDTH_CHECK_INTERVAL_SECS)
        {
            self.bytes_this_window = 0;
            self.bandwidth_window_start = Instant::now();
        }
        false
    }

    /// Shorthand: handshake complete?
    #[inline]
    fn is_established(&self) -> bool {
        self.protocol.is_established()
    }

    /// Record bytes received and update protocol stats.
    fn record_bytes_received(&mut self, n: u64) {
        self.protocol.bytes_received += n;
    }

    /// Record bytes sent and update protocol stats.
    fn record_bytes_sent(&mut self, n: u64) {
        self.protocol.bytes_sent += n;
    }
}

pub struct P2P {
    pub peers: Arc<PeerManager>,
    pub message_pool: Vec<String>,
    /// Seen TX hashes (capped at 50K to prevent memory leak)
    pub tx_seen: HashSet<String>,
    /// Peer activity tracking (pruned periodically)
    peer_last_message: HashMap<String, Instant>,
    pub best_height: u64,
    pub listen_addr: String,
    pub network: NetworkMode,
    /// Network magic bytes from config (separates mainnet/testnet/regtest)
    pub network_magic: [u8; 4],
    /// Anti-Eclipse: enforces subnet diversity + crypto identity
    pub diversity: crate::service::network::p2p::peer_diversity::PeerDiversity,
    /// Dandelion++: privacy-preserving TX relay
    pub dandelion: crate::service::network::propagation::dandelion::DandelionRelay,
}

// NOTE: Default impl removed — P2P::new() returns Result<Self, NetworkError>
// and there is no safe fallback. Callers must use P2P::new() explicitly
// and handle the error. The previous Default used expect() which would
// panic on initialization failure (remote DoS via resource exhaustion).

impl P2P {
    #[deprecated(
        note = "Use P2P::new_with_config() — P2P::new() defaults to Mainnet which may be wrong"
    )]
    pub fn new() -> Result<Self, crate::errors::NetworkError> {
        Self::new_with_config(&NodeConfig::for_network(NetworkMode::Mainnet))
    }

    pub fn new_with_config(cfg: &NodeConfig) -> Result<Self, crate::errors::NetworkError> {
        let peers = Arc::new(PeerManager::new_default_path(&cfg.peers_path_str())?);
        Self::new_with_config_and_peers(cfg, peers)
    }

    pub fn new_with_config_and_peers(
        cfg: &NodeConfig,
        peers: Arc<PeerManager>,
    ) -> Result<Self, crate::errors::NetworkError> {
        let magic = cfg.network.magic();
        slog_info!("p2p", "network_init", network => cfg.network.name(), port => cfg.p2p_port, magic => &format!("{:02x}{:02x}{:02x}{:02x}", magic[0], magic[1], magic[2], magic[3]));
        Ok(Self {
            peers,
            message_pool: Vec::new(),
            tx_seen: HashSet::new(),
            peer_last_message: HashMap::new(),
            best_height: 0,
            listen_addr: format!("0.0.0.0:{}", cfg.p2p_port),
            network: cfg.network.clone(),
            network_magic: magic,
            diversity: crate::service::network::p2p::peer_diversity::PeerDiversity::new(),
            dandelion: crate::service::network::propagation::dandelion::DandelionRelay::new(),
        })
    }

    pub fn start(&mut self) -> Result<(), crate::errors::NetworkError> {
        slog_info!("p2p", "network_start", listen_addr => &self.listen_addr);

        // Bind BEFORE spawning — fail fast if port unavailable
        let listener = TcpListener::bind(&self.listen_addr).map_err(|e| {
            crate::errors::NetworkError::ConnectionFailed(format!(
                "P2P bind {} failed: {}",
                self.listen_addr, e
            ))
        })?;

        let magic = self.network_magic;
        let peers = Arc::clone(&self.peers);
        thread::spawn(move || {
            if let Err(e) = Self::accept_loop(listener, magic, &peers) {
                slog_error!("p2p", "accept_loop_error", error => &e.to_string());
            }
        });

        self.peers.bootstrap_for_network(&self.network);

        // Whitelist the trusted seeds so the operator's own nodes never DoS-ban
        // each other: seeds must serve an unbounded IBD backlog to a lagging peer
        // without tripping rate/lag heuristics (which otherwise stall convergence
        // for an hour-long Resource ban). Resolve each seed (IP literal or DNS)
        // to its IP(s); on resolution failure, whitelist the literal as fallback.
        for seed in crate::config::network::bootstrap_nodes::BootstrapNodes::for_network(&self.network)
        {
            match seed.to_socket_addrs() {
                Ok(addrs) => {
                    for a in addrs {
                        crate::service::network::dos_guard::whitelist_peer(&a.ip().to_string());
                    }
                }
                Err(_) => crate::service::network::dos_guard::whitelist_peer(seed),
            }
        }

        let discovered = self.peers.discover_peers();
        if discovered.is_empty() {
            slog_warn!("p2p", "peer_discovery_found_none");
        }
        self.connect_to_peers();
        // Keep connections alive across drops/restarts (auto-reconnect).
        self.spawn_reconnect_loop();
        // Decay DoS ban scores + evict cleared records so peers recover from
        // transient bans and the ban/penalty tables stay bounded on a long node.
        self.spawn_maintenance_loop();

        slog_info!("p2p", "peers_connected", count => self.peers.count());

        self.request_headers_sync();
        Ok(())
    }

    fn accept_loop(
        listener: std::net::TcpListener,
        magic: [u8; 4],
        peer_manager: &Arc<PeerManager>,
    ) -> std::io::Result<()> {
        let addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        slog_info!("p2p", "listener_bound", addr => &addr);

        // Connection throttle state
        let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut accept_count: u32 = 0;
        let mut last_accept_sec = std::time::Instant::now();

        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    // ── Rate limit: max N new connections per second ──
                    if last_accept_sec.elapsed() >= Duration::from_secs(1) {
                        accept_count = 0;
                        last_accept_sec = std::time::Instant::now();
                    }
                    accept_count += 1;
                    if accept_count > MAX_INBOUND_PER_SEC {
                        slog_warn!("p2p", "inbound_throttle", max_per_sec => MAX_INBOUND_PER_SEC);
                        drop(s);
                        continue;
                    }

                    // ── Pending connection limit (atomic check+increment) ──
                    // Use fetch_add to atomically increment, then rollback if over limit.
                    // This closes the TOCTOU race where multiple threads pass the check
                    // before any of them increment.
                    let prev_pending = pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    if prev_pending >= MAX_PENDING_CONNECTIONS {
                        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        slog_warn!("p2p", "too_many_pending_connections", pending => prev_pending);
                        drop(s);
                        continue;
                    }

                    let peer_addr = s
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    // Extract IP without port for ban checking — banning
                    // ip:port is useless because the ephemeral port changes
                    // on every connection.
                    let ban_key = if let Ok(addr) = s.peer_addr() {
                        addr.ip().to_string()
                    } else {
                        peer_addr.clone()
                    };

                    // ── Check if peer is banned ──
                    if DOS_GUARD.is_banned(&ban_key) {
                        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        slog_warn!("p2p", "rejected_banned_peer", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    // ── Anti-eclipse: cap live inbound connections per IP ──
                    // Prevents a single host from monopolizing inbound slots.
                    if !try_register_inbound_ip(&ban_key) {
                        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        slog_warn!("p2p", "rejected_too_many_per_ip", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    // ── Anti-eclipse: cap live inbound connections per /16 ──
                    // Closes the per-IP bypass where an attacker owning a whole
                    // /16 opens many distinct IPs. Whitelisted trusted seeds
                    // bypass the cap (a node must always accept its seeds); they
                    // are still counted + released symmetrically.
                    if !register_inbound_subnet(&ban_key)
                        && !crate::service::network::dos_guard::is_whitelisted(&ban_key)
                    {
                        release_inbound_subnet(&ban_key);
                        release_inbound_ip(&ban_key);
                        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        slog_warn!("p2p", "rejected_too_many_per_subnet", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    slog_info!("p2p", "inbound_connection", addr => &peer_addr);
                    // Query fresh peer list on each connection (fix stale snapshot)
                    let peers_snapshot = peer_manager.get_addr_list_limited(100);
                    let pending_clone = Arc::clone(&pending);
                    let ip_key = ban_key.clone();

                    thread::spawn(move || {
                        let result = Self::handle_peer_connection(s, false, magic, peers_snapshot);
                        pending_clone.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        release_inbound_ip(&ip_key);
                        release_inbound_subnet(&ip_key);
                        if let Err(e) = result {
                            slog_error!("p2p", "peer_connection_error", addr => &peer_addr, error => &e.to_string());
                        }
                    });
                }
                Err(e) => slog_error!("p2p", "accept_error", error => &e.to_string()),
            }
        }
        Ok(())
    }

    fn handle_peer_connection(
        stream: TcpStream,
        outbound: bool,
        magic: [u8; 4],
        known_peers: Vec<String>,
    ) -> Result<(), NetworkError> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        let peer_addr = stream
            .peer_addr()
            .map_err(|e| NetworkError::ConnectionFailed(format!("No peer addr: {}", e)))?;
        let peer_str = peer_addr.to_string();
        // IP-only key for ban scoring — ephemeral port changes on reconnect
        let peer_ip = peer_addr.ip().to_string();
        {
            // Seed a new peer's outbound cursor at the CURRENT broadcast seq, not
            // 0 — a fresh peer starting at 0 would pin min_ack at 0 and freeze the
            // outbound-queue pruning (drain_outbound_since) until a restart. The
            // historical backlog reaches a new peer via its own header-sync, never
            // the broadcast queue, so skipping it here is correct.
            let mut acks = PEER_LAST_OUTBOUND.lock();
            acks.entry(peer_str.clone()).or_insert_with(current_outbound_seq);
        }

        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);

        // Session state: ProtocolSession + connection-level fields
        let mut session = ConnectionSession::new(peer_addr, outbound);

        // ── Connection puzzle (anti-Sybil) ─────────────────────────────────
        if !outbound {
            // Inbound: send puzzle challenge, wait for solution
            let challenge = ConnectionPuzzle::generate_challenge();
            if let Err(e) = session.protocol.sent_puzzle_challenge(&challenge.challenge) {
                return Err(NetworkError::ConnectionFailed(format!(
                    "State error: {}",
                    e
                )));
            }
            let bytes = Self::write_message(
                &mut writer,
                &P2PMessage::PuzzleChallenge {
                    challenge: challenge.challenge.clone(),
                },
                magic,
            )?;
            session.record_bytes_sent(bytes);

            match Self::read_message(&mut reader, magic) {
                Ok((
                    P2PMessage::PuzzleSolution {
                        challenge: c,
                        nonce,
                        hash,
                    },
                    _,
                    sz,
                )) => {
                    session.record_bytes_received(sz as u64);
                    let sol = ChallengeSolution {
                        challenge: c,
                        nonce,
                        hash,
                    };
                    if !ConnectionPuzzle::verify(&challenge, &sol) {
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            100,
                            "invalid puzzle solution",
                            BanCategory::Malicious,
                        );
                        DOS_GUARD.add_ban_score_cat(
                            &peer_ip,
                            100,
                            "invalid puzzle solution",
                            BanCategory::Malicious,
                        );
                        return Err(NetworkError::ConnectionFailed(format!(
                            "Invalid puzzle solution from {}",
                            peer_str
                        )));
                    }
                    session.protocol.puzzle_verified().map_err(|e| {
                        NetworkError::ConnectionFailed(format!("State error: {}", e))
                    })?;
                    slog_info!("p2p", "puzzle_verified", addr => &peer_str);
                }
                Ok((_, cmd, _)) => {
                    DOS_GUARD.add_ban_score_cat(
                        &peer_str,
                        50,
                        "expected puzzle solution",
                        BanCategory::Malicious,
                    );
                    DOS_GUARD.add_ban_score_cat(
                        &peer_ip,
                        50,
                        "expected puzzle solution",
                        BanCategory::Malicious,
                    );
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Expected PuzzleSolution from {}, got {}",
                        peer_str, cmd
                    )));
                }
                Err(e) => {
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Puzzle exchange failed with {}: {}",
                        peer_str, e
                    )));
                }
            }
        } else {
            // Outbound: wait for puzzle challenge, solve it, send solution
            match Self::read_message(&mut reader, magic) {
                Ok((P2PMessage::PuzzleChallenge { challenge }, _, sz)) => {
                    session.record_bytes_received(sz as u64);
                    session
                        .protocol
                        .received_puzzle_challenge(&challenge)
                        .map_err(|e| {
                            NetworkError::ConnectionFailed(format!("State error: {}", e))
                        })?;
                    let sol = ConnectionPuzzle::solve(&challenge);
                    let sol_msg = P2PMessage::PuzzleSolution {
                        challenge: sol.challenge,
                        nonce: sol.nonce,
                        hash: sol.hash,
                    };
                    let bytes = Self::write_message(&mut writer, &sol_msg, magic)?;
                    session.record_bytes_sent(bytes);
                    session.protocol.puzzle_verified().map_err(|e| {
                        NetworkError::ConnectionFailed(format!("State error: {}", e))
                    })?;
                }
                Ok((msg, cmd, sz)) => {
                    // Legacy peer sent a non-puzzle message first.
                    // Accept it but mark this peer as legacy (no puzzle support).
                    // Only allow Version as the first non-puzzle message — anything
                    // else is suspicious and gets a ban score.
                    session.record_bytes_received(sz as u64);
                    session.touch();
                    session.protocol.puzzle_verified().ok();
                    session.legacy_peer = true;
                    if cmd != CommandId::Version {
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            20,
                            &format!(
                                "non-Version first message ({}), expected puzzle or Version",
                                cmd
                            ),
                            BanCategory::Malformed,
                        );
                        DOS_GUARD.add_ban_score_cat(
                            &peer_ip,
                            20,
                            &format!(
                                "non-Version first message ({}), expected puzzle or Version",
                                cmd
                            ),
                            BanCategory::Malformed,
                        );
                    }
                    if cmd == CommandId::Version {
                        // Version is part of handshake — dispatch it
                        if let Err(e) = Self::dispatch_message(
                            &mut writer,
                            msg,
                            &peer_str,
                            magic,
                            &mut session,
                            &known_peers,
                            cmd,
                        ) {
                            slog_debug!("p2p", "dispatch_error", addr => &peer_str, error => &e.to_string());
                        }
                    }
                    // Non-Version messages are dropped (ban score already added above).
                    // Dispatching before the handshake (Version/VerAck) completes
                    // violates the protocol state machine.
                }
                Err(e) => {
                    let emsg = e.to_string().to_lowercase();
                    if !emsg.contains("timed out")
                        && !emsg.contains("would block")
                        && !emsg.contains("wouldblock")
                        && !emsg.contains("temporarily unavailable")
                        && !emsg.contains("os error 11")
                        && !emsg.contains("os error 10035")
                    {
                        return Err(e);
                    }
                    // Timeout waiting for puzzle challenge — peer might be slow or legacy.
                    // Allow connection but flag as legacy. The handshake timeout in the
                    // main loop will catch peers that never complete Version/VerAck.
                    session.protocol.puzzle_verified().ok();
                    session.legacy_peer = true;
                }
            }
        }

        // ── Send our Version (after puzzle phase) ──────────────────────────
        let bytes = Self::send_version(&mut writer, 0, magic)?;
        session.record_bytes_sent(bytes);
        session
            .protocol
            .sent_version()
            .map_err(|e| NetworkError::ConnectionFailed(format!("protocol state error: {}", e)))?;

        // ── Main message loop ──────────────────────────────────────────────
        loop {
            match Self::read_message(&mut reader, magic) {
                Ok((msg, cmd, bytes_read)) => {
                    session.record_bytes_received(bytes_read as u64);
                    session.protocol.msgs_received += 1;
                    session.touch();

                    // Bandwidth enforcement
                    if session.check_bandwidth(bytes_read as u64) {
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            50,
                            "bandwidth abuse (>100MB/min)",
                            BanCategory::Resource,
                        );
                        DOS_GUARD.add_ban_score_cat(
                            &peer_ip,
                            50,
                            "bandwidth abuse (>100MB/min)",
                            BanCategory::Resource,
                        );
                        slog_warn!("p2p", "bandwidth_abuse_disconnect", addr => &peer_str, bytes_per_min => session.bytes_this_window);
                        break;
                    }

                    // Protocol state machine: is this command allowed right now?
                    if let Err(pe) = session.protocol.check_command_allowed(cmd) {
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            pe.ban_score as u64,
                            &pe.message,
                            if pe.ban_score >= 50 {
                                BanCategory::Malicious
                            } else {
                                BanCategory::Malformed
                            },
                        );
                        DOS_GUARD.add_ban_score_cat(
                            &peer_ip,
                            pe.ban_score as u64,
                            &pe.message,
                            if pe.ban_score >= 50 {
                                BanCategory::Malicious
                            } else {
                                BanCategory::Malformed
                            },
                        );
                        slog_warn!("p2p", "command_rejected", addr => &peer_str, command => &cmd.to_string(), state => &session.protocol.state.to_string(), ban_score => pe.ban_score);
                        if pe.ban_score >= 50 {
                            break;
                        }
                        continue;
                    }

                    // Lifecycle filter: restricted peers limited to Ping/Pong/Reject
                    if let Err(pe) = session.protocol.check_lifecycle_allowed(cmd) {
                        session.lifecycle_violations += 1;
                        let (score, cat) = if session.lifecycle_violations > 5 {
                            (20u64, BanCategory::Malformed) // persistent = likely intentional
                        } else {
                            (5u64, BanCategory::Resource) // few violations = possibly buggy client
                        };
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            score,
                            &format!(
                                "lifecycle violation #{}: {}",
                                session.lifecycle_violations, pe
                            ),
                            cat,
                        );
                        DOS_GUARD.add_ban_score_cat(
                            &peer_ip,
                            score,
                            &format!(
                                "lifecycle violation #{}: {}",
                                session.lifecycle_violations, pe
                            ),
                            cat,
                        );
                        slog_warn!("p2p", "lifecycle_blocked", addr => &peer_str, command => &cmd.to_string(), violation_count => session.lifecycle_violations);
                        if session.lifecycle_violations > 10 {
                            slog_warn!("p2p", "excessive_lifecycle_violations_disconnect", addr => &peer_str);
                            break;
                        }
                        continue;
                    }

                    if let Err(e) = Self::dispatch_message(
                        &mut writer,
                        msg,
                        &peer_str,
                        magic,
                        &mut session,
                        &known_peers,
                        cmd,
                    ) {
                        slog_error!("p2p", "dispatch_error", addr => &peer_str, error => &e.to_string());
                        break;
                    }

                    // Flush broadcast + targeted outbound messages
                    if !Self::flush_outbound(&mut writer, &peer_str, &mut session, magic) {
                        let _ = Self::write_message(
                            &mut writer,
                            &P2PMessage::Reject {
                                reason: "peer too slow for outbound stream".to_string(),
                            },
                            magic,
                        );
                        session.protocol.begin_disconnect();
                        break;
                    }
                }
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    let is_timeout = msg.contains("timed out")
                        || msg.contains("would block")
                        || msg.contains("wouldblock")
                        || msg.contains("temporarily unavailable")
                        || msg.contains("os error 11")
                        || msg.contains("os error 10035")
                        // Windows returns WSAETIMEDOUT (10060) for an SO_RCVTIMEO
                        // read-timeout expiry, not EWOULDBLOCK — without this a
                        // Windows node drops every peer every 2s (the read poll
                        // interval). Real dead connections are still caught by the
                        // pong timeout below.
                        || msg.contains("os error 10060")
                        || msg.contains("did not properly respond");

                    if is_timeout {
                        // Keepalive ping
                        if session.is_established()
                            && session.last_ping_sent.elapsed()
                                >= Duration::from_secs(KEEPALIVE_INTERVAL_SECS)
                        {
                            let nonce = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_nanos() as u64)
                                .unwrap_or(0);
                            match Self::write_message(
                                &mut writer,
                                &P2PMessage::Ping { nonce },
                                magic,
                            ) {
                                Ok(bytes) => {
                                    session.record_bytes_sent(bytes);
                                    session.last_ping_sent = Instant::now();
                                }
                                Err(we) => {
                                    slog_error!("p2p", "keepalive_write_error", addr => &peer_str, error => &we.to_string());
                                    break;
                                }
                            }
                        }

                        // Pong timeout
                        if session.is_established()
                            && session.last_pong.elapsed() >= Duration::from_secs(PONG_TIMEOUT_SECS)
                        {
                            slog_warn!("p2p", "pong_timeout_disconnect", addr => &peer_str, timeout_secs => PONG_TIMEOUT_SECS);
                            let _ = Self::write_message(
                                &mut writer,
                                &P2PMessage::Reject {
                                    reason: "pong timeout".to_string(),
                                },
                                magic,
                            );
                            session.protocol.begin_disconnect();
                            break;
                        }

                        // Handshake timeout (protocol state machine)
                        if let Err(pe) = session.protocol.check_handshake_timeout() {
                            slog_warn!("p2p", "handshake_timeout", addr => &peer_str, error => &pe.to_string());
                            let _ = Self::write_message(
                                &mut writer,
                                &P2PMessage::Reject {
                                    reason: format!("timeout: {}", pe),
                                },
                                magic,
                            );
                            session.protocol.begin_disconnect();
                            break;
                        }

                        if !Self::flush_outbound(&mut writer, &peer_str, &mut session, magic) {
                            let _ = Self::write_message(
                                &mut writer,
                                &P2PMessage::Reject {
                                    reason: "peer too slow for outbound stream".to_string(),
                                },
                                magic,
                            );
                            session.protocol.begin_disconnect();
                            break;
                        }
                        continue;
                    }

                    // Graceful disconnect
                    let _ = Self::write_message(
                        &mut writer,
                        &P2PMessage::Reject {
                            reason: format!("disconnect: {}", e),
                        },
                        magic,
                    );
                    session.protocol.begin_disconnect();
                    slog_info!("p2p", "peer_disconnected", addr => &peer_str, reason => &e.to_string());
                    break;
                }
            }
        }

        slog_debug!("p2p", "connection_closed", addr => &peer_str, state => &session.protocol.state.to_string(), lifecycle => &session.protocol.lifecycle.to_string(), bytes_rx => session.protocol.bytes_received, bytes_tx => session.protocol.bytes_sent);
        cleanup_peer_state(&peer_str);
        Ok(())
    }

    /// Flush broadcast + targeted outbound messages to a peer.
    fn flush_outbound(
        writer: &mut BufWriter<&TcpStream>,
        peer_str: &str,
        session: &mut ConnectionSession,
        magic: [u8; 4],
    ) -> bool {
        let (outbound, global_seq) = drain_outbound_since(session.last_outbound_seq);
        if !outbound.is_empty() {
            // Lag is measured against the GLOBAL newest seq, not the (batched)
            // returned slice, so capping the flush batch doesn't mask real lag.
            let lag = global_seq.saturating_sub(session.last_outbound_seq);
            if lag > MAX_OUTBOUND_LAG_SEQS
                && !crate::service::network::dos_guard::is_whitelisted(peer_str)
            {
                let ip_key = extract_ban_ip(peer_str);
                DOS_GUARD.add_ban_score_cat(
                    peer_str,
                    25,
                    "excessive outbound lag; disconnecting slow peer",
                    BanCategory::Resource,
                );
                if ip_key != peer_str {
                    DOS_GUARD.add_ban_score_cat(
                        &ip_key,
                        25,
                        "excessive outbound lag; disconnecting slow peer",
                        BanCategory::Resource,
                    );
                }
                slog_warn!("p2p", "disconnecting_lagging_peer",
                    peer => peer_str,
                    lag_seqs => lag,
                    threshold => MAX_OUTBOUND_LAG_SEQS);
                return false;
            }
        }
        // Track the last successfully sent sequence number.
        // If a write fails mid-way, we only advance to the last message
        // that was actually delivered, so unsent messages will be retried
        // on the next flush (drain_outbound_since reads from the shared
        // queue without removing, so they remain available).
        let old_seq = session.last_outbound_seq;
        let mut last_successful_seq = old_seq;
        for (seq, out_msg) in &outbound {
            match Self::write_message(writer, out_msg, magic) {
                Ok(bytes) => {
                    session.record_bytes_sent(bytes);
                    last_successful_seq = *seq;
                }
                Err(we) => {
                    // Don't advance past this point — failed and subsequent
                    // messages will be retried on the next flush.
                    slog_warn!("p2p", "outbound_write_failed", addr => peer_str,
                        error => &we.to_string(),
                        sent_up_to_seq => last_successful_seq,
                        failed_seq => *seq
                    );
                    break; // Stop sending more to this peer
                }
            }
        }
        // Only update to the last sequence that was actually sent successfully.
        session.last_outbound_seq = last_successful_seq;
        {
            let mut acks = PEER_LAST_OUTBOUND.lock();
            acks.insert(peer_str.to_string(), last_successful_seq);
        }

        let targeted = drain_targeted_for(peer_str);
        for t_msg in targeted {
            match Self::write_message(writer, &t_msg, magic) {
                Ok(bytes) => session.record_bytes_sent(bytes),
                Err(we) => {
                    slog_error!("p2p", "write_error_targeted", addr => peer_str, error => &we.to_string());
                    // Re-queue the undelivered targeted message so it is not
                    // permanently lost. The next flush cycle will retry delivery.
                    {
                        let mut q = TARGETED_MSGS.lock();
                        q.push((peer_str.to_string(), t_msg));
                    }
                    return false;
                }
            }
        }
        true
    }

    /// Write a framed message with 13-byte wire header (magic + cmd + len + checksum).
    ///
    /// The checksum (first 4 bytes of SHA-256(payload)) is computed and verified
    /// on both ends — protects against bit flips, truncation, and tampering.
    fn write_message(
        writer: &mut BufWriter<&TcpStream>,
        msg: &P2PMessage,
        magic: [u8; 4],
    ) -> Result<u64, NetworkError> {
        let payload =
            bincode::serialize(msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::Serialization(format!(
                "Message too large: {} bytes > {}",
                payload.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        // Map P2PMessage variant → CommandId for the wire header
        let cmd = Self::msg_to_command_id(msg);

        // Build 13-byte header: magic(4) + cmd(1) + len(4) + checksum(4)
        let header = WireHeader::for_payload(magic, cmd as u8, &payload);
        let hdr_bytes = header.encode();

        let mut buf = Vec::with_capacity(WIRE_HEADER_SIZE + payload.len());
        buf.extend_from_slice(&hdr_bytes);
        buf.extend_from_slice(&payload);

        let total = buf.len() as u64;
        writer
            .write_all(&buf)
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        writer
            .flush()
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        Ok(total)
    }

    /// Map a P2PMessage variant to its CommandId for wire framing.
    fn msg_to_command_id(msg: &P2PMessage) -> CommandId {
        match msg {
            P2PMessage::Version { .. } => CommandId::Version,
            P2PMessage::VerAck => CommandId::VerAck,
            P2PMessage::Ping { .. } => CommandId::Ping,
            P2PMessage::Pong { .. } => CommandId::Pong,
            P2PMessage::GetAddr => CommandId::GetAddr,
            P2PMessage::Addr { .. } => CommandId::Addr,
            P2PMessage::Inv { .. } => CommandId::Inv,
            P2PMessage::GetData { .. } => CommandId::GetData,
            P2PMessage::Block { .. } => CommandId::Block,
            P2PMessage::Tx { .. } => CommandId::Tx,
            P2PMessage::GetHeaders { .. } => CommandId::GetHeaders,
            P2PMessage::Headers { .. } => CommandId::Headers,
            P2PMessage::GetBlock { .. } => CommandId::GetBlock,
            P2PMessage::Reject { .. } => CommandId::Reject,
            P2PMessage::PuzzleChallenge { .. } => CommandId::PuzzleChallenge,
            P2PMessage::PuzzleSolution { .. } => CommandId::PuzzleSolution,
            P2PMessage::ShadowTx { .. } => CommandId::ShadowTx,
            P2PMessage::OnionTx { .. } => CommandId::OnionTx,
            P2PMessage::GetMempool => CommandId::GetMempool,
        }
    }

    /// Read a framed message with full wire header validation.
    ///
    /// Validation order (defense-in-depth):
    ///   1. Read 13-byte header
    ///   2. Validate magic (wrong network → reject immediately)
    ///   3. Validate command_id (unknown → reject before reading payload)
    ///   4. Validate payload_len (oversize → reject before allocating)
    ///   5. Read payload bytes
    ///   6. Validate checksum (corrupted/tampered → reject before deserializing)
    ///   7. Validate per-command payload size bounds
    ///   8. Deserialize payload (only after all structural checks pass)
    fn read_message(
        reader: &mut BufReader<&TcpStream>,
        magic: [u8; 4],
    ) -> Result<(P2PMessage, CommandId, usize), NetworkError> {
        // 1. Read wire header (13 bytes)
        let mut hdr_buf = [0u8; WIRE_HEADER_SIZE];
        reader
            .read_exact(&mut hdr_buf)
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        let header = WireHeader::decode(&hdr_buf);

        // 2-4. Validate header: magic, command_id, payload_len
        let cmd = validate_header(&header, magic)
            .map_err(|pe| NetworkError::Serialization(format!("[Protocol] {}", pe)))?;

        // 5. Validate per-command payload size bounds BEFORE allocation/read.
        // This prevents adversaries from forcing large allocations for commands
        // that should have tiny payloads (e.g. Ping/Pong).
        let payload_len = header.payload_len as usize;
        validate_payload_size(cmd, payload_len)
            .map_err(|pe| NetworkError::Serialization(format!("[Protocol] {}", pe)))?;

        // 6. Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader
                .read_exact(&mut payload)
                .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        }

        // 7. Validate checksum (BEFORE deserialization — blocks tampered data)
        validate_payload_checksum(&payload, header.checksum)
            .map_err(|pe| NetworkError::Serialization(format!("[Protocol] {}", pe)))?;

        // 8. Deserialize payload (bincode, allocation-bounded)
        let msg: P2PMessage = bounded_deserialize(&payload).map_err(|e| {
            NetworkError::Serialization(format!("[Protocol] {} deserialize failed: {}", cmd, e))
        })?;

        Ok((msg, cmd, WIRE_HEADER_SIZE + payload_len))
    }

    /// Map CommandId to DoS guard MsgType for rate limiting.
    fn cmd_to_dos_type(cmd: CommandId) -> MsgType {
        match cmd {
            CommandId::Version => MsgType::Version,
            CommandId::VerAck => MsgType::VerAck,
            CommandId::Ping => MsgType::Ping,
            CommandId::Pong => MsgType::Pong,
            CommandId::Tx => MsgType::Tx,
            CommandId::Block => MsgType::Block,
            CommandId::Inv => MsgType::Inv,
            CommandId::GetData => MsgType::GetData,
            CommandId::GetAddr => MsgType::GetAddr,
            CommandId::Addr => MsgType::Addr,
            CommandId::GetHeaders => MsgType::GetHeaders,
            CommandId::Headers => MsgType::Headers,
            CommandId::GetBlock => MsgType::GetBlocks,
            CommandId::GetMempool => MsgType::Mempool,
            CommandId::Reject => MsgType::Reject,
            CommandId::ShadowTx => MsgType::Tx, // Same cost as regular TX
            CommandId::OnionTx => MsgType::Tx,  // Same cost as regular TX
            CommandId::PuzzleChallenge => MsgType::Version, // Handshake cost
            CommandId::PuzzleSolution => MsgType::Version,
        }
    }

    fn dispatch_message(
        writer: &mut BufWriter<&TcpStream>,
        msg: P2PMessage,
        peer: &str,
        magic: [u8; 4],
        session: &mut ConnectionSession,
        known_peers: &[String],
        wire_cmd: CommandId,
    ) -> Result<(), NetworkError> {
        // ── DoS Guard: rate limit + ban check ──
        let cmd = Self::msg_to_command_id(&msg);

        // Verify the deserialized message matches the wire header command.
        // Without this check, an attacker can claim cmd=Ping in the header
        // (bypassing handshake restrictions for Ping) but send a Block
        // payload, getting it processed before handshake completes.
        if cmd != wire_cmd {
            DOS_GUARD.add_ban_score_cat(
                peer,
                100,
                &format!("cmd/payload mismatch: header={} actual={}", wire_cmd, cmd),
                BanCategory::Malicious,
            );
            return Ok(());
        }
        let dos_type = Self::cmd_to_dos_type(cmd);
        // Estimate actual payload size (heap data) rather than stack enum size.
        // size_of_val only measures the enum discriminant + inline fields, missing
        // heap-allocated Vec<u8>/String contents which dominate real message size.
        let msg_size = match &msg {
            P2PMessage::Block { data } => data.len(),
            P2PMessage::Tx { data } => data.len(),
            P2PMessage::ShadowTx { data } => data.len(),
            P2PMessage::OnionTx { data } => data.len(),
            P2PMessage::Addr { peers } => peers.iter().map(|s| s.len()).sum(),
            P2PMessage::Headers { hashes } => hashes.iter().map(|s| s.len()).sum(),
            P2PMessage::Inv { items } => items.iter().map(|i| i.kind.len() + i.hash.len()).sum(),
            P2PMessage::GetData { items } => {
                items.iter().map(|i| i.kind.len() + i.hash.len()).sum()
            }
            P2PMessage::PuzzleSolution {
                challenge, hash, ..
            } => challenge.len() + hash.len() + 8,
            P2PMessage::PuzzleChallenge { challenge } => challenge.len(),
            P2PMessage::Version { user_agent, .. } => user_agent.len() + 32,
            P2PMessage::Reject { reason } => reason.len(),
            P2PMessage::GetHeaders { from_hash, .. } => from_hash.len() + 4,
            P2PMessage::GetBlock { hash } => hash.len(),
            _ => std::mem::size_of_val(&msg), // small fixed-size messages (Ping, Pong, etc.)
        };
        match DOS_GUARD.check(peer, &dos_type, msg_size) {
            DosVerdict::Allow => {}
            DosVerdict::BanActive => {
                return Err(NetworkError::PeerBanned(peer.to_string()));
            }
            DosVerdict::RateLimited { .. } => {
                slog_warn!("p2p", "rate_limited", addr => peer);
                return Ok(());
            }
            DosVerdict::GlobalRateLimited => {
                return Ok(());
            }
            DosVerdict::OversizedMessage { allowed, got } => {
                slog_warn!("p2p", "oversized_message", addr => peer, size => got, max_allowed => allowed);
                return Err(NetworkError::DosGuard(format!(
                    "oversized message from {}",
                    peer
                )));
            }
        }

        // NOTE: Handshake enforcement + lifecycle filtering are done in the
        // main loop BEFORE dispatch_message is called, using:
        //   session.protocol.check_command_allowed(cmd)
        //   session.protocol.check_lifecycle_allowed(cmd)

        match msg {
            // ── Puzzle messages (edge case: received in main loop) ──────
            P2PMessage::PuzzleChallenge { challenge } => {
                let sol = ConnectionPuzzle::solve(&challenge);
                let sol_msg = P2PMessage::PuzzleSolution {
                    challenge: sol.challenge,
                    nonce: sol.nonce,
                    hash: sol.hash,
                };
                let bytes = Self::write_message(writer, &sol_msg, magic)?;
                session.record_bytes_sent(bytes);
                session.protocol.puzzle_verified().ok();
            }

            P2PMessage::PuzzleSolution { .. } => {
                DOS_GUARD.add_ban_score_cat(
                    peer,
                    10,
                    "unexpected puzzle solution",
                    BanCategory::Malformed,
                );
            }

            // ── Version: full validation via ProtocolSession ────────���──
            P2PMessage::Version {
                version,
                height,
                timestamp,
                user_agent,
                bps,
                chain_id,
                services,
                nonce,
            } => {
                // Self-connection: the peer echoed OUR stable identity nonce, so
                // this connection is to ourselves (our own IP is in the seed
                // list). Record the IP so the dial/reconnect loop stops targeting
                // it, and drop the connection (NO ban — it's us). Without this a
                // node churns endlessly connecting to itself instead of to real
                // peers, and never catches up.
                if nonce == crate::service::network::p2p::protocol::local_identity_nonce() {
                    mark_self_addr(peer);
                    slog_info!("p2p", "self_connection_dropped", addr => peer);
                    return Err(NetworkError::ConnectionFailed(format!(
                        "self-connection to {} dropped",
                        peer
                    )));
                }
                // Build VersionPayload and validate through protocol state machine.
                // Do NOT normalize zero values — reject them outright.
                // Zero bps/services indicates a broken or malicious peer; silently
                // substituting defaults masks protocol violations and lets
                // incompatible peers connect.
                if bps == 0 {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        100,
                        "version bps=0 (invalid)",
                        BanCategory::Malformed,
                    );
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Rejected version from {}: bps=0",
                        peer
                    )));
                }
                if services == 0 {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        100,
                        "version services=0 (invalid)",
                        BanCategory::Malformed,
                    );
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Rejected version from {}: services=0",
                        peer
                    )));
                }
                let payload = VersionPayload {
                    version,
                    height,
                    timestamp,
                    user_agent: user_agent.clone(),
                    bps,
                    chain_id,
                    services,
                    nonce,
                };

                // ProtocolSession::received_version validates:
                //   - version range [1, PROTOCOL_VERSION]
                //   - BPS match
                //   - chain_id match
                //   - timestamp drift (±5 min)
                //   - user_agent bounds + control chars
                //   - service flags
                //   - duplicate version (100 ban_score)
                if let Err(pe) = session.protocol.received_version(payload) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        if pe.ban_score >= 100 {
                            BanCategory::Malicious
                        } else {
                            BanCategory::Malformed
                        },
                    );
                    if pe.ban_score >= 50 {
                        return Err(NetworkError::ConnectionFailed(format!(
                            "Version rejected from {}: {}",
                            peer, pe
                        )));
                    }
                    return Ok(());
                }

                // Log peer identity. Use char-safe truncation: `id` derives from
                // the attacker-controlled Version user_agent, so byte-slicing
                // `&id[..16]` could land mid-UTF-8 and panic the peer thread
                // (and leak its PEER_LAST_OUTBOUND entry since cleanup runs after
                // the loop).
                if let Some(id) = session.protocol.peer_identity() {
                    let short: String = id.chars().take(16).collect();
                    slog_debug!("p2p", "peer_identity", addr => peer, identity => &short);
                }

                let bytes = Self::write_message(writer, &P2PMessage::VerAck, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── VerAck: complete handshake via state machine ───────────
            P2PMessage::VerAck => {
                if let Err(pe) = session.protocol.received_verack() {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                slog_info!("p2p", "handshake_complete", addr => peer, height => session.protocol.peer_height(), lifecycle => &session.protocol.lifecycle.to_string());

                // Initiate sync if peer is ahead
                let peer_height = session.protocol.peer_height();
                if peer_height > 0 {
                    session.protocol.begin_header_sync(peer_height);
                } else {
                    session.protocol.sync_complete();
                }

                // Request peer addresses
                let bytes = Self::write_message(writer, &P2PMessage::GetAddr, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── GetAddr: validated address list ─���──────────────────────
            P2PMessage::GetAddr => {
                let addrs: Vec<String> = known_peers.iter().take(100).cloned().collect();
                let response = P2PMessage::Addr { peers: addrs };
                let bytes = Self::write_message(writer, &response, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── Addr: validate list size ──���────────────────────────────
            P2PMessage::Addr { ref peers } => {
                if let Err(pe) = validate_addr_list(peers) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                // Queue addresses for the daemon event loop to feed to PeerManager.
                // SECURITY: only enqueue entries that parse as a ROUTABLE
                // SocketAddr. validate_addr_list checks list length only — without
                // this per-entry check, arbitrary garbage strings get persisted as
                // peer records (each distinct string is a unique "ip", so the
                // per-IP cap never trips), letting a handshaked peer grow the peer
                // DB without bound (disk exhaustion) and poison peer selection.
                {
                    let mut q = RECEIVED_ADDRS.lock();
                    let mut rejected = 0u32;
                    for addr in peers {
                        if !is_routable_peer_addr(addr) {
                            rejected = rejected.saturating_add(1);
                            continue;
                        }
                        if q.len() < 4096 {
                            q.push(addr.clone());
                        }
                    }
                    drop(q);
                    if rejected > 0 {
                        // Penalize peers that send invalid/garbage addresses.
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            (rejected as u64).min(50),
                            "invalid addr entries",
                            BanCategory::Malformed,
                        );
                    }
                }
                slog_debug!("p2p", "received_addresses", count => peers.len(), addr => peer);
            }

            // ── Ping: anti-replay via ProtocolSession nonce tracking ───
            P2PMessage::Ping { nonce } => {
                if !session.protocol.record_nonce(nonce) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        20,
                        "duplicate ping nonce (replay)",
                        BanCategory::Malicious,
                    );
                    slog_warn!("p2p", "replay_detected", addr => peer, nonce => nonce);
                    return Ok(());
                }
                let bytes = Self::write_message(writer, &P2PMessage::Pong { nonce }, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── Pong: anti-replay + keepalive tracking ─────────────────
            P2PMessage::Pong { nonce } => {
                if !session.protocol.record_nonce(nonce) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        20,
                        "duplicate pong nonce (replay)",
                        BanCategory::Malicious,
                    );
                    return Ok(());
                }
                session.last_pong = Instant::now();
            }

            // ── Tx: DagShield pre-validation + queue management ────��───
            P2PMessage::Tx { data } => {
                match bounded_deserialize::<Transaction>(&data) {
                    Ok(tx) => {
                        match DagShield::pre_validate_tx(&tx) {
                            Ok(()) => {
                                // Atomicize quota check + queue push under a single lock scope
                                // to prevent TOCTOU race where multiple threads pass the check.
                                let pushed = {
                                    let mut q = PENDING_TXS.lock();
                                    if q.len() >= 10_000 {
                                        false
                                    } else {
                                        // Check per-peer quota inside the same critical section
                                        let mut m = PEER_PENDING.lock();
                                        let entry = m.entry(peer.to_string()).or_insert((0, 0));
                                        if entry.0 >= MAX_PENDING_TXS_PER_PEER {
                                            false
                                        } else {
                                            entry.0 += 1;
                                            q.push((peer.to_string(), tx));
                                            true
                                        }
                                    }
                                };

                                if !pushed {
                                    DOS_GUARD.add_ban_score_cat(
                                        peer,
                                        5,
                                        "TX queue quota exceeded or full",
                                        BanCategory::Resource,
                                    );
                                }
                            }
                            Err(rej) => {
                                DOS_GUARD.add_ban_score_cat(
                                    peer,
                                    rej.ban_score as u64,
                                    rej.reason,
                                    BanCategory::Malformed,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // Malformed bincode = either attack or deeply broken client.
                        // Score 25 so 4 malformed TXs = auto-ban (100).
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            25,
                            "invalid tx deserialization",
                            BanCategory::Malformed,
                        );
                        slog_error!("p2p", "invalid_tx_deserialize", addr => peer, error => &e.to_string());
                    }
                }
            }

            // ── Block: DagShield pre-validation + queue management ──────
            P2PMessage::Block { data } => {
                match bounded_deserialize::<Block>(&data) {
                    Ok(block) => {
                        match DagShield::pre_validate_block(&block) {
                            Ok(()) => {
                                // Atomicize quota check + queue push (same pattern as Tx)
                                let pushed = {
                                    let mut q = PENDING_BLOCKS.lock();
                                    if q.len() >= 1_000 {
                                        false
                                    } else {
                                        let mut m = PEER_PENDING.lock();
                                        let entry = m.entry(peer.to_string()).or_insert((0, 0));
                                        if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
                                            false
                                        } else {
                                            entry.1 += 1;
                                            q.push((peer.to_string(), block));
                                            true
                                        }
                                    }
                                };

                                if !pushed {
                                    DOS_GUARD.add_ban_score_cat(
                                        peer,
                                        10,
                                        "block queue quota exceeded or full",
                                        BanCategory::Resource,
                                    );
                                }
                            }
                            Err(rej) => {
                                DOS_GUARD.add_ban_score_cat(
                                    peer,
                                    rej.ban_score as u64,
                                    rej.reason,
                                    BanCategory::Malformed,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // Malformed block bincode = immediate high penalty.
                        // Score 50 so 2 malformed blocks = auto-ban.
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            50,
                            "invalid block deserialization",
                            BanCategory::Malformed,
                        );
                        slog_error!("p2p", "invalid_block_deserialize", addr => peer, error => &e.to_string());
                    }
                }
            }

            // ── Inv: validate item list via protocol validators ─────────
            P2PMessage::Inv { ref items } => {
                let pairs: Vec<(String, String)> = items
                    .iter()
                    .map(|i| (i.kind.clone(), i.hash.clone()))
                    .collect();
                if let Err(pe) = validate_inv_items(&pairs) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                // Filter out items we already have to avoid redundant GetData
                // requests. Without this, a peer can send repeated Inv messages
                // to force us to re-download everything we already have.
                let needed: Vec<_> = {
                    let pending = PENDING_BLOCKS.lock();
                    items
                        .iter()
                        .filter(|i| !pending.iter().any(|(_, b)| b.header.hash == i.hash))
                        .cloned()
                        .collect()
                };
                if !needed.is_empty() {
                    let get_data = P2PMessage::GetData { items: needed };
                    let bytes = Self::write_message(writer, &get_data, magic)?;
                    session.record_bytes_sent(bytes);
                }
            }

            // ── GetData: validate item list and serve requested data ────
            P2PMessage::GetData { ref items } => {
                let pairs: Vec<(String, String)> = items
                    .iter()
                    .map(|i| (i.kind.clone(), i.hash.clone()))
                    .collect();
                if let Err(pe) = validate_inv_items(&pairs) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                // Serve requested data by forwarding to per-peer targeted queue.
                // The peer's connection thread drains targeted messages and writes
                // them to the socket, so we never touch the TcpStream directly.
                for item in items {
                    match item.kind.as_str() {
                        "block" => {
                            // Block serving needs block_store access (not
                            // available here). Queue the request for the daemon
                            // event loop, which serves it to this peer.
                            push_block_request(peer, &item.hash);
                        }
                        "tx" => {
                            // TX serving requires mempool access which this layer
                            // doesn't have. Log the request for the upper layer.
                            slog_debug!("p2p", "getdata_tx_requested", hash => &item.hash, peer => peer);
                        }
                        _ => {
                            slog_debug!("p2p", "getdata_unknown_kind", kind => &item.kind, peer => peer);
                        }
                    }
                }
            }

            // ── GetHeaders: queue a forward-walk header response ─────────
            P2PMessage::GetHeaders { ref from_hash, .. } => {
                if !from_hash.is_empty() {
                    if let Err(pe) = validate_hash_hex(from_hash) {
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            pe.ban_score as u64,
                            &pe.message,
                            BanCategory::Malformed,
                        );
                        return Ok(());
                    }
                }
                let count = match msg {
                    P2PMessage::GetHeaders { count, .. } => count,
                    _ => 512,
                };
                // Serving real sequential headers needs block_store access, which
                // dispatch_message lacks. Queue for the daemon event loop, which
                // walks the chain forward from from_hash and replies to this peer.
                push_header_request(peer, from_hash, count);
            }

            // ── Headers: validate hash list and queue blocks for download ─
            P2PMessage::Headers { ref hashes } => {
                slog_info!("p2p", "headers_received", from => peer, count => hashes.len());
                if let Err(pe) = validate_headers_list(hashes) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                // Limit GetBlock requests to prevent amplification attacks.
                // A malicious peer could send 2000 header hashes to trigger
                // 2000 outbound GetBlock requests in one message.
                let mut seen = std::collections::HashSet::new();
                // Max blocks to request per Headers message. Bounded to cap the
                // outbound amplification a hostile peer can trigger, but large
                // enough that IBD backfill isn't throttled to a crawl — a node
                // catching up a tall chain needs to pull the served range (up to
                // 512 hashes) in a few round-trips, not 64 at a time (W3). The
                // GetBlock serve side is itself bounded (512/tick), so this is
                // safe. (was 64 — too slow to close a large gap.)
                let max_requests = 512; // one full served Headers range per round
                let mut request_count = 0;
                for hash in hashes {
                    if request_count >= max_requests {
                        break;
                    }
                    if hash.is_empty() || !seen.insert(hash.clone()) {
                        continue;
                    }
                    // Skip blocks already in the pending queue — avoids
                    // redundant GetBlock requests that waste bandwidth.
                    {
                        let pending = PENDING_BLOCKS.lock();
                        if pending.iter().any(|(_, b)| b.header.hash == *hash) {
                            continue;
                        }
                    }
                    let req = P2PMessage::GetBlock { hash: hash.clone() };
                    let bytes = Self::write_message(writer, &req, magic)?;
                    session.record_bytes_sent(bytes);
                    request_count += 1;
                }
            }

            // ── GetBlock: validate hash and log the request ─────────────
            P2PMessage::GetBlock { ref hash } => {
                if let Err(pe) = validate_hash_hex(hash) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                // Block serving needs block_store access (not available here).
                // Queue the request for the daemon event loop, which looks the
                // block up and replies to this peer via push_outbound_to_peer.
                push_block_request(peer, hash);
            }

            // ── Reject: validate reason length ──────────────────────────
            P2PMessage::Reject { ref reason } => {
                if let Err(pe) = validate_reject(reason) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                slog_warn!("p2p", "rejected_by_peer", addr => peer, reason => reason.as_str());
            }

            // ── ShadowTx / OnionTx / GetMempool: not yet implemented ───
            P2PMessage::ShadowTx { .. } | P2PMessage::OnionTx { .. } | P2PMessage::GetMempool => {
                session.unsupported_msg_violations =
                    session.unsupported_msg_violations.saturating_add(1);
                let (score, cat) = if session.unsupported_msg_violations >= 5 {
                    (50u64, BanCategory::Malformed)
                } else {
                    (10u64, BanCategory::Resource)
                };
                let reason = format!(
                    "unsupported message type (count={})",
                    session.unsupported_msg_violations
                );
                report_bad_peer_cat(peer, score, &reason, cat);
                slog_warn!("p2p", "unsupported_message",
                    addr => peer,
                    cmd => &format!("{:?}", Self::msg_to_command_id(&msg)),
                    violation_count => session.unsupported_msg_violations);
                if session.unsupported_msg_violations >= 3 {
                    return Err(NetworkError::ConnectionFailed(format!(
                        "disconnecting {} for repeated unsupported messages",
                        peer
                    )));
                }
            }
        }
        Ok(())
    }

    fn send_version(
        writer: &mut BufWriter<&TcpStream>,
        height: u64,
        magic: [u8; 4],
    ) -> Result<u64, NetworkError> {
        let identity = PeerIdentity::generate();
        let user_agent = format!(
            "ShadowDAG/{} id:{}",
            env!("CARGO_PKG_VERSION"),
            identity.public_key
        );
        let vp = build_version_payload(&user_agent, height, DEFAULT_BPS);

        let msg = P2PMessage::Version {
            version: vp.version,
            height: vp.height,
            timestamp: vp.timestamp,
            user_agent: vp.user_agent,
            bps: vp.bps,
            chain_id: vp.chain_id,
            services: vp.services,
            nonce: vp.nonce,
        };
        Self::write_message(writer, &msg, magic)
    }

    fn connect_to_peers(&mut self) {
        let peer_list = self.peers.get_peers();
        let count = peer_list.len().min(MAX_PEERS);
        let magic = self.network_magic;
        let known_peers = self.peers.get_addr_list_limited(100);
        slog_info!("p2p", "connecting_to_peers", count => count);

        for addr in peer_list.into_iter().take(count) {
            Self::spawn_outbound(addr, magic, known_peers.clone());
        }
    }

    /// Dial one peer in its own thread, tracking the live connection in
    /// CONNECTED_OUTBOUND so it is neither double-dialed nor left un-redialed.
    /// Skips peers already connected; frees the slot when the connection ends so
    /// the reconnect loop can re-dial. This is the unit of auto-reconnect.
    fn spawn_outbound(addr: String, magic: [u8; 4], peers_snapshot: Vec<String>) {
        // Never dial our own IP (identified via the identity-nonce self-check).
        // The seed list contains this node's own address; without this the node
        // wastes every dial re-connecting to itself instead of to real peers.
        if is_self_addr(&addr) {
            return;
        }
        // Anti-eclipse: keep OUTBOUND links spread across /16 subnets so an
        // attacker owning one subnet can't occupy every outbound slot and
        // control our view of the chain. Whitelisted trusted seeds are exempt
        // (a node must always be able to reach its configured seeds); the limit
        // therefore constrains only untrusted peers.
        if !crate::service::network::dos_guard::is_whitelisted(&addr)
            && outbound_subnet_would_saturate(&addr)
        {
            slog_debug!("p2p", "outbound_subnet_diversity_skip", addr => &addr);
            return;
        }
        // Reserve the slot up front (atomic check-and-insert) so two callers
        // can't both dial the same peer.
        {
            let mut set = CONNECTED_OUTBOUND.lock();
            if set.contains(&addr) {
                return;
            }
            set.insert(addr.clone());
        }
        LAST_DIAL.lock().insert(addr.clone(), Instant::now());
        thread::spawn(move || {
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    slog_info!("p2p", "outbound_connected", addr => &addr);
                    if let Err(e) =
                        Self::handle_peer_connection(stream, true, magic, peers_snapshot)
                    {
                        slog_info!("p2p", "peer_connection_ended", addr => &addr, reason => &e.to_string());
                    }
                }
                Err(e) => {
                    slog_warn!("p2p", "outbound_connect_failed", addr => &addr, error => &e.to_string());
                }
            }
            // Connection ended or failed — free the slot for re-dial.
            CONNECTED_OUTBOUND.lock().remove(&addr);
        });
    }

    /// Background maintenance: every 15s, re-dial any known peer that has no live
    /// outbound connection. Without this a node stays isolated after a restart,
    /// a dropped connection, or a transient refusal — which is exactly why forked
    /// nodes never reconverged. Runs for the life of the process.
    fn spawn_reconnect_loop(&self) {
        let peers = Arc::clone(&self.peers);
        let magic = self.network_magic;
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(10));
            let known_snapshot = peers.get_addr_list_limited(100);
            for addr in peers.get_peers() {
                // Already connected — leave it.
                if CONNECTED_OUTBOUND.lock().contains(&addr) {
                    continue;
                }
                // Never dial a banned peer (a stale ban or a real one): dialing
                // it just gets rejected and re-bans via connection spam.
                if peers.is_banned(&addr) {
                    continue;
                }
                // Rate-limit re-dials of the same peer so a fast-failing target
                // (banned, or our own IP self-connecting) doesn't churn.
                if let Some(last) = LAST_DIAL.lock().get(&addr) {
                    if last.elapsed() < std::time::Duration::from_secs(MIN_REDIAL_INTERVAL_SECS) {
                        continue;
                    }
                }
                Self::spawn_outbound(addr, magic, known_snapshot.clone());
            }
        });
    }

    /// Periodic network-health maintenance (every 60s): decay DoS ban scores +
    /// evict cleared records (so a peer wrongly/transiently banned recovers and
    /// the ban table stays bounded), and decay the peer-manager penalty scores +
    /// bound the addr cache. These `tick_decay`/`evict_inactive`/`decay_penalties`
    /// primitives existed but were never driven by any running loop.
    fn spawn_maintenance_loop(&self) {
        let peers = Arc::clone(&self.peers);
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(60));
            maintain_dos_guard(&DOS_GUARD);
            peers.decay_penalties();
            peers.evict_addr_cache_if_full();
        });
    }

    /// Proactively request headers from all connected peers to initiate sync.
    /// Sends GetHeaders with the latest known DAG tip so peers respond with
    /// any blocks we don't have yet.
    fn request_headers_sync(&self) {
        let mut tips = crate::service::network::nodes::full_node::get_dag_tips();
        tips.sort(); // deterministic ordering
                     // Send GetHeaders for EACH DAG tip so peers respond with branches
                     // we might be missing. Previously only the first tip was used,
                     // which could miss entire DAG branches.
        if tips.is_empty() {
            // Fresh node — request from genesis
            push_outbound(P2PMessage::GetHeaders {
                from_hash: String::new(),
                count: 2000,
            });
            slog_info!("p2p", "requesting_headers_sync_genesis");
            return;
        }
        for tip in &tips {
            push_outbound(P2PMessage::GetHeaders {
                from_hash: tip.clone(),
                count: 2000,
            });
        }
        slog_info!("p2p", "requesting_headers_sync",
            height => self.best_height,
            tips => tips.len(),
            note => "sent GetHeaders for each DAG tip");
    }

    pub fn allow_peer(&mut self, peer_id: &str) -> bool {
        let now = Instant::now();
        if let Some(last) = self.peer_last_message.get(peer_id) {
            if now.duration_since(*last) < Duration::from_millis(RATE_LIMIT_MS) {
                return false;
            }
        }
        self.peer_last_message.insert(peer_id.to_string(), now);
        true
    }

    pub fn fast_sync_headers(&self) {
        slog_debug!("p2p", "fast_sync_headers_deprecated");
    }
    pub fn fast_sync_blocks(&self) {
        slog_debug!("p2p", "fast_sync_blocks_deprecated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::network::p2p::peer_manager::MAX_PEERS_PER_IP;

    #[test]
    fn inbound_per_ip_cap_enforced_and_released() {
        // Unique IP so this test does not race the global map with others.
        let ip = "203.0.113.77";
        // Up to the cap succeeds...
        for _ in 0..MAX_PEERS_PER_IP {
            assert!(try_register_inbound_ip(ip), "within cap must register");
        }
        // ...the next is rejected (anti-eclipse).
        assert!(!try_register_inbound_ip(ip), "over cap must be rejected");
        // Releasing one frees a slot.
        release_inbound_ip(ip);
        assert!(try_register_inbound_ip(ip), "slot freed after release");
        // Clean up so the map does not leak this IP across the suite.
        for _ in 0..MAX_PEERS_PER_IP {
            release_inbound_ip(ip);
        }
        // Over-release must not underflow/panic.
        release_inbound_ip(ip);
    }

    #[test]
    fn inbound_per_subnet_cap_enforced_and_released() {
        // Distinct IPs in the SAME /16 (198.51.x) — the per-IP cap would let
        // each in, but the per-subnet cap must bound the /16 total. Unique
        // second octet keeps this test off other tests' subnets.
        let ip = |h: u32| format!("198.51.{}.{}", h / 250, h % 250);
        // Register up to the subnet cap: each returns "within cap" == true.
        for i in 0..MAX_INBOUND_PER_SUBNET {
            assert!(
                register_inbound_subnet(&ip(i)),
                "within subnet cap must be within-limit"
            );
        }
        // The next distinct IP in the same /16 is OVER the cap.
        assert!(
            !register_inbound_subnet(&ip(999)),
            "over subnet cap must report over-limit"
        );
        // That over-cap call still incremented (always-increment semantics), so
        // release it to stay symmetric, then release the in-cap registrations.
        release_inbound_subnet(&ip(999));
        // Releasing one frees a subnet slot.
        release_inbound_subnet(&ip(0));
        assert!(
            register_inbound_subnet(&ip(1000)),
            "subnet slot freed after release"
        );
        // Clean up the whole subnet so it does not leak across the suite.
        release_inbound_subnet(&ip(1000));
        for i in 1..MAX_INBOUND_PER_SUBNET {
            release_inbound_subnet(&ip(i));
        }
        release_inbound_subnet(&ip(0)); // idempotent / no underflow
    }

    #[test]
    fn outbound_subnet_diversity_limits_same_16() {
        use crate::service::network::p2p::peer_diversity::MAX_PEERS_PER_SUBNET;
        // Two peers already connected from the same /16 (192.0.2.x) saturate it.
        let connected: std::collections::HashSet<String> = (0..MAX_PEERS_PER_SUBNET)
            .map(|i| format!("192.0.2.{}:19333", i + 1))
            .collect();
        assert!(
            subnet_saturated_among("192.0.2.200:19333", connected.iter()),
            "a third peer in the same /16 must be blocked"
        );
        // A peer in a DIFFERENT /16 is allowed (diversity, not a global cap).
        assert!(
            !subnet_saturated_among("198.51.100.9:19333", connected.iter()),
            "a distinct /16 must still be dialable"
        );
        // Empty connected set never saturates.
        assert!(!subnet_saturated_among("192.0.2.1:19333", std::iter::empty()));
    }

    #[test]
    fn self_addr_marking_stops_dialing_own_ip() {
        // A documentation-range IP unique to this test. Marking it as self must
        // make it recognized as self on ANY port (so the dial loop skips it),
        // while other IPs stay non-self.
        assert!(!is_self_addr("203.0.113.211:19333"));
        mark_self_addr("203.0.113.211:19333");
        assert!(is_self_addr("203.0.113.211:19333"));
        assert!(
            is_self_addr("203.0.113.211:41122"),
            "self is matched by IP, any port"
        );
        assert!(
            !is_self_addr("198.51.100.211:19333"),
            "a different IP must not be treated as self"
        );
    }

    #[test]
    fn maintenance_evicts_cleared_dos_records() {
        // Two tracked-but-cleared peers (score 0, not banned) must be evicted by
        // one maintenance round — the wiring that keeps the ban table bounded.
        let g = DosGuard::new();
        g.check("p_a", &MsgType::Ping, 10);
        g.check("p_b", &MsgType::Ping, 10);
        assert_eq!(g.stats().tracked_peers, 2);
        maintain_dos_guard(&g);
        assert_eq!(
            g.stats().tracked_peers,
            0,
            "maintenance must decay + evict cleared DoS records"
        );
    }

    #[test]
    fn new_session_cursor_is_current_not_zero() {
        // A fresh session must adopt the live broadcast counter, not 0. Starting
        // at 0 made the outbound-lag check treat a newly-connected peer as
        // thousands of seqs behind and disconnect it as "slow" — which stalled
        // chain convergence for any node behind the counter (observed live:
        // restarted peers could never catch up to the mining seed).
        for _ in 0..3 {
            push_outbound(P2PMessage::Ping { nonce: 7 });
        }
        let s = ConnectionSession::new("1.2.3.4:9333".parse().unwrap(), true);
        assert!(
            s.last_outbound_seq >= 3,
            "new session cursor must track the global seq, got {}",
            s.last_outbound_seq
        );
    }

    #[test]
    fn addr_routability_filter_rejects_garbage_and_unroutable() {
        // Valid routable addresses are accepted.
        assert!(is_routable_peer_addr("203.0.113.9:9333"));
        assert!(is_routable_peer_addr("[2001:db8::1]:9333"));
        // Garbage / unparseable strings are rejected (they would otherwise bloat
        // the peer DB unbounded — each distinct string a unique "ip").
        assert!(!is_routable_peer_addr("not-an-address"));
        assert!(!is_routable_peer_addr(""));
        assert!(!is_routable_peer_addr("AAAA".repeat(50).as_str()));
        assert!(!is_routable_peer_addr("1.2.3.4")); // no port
        // Loopback / unspecified / multicast are rejected.
        assert!(!is_routable_peer_addr("127.0.0.1:9333"));
        assert!(!is_routable_peer_addr("0.0.0.0:9333"));
        assert!(!is_routable_peer_addr("224.0.0.1:9333"));
    }

    #[test]
    fn bounded_deserialize_wire_compatible() {
        // Proves bounded_deserialize round-trips data produced by the
        // bincode::serialize used on the send side (same wire format).
        let msg = P2PMessage::Ping { nonce: 0xdead_beef };
        let bytes = bincode::serialize(&msg).expect("serialize");
        let back: P2PMessage = bounded_deserialize(&bytes).expect("bounded deserialize");
        assert!(matches!(back, P2PMessage::Ping { nonce } if nonce == 0xdead_beef));

        // A buffer whose declared inner length exceeds the buffer must fail
        // cleanly (not allocate). Vec<u8> with a fixint length prefix of
        // u64::MAX followed by no data:
        let mut evil = Vec::new();
        evil.extend_from_slice(&u64::MAX.to_le_bytes()); // claimed length
        let r: Result<Vec<u8>, _> = bounded_deserialize(&evil);
        assert!(r.is_err(), "oversized inner length must be rejected, not allocated");
    }
}
