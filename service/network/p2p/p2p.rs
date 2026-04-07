// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashSet, HashMap};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write, BufReader, BufWriter};
use std::sync::Arc;
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::thread;

use serde::{Serialize, Deserialize};

use crate::errors::NetworkError;
use crate::{slog_info, slog_warn, slog_error, slog_debug};
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::service::network::dos_guard::{DosGuard, DosVerdict, MsgType, BanCategory};
use crate::config::network::network_params::NetworkParams;
use crate::config::node::node_config::{NodeConfig, NetworkMode};
use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::Transaction;
use crate::engine::dag::security::dag_shield::DagShield;
use crate::service::network::p2p::connection_puzzle::{ConnectionPuzzle, ChallengeSolution};
use crate::service::network::p2p::peer_diversity::PeerIdentity;
use crate::service::network::p2p::protocol::{
    self, WireHeader, CommandId, ProtocolSession, VersionPayload,
    WIRE_HEADER_SIZE, CHAIN_ID, DEFAULT_BPS, MAX_MESSAGE_SIZE,
    validate_header, validate_payload_checksum, validate_payload_size,
    validate_inv_items, validate_addr_list, validate_headers_list, validate_hash_hex,
    validate_reject, build_version_payload,
};

/// Global DoS guard — shared across all peer threads.
static DOS_GUARD: Lazy<DosGuard> = Lazy::new(DosGuard::new);

/// Inbound connection throttle: max new connections per second.
const MAX_INBOUND_PER_SEC: u32 = 10;
/// Max pending (not-yet-handshaked) connections.
const MAX_PENDING_CONNECTIONS: usize = 64;

pub const MAX_PEERS:             usize    = NetworkParams::MAX_PEERS;
pub const MIN_PEERS:             usize    = NetworkParams::MIN_PEERS;
pub const HANDSHAKE_TIMEOUT_MS:  u64      = 5_000;
pub const MSG_MAX_BYTES:         usize    = 4 * 1024 * 1024;
pub const RATE_LIMIT_MS:         u64      = 50;

pub const DEFAULT_PORT:          u16      = NetworkParams::DEFAULT_PORT;
pub const PROTOCOL_VERSION:      u32      = 1;

// Cross-thread pending queues: P2P handler threads push here, node main loop drains.
// Uses Arc<Mutex<>> so ANY thread can push and ANY thread can drain.
// Each item is tagged with the peer_id that sent it, so the event loop
// can ban_score on rejection (closing the feedback gap).
use parking_lot::Mutex as PlMutex;
use once_cell::sync::Lazy;

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
/// Max pending blocks allowed from a single peer before dropping.
const MAX_PENDING_BLOCKS_PER_PEER: u32 = 50;
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

/// Received peer addresses from Addr messages — drained by daemon event loop
/// and fed to PeerManager.
static RECEIVED_ADDRS: Lazy<Arc<PlMutex<Vec<String>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::new())));

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
    { let mut q = TARGETED_MSGS.lock(); q.retain(|(target, _)| target != peer_id); }
    { let mut p = PEER_PENDING.lock(); p.remove(peer_id); }
}

/// Drain all received peer addresses from Addr messages (call from node main loop).
/// Thread-safe: works from ANY thread.
pub fn drain_received_addrs() -> Vec<String> {
    std::mem::take(&mut *RECEIVED_ADDRS.lock())
}

/// Requeue excess blocks that couldn't be processed in this tick.
/// Prepends them to the front of the queue so they're processed first next tick.
/// Re-increments PEER_PENDING block counts that were decremented during drain.
pub fn requeue_pending_blocks(items: Vec<(String, Block)>) {
    if items.is_empty() { return; }
    // Restore per-peer pending counts that were decremented during drain
    {
        let mut counts = PEER_PENDING.lock();
        for (peer_id, _) in &items {
            let entry = counts.entry(peer_id.clone()).or_insert((0, 0));
            entry.1 = entry.1.saturating_add(1);
        }
    }
    let mut q = PENDING_BLOCKS.lock();
    let mut combined = items;
    combined.extend(q.drain(..));
    *q = combined;
}

/// Requeue excess transactions that couldn't be processed in this tick.
/// Re-increments PEER_PENDING tx counts that were decremented during drain.
pub fn requeue_pending_txs(items: Vec<(String, Transaction)>) {
    if items.is_empty() { return; }
    // Restore per-peer pending counts that were decremented during drain
    {
        let mut counts = PEER_PENDING.lock();
        for (peer_id, _) in &items {
            let entry = counts.entry(peer_id.clone()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
        }
    }
    let mut q = PENDING_TXS.lock();
    let mut combined = items;
    combined.extend(q.drain(..));
    *q = combined;
}

/// Push a block into the pending queue for consensus validation.
/// Thread-safe: can be called from RPC or any thread.
/// The daemon event loop drains this queue and processes each block
/// through FullNode::process_block() (full validation pipeline).
pub fn push_pending_block(peer_id: &str, block: Block) -> bool {
    // Reserve slot FIRST (increment before push) to close TOCTOU race.
    // If the queue is full, rollback the increment.
    {
        let mut pending = PEER_PENDING.lock();
        let entry = pending.entry(peer_id.to_string()).or_insert((0, 0));
        if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
            slog_warn!("p2p", "per_peer_block_limit_reached", peer => peer_id);
            return false;
        }
        entry.1 += 1;
    }

    let mut q = PENDING_BLOCKS.lock();
    if q.len() < 1_000 {
        q.push((peer_id.to_string(), block));
        true
    } else {
        // Rollback the increment since we couldn't push
        let mut pending = PEER_PENDING.lock();
        if let Some(entry) = pending.get_mut(peer_id) {
            entry.1 = entry.1.saturating_sub(1);
        }
        slog_warn!("p2p", "pending_block_queue_full");
        false
    }
}

/// Push a transaction into the pending queue for mempool validation.
/// Thread-safe: can be called from RPC or any thread.
pub fn push_pending_tx(peer_id: &str, tx: Transaction) -> bool {
    // Reserve slot FIRST (increment before push) to close TOCTOU race.
    // If the queue is full, rollback the increment.
    {
        let mut pending = PEER_PENDING.lock();
        let entry = pending.entry(peer_id.to_string()).or_insert((0, 0));
        if entry.0 >= MAX_PENDING_TXS_PER_PEER {
            slog_warn!("p2p", "per_peer_tx_limit_reached", peer => peer_id);
            return false;
        }
        entry.0 += 1;
    }

    let mut q = PENDING_TXS.lock();
    if q.len() < 10_000 {
        q.push((peer_id.to_string(), tx));
        true
    } else {
        // Rollback the increment since we couldn't push
        let mut pending = PEER_PENDING.lock();
        if let Some(entry) = pending.get_mut(peer_id) {
            entry.0 = entry.0.saturating_sub(1);
        }
        slog_warn!("p2p", "pending_tx_queue_full");
        false
    }
}

/// Report a bad TX/block to the DoS guard (called by event loop on rejection).
/// Closes the feedback loop: event_loop → ban_score → P2P disconnects peer.
pub fn report_bad_peer(peer_id: &str, score: u64, reason: &str) {
    DOS_GUARD.add_ban_score(peer_id, score, reason);
}

/// Categorized version of report_bad_peer for callers that know the offense type.
pub fn report_bad_peer_cat(peer_id: &str, score: u64, reason: &str, category: BanCategory) {
    DOS_GUARD.add_ban_score_cat(peer_id, score, reason, category);
}

/// Push a message to be broadcast to all connected peers.
/// Thread-safe: can be called from any thread (e.g. TxRelay, mempool).
pub fn push_outbound(msg: P2PMessage) {
    let mut q = OUTBOUND_MSGS.lock();
    if q.1.len() < 10_000 {
        let seq = q.0 + 1;
        q.0 = seq;
        q.1.push((seq, msg));
    } else {
        slog_warn!("p2p", "outbound_queue_full");
    }
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
fn drain_outbound_since(since: u64) -> (Vec<P2PMessage>, u64) {
    let mut q = OUTBOUND_MSGS.lock();
    let new_msgs: Vec<P2PMessage> = q.1.iter()
        .filter(|(seq, _)| *seq > since)
        .map(|(_, msg)| msg.clone())
        .collect();
    let max_seq = q.0;
    // Prune: keep only the last 2000 messages to bound memory
    if q.1.len() > 2000 {
        let drain_to = q.1.len() - 1000;
        q.1.drain(..drain_to);
    }
    (new_msgs, max_seq)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Connection puzzle challenge (anti-Sybil, sent by inbound acceptor).
    PuzzleChallenge { challenge: String },
    /// Connection puzzle solution (sent by connector in response).
    PuzzleSolution  { challenge: String, nonce: u64, hash: String },

    Version {
        version:    u32,
        height:     u64,
        timestamp:  u64,
        user_agent: String,
        /// Blocks per second — must match for same-chain peers.
        #[serde(default)]
        bps:        u32,
        /// Chain identifier — prevents cross-chain connections.
        #[serde(default)]
        chain_id:   u32,
        /// Service flags (capabilities bitmap).
        #[serde(default)]
        services:   u64,
        /// Random nonce for self-connection detection.
        #[serde(default)]
        nonce:      u64,
    },
    VerAck,

    GetAddr,
    Addr { peers: Vec<String> },

    GetHeaders { from_hash: String, count: u32 },
    Headers    { hashes: Vec<String> },
    GetBlock   { hash: String },
    Block      { data: Vec<u8> },

    Tx         { data: Vec<u8> },
    Inv        { items: Vec<InvItem> },
    GetData    { items: Vec<InvItem> },

    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Reject { reason: String },
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
            protocol:               ProtocolSession::new(outbound, DEFAULT_BPS),
            _addr: addr,
            last_pong:              Instant::now(),
            last_ping_sent:         Instant::now(),
            bytes_this_window:      0,
            bandwidth_window_start: Instant::now(),
            last_message_at:        now,
            lifecycle_violations:   0,
            legacy_peer:            false,
            last_outbound_seq:      0,
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

        // Reset window every BANDWIDTH_CHECK_INTERVAL_SECS
        if self.bandwidth_window_start.elapsed() >= Duration::from_secs(BANDWIDTH_CHECK_INTERVAL_SECS) {
            if self.bytes_this_window > MAX_BYTES_PER_PEER_PER_MIN {
                return true; // disconnect
            }
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
    pub peers:             Arc<PeerManager>,
    pub message_pool:      Vec<String>,
    /// Seen TX hashes (capped at 50K to prevent memory leak)
    pub tx_seen:           HashSet<String>,
    /// Peer activity tracking (pruned periodically)
    peer_last_message:     HashMap<String, Instant>,
    pub best_height:       u64,
    pub listen_addr:       String,
    pub network:           NetworkMode,
    /// Network magic bytes from config (separates mainnet/testnet/regtest)
    pub network_magic:     [u8; 4],
    /// Anti-Eclipse: enforces subnet diversity + crypto identity
    pub diversity:         crate::service::network::p2p::peer_diversity::PeerDiversity,
    /// Dandelion++: privacy-preserving TX relay
    pub dandelion:         crate::service::network::propagation::dandelion::DandelionRelay,
}

// NOTE: Default impl removed — P2P::new() returns Result<Self, NetworkError>
// and there is no safe fallback. Callers must use P2P::new() explicitly
// and handle the error. The previous Default used expect() which would
// panic on initialization failure (remote DoS via resource exhaustion).

impl P2P {
    #[deprecated(note = "Use P2P::new_with_config() — P2P::new() defaults to Mainnet which may be wrong")]
    pub fn new() -> Result<Self, crate::errors::NetworkError> {
        Self::new_with_config(&NodeConfig::for_network(NetworkMode::Mainnet))
    }

    pub fn new_with_config(cfg: &NodeConfig) -> Result<Self, crate::errors::NetworkError> {
        let magic = cfg.network.magic();
        slog_info!("p2p", "network_init", network => cfg.network.name(), port => cfg.p2p_port, magic => &format!("{:02x}{:02x}{:02x}{:02x}", magic[0], magic[1], magic[2], magic[3]));
        Ok(Self {
            peers:             Arc::new(PeerManager::new_default_path(&cfg.peers_path_str())?),
            message_pool:      Vec::new(),
            tx_seen:           HashSet::new(),
            peer_last_message: HashMap::new(),
            best_height:       0,
            listen_addr:       format!("0.0.0.0:{}", cfg.p2p_port),
            network:           cfg.network.clone(),
            network_magic:     magic,
            diversity:         crate::service::network::p2p::peer_diversity::PeerDiversity::new(),
            dandelion:         crate::service::network::propagation::dandelion::DandelionRelay::new(),
        })
    }

    pub fn start(&mut self) -> Result<(), crate::errors::NetworkError> {
        slog_info!("p2p", "network_start", listen_addr => &self.listen_addr);

        // Bind BEFORE spawning — fail fast if port unavailable
        let listener = TcpListener::bind(&self.listen_addr)
            .map_err(|e| crate::errors::NetworkError::ConnectionFailed(format!(
                "P2P bind {} failed: {}", self.listen_addr, e
            )))?;

        let magic = self.network_magic;
        let peers = Arc::clone(&self.peers);
        thread::spawn(move || {
            if let Err(e) = Self::accept_loop(listener, magic, &peers) {
                slog_error!("p2p", "accept_loop_error", error => &e.to_string());
            }
        });

        self.peers.bootstrap_for_network(&self.network);
        let discovered = self.peers.discover_peers();
        if discovered.is_empty() {
            slog_warn!("p2p", "peer_discovery_found_none");
        }
        self.connect_to_peers();

        slog_info!("p2p", "peers_connected", count => self.peers.count());

        self.request_headers_sync();
        Ok(())
    }

    fn accept_loop(listener: std::net::TcpListener, magic: [u8; 4], peer_manager: &Arc<PeerManager>) -> std::io::Result<()> {
        let addr = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
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

                    // ── Pending connection limit ──
                    let current_pending = pending.load(std::sync::atomic::Ordering::Relaxed);
                    if current_pending >= MAX_PENDING_CONNECTIONS {
                        slog_warn!("p2p", "too_many_pending_connections", pending => current_pending);
                        drop(s);
                        continue;
                    }

                    let peer_addr = s.peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    // ── Check if peer is banned ──
                    if DOS_GUARD.is_banned(&peer_addr) {
                        slog_warn!("p2p", "rejected_banned_peer", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    slog_info!("p2p", "inbound_connection", addr => &peer_addr);
                    // Query fresh peer list on each connection (fix stale snapshot)
                    let peers_snapshot = peer_manager.get_addr_list_limited(100);
                    let pending_clone = Arc::clone(&pending);
                    pending_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    thread::spawn(move || {
                        let result = Self::handle_peer_connection(s, false, magic, peers_snapshot);
                        pending_clone.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
        stream.set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        let peer_addr = stream.peer_addr()
            .map_err(|e| NetworkError::ConnectionFailed(format!("No peer addr: {}", e)))?;
        let peer_str = peer_addr.to_string();

        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);

        // Session state: ProtocolSession + connection-level fields
        let mut session = ConnectionSession::new(peer_addr, outbound);

        // ── Connection puzzle (anti-Sybil) ─────────────────────────────────
        if !outbound {
            // Inbound: send puzzle challenge, wait for solution
            let challenge = ConnectionPuzzle::generate_challenge();
            if let Err(e) = session.protocol.sent_puzzle_challenge(&challenge.challenge) {
                return Err(NetworkError::ConnectionFailed(format!("State error: {}", e)));
            }
            let bytes = Self::write_message(&mut writer, &P2PMessage::PuzzleChallenge {
                challenge: challenge.challenge.clone(),
            }, magic)?;
            session.record_bytes_sent(bytes);

            match Self::read_message(&mut reader, magic) {
                Ok((P2PMessage::PuzzleSolution { challenge: c, nonce, hash }, _, sz)) => {
                    session.record_bytes_received(sz as u64);
                    let sol = ChallengeSolution { challenge: c, nonce, hash };
                    if !ConnectionPuzzle::verify(&challenge, &sol) {
                        DOS_GUARD.add_ban_score_cat(&peer_str, 100, "invalid puzzle solution", BanCategory::Malicious);
                        return Err(NetworkError::ConnectionFailed(
                            format!("Invalid puzzle solution from {}", peer_str)));
                    }
                    session.protocol.puzzle_verified().map_err(|e|
                        NetworkError::ConnectionFailed(format!("State error: {}", e)))?;
                    slog_info!("p2p", "puzzle_verified", addr => &peer_str);
                }
                Ok((_, cmd, _)) => {
                    DOS_GUARD.add_ban_score_cat(&peer_str, 50, "expected puzzle solution", BanCategory::Malicious);
                    return Err(NetworkError::ConnectionFailed(
                        format!("Expected PuzzleSolution from {}, got {}", peer_str, cmd)));
                }
                Err(e) => {
                    return Err(NetworkError::ConnectionFailed(
                        format!("Puzzle exchange failed with {}: {}", peer_str, e)));
                }
            }
        } else {
            // Outbound: wait for puzzle challenge, solve it, send solution
            match Self::read_message(&mut reader, magic) {
                Ok((P2PMessage::PuzzleChallenge { challenge }, _, sz)) => {
                    session.record_bytes_received(sz as u64);
                    session.protocol.received_puzzle_challenge(&challenge).map_err(|e|
                        NetworkError::ConnectionFailed(format!("State error: {}", e)))?;
                    let sol = ConnectionPuzzle::solve(&challenge);
                    let sol_msg = P2PMessage::PuzzleSolution {
                        challenge: sol.challenge,
                        nonce: sol.nonce,
                        hash: sol.hash,
                    };
                    let bytes = Self::write_message(&mut writer, &sol_msg, magic)?;
                    session.record_bytes_sent(bytes);
                    session.protocol.puzzle_verified().map_err(|e|
                        NetworkError::ConnectionFailed(format!("State error: {}", e)))?;
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
                        DOS_GUARD.add_ban_score_cat(&peer_str, 20,
                            &format!("non-Version first message ({}), expected puzzle or Version", cmd),
                            BanCategory::Malformed);
                    }
                    if let Err(e) = Self::dispatch_message(
                        &mut writer, msg, &peer_str, magic, &mut session, &known_peers,
                    ) {
                        slog_debug!("p2p", "dispatch_error", addr => &peer_str, error => &e.to_string());
                    }
                }
                Err(e) => {
                    let emsg = e.to_string().to_lowercase();
                    if !emsg.contains("timed out") && !emsg.contains("would block") && !emsg.contains("wouldblock")
                        && !emsg.contains("temporarily unavailable") && !emsg.contains("os error 11") && !emsg.contains("os error 10035") {
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
        session.protocol.sent_version()
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
                        DOS_GUARD.add_ban_score_cat(&peer_str, 50, "bandwidth abuse (>100MB/min)", BanCategory::Resource);
                        slog_warn!("p2p", "bandwidth_abuse_disconnect", addr => &peer_str, bytes_per_min => session.bytes_this_window);
                        break;
                    }

                    // Protocol state machine: is this command allowed right now?
                    if let Err(pe) = session.protocol.check_command_allowed(cmd) {
                        DOS_GUARD.add_ban_score_cat(&peer_str, pe.ban_score as u64, &pe.message,
                            if pe.ban_score >= 50 { BanCategory::Malicious } else { BanCategory::Malformed });
                        slog_warn!("p2p", "command_rejected", addr => &peer_str, command => &cmd.to_string(), state => &session.protocol.state.to_string(), ban_score => pe.ban_score);
                        if pe.ban_score >= 50 { break; }
                        continue;
                    }

                    // Lifecycle filter: restricted peers limited to Ping/Pong/Reject
                    if let Err(pe) = session.protocol.check_lifecycle_allowed(cmd) {
                        session.lifecycle_violations += 1;
                        let (score, cat) = if session.lifecycle_violations > 5 {
                            (20u64, BanCategory::Malformed)  // persistent = likely intentional
                        } else {
                            (5u64, BanCategory::Resource)    // few violations = possibly buggy client
                        };
                        DOS_GUARD.add_ban_score_cat(&peer_str, score,
                            &format!("lifecycle violation #{}: {}", session.lifecycle_violations, pe), cat);
                        slog_warn!("p2p", "lifecycle_blocked", addr => &peer_str, command => &cmd.to_string(), violation_count => session.lifecycle_violations);
                        if session.lifecycle_violations > 10 {
                            slog_warn!("p2p", "excessive_lifecycle_violations_disconnect", addr => &peer_str);
                            break;
                        }
                        continue;
                    }

                    if let Err(e) = Self::dispatch_message(
                        &mut writer, msg, &peer_str, magic,
                        &mut session, &known_peers,
                    ) {
                        slog_error!("p2p", "dispatch_error", addr => &peer_str, error => &e.to_string());
                        break;
                    }

                    // Flush broadcast + targeted outbound messages
                    Self::flush_outbound(&mut writer, &peer_str, &mut session, magic);
                }
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    let is_timeout = msg.contains("timed out")
                        || msg.contains("would block")
                        || msg.contains("wouldblock")
                        || msg.contains("temporarily unavailable")
                        || msg.contains("os error 11")
                        || msg.contains("os error 10035");

                    if is_timeout {
                        // Keepalive ping
                        if session.is_established()
                            && session.last_ping_sent.elapsed() >= Duration::from_secs(KEEPALIVE_INTERVAL_SECS)
                        {
                            let nonce = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_nanos() as u64)
                                .unwrap_or(0);
                            match Self::write_message(&mut writer, &P2PMessage::Ping { nonce }, magic) {
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
                                &P2PMessage::Reject { reason: "pong timeout".to_string() },
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
                                &P2PMessage::Reject { reason: format!("timeout: {}", pe) },
                                magic,
                            );
                            session.protocol.begin_disconnect();
                            break;
                        }

                        Self::flush_outbound(&mut writer, &peer_str, &mut session, magic);
                        continue;
                    }

                    // Graceful disconnect
                    let _ = Self::write_message(
                        &mut writer,
                        &P2PMessage::Reject { reason: format!("disconnect: {}", e) },
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
    ) {
        let (outbound, new_seq) = drain_outbound_since(session.last_outbound_seq);
        session.last_outbound_seq = new_seq;
        for out_msg in &outbound {
            match Self::write_message(writer, out_msg, magic) {
                Ok(bytes) => session.record_bytes_sent(bytes),
                Err(we) => {
                    slog_error!("p2p", "write_error", addr => peer_str, error => &we.to_string());
                    return;
                }
            }
        }
        let targeted = drain_targeted_for(peer_str);
        for t_msg in &targeted {
            match Self::write_message(writer, t_msg, magic) {
                Ok(bytes) => session.record_bytes_sent(bytes),
                Err(we) => {
                    slog_error!("p2p", "write_error_targeted", addr => peer_str, error => &we.to_string());
                    return;
                }
            }
        }
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
        let payload = bincode::serialize(msg)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::Serialization(
                format!("Message too large: {} bytes > {}", payload.len(), MAX_MESSAGE_SIZE)));
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
        writer.write_all(&buf).map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        writer.flush().map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        Ok(total)
    }

    /// Map a P2PMessage variant to its CommandId for wire framing.
    fn msg_to_command_id(msg: &P2PMessage) -> CommandId {
        match msg {
            P2PMessage::Version { .. }         => CommandId::Version,
            P2PMessage::VerAck                 => CommandId::VerAck,
            P2PMessage::Ping { .. }            => CommandId::Ping,
            P2PMessage::Pong { .. }            => CommandId::Pong,
            P2PMessage::GetAddr                => CommandId::GetAddr,
            P2PMessage::Addr { .. }            => CommandId::Addr,
            P2PMessage::Inv { .. }             => CommandId::Inv,
            P2PMessage::GetData { .. }         => CommandId::GetData,
            P2PMessage::Block { .. }           => CommandId::Block,
            P2PMessage::Tx { .. }              => CommandId::Tx,
            P2PMessage::GetHeaders { .. }      => CommandId::GetHeaders,
            P2PMessage::Headers { .. }         => CommandId::Headers,
            P2PMessage::GetBlock { .. }        => CommandId::GetBlock,
            P2PMessage::Reject { .. }          => CommandId::Reject,
            P2PMessage::PuzzleChallenge { .. } => CommandId::PuzzleChallenge,
            P2PMessage::PuzzleSolution { .. }  => CommandId::PuzzleSolution,
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
        reader.read_exact(&mut hdr_buf)
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        let header = WireHeader::decode(&hdr_buf);

        // 2-4. Validate header: magic, command_id, payload_len
        let cmd = validate_header(&header, magic).map_err(|pe| {
            NetworkError::Serialization(format!("[Protocol] {}", pe))
        })?;

        // 5. Read payload
        let payload_len = header.payload_len as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload)
                .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        }

        // 6. Validate checksum (BEFORE deserialization — blocks tampered data)
        validate_payload_checksum(&payload, header.checksum).map_err(|pe| {
            NetworkError::Serialization(format!("[Protocol] {}", pe))
        })?;

        // 7. Validate per-command payload size bounds
        validate_payload_size(cmd, payload_len).map_err(|pe| {
            NetworkError::Serialization(format!("[Protocol] {}", pe))
        })?;

        // 8. Deserialize payload (bincode)
        let msg: P2PMessage = bincode::deserialize(&payload)
            .map_err(|e| NetworkError::Serialization(
                format!("[Protocol] {} deserialize failed: {}", cmd, e)))?;

        Ok((msg, cmd, WIRE_HEADER_SIZE + payload_len))
    }

    /// Map CommandId to DoS guard MsgType for rate limiting.
    fn cmd_to_dos_type(cmd: CommandId) -> MsgType {
        match cmd {
            CommandId::Version         => MsgType::Version,
            CommandId::VerAck          => MsgType::VerAck,
            CommandId::Ping            => MsgType::Ping,
            CommandId::Pong            => MsgType::Pong,
            CommandId::Tx              => MsgType::Tx,
            CommandId::Block           => MsgType::Block,
            CommandId::Inv             => MsgType::Inv,
            CommandId::GetData         => MsgType::GetData,
            CommandId::GetAddr         => MsgType::GetAddr,
            CommandId::Addr            => MsgType::Addr,
            CommandId::GetHeaders      => MsgType::GetHeaders,
            CommandId::Headers         => MsgType::Headers,
            CommandId::GetBlock        => MsgType::GetBlocks,
            CommandId::GetMempool      => MsgType::Mempool,
            CommandId::Reject          => MsgType::Reject,
            _                          => MsgType::Unknown,
        }
    }

    fn dispatch_message(
        writer: &mut BufWriter<&TcpStream>,
        msg: P2PMessage,
        peer: &str,
        magic: [u8; 4],
        session: &mut ConnectionSession,
        known_peers: &[String],
    ) -> Result<(), NetworkError> {
        // ── DoS Guard: rate limit + ban check ──
        let cmd = Self::msg_to_command_id(&msg);
        let dos_type = Self::cmd_to_dos_type(cmd);
        let msg_size = std::mem::size_of_val(&msg);
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
                return Err(NetworkError::DosGuard(format!("oversized message from {}", peer)));
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
                DOS_GUARD.add_ban_score_cat(peer, 10, "unexpected puzzle solution", BanCategory::Malformed);
            }

            // ── Version: full validation via ProtocolSession ────────���──
            P2PMessage::Version { version, height, timestamp, user_agent,
                                  bps, chain_id, services, nonce } => {
                // Build VersionPayload and validate through protocol state machine
                let payload = VersionPayload {
                    version,
                    height,
                    timestamp,
                    user_agent: user_agent.clone(),
                    bps:      if bps == 0 { DEFAULT_BPS } else { bps },  // backward compat
                    chain_id: if chain_id == 0 { CHAIN_ID } else { chain_id },
                    services: if services == 0 { protocol::SERVICE_NODE_NETWORK } else { services },
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
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message,
                        if pe.ban_score >= 100 { BanCategory::Malicious } else { BanCategory::Malformed });
                    if pe.ban_score >= 50 {
                        return Err(NetworkError::ConnectionFailed(
                            format!("Version rejected from {}: {}", peer, pe)));
                    }
                    return Ok(());
                }

                // Log peer identity
                if let Some(id) = session.protocol.peer_identity() {
                    slog_debug!("p2p", "peer_identity", addr => peer, identity => &id[..id.len().min(16)]);
                }

                let bytes = Self::write_message(writer, &P2PMessage::VerAck, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── VerAck: complete handshake via state machine ───────────
            P2PMessage::VerAck => {
                if let Err(pe) = session.protocol.received_verack() {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
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
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
                // Queue addresses for the daemon event loop to feed to PeerManager
                {
                    let mut q = RECEIVED_ADDRS.lock();
                    for addr in peers {
                        if q.len() < 4096 {
                            q.push(addr.clone());
                        }
                    }
                }
                slog_debug!("p2p", "received_addresses", count => peers.len(), addr => peer);
            }

            // ── Ping: anti-replay via ProtocolSession nonce tracking ───
            P2PMessage::Ping { nonce } => {
                if !session.protocol.record_nonce(nonce) {
                    DOS_GUARD.add_ban_score_cat(peer, 20, "duplicate ping nonce (replay)", BanCategory::Malicious);
                    slog_warn!("p2p", "replay_detected", addr => peer, nonce => nonce);
                    return Ok(());
                }
                let bytes = Self::write_message(writer, &P2PMessage::Pong { nonce }, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── Pong: anti-replay + keepalive tracking ─────────────────
            P2PMessage::Pong { nonce } => {
                if !session.protocol.record_nonce(nonce) {
                    DOS_GUARD.add_ban_score_cat(peer, 20, "duplicate pong nonce (replay)", BanCategory::Malicious);
                    return Ok(());
                }
                session.last_pong = Instant::now();
            }

            // ── Tx: DagShield pre-validation + queue management ────��───
            P2PMessage::Tx { data } => {
                match bincode::deserialize::<Transaction>(&data) {
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
                                    DOS_GUARD.add_ban_score_cat(peer, 5, "TX queue quota exceeded or full", BanCategory::Resource);
                                }
                            }
                            Err(rej) => {
                                DOS_GUARD.add_ban_score_cat(peer, rej.ban_score as u64, rej.reason, BanCategory::Malformed);
                            }
                        }
                    }
                    Err(e) => {
                        // Malformed bincode = either attack or deeply broken client.
                        // Score 25 so 4 malformed TXs = auto-ban (100).
                        DOS_GUARD.add_ban_score_cat(peer, 25, "invalid tx deserialization", BanCategory::Malformed);
                        slog_error!("p2p", "invalid_tx_deserialize", addr => peer, error => &e.to_string());
                    }
                }
            }

            // ── Block: DagShield pre-validation + queue management ──────
            P2PMessage::Block { data } => {
                match bincode::deserialize::<Block>(&data) {
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
                                    DOS_GUARD.add_ban_score_cat(peer, 10, "block queue quota exceeded or full", BanCategory::Resource);
                                }
                            }
                            Err(rej) => {
                                DOS_GUARD.add_ban_score_cat(peer, rej.ban_score as u64, rej.reason, BanCategory::Malformed);
                            }
                        }
                    }
                    Err(e) => {
                        // Malformed block bincode = immediate high penalty.
                        // Score 50 so 2 malformed blocks = auto-ban.
                        DOS_GUARD.add_ban_score_cat(peer, 50, "invalid block deserialization", BanCategory::Malformed);
                        slog_error!("p2p", "invalid_block_deserialize", addr => peer, error => &e.to_string());
                    }
                }
            }

            // ── Inv: validate item list via protocol validators ─────────
            P2PMessage::Inv { ref items } => {
                let pairs: Vec<(String, String)> = items.iter()
                    .map(|i| (i.kind.clone(), i.hash.clone()))
                    .collect();
                if let Err(pe) = validate_inv_items(&pairs) {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
                let get_data = P2PMessage::GetData { items: items.clone() };
                let bytes = Self::write_message(writer, &get_data, magic)?;
                session.record_bytes_sent(bytes);
            }

            // ── GetData: validate item list ─────────────────────────────
            P2PMessage::GetData { ref items } => {
                let pairs: Vec<(String, String)> = items.iter()
                    .map(|i| (i.kind.clone(), i.hash.clone()))
                    .collect();
                if let Err(pe) = validate_inv_items(&pairs) {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
                // Data serving handled by upper layer
            }

            // ── GetHeaders: validate hash ───────────────────────────────
            P2PMessage::GetHeaders { ref from_hash, .. } => {
                if !from_hash.is_empty() {
                    if let Err(pe) = validate_hash_hex(from_hash) {
                        DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                        return Ok(());
                    }
                }
            }

            // ── Headers: validate hash list ─────────────────────────────
            P2PMessage::Headers { ref hashes } => {
                if let Err(pe) = validate_headers_list(hashes) {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
            }

            // ── GetBlock: validate hash ─────────────────────────────────
            P2PMessage::GetBlock { ref hash } => {
                if let Err(pe) = validate_hash_hex(hash) {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
            }

            // ── Reject: validate reason length ──────────────────────────
            P2PMessage::Reject { ref reason } => {
                if let Err(pe) = validate_reject(reason) {
                    DOS_GUARD.add_ban_score_cat(peer, pe.ban_score as u64, &pe.message, BanCategory::Malformed);
                    return Ok(());
                }
                slog_warn!("p2p", "rejected_by_peer", addr => peer, reason => reason.as_str());
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
        let user_agent = format!("ShadowDAG/{} id:{}", env!("CARGO_PKG_VERSION"), identity.public_key);
        let vp = build_version_payload(&user_agent, height, DEFAULT_BPS);

        let msg = P2PMessage::Version {
            version:    vp.version,
            height:     vp.height,
            timestamp:  vp.timestamp,
            user_agent: vp.user_agent,
            bps:        vp.bps,
            chain_id:   vp.chain_id,
            services:   vp.services,
            nonce:      vp.nonce,
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
            let addr_clone = addr.clone();
            let peers_snapshot = known_peers.clone();
            thread::spawn(move || {
                match TcpStream::connect(&addr_clone) {
                    Ok(stream) => {
                        slog_info!("p2p", "outbound_connected", addr => &addr_clone);
                        if let Err(e) = Self::handle_peer_connection(stream, true, magic, peers_snapshot) {
                            slog_error!("p2p", "peer_connection_error", addr => &addr_clone, error => &e.to_string());
                        }
                    }
                    Err(e) => {
                        slog_error!("p2p", "outbound_connect_failed", addr => &addr_clone, error => &e.to_string());
                    }
                }
            });
        }
    }

    /// NOTE: Header sync happens via peer dispatch (GetHeaders/Headers messages),
    /// not from this function. This only logs the intent to sync.
    /// TODO: Implement proactive header request to connected peers.
    fn request_headers_sync(&self) {
        slog_info!("p2p", "requesting_headers_sync",
            height => self.best_height,
            note => "sync initiated via per-peer GetHeaders exchange");
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
