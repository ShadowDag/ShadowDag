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
    validate_headers_list, validate_inv_count, validate_inv_item, validate_payload_checksum,
    validate_payload_size, validate_reject, CommandId, ProtocolSession, VersionPayload, WireHeader,
    DEFAULT_BPS, HANDSHAKE_TIMEOUT_SECS, MAX_INV_PER_MSG, MAX_MESSAGE_SIZE, PUZZLE_TIMEOUT_SECS,
    WIRE_HEADER_SIZE,
};
use crate::{slog_debug, slog_error, slog_info, slog_warn};

/// Global DoS guard — shared across all peer threads.
static DOS_GUARD: Lazy<DosGuard> = Lazy::new(DosGuard::new);

/// Inbound connection throttle: max new connections per second from ONE source
/// IP. This used to be a single process-global budget, checked before the
/// peer's address was even resolved — which made it the one accept gate with
/// neither a trusted-seed bypass nor any per-source scoping. 11 completed TCP
/// connects in a second from a single host, free to produce, then refused every
/// other inbound connection for the rest of that second, the node's own seeds
/// included.
const MAX_INBOUND_PER_SEC: u32 = 10;
/// Max pending (not-yet-handshaked) connections.
const MAX_PENDING_CONNECTIONS: usize = 64;
/// Max inbound arrivals per second from one /16 subnet. The per-IP budget alone
/// is bypassed by an attacker who owns a whole /16 — every address passes its
/// own budget — which is the same bypass that puts `MAX_INBOUND_PER_SUBNET`
/// beside `MAX_PEERS_PER_IP` for live connections. Three attempts per second per
/// live slot the subnet is allowed to hold.
const MAX_INBOUND_PER_SEC_PER_SUBNET: u32 = MAX_INBOUND_PER_SUBNET * 3;
/// Backstop on TOTAL inbound arrivals per second, so a flood spread across many
/// subnets still cannot spin the accept thread without bound. Tied to
/// `MAX_PENDING_CONNECTIONS`: the node may be asked to build at most one pending
/// pool's worth of pre-handshake state per second.
const MAX_INBOUND_GLOBAL_PER_SEC: u32 = MAX_PENDING_CONNECTIONS as u32;
/// Distinct keys (source IPs, and separately /16s) tracked within one throttle
/// window, bounding each per-window map against a flood that rolls addresses.
const MAX_THROTTLE_TRACKED_IPS: usize = 4_096;
/// TOTAL wall-clock budget, from the moment the connection is handled, for a
/// peer to finish its handshake.
///
/// Every pre-handshake read was already bounded by the 100 ms `SO_RCVTIMEO`,
/// but a per-recv timeout is not a deadline: `read_exact` fails only when ONE
/// recv returns nothing, so a byte every 99 ms kept a stranger looping inside a
/// single read indefinitely — holding an inbound slot, a `MAX_PEERS_PER_IP`
/// registration, a `MAX_INBOUND_PER_SUBNET` registration and a blocked OS
/// thread for about 10 B/s.
///
/// One second past the longest handshake the protocol itself permits: it
/// measures `PUZZLE_TIMEOUT_SECS` and `HANDSHAKE_TIMEOUT_SECS` from
/// `connected_at` in whole seconds and fires on `elapsed >`, so this deadline
/// can never cut a handshake the state machine would still have allowed. The
/// assert keeps that true if either protocol constant moves.
const PRE_HANDSHAKE_DEADLINE_SECS: u64 = PUZZLE_TIMEOUT_SECS + 1;
const _: () = assert!(
    PRE_HANDSHAKE_DEADLINE_SECS > PUZZLE_TIMEOUT_SECS
        && PRE_HANDSHAKE_DEADLINE_SECS > HANDSHAKE_TIMEOUT_SECS,
    "the read deadline must outlast every handshake the protocol permits"
);

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
use parking_lot::{Mutex as PlMutex, RwLock as PlRwLock};

/// (peer_id, transaction) — peer attribution for ban feedback on rejection.
#[allow(clippy::type_complexity)]
static PENDING_TXS: Lazy<Arc<PlMutex<Vec<(String, Transaction)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(1024))));
/// The pending-block queue, (peer_id, block) for ban attribution on rejection,
/// paired with an index of the hashes it holds.
///
/// The index exists because membership in this queue is tested on the hot
/// inbound path: the Inv and Headers handlers check every announced hash
/// against it. That test used to be a walk of the queue, with the queue's own
/// lock held, which made one Inv up to 5,000 x `MAX_PENDING_BLOCK_QUEUE` string
/// comparisons on the single lock the consensus loop needs to drain its work —
/// and it got more expensive as the backlog grew, so the further behind the node
/// fell, the more each announcement cost it.
///
/// All three live under one lock so they cannot drift apart.
struct PendingBlocks {
    queue: Vec<(String, Block)>,
    /// How many queued entries carry each hash. A count rather than a set
    /// because two peers may each hold a copy of the same block.
    hashes: HashMap<String, u32>,
    /// Which hashes each peer already has queued.
    ///
    /// The dedup key is per PEER, and that matters twice over. The hash is a
    /// peer-chosen field here: `DagShield::pre_validate_block` checks only that
    /// it is 64 hex characters, and nothing binds it to the content until full
    /// validation recomputes it after the drain — so a hash-wide key would let
    /// one peer name any hash and have every honest copy of that block thrown
    /// away on arrival. And the entry's peer is also what `retain_other_peers`
    /// deletes by, so a hash-wide key would make the first deliverer's
    /// disconnect destroy the only copy the node holds. Per peer still stops one
    /// peer filling its own quota with copies of one block, which is all the
    /// dedup is for.
    owned: HashMap<String, HashSet<String>>,
}

impl PendingBlocks {
    fn new() -> Self {
        Self {
            queue: Vec::with_capacity(128),
            hashes: HashMap::with_capacity(128),
            owned: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    /// One hash lookup, whatever the queue's depth: does ANY peer have this
    /// block queued?
    fn contains(&self, hash: &str) -> bool {
        self.hashes.contains_key(hash)
    }

    /// Does this peer already have this block queued?
    fn owns(&self, peer_id: &str, hash: &str) -> bool {
        self.owned
            .get(peer_id)
            .is_some_and(|hashes| hashes.contains(hash))
    }

    /// Append a block. Returns false when THIS PEER already has that hash
    /// queued, in which case nothing was stored and the caller must charge no
    /// quota for it.
    fn push(&mut self, peer_id: &str, block: Block) -> bool {
        if !self
            .owned
            .entry(peer_id.to_string())
            .or_default()
            .insert(block.header.hash.clone())
        {
            return false;
        }
        *self.hashes.entry(block.header.hash.clone()).or_insert(0) += 1;
        self.queue.push((peer_id.to_string(), block));
        true
    }

    /// Rebuild both indexes from the queue, which is the only source of truth.
    ///
    /// Used wherever entries leave in bulk: a rebuild cannot leave a phantom
    /// behind the way a decrement-and-remove can, and a phantom would make us
    /// refuse to request that block again.
    fn reindex(&mut self) {
        self.hashes.clear();
        self.owned.clear();
        for (peer, block) in &self.queue {
            *self.hashes.entry(block.header.hash.clone()).or_insert(0) += 1;
            self.owned
                .entry(peer.clone())
                .or_default()
                .insert(block.header.hash.clone());
        }
    }

    /// Of `items`, those that can really go back into the queue: not already
    /// queued, not a repeat within the batch, and within `available` slots.
    /// Returns them in order with the count it refused.
    ///
    /// Separated from the quota accounting so the caller charges a peer for
    /// exactly what gets stored. A count charged for a block that was never
    /// stored never comes back down, and a peer whose count is stuck at the
    /// per-peer limit has every block it sends dropped from then on.
    fn admissible_for_requeue(
        &self,
        items: Vec<(String, Block)>,
        available: usize,
    ) -> (Vec<(String, Block)>, usize) {
        let mut admitted: Vec<(String, Block)> = Vec::with_capacity(items.len().min(available));
        let mut batch: HashSet<(String, String)> =
            HashSet::with_capacity(items.len().min(available));
        let mut refused = 0usize;
        // The batch is MOVED through, not copied: a requeue can carry hundreds
        // of blocks of up to 2 MiB each, every tick.
        for (peer_id, block) in items {
            let key = (peer_id.clone(), block.header.hash.clone());
            if admitted.len() >= available || self.owns(&key.0, &key.1) || !batch.insert(key) {
                refused = refused.saturating_add(1);
                continue;
            }
            admitted.push((peer_id, block));
        }
        (admitted, refused)
    }

    /// Put already-admitted items back at the front, index in step.
    ///
    /// Callers filter with [`PendingBlocks::admissible_for_requeue`] first, so a
    /// hash arriving here twice is a bug rather than a case to handle; the index
    /// is written unconditionally so a release build cannot desync even if one
    /// slips through.
    fn prepend(&mut self, items: Vec<(String, Block)>) {
        if items.is_empty() {
            return;
        }
        for (peer, block) in &items {
            let fresh = self
                .owned
                .entry(peer.clone())
                .or_default()
                .insert(block.header.hash.clone());
            debug_assert!(fresh, "requeued a block this peer already had queued");
            *self.hashes.entry(block.header.hash.clone()).or_insert(0) += 1;
        }
        let mut combined = items;
        combined.append(&mut self.queue);
        self.queue = combined;
    }

    /// Take the whole queue; the indexes empty with it.
    fn take(&mut self) -> Vec<(String, Block)> {
        self.hashes.clear();
        self.owned.clear();
        std::mem::take(&mut self.queue)
    }

    /// Drop everything attributed to one peer, returning how many went.
    ///
    /// The indexes are rebuilt from what survives rather than having the
    /// dropped entries removed from them: a rebuild cannot leave a phantom
    /// behind, and a phantom would make us refuse to request that block again.
    ///
    /// Note what this does NOT do: another peer's copy of the same block is a
    /// separate entry and stays. That is the whole reason the dedup key carries
    /// the peer — this delete is by peer, so a hash-wide dedup would make one
    /// peer's disconnect destroy a block several peers had handed us.
    fn retain_other_peers(&mut self, peer_id: &str) -> usize {
        let before = self.queue.len();
        self.queue.retain(|(peer, _)| peer != peer_id);
        let dropped = before.saturating_sub(self.queue.len());
        if dropped > 0 {
            self.reindex();
        }
        dropped
    }
}

static PENDING_BLOCKS: Lazy<Arc<PlRwLock<PendingBlocks>>> =
    Lazy::new(|| Arc::new(PlRwLock::new(PendingBlocks::new())));

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
/// Ceiling on blocks queued from the NETWORK path, deliberately below
/// `MAX_PENDING_BLOCK_QUEUE` (which also bounds requeue and local submission)
/// because every entry is a deserialized block of up to 2 MiB. Named here
/// rather than left as a bare literal in the Block arm, where it read as a
/// contradiction of the global cap declared beside it.
const MAX_NETWORK_PENDING_BLOCKS: usize = 1_000;
/// Items one Inv announcement can make us request.
///
/// Never ask a peer for more than we could accept from it: the surplus is
/// dropped by the per-peer quota the moment it arrives and then re-requested,
/// so it buys nothing and costs a round of inbound bandwidth. Blocks and
/// transactions share the announcement, so the bound is the tighter quota.
const MAX_INV_ITEMS_REQUESTED: usize = if MAX_PENDING_BLOCKS_PER_PEER < MAX_PENDING_TXS_PER_PEER {
    MAX_PENDING_BLOCKS_PER_PEER as usize
} else {
    MAX_PENDING_TXS_PER_PEER as usize
};
const _: () = assert!(
    MAX_NETWORK_PENDING_BLOCKS <= MAX_PENDING_BLOCK_QUEUE,
    "the network path must not be allowed to fill more than the whole queue"
);
const _: () = assert!(
    MAX_INV_ITEMS_REQUESTED > 0 && MAX_INV_ITEMS_REQUESTED < MAX_INV_PER_MSG,
    "the per-announcement request cap must bind below the wire limit"
);
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

/// Estimated payload bytes of a message: the heap data, not the stack enum.
///
/// `size_of_val` measures only the discriminant and inline fields, missing the
/// `Vec<u8>`/`String` contents that dominate a real message. Extracted so the
/// DoS guard's accounting and the targeted queue's byte budget share ONE
/// estimate — two implementations of the same notion drift, and a byte budget
/// that disagrees with the rate limiter about what a message costs is worse
/// than no budget.
fn payload_size_estimate(msg: &P2PMessage) -> usize {
    match msg {
        P2PMessage::Block { data } => data.len(),
        P2PMessage::Tx { data } => data.len(),
        P2PMessage::ShadowTx { data } => data.len(),
        P2PMessage::OnionTx { data } => data.len(),
        P2PMessage::Addr { peers } => peers.iter().map(|s| s.len()).sum(),
        P2PMessage::Headers { hashes } => hashes.iter().map(|s| s.len()).sum(),
        P2PMessage::Inv { items } => items.iter().map(|i| i.kind.len() + i.hash.len()).sum(),
        P2PMessage::GetData { items } => items.iter().map(|i| i.kind.len() + i.hash.len()).sum(),
        P2PMessage::PuzzleSolution {
            challenge, hash, ..
        } => challenge.len() + hash.len() + 8,
        P2PMessage::PuzzleChallenge { challenge } => challenge.len(),
        P2PMessage::Version { user_agent, .. } => user_agent.len() + 32,
        P2PMessage::Reject { reason } => reason.len(),
        P2PMessage::GetHeaders { from_hash, .. } => from_hash.len() + 4,
        P2PMessage::GetBlock { hash } => hash.len(),
        // Small fixed-size messages (Ping, Pong, GetAddr, VerAck, GetMempool).
        other => std::mem::size_of_val(other),
    }
}

/// Entries one peer may hold in the targeted queue.
///
/// Sized by the burst it answers: a peer catching up can have up to
/// `MAX_BLOCK_REQUESTS_PER_IP` block replies owed to it.
const MAX_TARGETED_PER_PEER: usize = MAX_BLOCK_REQUESTS_PER_IP;
/// Bytes one peer may hold. This is the send-side bound the process had NOWHERE:
/// `check_bandwidth` counts inbound only, and `record_bytes_sent` feeds a
/// counter whose only reader is a debug line at connection close. Four
/// serve passes' worth at `MAX_BLOCK_SERVE_BYTES_PER_TICK`.
const MAX_TARGETED_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
/// Entries and bytes across all peers.
const MAX_TARGETED_ENTRIES: usize = 10_000;
const MAX_TARGETED_BYTES: usize = 64 * 1024 * 1024;
/// How long an undelivered targeted message is kept.
///
/// A peer flushes on every pass of its connection loop, so a message still
/// queued after this has missed hundreds of them: its peer is gone, or wedged.
/// The queue's two removers are a peer's own flush and its cleanup, and the
/// daemon can enqueue for a peer AFTER its cleanup ran — so without an age
/// bound such an entry is immortal, and enough of them refuse every future
/// targeted message for the life of the process.
const TARGETED_TTL_SECS: u64 = 60;

const _: () = assert!(
    MAX_TARGETED_BYTES_PER_PEER >= crate::service::network::dos_guard::MAX_BLOCK_BYTES,
    "one maximum block must fit in a peer's send budget"
);
const _: () = assert!(
    MAX_TARGETED_BYTES >= MAX_TARGETED_BYTES_PER_PEER,
    "the global send budget must admit at least one peer's"
);

/// One peer's undelivered targeted messages, oldest first.
struct PeerTargeted {
    msgs: std::collections::VecDeque<(Instant, usize, P2PMessage)>,
    bytes: usize,
}

/// Targeted outbound messages, keyed by target peer.
///
/// Used by the block and header serve paths and by the Dandelion++ stem phase
/// to send to exactly one peer.
///
/// Keyed by peer rather than a flat list, which is what makes the rest cheap: a
/// drain is one `remove` that MOVES that peer's messages out, where the flat
/// version walked all 10,000 entries and deep-CLONED every match under the
/// global lock — up to 2 MiB per block — although the entry was removed in the
/// same pass. A per-peer cap also becomes O(1), so an overflow can evict the
/// backlog of the peer that caused it instead of dropping the arriving message,
/// which belonged to whichever peer was behaving.
struct TargetedQueue {
    by_peer: HashMap<String, PeerTargeted>,
    entries: usize,
    bytes: usize,
}

impl TargetedQueue {
    fn new() -> Self {
        Self {
            by_peer: HashMap::new(),
            entries: 0,
            bytes: 0,
        }
    }

    fn len(&self) -> usize {
        self.entries
    }

    fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop one peer's oldest message. Returns false when it had none.
    fn drop_oldest_for(&mut self, peer: &str) -> bool {
        let Some(pt) = self.by_peer.get_mut(peer) else {
            return false;
        };
        match pt.msgs.pop_front() {
            Some((_, size, _)) => {
                pt.bytes = pt.bytes.saturating_sub(size);
                self.entries = self.entries.saturating_sub(1);
                self.bytes = self.bytes.saturating_sub(size);
                if pt.msgs.is_empty() {
                    self.by_peer.remove(peer);
                }
                true
            }
            None => {
                self.by_peer.remove(peer);
                false
            }
        }
    }

    /// The peer holding the most bytes — the one to charge a global overflow to.
    fn heaviest_peer(&self) -> Option<String> {
        self.by_peer
            .iter()
            .max_by_key(|(_, pt)| pt.bytes)
            .map(|(p, _)| p.clone())
    }

    /// Queue a message for `peer`, making room by evicting the backlog of
    /// whoever is responsible for the overflow rather than refusing the arrival.
    fn push(&mut self, peer: &str, msg: P2PMessage, front: bool) {
        let size = payload_size_estimate(&msg);
        // That peer's own quota first.
        loop {
            let pt = self.by_peer.get(peer);
            let (n, b) = pt.map_or((0, 0), |pt| (pt.msgs.len(), pt.bytes));
            if n == 0 || (n < MAX_TARGETED_PER_PEER && b + size <= MAX_TARGETED_BYTES_PER_PEER) {
                break;
            }
            if !self.drop_oldest_for(peer) {
                break;
            }
        }
        // Then the global budget, charged to whoever holds the most.
        while self.entries >= MAX_TARGETED_ENTRIES || self.bytes + size > MAX_TARGETED_BYTES {
            let Some(victim) = self.heaviest_peer() else {
                break;
            };
            if !self.drop_oldest_for(&victim) {
                break;
            }
        }
        let pt = self.by_peer.entry(peer.to_string()).or_insert(PeerTargeted {
            msgs: std::collections::VecDeque::new(),
            bytes: 0,
        });
        if front {
            pt.msgs.push_front((Instant::now(), size, msg));
        } else {
            pt.msgs.push_back((Instant::now(), size, msg));
        }
        pt.bytes = pt.bytes.saturating_add(size);
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
    }

    /// Take everything queued for one peer, oldest first. Moves; clones nothing.
    fn take_for(&mut self, peer: &str) -> Vec<P2PMessage> {
        match self.by_peer.remove(peer) {
            Some(pt) => {
                self.entries = self.entries.saturating_sub(pt.msgs.len());
                self.bytes = self.bytes.saturating_sub(pt.bytes);
                pt.msgs.into_iter().map(|(_, _, m)| m).collect()
            }
            None => Vec::new(),
        }
    }

    fn remove_peer(&mut self, peer: &str) {
        let _ = self.take_for(peer);
    }

    /// Drop messages older than `ttl`. Returns how many went.
    ///
    /// The age bound is a parameter so a test can observe expiry without
    /// waiting out `TARGETED_TTL_SECS`: a zero TTL expires everything, which is
    /// the only way to see that the sweep really walks each peer's queue and
    /// keeps the totals in step.
    fn sweep_expired(&mut self, ttl: Duration) -> usize {
        let mut dropped = 0usize;
        let mut empty: Vec<String> = Vec::new();
        for (peer, pt) in self.by_peer.iter_mut() {
            while let Some((queued_at, size, _)) = pt.msgs.front() {
                if queued_at.elapsed() < ttl {
                    break;
                }
                let size = *size;
                pt.msgs.pop_front();
                pt.bytes = pt.bytes.saturating_sub(size);
                self.entries = self.entries.saturating_sub(1);
                self.bytes = self.bytes.saturating_sub(size);
                dropped += 1;
            }
            if pt.msgs.is_empty() {
                empty.push(peer.clone());
            }
        }
        for peer in empty {
            self.by_peer.remove(&peer);
        }
        dropped
    }
}

static TARGETED_MSGS: Lazy<Arc<PlMutex<TargetedQueue>>> =
    Lazy::new(|| Arc::new(PlMutex::new(TargetedQueue::new())));

/// Block-serve requests from peers: (requesting_peer_id, block_hash). Filled by
/// the GetBlock/GetData handlers (which lack block_store access) and drained by
/// the daemon event loop, which looks the block up and replies to that peer.
/// Without this, GetBlock is a no-op and peers can never download missing
/// ancestors — so forked nodes never converge.
#[allow(clippy::type_complexity)]
static PENDING_BLOCK_REQUESTS: Lazy<Arc<PlMutex<Vec<(String, String)>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(Vec::with_capacity(256))));
const MAX_BLOCK_REQUEST_QUEUE: usize = 5_000;

/// Block-serve requests accepted per SOURCE IP since the last drain.
///
/// Keyed on the IP for the same reason as `HEADER_REQUESTS_PER_IP`: the share
/// belongs to the host, and the port is the attacker's to choose. Cleared
/// wholesale by `drain_block_requests`, so there is nothing to decrement and no
/// counter can outlive the requests it counts.
static BLOCK_REQUESTS_PER_IP: Lazy<Arc<PlMutex<HashMap<String, usize>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Max block-serve requests ONE source IP may hold in the queue per drain
/// window.
///
/// The queue had only the global cap, so one legal GetData of `MAX_INV_PER_MSG`
/// block hashes filled all 5,000 entries by itself and every other peer's
/// GetBlock was refused at the push until the next drain — the fleet's own
/// seeds included. The sibling header queue was given this share in fab1e19;
/// the block queue never got it.
///
/// Sized by the largest burst an honest peer can legitimately send: a peer
/// catching up answers one of our Headers replies with at most
/// `MAX_PENDING_BLOCKS_PER_PEER` individual GetBlock messages, because that is
/// the bound our own Headers arm requests under.
/// Public so the daemon's per-pass serve budget can be checked against it. A
/// budget below this burst is the defect an adversarial review caught here, and
/// a cross-module invariant with no check is how it got written in the first
/// place.
pub const MAX_BLOCK_REQUESTS_PER_IP: usize = MAX_PENDING_BLOCKS_PER_PEER as usize;

/// How much of the block-request queue strangers may fill between drains. The
/// remainder — two full bursts — is reachable only by a whitelisted peer, so a
/// flood cannot squeeze the fleet's own seeds out of the queue at push time.
/// Two rather than five because one burst is six times larger here than on the
/// header path: a seed needs one burst in flight and one arriving.
const BLOCK_QUEUE_STRANGER_CAP: usize =
    MAX_BLOCK_REQUEST_QUEUE - MAX_BLOCK_REQUESTS_PER_IP * 2;
const _: () = assert!(
    BLOCK_QUEUE_STRANGER_CAP > MAX_BLOCK_REQUESTS_PER_IP,
    "strangers must still be able to fill more than one burst between drains"
);

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

/// Header requests accepted per SOURCE IP since the last drain.
///
/// Keyed on the IP, not on `ip:port`: the share belongs to the host, and the
/// accept gates and the whitelist key the same way — the port is the
/// attacker's to choose, so a per-socket share would hand one host
/// `MAX_PEERS_PER_IP` shares.
///
/// Cleared wholesale by `drain_header_requests`, which takes the queue in one
/// piece — so there is nothing to decrement, and no counter can outlive the
/// requests it counts. Needing a symmetric release is how the other per-peer
/// maps grow stale entries; a per-window map cannot.
static HEADER_REQUESTS_PER_IP: Lazy<Arc<PlMutex<HashMap<String, usize>>>> =
    Lazy::new(|| Arc::new(PlMutex::new(HashMap::new())));

/// Max header-serve requests ONE source IP may hold in the queue per drain
/// window.
///
/// The queue had only the global cap, so one established peer could own all
/// 2,000 entries: at the guard's 800 tok/s refill and the old
/// COST_MSG_DEFAULT it can ask 800 times a second, and every entry costs us
/// up to 512 RocksDB prefix iterators plus a 36,889-byte reply for a 29-byte
/// request.
///
/// This bounds the BURST — how much of the queue one host may own at once. The
/// RATE is bounded elsewhere: by the token bucket (COST_GETHEADERS against
/// BUCKET_REFILL_RATE, keyed per socket) and by the daemon's paced per-pass
/// serve budget. Fairness does not rest on this number either, because the
/// serve order is round-robin by host.
///
/// Sized by the largest burst an honest peer can legitimately send:
/// `request_headers_sync` asks once per DAG tip at startup, and the published
/// tip list is truncated to `MAX_PARENTS`, so that sweep is at most
/// MAX_PARENTS requests arriving together. Anything tighter silently dropped
/// most of it, and that per-tip sweep exists precisely because asking from one
/// tip alone "could miss entire DAG branches".
const MAX_HEADER_REQUESTS_PER_IP: usize =
    crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS;

/// How much of the header queue strangers may fill between drains. The
/// remainder — five seeds' worth of full burst — is reachable only by a
/// whitelisted peer, so a flood cannot squeeze the fleet's own seeds out of
/// the queue at push time.
const HEADER_QUEUE_STRANGER_CAP: usize =
    MAX_HEADER_REQUEST_QUEUE - MAX_HEADER_REQUESTS_PER_IP * 5;

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

/// Whether the inbound arrival throttle must refuse this connection.
///
/// The three counts are arrivals in the current one-second window, this arrival
/// included: from this IP, from its /16, and in total. A whitelisted seed is
/// COUNTED but never refused — the same shape as the pending, per-IP and
/// per-/16 caps, and the invariant the whitelist itself documents: trusted peers
/// are never rate-limited or banned.
///
/// Refusing is the whole response; no ban score. Many honest hosts share one
/// public IP behind a NAT, so a burst of connects from one address is not
/// evidence of abuse, and a 6-24 h ban for it would be a false positive that the
/// live per-IP cap (`MAX_PEERS_PER_IP`) already makes unnecessary.
fn inbound_throttle_rejects(
    whitelisted: bool,
    per_ip: u32,
    per_subnet: u32,
    global: u32,
) -> bool {
    !whitelisted
        && (per_ip > MAX_INBOUND_PER_SEC
            || per_subnet > MAX_INBOUND_PER_SEC_PER_SUBNET
            || global > MAX_INBOUND_GLOBAL_PER_SEC)
}

/// Count one arrival against `key`'s budget for the current throttle window and
/// report its running count. `key` is a source IP or a /16, one map each.
///
/// Bounded: past `MAX_THROTTLE_TRACKED_IPS` distinct keys in one window the map
/// stops growing and an untracked arrival reports 0, so it is judged by the
/// wider budgets alone rather than refused for want of bookkeeping.
fn count_arrival(arrivals: &mut HashMap<String, u32>, key: &str) -> u32 {
    if arrivals.len() >= MAX_THROTTLE_TRACKED_IPS && !arrivals.contains_key(key) {
        return 0;
    }
    let seen = arrivals.entry(key.to_string()).or_insert(0);
    *seen = seen.saturating_add(1);
    *seen
}

/// Whether the pending-connection cap must refuse this inbound connection.
///
/// A whitelisted seed is COUNTED against the cap but never refused by it. The
/// per-IP and per-/16 caps already work this way; this one did not, and it
/// runs ahead of them, so a saturated counter used to lock a follower out of
/// its own seeds permanently.
fn pending_cap_rejects(prev_pending: usize, whitelisted: bool) -> bool {
    prev_pending >= MAX_PENDING_CONNECTIONS && !whitelisted
}

/// Wall-clock bound on ONE outbound dial.
///
/// `TcpStream::connect` has no timeout, so a blackholed address parks the dial
/// thread for the OS SYN-retry window — about two minutes on Linux's default
/// `tcp_syn_retries`. Kept under `MIN_REDIAL_INTERVAL_SECS` so a dial that
/// times out is eligible again on a later reconnect cycle instead of being
/// held off by the re-dial rate limit as well.
const OUTBOUND_CONNECT_TIMEOUT_SECS: u64 = 10;
const _: () = assert!(
    OUTBOUND_CONNECT_TIMEOUT_SECS < MIN_REDIAL_INTERVAL_SECS,
    "a dial must be able to time out and still be re-dialable on a later cycle"
);

/// Dial `addr`, bounding the connect at `timeout`.
///
/// Every address in the peer store parses as a `SocketAddr` —
/// `is_routable_peer_addr` requires it before one is ever enqueued — so for
/// those this resolves without touching DNS. A configured seed may still be a
/// hostname, which `to_socket_addrs` resolves.
///
/// The timeout is a parameter so a test can observe that it reaches
/// `connect_timeout`: plain `connect` would reject an unparseable address just
/// the same, so nothing else distinguishes a bounded dial from an unbounded one
/// without waiting out a real SYN-retry window.
fn connect_within(addr: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    let target = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unresolvable peer address")
        })?;
    TcpStream::connect_timeout(&target, timeout)
}

/// Dial `addr` with the node's outbound connect bound.
fn connect_with_timeout(addr: &str) -> std::io::Result<TcpStream> {
    connect_within(addr, Duration::from_secs(OUTBOUND_CONNECT_TIMEOUT_SECS))
}

/// Whether the outbound slot budget is spent.
///
/// `in_use` counts live outbound connections AND dials still in flight, because
/// a slot is reserved before the dial thread starts — which is what makes this
/// bound the number of dial THREADS and not just the connection count.
///
/// Whitelisted seeds are exempt: a node must always be able to reach its
/// configured seeds, the same rule every inbound gate follows.
fn outbound_slots_full(in_use: usize, whitelisted: bool) -> bool {
    !whitelisted && in_use >= MAX_PEERS
}

/// Releases an outbound dial's slot on EVERY exit path, including an unwinding
/// panic.
///
/// The slot is taken before the dial thread starts and used to be released by
/// a plain statement after `handle_peer_connection` returned, so any path that
/// never returned kept the address marked "connected" for the life of the
/// process. That was only a wasted re-dial while dials were unbounded. With
/// `outbound_slots_full` above it would be a LOCKOUT: enough leaked slots and
/// the node stops dialling anyone — exactly how the inbound pending cap left
/// two testnet followers unable to accept their own seeds for 76 days. The
/// guard therefore lands WITH the cap, not after it.
struct OutboundSlot {
    addr: String,
}

impl Drop for OutboundSlot {
    fn drop(&mut self) {
        CONNECTED_OUTBOUND.lock().remove(&self.addr);
    }
}

/// Choose up to `deficit` dial candidates from a peer list of `len` entries,
/// starting at `cursor`, and report where the next cycle should start.
///
/// The rotation is the point. `get_peers()` returns the store in lexicographic
/// key order, so a budgeted loop that always started at the front would spend
/// every cycle on whatever sorts first — and a peer that gossips addresses can
/// choose that. Rotating means every stored address is reached within
/// ceil(len / deficit) cycles: about 43 minutes for a full 16,384-entry store
/// at MAX_PEERS per 10 s, and immediately for the seeds, which are dialled in
/// their own earlier pass.
///
/// The walk stops after one full pass (`examined < len`) so a cycle in which
/// nothing is due cannot spin.
fn dial_window(
    len: usize,
    cursor: usize,
    deficit: usize,
    mut due: impl FnMut(usize) -> bool,
) -> (Vec<usize>, usize) {
    if len == 0 || deficit == 0 {
        return (Vec::new(), cursor);
    }
    let start = cursor % len;
    let mut picked = Vec::with_capacity(deficit.min(len));
    let mut examined = 0usize;
    while picked.len() < deficit && examined < len {
        let i = (start + examined) % len;
        examined += 1;
        if due(i) {
            picked.push(i);
        }
    }
    (picked, (start + examined) % len)
}

/// Whether this stored peer is worth dialling on this reconnect cycle.
///
/// Extracted so the loop can run it over two passes — seeds, then everyone
/// else — without repeating the conditions.
fn reconnect_due(peers: &PeerManager, addr: &str) -> bool {
    // Already connected, or a dial already in flight.
    if CONNECTED_OUTBOUND.lock().contains(addr) {
        return false;
    }
    // Never dial a banned peer (a stale ban or a real one): dialing it just
    // gets rejected and re-bans via connection spam.
    if peers.is_banned(addr) {
        return false;
    }
    // Rate-limit re-dials of the same peer so a fast-failing target (banned,
    // or our own IP self-connecting) doesn't churn.
    if let Some(last) = LAST_DIAL.lock().get(addr) {
        if last.elapsed() < Duration::from_secs(MIN_REDIAL_INTERVAL_SECS) {
            return false;
        }
    }
    true
}

/// Whether we owe this peer a connection-puzzle solution.
///
/// Solving is work WE pay for, so it is allowed only where the protocol
/// actually asks for it: a connection we dialled (on an inbound connection we
/// are the challenger, never the solver), at most one puzzle per connection,
/// and only for a challenge of the exact shape `generate_challenge` emits.
fn should_solve_puzzle(is_outbound: bool, puzzles_solved: u32, challenge: &str) -> bool {
    is_outbound && puzzles_solved == 0 && ConnectionPuzzle::is_well_formed(challenge)
}

/// Error text the deadline reader reports once the budget is spent.
///
/// Deliberately NOT one of the substrings `is_transient_read_timeout` matches:
/// a spent deadline is terminal, while an `SO_RCVTIMEO` expiry is the ordinary
/// idle poll that drives keepalive and the outbound flush. Classifying the
/// deadline as transient would spin the connection loop on an error that can
/// never clear instead of ending the connection.
const DEADLINE_ERROR_TEXT: &str = "pre-handshake read deadline exceeded";

/// A `Read` that refuses to make progress once a wall-clock deadline passes.
///
/// Returning an error from `read` (rather than, say, shutting the socket down
/// from a reaper) unwinds `read_exact` -> `read_message` ->
/// `handle_peer_connection` through the ordinary error path, so
/// `InboundSlot::drop` releases the pending slot and both anti-eclipse
/// registrations on the way out.
///
/// `disarm` drops the deadline once the handshake completes: an established
/// peer has solved the puzzle and holds a live slot that `MAX_PEERS_PER_IP` and
/// `MAX_INBOUND_PER_SUBNET` already bound, and a total deadline there would cut
/// an honest follower's slow bulk transfer during IBD.
struct DeadlineReader<R> {
    inner: R,
    deadline: Option<Instant>,
}

impl<R> DeadlineReader<R> {
    fn new(inner: R, deadline: Instant) -> Self {
        Self {
            inner,
            deadline: Some(deadline),
        }
    }

    fn disarm(&mut self) {
        self.deadline = None;
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    DEADLINE_ERROR_TEXT,
                ));
            }
        }
        self.inner.read(buf)
    }
}

/// Whether a read error is the ordinary idle poll expiring, rather than a
/// condition that ends the connection.
///
/// One classifier for both read sites. They carried two hand-written copies of
/// this list and the pre-handshake one was missing Windows' `WSAETIMEDOUT`
/// (10060) — which that platform returns for an `SO_RCVTIMEO` expiry, as the
/// main loop's own copy documents — so on Windows a peer that had not sent its
/// puzzle challenge within 100 ms was dropped instead of treated as legacy.
fn is_transient_read_timeout(msg_lowercase: &str) -> bool {
    msg_lowercase.contains("timed out")
        || msg_lowercase.contains("would block")
        || msg_lowercase.contains("wouldblock")
        || msg_lowercase.contains("temporarily unavailable")
        || msg_lowercase.contains("os error 11")
        || msg_lowercase.contains("os error 10035")
        || msg_lowercase.contains("os error 10060")
        || msg_lowercase.contains("did not properly respond")
}

/// The ban category a protocol ban score implies, as the post-read command
/// check has always chosen it.
fn category_for_score(ban_score: u64) -> BanCategory {
    if ban_score >= 50 {
        BanCategory::Malicious
    } else {
        BanCategory::Malformed
    }
}

/// Why a read ended without yielding a message.
enum ReadStop {
    /// IO, framing, checksum or deserialization failure — the path every read
    /// error took before, classified at the call site by
    /// `is_transient_read_timeout`.
    Failed(NetworkError),
    /// The command DECLARED in the 13-byte header is not allowed in the
    /// current handshake state, so its payload was never sized, allocated or
    /// read. Carries the state machine's own ban score, which the call site
    /// applies exactly as the post-read check did.
    Premature {
        cmd: CommandId,
        reason: String,
        ban_score: u64,
    },
}

/// Releases an accepted inbound connection's accounting on EVERY exit path,
/// including an unwinding panic.
///
/// The three counters — the pending-connection slot, the per-IP cap and the
/// per-/16 cap — used to be decremented by plain statements placed after
/// `handle_peer_connection` returned. Any path that never returned skipped all
/// three, and a leaked `pending` slot is unrecoverable: once
/// `MAX_PENDING_CONNECTIONS` of them accumulate, the accept gate rejects every
/// inbound connection for the rest of the process's life. That is not
/// theoretical — on 2026-10-28 two testnet followers were found frozen since
/// August with `pending` reading 64 while the kernel reported 2 live sockets,
/// so neither could accept the miner and neither had synced in 76 days.
///
/// Honest scope: a guard runs on scope exit, so it fixes the panic path and
/// any early return. It CANNOT release a thread that is parked forever (the
/// followers above were blocked on a lock, not panicking). That is why the
/// pending cap below must also let a whitelisted seed through — the guard
/// protects the accounting, the whitelist protects liveness.
struct InboundSlot {
    pending: Arc<std::sync::atomic::AtomicUsize>,
    ip_key: String,
    ip_registered: bool,
    subnet_registered: bool,
}

impl InboundSlot {
    /// Takes ownership of one already-incremented `pending` slot.
    fn new(pending: &Arc<std::sync::atomic::AtomicUsize>, ip_key: String) -> Self {
        Self {
            pending: Arc::clone(pending),
            ip_key,
            ip_registered: false,
            subnet_registered: false,
        }
    }
}

impl Drop for InboundSlot {
    fn drop(&mut self) {
        // Reverse registration order, then the slot itself.
        if self.subnet_registered {
            release_inbound_subnet(&self.ip_key);
        }
        if self.ip_registered {
            release_inbound_ip(&self.ip_key);
        }
        self.pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Register one more inbound connection for `ip` and report whether the IP is
/// still WITHIN `MAX_PEERS_PER_IP`. ALWAYS increments (pair with exactly one
/// `release_inbound_ip`), so a caller that rejects on `false` can release
/// immediately without desyncing the counter — and a whitelisted seed that
/// bypasses the cap is still tracked and released symmetrically. This mirrors
/// `register_inbound_subnet` so both anti-eclipse caps share one shape.
fn register_inbound_ip(ip: &str) -> bool {
    use crate::service::network::p2p::peer_manager::MAX_PEERS_PER_IP;
    let mut map = INBOUND_CONN_PER_IP.lock();
    let entry = map.entry(ip.to_string()).or_insert(0);
    *entry += 1;
    *entry <= MAX_PEERS_PER_IP
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
/// `register_inbound_ip`).
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
    let items = PENDING_BLOCKS.write().take();
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
        let dropped = PENDING_BLOCKS.write().retain_other_peers(peer_id);
        if dropped > 0 {
            slog_warn!("p2p", "cleanup_dropped_pending_blocks", peer => peer_id, dropped => dropped);
        }
    }
    {
        TARGETED_MSGS.lock().remove_peer(peer_id);
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
    // The outbound cursor is NOT removed here: `OutboundCursor` owns it for the
    // life of the connection and drops it on every exit path, panics included.
    // Removing it in both places would mean two owners for one entry, and the
    // loser would delete a cursor the next connection from the same ip:port had
    // just seeded — which silently drops that peer out of the pruning minimum.
}

/// Drain all received peer addresses from Addr messages (call from node main loop).
/// Thread-safe: works from ANY thread.
pub fn drain_received_addrs() -> Vec<String> {
    std::mem::take(&mut *RECEIVED_ADDRS.lock())
}

/// Whether a block-serve request must be refused at the push.
///
/// A whitelisted seed is bounded only by the global cap: counted, but never
/// refused while there is room at all. A stranger is bounded both by its own
/// per-host share and by the stranger cap, which reserves the remainder so one
/// flood cannot take the queue the seeds need.
fn block_request_rejects(whitelisted: bool, queued_for_ip: usize, queued_total: usize) -> bool {
    if whitelisted {
        return queued_total >= MAX_BLOCK_REQUEST_QUEUE;
    }
    queued_total >= BLOCK_QUEUE_STRANGER_CAP || queued_for_ip >= MAX_BLOCK_REQUESTS_PER_IP
}

/// Queue a peer's block-serve request. The GetBlock/GetData handlers call this;
/// the daemon event loop drains it and serves the block from the BlockStore.
pub fn push_block_request(peer_id: &str, hash: &str) {
    push_block_requests(peer_id, vec![hash.to_string()]);
}

/// Queue a batch of block-serve requests under ONE lock.
///
/// A GetData carries up to `MAX_INV_PER_MSG` hashes, and pushing them one at a
/// time took the request queue's lock once per hash.
///
/// LOCK ORDER: PENDING_BLOCK_REQUESTS first, then BLOCK_REQUESTS_PER_IP. The
/// whitelist is consulted BEFORE either, so neither guard is held across it.
pub fn push_block_requests(peer_id: &str, hashes: Vec<String>) {
    if hashes.is_empty() {
        return;
    }
    let ip = extract_ban_ip(peer_id);
    let whitelisted = crate::service::network::dos_guard::is_whitelisted(&ip);
    let offered = hashes.len();
    let mut queued = 0usize;
    {
        let mut q = PENDING_BLOCK_REQUESTS.lock();
        let mut per_ip = BLOCK_REQUESTS_PER_IP.lock();
        for hash in hashes {
            let for_ip = per_ip.get(&ip).copied().unwrap_or(0);
            if block_request_rejects(whitelisted, for_ip, q.len()) {
                break;
            }
            q.push((peer_id.to_string(), hash));
            *per_ip.entry(ip.clone()).or_insert(0) += 1;
            queued += 1;
        }
    }
    if queued < offered {
        slog_debug!("p2p", "block_requests_dropped",
            peer => peer_id,
            offered => offered,
            queued => queued);
    }
}

/// Which items of an Inv announcement to actually request: the announcement's
/// own order, each hash once, nothing the pending-block queue already holds,
/// and at most `MAX_INV_ITEMS_REQUESTED` of them.
///
/// `is_queued` is consulted once per DISTINCT item, after the repeat filter, so
/// a thousand copies of one hash cost one lookup on the shared queue instead of
/// a thousand.
fn inv_items_to_request(items: &[InvItem], is_queued: impl Fn(&str) -> bool) -> Vec<InvItem> {
    let mut out: Vec<InvItem> = Vec::new();
    let mut seen: HashSet<(&str, &str)> =
        HashSet::with_capacity(items.len().min(MAX_INV_ITEMS_REQUESTED));
    for item in items {
        if out.len() >= MAX_INV_ITEMS_REQUESTED {
            break;
        }
        if !seen.insert((item.kind.as_str(), item.hash.as_str())) {
            continue;
        }
        if is_queued(&item.hash) {
            continue;
        }
        out.push(item.clone());
    }
    out
}

/// Which hashes of a Headers reply to request as blocks: in order, each once,
/// skipping empties and anything already queued, at most `limit` of them.
///
/// Returned as a list so the caller can write the requests with no lock held;
/// the queue's lock used to be taken per hash, inside the write loop.
fn blocks_to_request<'a>(
    hashes: &'a [String],
    limit: usize,
    is_queued: impl Fn(&str) -> bool,
) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    let mut seen: HashSet<&'a str> = HashSet::with_capacity(hashes.len().min(limit));
    for hash in hashes {
        if out.len() >= limit {
            break;
        }
        let hash = hash.as_str();
        if hash.is_empty() || !seen.insert(hash) || is_queued(hash) {
            continue;
        }
        out.push(hash);
    }
    out
}

/// Put block-serve requests a pass could not reach back at the FRONT of the
/// queue, so a per-pass budget defers work instead of destroying it.
///
/// Without this the remainder of a pass was simply dropped, and the requester
/// has no in-flight ledger and no retry for an unanswered GetBlock: it re-asks
/// only when its next GetHeaders round returns the same range. A budget that
/// drops is a throughput ceiling of (budget / round interval); a budget that
/// defers is a rate limit, which is what was wanted.
///
/// The per-IP shares are re-counted because the drain cleared them: these
/// requests occupy queue space in the NEW window, so they must be charged to it
/// or a host could hold more than its share by being deferred.
///
/// LOCK ORDER: PENDING_BLOCK_REQUESTS first, then BLOCK_REQUESTS_PER_IP.
pub fn requeue_block_requests(items: Vec<(String, String)>) {
    if items.is_empty() {
        return;
    }
    let mut q = PENDING_BLOCK_REQUESTS.lock();
    let mut per_ip = BLOCK_REQUESTS_PER_IP.lock();
    let available = MAX_BLOCK_REQUEST_QUEUE.saturating_sub(q.len());
    let mut kept: Vec<(String, String)> = Vec::with_capacity(items.len().min(available));
    let mut dropped = 0usize;
    for (peer_id, hash) in items {
        if kept.len() >= available {
            dropped = dropped.saturating_add(1);
            continue;
        }
        *per_ip.entry(extract_ban_ip(&peer_id)).or_insert(0) += 1;
        kept.push((peer_id, hash));
    }
    if dropped > 0 {
        slog_warn!("p2p", "block_requests_requeue_dropped", dropped => dropped);
    }
    let mut combined = kept;
    combined.append(&mut q);
    *q = combined;
}

/// Drain queued block-serve requests (call from the node main loop).
///
/// LOCK ORDER: PENDING_BLOCK_REQUESTS first, then BLOCK_REQUESTS_PER_IP, which
/// is cleared with the queue so a share cannot outlive the requests it counted.
pub fn drain_block_requests() -> Vec<(String, String)> {
    let mut q = PENDING_BLOCK_REQUESTS.lock();
    let mut per_ip = BLOCK_REQUESTS_PER_IP.lock();
    let taken = std::mem::take(&mut *q);
    per_ip.clear();
    taken
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

/// Whether the header-request queue must refuse this request.
///
/// Strangers share `HEADER_QUEUE_STRANGER_CAP`; the rest of the queue is
/// reserved for whitelisted seeds.
///
/// One global cap for everyone looked safe because a refusal here only delays
/// a peer's next sync round — but that reasoning holds for ONE refusal, not
/// for a sustained flood. At `MAX_HEADER_REQUESTS_PER_IP` each, ~25 hosts fill
/// a 2,000-entry queue, and a flooder refills it within milliseconds of every
/// drain, so an honest peer arriving at an arbitrary phase keeps finding it
/// full. The reservation is what the fleet's own seeds cannot be squeezed out
/// of.
///
/// A seed is still bounded by the queue's hard ceiling, because it bypasses
/// everything else: `DosGuard::check` returns Allow for a whitelisted peer, so
/// a seed has no token bucket either, and this is the only limit left. At
/// roughly 100 bytes an entry the whole queue is ~200 KB.
fn header_request_rejects(
    whitelisted: bool,
    queued_for_ip: usize,
    queued_total: usize,
) -> bool {
    if whitelisted {
        return queued_total >= MAX_HEADER_REQUEST_QUEUE;
    }
    queued_total >= HEADER_QUEUE_STRANGER_CAP || queued_for_ip >= MAX_HEADER_REQUESTS_PER_IP
}

/// Queue a peer's GetHeaders request. The daemon walks the chain forward from
/// `from_hash` and replies with a batch of block hashes for bulk catch-up.
///
/// LOCK ORDER: PENDING_HEADER_REQUESTS first, then HEADER_REQUESTS_PER_IP.
/// This is the only site that holds both; `drain_header_requests` takes them
/// one after the other, never nested, and nothing else touches either.
pub fn push_header_request(peer_id: &str, from_hash: &str, count: u32) {
    let ip = extract_ban_ip(peer_id);
    let whitelisted = crate::service::network::dos_guard::is_whitelisted(&ip);
    let mut q = PENDING_HEADER_REQUESTS.lock();
    let mut per_ip = HEADER_REQUESTS_PER_IP.lock();
    let queued_for_ip = per_ip.get(&ip).copied().unwrap_or(0);
    if header_request_rejects(whitelisted, queued_for_ip, q.len()) {
        return;
    }
    q.push((peer_id.to_string(), from_hash.to_string(), count));
    *per_ip.entry(ip).or_insert(0) += 1;
}

/// Drain queued header-serve requests (call from the node main loop).
///
/// Also opens the next per-IP quota window: the queue is taken whole, so every
/// counter it tracked is spent. This is also what keeps the map bounded — its
/// keys live at most one window.
///
/// LOCK ORDER: PENDING_HEADER_REQUESTS first, then HEADER_REQUESTS_PER_IP —
/// the same order `push_header_request` takes them, and held across BOTH
/// steps. Releasing the queue lock in between left a window in which a push
/// saw an empty queue but a spent counter, and refused a peer that had nothing
/// outstanding.
pub fn drain_header_requests() -> Vec<(String, String, u32)> {
    let mut q = PENDING_HEADER_REQUESTS.lock();
    let mut per_ip = HEADER_REQUESTS_PER_IP.lock();
    let taken = std::mem::take(&mut *q);
    per_ip.clear();
    taken
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
    let mut q = PENDING_BLOCKS.write();

    // Keep queue bounded even during requeue. Under load, new incoming items
    // can arrive between drain and requeue; without this cap, requeue could
    // temporarily exceed the global queue limit. A copy of a requeued block can
    // also have arrived in that window, and the orphan pool can hand back one
    // the queue already holds, so ask the queue what it can really take.
    let available = MAX_PENDING_BLOCK_QUEUE.saturating_sub(q.len());
    let (candidates, mut dropped) = q.admissible_for_requeue(items, available);

    let mut counts = PEER_PENDING.lock();
    let mut requeued: Vec<(String, Block)> = Vec::with_capacity(candidates.len());
    for (peer_id, block) in candidates {
        let entry = counts.entry(peer_id.clone()).or_insert((0, 0));
        if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
            dropped = dropped.saturating_add(1);
            continue;
        }
        entry.1 = entry.1.saturating_add(1);
        requeued.push((peer_id, block));
    }
    drop(counts);
    if dropped > 0 {
        slog_warn!("p2p", "pending_block_requeue_dropped", dropped => dropped);
    }

    q.prepend(requeued);
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
    let mut q = PENDING_BLOCKS.write();
    if q.len() >= MAX_PENDING_BLOCK_QUEUE {
        slog_warn!("p2p", "pending_block_queue_full");
        return false;
    }
    // Drop duplicate block hashes already waiting in queue — one hash lookup,
    // not a walk of the queue.
    if q.contains(&block.header.hash) {
        return true;
    }

    let mut pending = PEER_PENDING.lock();
    let entry = pending.entry(peer_id.to_string()).or_insert((0, 0));
    if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
        slog_warn!("p2p", "per_peer_block_limit_reached", peer => peer_id);
        return false;
    }
    // Charge the quota only for a block that was really stored.
    if q.push(peer_id, block) {
        entry.1 += 1;
    }
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
/// Public so the daemon's header-serve fairness can key on the same host
/// identity the queue quota and the accept gates use, instead of
/// reimplementing the IPv4/IPv6/bracketed forms.
pub fn extract_ban_ip(addr: &str) -> String {
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

/// Push a message targeted at a specific peer (block/header serve, and the
/// Dandelion++ stem phase). Thread-safe: can be called from any thread.
///
/// Never refuses: an overflow evicts the oldest backlog of the peer
/// responsible, because dropping the arriving message punished whichever peer
/// was behaving.
pub fn push_outbound_to_peer(peer_id: &str, msg: P2PMessage) {
    TARGETED_MSGS.lock().push(peer_id, msg, false);
}

/// Put an undelivered targeted message back at the FRONT of its peer's queue,
/// so a retry keeps its place in order.
///
/// Goes through the same bounds as any other push: the old requeue wrote
/// straight into the queue with no cap check at all, so the global cap was not
/// a hard cap.
fn requeue_targeted_front(peer_id: &str, msg: P2PMessage) {
    TARGETED_MSGS.lock().push(peer_id, msg, true);
}

/// Drain targeted messages for a specific peer_id.
/// Each peer connection thread calls this with its own ID.
fn drain_targeted_for(peer_id: &str) -> Vec<P2PMessage> {
    TARGETED_MSGS.lock().take_for(peer_id)
}

/// Drop targeted messages nobody came to collect.
///
/// Called from the maintenance loop. The queue's only other removers are a
/// peer's own flush and its `cleanup_peer_state`, and the daemon can enqueue
/// for a peer AFTER its cleanup has run — the drain and the cleanup are
/// separate critical sections — so without this an entry for a departed peer
/// is immortal and enough of them refuse every future targeted message for the
/// life of the process.
pub fn sweep_targeted_expired() {
    let (dropped, left, bytes) = {
        let mut q = TARGETED_MSGS.lock();
        (
            q.sweep_expired(Duration::from_secs(TARGETED_TTL_SECS)),
            q.len(),
            q.bytes(),
        )
    };
    if dropped > 0 {
        slog_warn!("p2p", "targeted_expired_dropped",
            dropped => dropped,
            entries_left => left,
            bytes_left => bytes);
    }
}

/// The lowest outbound cursor any live connection holds, or None when none do.
///
/// Read BEFORE the broadcast queue is locked, NEVER from inside it. Taking the
/// cursor map while holding the queue was one half of a lock-order inversion:
/// seeding a cursor read the queue's sequence from inside the cursor lock, so
/// one thread held cursors and wanted the queue while another held the queue and
/// wanted cursors. Both are `parking_lot` mutexes with no timeout, so the pair
/// wedges the accept path, every peer's flush, and — through `push_outbound` —
/// the daemon event loop, with nothing to break it but a restart.
///
/// The minimum this returns CAN be overtaken: a connection that has already
/// read the sequence it will seed with, and is then descheduled, inserts that
/// older value after this call, so the early read is not conservative by
/// itself. What makes pruning safe is the order at the seeding site: a
/// connection's DELIVERY cursor is read AFTER its entry is seeded
/// (`OutboundCursor::seed`, then `ConnectionSession::new`), so the delivery
/// cursor is never below the seeded value, and the global sequence only rises.
/// Whichever order this read and that seed happen in, the minimum returned is
/// at or below that connection's delivery cursor — before the seed, it is at
/// most the global sequence of an earlier instant; after it, at most the seeded
/// value itself. So no live peer loses a broadcast it still wants. Seeding from
/// a cached sequence, or reading the delivery cursor earlier, would break that.
fn min_outbound_ack() -> Option<u64> {
    PEER_LAST_OUTBOUND.lock().values().copied().min()
}

/// How far the broadcast queue may be pruned: everything at or below the
/// returned sequence is dropped.
///
/// `min_ack` is what every live peer has already consumed. The hard retain is
/// the backstop for when that cursor is pinned or stale — a leaked entry, or a
/// retained whitelisted laggard — because a queue that stops pruning first
/// slows every flush and finally wedges sync when it fills. Messages older than
/// the newest `OUTBOUND_HARD_RETAIN` are stale gossip by definition; a peer that
/// far behind backfills through header-sync/IBD instead.
fn prune_cutoff(min_ack: Option<u64>, max_seq: u64) -> u64 {
    const OUTBOUND_HARD_RETAIN: u64 = 4_096;
    let hard = max_seq.saturating_sub(OUTBOUND_HARD_RETAIN);
    min_ack.unwrap_or(0).max(hard)
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
    // Before the queue is locked, so this function holds one lock at a time.
    let min_ack = min_outbound_ack();
    let mut q = OUTBOUND_MSGS.lock();
    let new_msgs: Vec<(u64, P2PMessage)> =
        q.1.iter()
            .filter(|(seq, _)| *seq > since)
            .take(OUTBOUND_FLUSH_BATCH)
            .map(|(seq, msg)| (*seq, msg.clone()))
            .collect();
    let max_seq = q.0;
    let cutoff = prune_cutoff(min_ack, max_seq);
    if cutoff > 0 {
        let before = q.1.len();
        q.1.retain(|(seq, _)| *seq > cutoff);
        let dropped = before.saturating_sub(q.1.len());
        if dropped > 0 {
            slog_debug!("p2p", "outbound_queue_pruned",
                dropped => dropped,
                cutoff_seq => cutoff,
                min_ack_seq => min_ack.unwrap_or(0));
        }
    }
    (new_msgs, max_seq)
}

/// Owns one peer's outbound-broadcast cursor for the life of its connection.
///
/// The cursor was seeded at the top of `handle_peer_connection` and removed only
/// by `cleanup_peer_state` after the main loop — with sixteen early exits in
/// between and no `catch_unwind` anywhere in this file, so every failed
/// handshake orphaned an entry keyed on the peer's own ephemeral port. The
/// cheapest trigger is a bare TCP connect that sends nothing, bounded only by
/// the inbound arrival budgets, and the entries are never swept.
///
/// Growth is the smaller half of it. `min_outbound_ack` takes the MINIMUM over
/// the whole map on every flush of every peer, so the first leaked entry pins
/// the broadcast queue's pruning cursor at the sequence it was abandoned on,
/// for the life of the process: ack-based pruning stops contributing, the queue
/// sits at its hard-retain ceiling, and every flush then walks and clones more
/// of it — which also widens the window of the inversion this entry's own
/// seeding used to open.
struct OutboundCursor {
    peer: String,
}

impl OutboundCursor {
    /// Seed `peer`'s cursor at `seq`, leaving an existing cursor alone.
    ///
    /// A new peer must start at the CURRENT broadcast sequence, not 0: a cursor
    /// of 0 pins the minimum at 0 and freezes pruning until a restart. The
    /// historical backlog reaches a new peer through its own header-sync, never
    /// the broadcast queue, so starting at the current sequence costs it
    /// nothing.
    ///
    /// `seq` is a parameter precisely so this cannot read it from inside the
    /// cursor lock — that is the order inversion described on
    /// [`min_outbound_ack`], and making the sequence an argument is what makes
    /// reintroducing it a compile error rather than a rare wedge.
    fn seed(peer: &str, seq: u64) -> Self {
        PEER_LAST_OUTBOUND
            .lock()
            .entry(peer.to_string())
            .or_insert(seq);
        Self {
            peer: peer.to_string(),
        }
    }
}

impl Drop for OutboundCursor {
    fn drop(&mut self) {
        PEER_LAST_OUTBOUND.lock().remove(&self.peer);
    }
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
    /// How many connection puzzles we have solved for this peer. A connection
    /// legitimately asks us to solve at most one, so anything beyond the first
    /// is unpaid work for a stranger.
    puzzles_solved: u32,
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
            puzzles_solved: 0,
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

        // Whitelist the trusted seeds so the operator's own nodes never DoS-ban
        // each other: seeds must serve an unbounded IBD backlog to a lagging peer
        // without tripping rate/lag heuristics (which otherwise stall convergence
        // for an hour-long Resource ban). Resolve each seed (IP literal or DNS)
        // to its IP(s); on resolution failure, whitelist the literal as fallback.
        //
        // This runs BEFORE the accept thread starts. Every inbound gate asks the
        // whitelist whether the peer is a seed, so populating it afterwards left
        // a startup window - as long as the blocking DNS resolution below - in
        // which a seed dialling in was judged a stranger by all four gates. The
        // listener is already bound, so arrivals wait in the kernel backlog
        // instead of being mis-judged.
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
        let mut window_start = std::time::Instant::now();
        let mut arrivals_total: u32 = 0;
        let mut arrivals_per_ip: HashMap<String, u32> = HashMap::new();
        let mut arrivals_per_subnet: HashMap<String, u32> = HashMap::new();
        let mut throttle_logged = false;

        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    // Identity first: EVERY gate below needs to know whether
                    // this is a trusted seed before it can decide — the arrival
                    // throttle included, which is why the address is resolved
                    // ahead of it.
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
                    // One lookup for all four gates below.
                    let whitelisted =
                        crate::service::network::dos_guard::is_whitelisted(&ban_key);

                    // ── Arrival throttle: per source IP, global as a backstop ──
                    if window_start.elapsed() >= Duration::from_secs(1) {
                        window_start = std::time::Instant::now();
                        arrivals_total = 0;
                        arrivals_per_ip.clear();
                        arrivals_per_subnet.clear();
                        throttle_logged = false;
                    }
                    arrivals_total = arrivals_total.saturating_add(1);
                    let per_ip = count_arrival(&mut arrivals_per_ip, &ban_key);
                    let per_subnet = count_arrival(
                        &mut arrivals_per_subnet,
                        &crate::service::network::p2p::peer_diversity::subnet_16(&ban_key),
                    );
                    if inbound_throttle_rejects(whitelisted, per_ip, per_subnet, arrivals_total) {
                        // One line per window: the flooder drives this path, so
                        // logging every refusal hands it the log volume too.
                        if !throttle_logged {
                            throttle_logged = true;
                            slog_warn!("p2p", "inbound_throttle", addr => &peer_addr, per_ip => per_ip, per_subnet => per_subnet, total => arrivals_total);
                        }
                        drop(s);
                        continue;
                    }

                    // ── Pending connection limit (atomic check+increment) ──
                    // fetch_add first so the TOCTOU race is closed (several
                    // threads can no longer all pass a bare check), then hand
                    // the slot to an `InboundSlot` guard that releases it on
                    // every exit path below, including an unwinding panic.
                    //
                    // A whitelisted seed is COUNTED but never REJECTED, exactly
                    // like the per-IP and per-/16 caps further down. Without
                    // this the cap was the one gate with no bypass, and it sits
                    // ahead of the others — so once 64 slots were held a
                    // follower stopped accepting its own seeds and could never
                    // sync again. Two testnet followers sat that way from
                    // August to October 2026.
                    let prev_pending = pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    let mut slot = InboundSlot::new(&pending, ban_key.clone());
                    if pending_cap_rejects(prev_pending, whitelisted) {
                        slog_warn!("p2p", "too_many_pending_connections", pending => prev_pending);
                        drop(s);
                        continue;
                    }

                    // ── Check if peer is banned ──
                    if DOS_GUARD.is_banned(&ban_key) {
                        slog_warn!("p2p", "rejected_banned_peer", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    // ── Anti-eclipse: cap live inbound connections per IP ──
                    // Prevents a single host from monopolizing inbound slots.
                    // Whitelisted trusted seeds bypass the cap (a node must
                    // ALWAYS accept its seeds — otherwise a follower can be
                    // isolated from its own seeds once stale/half-open slots
                    // fill, stalling sync) but are still counted + released
                    // symmetrically, exactly like the per-/16 cap below.
                    let ip_within_cap = register_inbound_ip(&ban_key);
                    // register_* ALWAYS increments, so the guard owns the
                    // release from here on whichever way this goes.
                    slot.ip_registered = true;
                    if !ip_within_cap && !whitelisted {
                        slog_warn!("p2p", "rejected_too_many_per_ip", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    // ── Anti-eclipse: cap live inbound connections per /16 ──
                    // Closes the per-IP bypass where an attacker owning a whole
                    // /16 opens many distinct IPs. Whitelisted trusted seeds
                    // bypass the cap (a node must always accept its seeds); they
                    // are still counted + released symmetrically.
                    let subnet_within_cap = register_inbound_subnet(&ban_key);
                    slot.subnet_registered = true;
                    if !subnet_within_cap && !whitelisted {
                        slog_warn!("p2p", "rejected_too_many_per_subnet", addr => &peer_addr);
                        drop(s);
                        continue;
                    }

                    slog_info!("p2p", "inbound_connection", addr => &peer_addr);
                    // Query fresh peer list on each connection (fix stale snapshot)
                    let peers_snapshot = peer_manager.get_addr_list_limited(100);

                    let pm = Arc::clone(peer_manager);
                    thread::spawn(move || {
                        // `slot` is moved in, so the pending slot and both
                        // anti-eclipse registrations are released when this
                        // closure unwinds as well as when it returns.
                        let _slot = slot;
                        let result =
                            Self::handle_peer_connection(s, false, magic, peers_snapshot, pm);
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
        peers: Arc<PeerManager>,
    ) -> Result<(), NetworkError> {
        // 100ms (was 2s): this timeout is also the idle FLUSH interval — served
        // block bodies sit in the targeted queue until the connection loop wakes
        // (on inbound, or this timeout) and flush_outbound writes them. At 2s an
        // idle sync link delivered only ~1 block per ~2.7s (the observed IBD
        // ceiling) despite spare CPU and a peer ready to serve; 100ms lets a
        // catching-up follower pull continuously. Keepalive/pong still fire on
        // their own elapsed() intervals, so faster polling doesn't change them.
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
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
        // Held for the whole connection, so every exit path takes the cursor
        // with it — the sixteen early returns between here and the main loop
        // included, and a panic too. The sequence is read before the guard
        // takes the cursor lock, not inside it.
        let _cursor = OutboundCursor::seed(&peer_str, current_outbound_seq());

        // The read timeout above bounds one recv; this bounds the whole
        // handshake. Disarmed in the main loop the moment it completes.
        let mut reader = BufReader::new(DeadlineReader::new(
            &stream,
            Instant::now() + Duration::from_secs(PRE_HANDSHAKE_DEADLINE_SECS),
        ));
        let mut writer = BufWriter::new(&stream);

        // Session state: ProtocolSession + connection-level fields
        let mut session = ConnectionSession::new(peer_addr, outbound);
        // Set when the handshake completes, so the store is told exactly once.
        let mut marked_tried = false;

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

            // Bound to a local first: the arms below mutate the session, so
            // the state borrow must end here.
            let first = Self::read_message(&mut reader, magic, &session.protocol);
            match first {
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
                Err(ReadStop::Premature {
                    cmd,
                    reason,
                    ban_score,
                }) => {
                    // Refused on the 13-byte header. This is the point the
                    // attack was cheapest: nothing has been solved or paid for
                    // yet, and the old order read the payload first, so a
                    // stranger could declare Block and have us allocate 4 MiB.
                    DOS_GUARD.add_ban_score_cat(
                        &peer_str,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    DOS_GUARD.add_ban_score_cat(
                        &peer_ip,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    return Err(NetworkError::ConnectionFailed(format!(
                        "{} not allowed before the handshake with {}: {}",
                        cmd, peer_str, reason
                    )));
                }
                Err(ReadStop::Failed(e)) => {
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Puzzle exchange failed with {}: {}",
                        peer_str, e
                    )));
                }
            }
        } else {
            // Outbound: wait for puzzle challenge, solve it, send solution
            let first = Self::read_message(&mut reader, magic, &session.protocol);
            match first {
                Ok((P2PMessage::PuzzleChallenge { challenge }, _, sz)) => {
                    session.record_bytes_received(sz as u64);
                    // Check the shape BEFORE `received_puzzle_challenge` stores
                    // the string and before solving: the challenge arrives off
                    // the wire and both retaining it and hashing it are sized
                    // by whatever the peer sent. Every real challenge is 64 hex
                    // characters, so no honest node fails this.
                    if !ConnectionPuzzle::is_well_formed(&challenge) {
                        DOS_GUARD.add_ban_score_cat(
                            &peer_str,
                            50,
                            "malformed puzzle challenge",
                            BanCategory::Malformed,
                        );
                        return Err(NetworkError::ConnectionFailed(format!(
                            "malformed puzzle challenge from {}",
                            peer_str
                        )));
                    }
                    session
                        .protocol
                        .received_puzzle_challenge(&challenge)
                        .map_err(|e| {
                            NetworkError::ConnectionFailed(format!("State error: {}", e))
                        })?;
                    let sol = match ConnectionPuzzle::solve(&challenge) {
                        Some(s) => s,
                        None => {
                            return Err(NetworkError::ConnectionFailed(format!(
                                "puzzle from {} exceeded the solver bound",
                                peer_str
                            )));
                        }
                    };
                    session.puzzles_solved = session.puzzles_solved.saturating_add(1);
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
                Err(ReadStop::Premature {
                    cmd,
                    reason,
                    ban_score,
                }) => {
                    DOS_GUARD.add_ban_score_cat(
                        &peer_str,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    DOS_GUARD.add_ban_score_cat(
                        &peer_ip,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    return Err(NetworkError::ConnectionFailed(format!(
                        "{} not allowed before the handshake with {}: {}",
                        cmd, peer_str, reason
                    )));
                }
                Err(ReadStop::Failed(e)) => {
                    if !is_transient_read_timeout(&e.to_string().to_lowercase()) {
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
            let next = Self::read_message(&mut reader, magic, &session.protocol);
            match next {
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

                    // The protocol state machine vetted this command inside
                    // read_message, on the header, before its payload was
                    // allocated — see ReadStop::Premature below.

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

                    // The handshake ends inside dispatch, when VerAck lands.
                    // Drop the deadline there so it can never cut an
                    // established peer's slow bulk transfer.
                    if session.is_established() {
                        reader.get_mut().disarm();
                        // Once per OUTBOUND connection: peer_str is then the
                        // address we dialled, which is the key the store holds
                        // the record under. On an inbound connection it is the
                        // peer's ephemeral source port instead, so the mark
                        // would land on no record at all — an orphan key in a
                        // prefix with no cap and no deleter, and a signal the
                        // eviction ranking could not use.
                        if outbound && !marked_tried {
                            marked_tried = true;
                            peers.mark_tried(&peer_str);
                        }
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
                Err(ReadStop::Premature {
                    cmd,
                    reason,
                    ban_score,
                }) => {
                    // Same scoring the post-read check applied, now reached
                    // without allocating the payload. We declined to consume
                    // that payload, so the stream can no longer be framed and
                    // the connection ends here — the only sub-50 rejection is
                    // the Disconnecting state, which is already ending.
                    DOS_GUARD.add_ban_score_cat(
                        &peer_str,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    DOS_GUARD.add_ban_score_cat(
                        &peer_ip,
                        ban_score,
                        &reason,
                        category_for_score(ban_score),
                    );
                    slog_warn!("p2p", "command_rejected", addr => &peer_str, command => &cmd.to_string(), state => &session.protocol.state.to_string(), ban_score => ban_score);
                    break;
                }
                Err(ReadStop::Failed(e)) => {
                    let is_timeout = is_transient_read_timeout(&e.to_string().to_lowercase());

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
                    requeue_targeted_front(peer_str, t_msg);
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
    ///   5. Gate the DECLARED command against the handshake state
    ///   6. Validate per-command payload size bounds
    ///   7. Read payload bytes
    ///   8. Validate checksum (corrupted/tampered → reject before deserializing)
    ///   9. Deserialize payload (only after all structural checks pass)
    fn read_message(
        reader: &mut BufReader<DeadlineReader<&TcpStream>>,
        magic: [u8; 4],
        protocol: &ProtocolSession,
    ) -> Result<(P2PMessage, CommandId, usize), ReadStop> {
        // 1. Read wire header (13 bytes)
        let mut hdr_buf = [0u8; WIRE_HEADER_SIZE];
        reader
            .read_exact(&mut hdr_buf)
            .map_err(|e| ReadStop::Failed(NetworkError::ConnectionFailed(e.to_string())))?;
        let header = WireHeader::decode(&hdr_buf);

        // 2-4. Validate header: magic, command_id, payload_len
        let cmd = validate_header(&header, magic).map_err(|pe| {
            ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
        })?;

        // 5. Gate the DECLARED command against the handshake state, BEFORE the
        // payload is sized, allocated or read. This check used to run after
        // the payload had been read, so a peer that had not solved the puzzle
        // could declare Block and have us allocate and read MAX_MESSAGE_SIZE
        // for free; the size bound below is per-command, so it bounded the
        // claim, not what the state permits. Only Version, VerAck, Reject and
        // the two puzzle commands pass here before the handshake, which caps a
        // stranger's allocation at Version's 1 KiB.
        if let Err(pe) = protocol.check_command_allowed(cmd) {
            let ban_score = pe.ban_score as u64;
            return Err(ReadStop::Premature {
                cmd,
                reason: pe.message,
                ban_score,
            });
        }

        // 6. Validate per-command payload size bounds BEFORE allocation/read.
        // This prevents adversaries from forcing large allocations for commands
        // that should have tiny payloads (e.g. Ping/Pong).
        let payload_len = header.payload_len as usize;
        validate_payload_size(cmd, payload_len).map_err(|pe| {
            ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
        })?;

        // 7. Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader
                .read_exact(&mut payload)
                .map_err(|e| ReadStop::Failed(NetworkError::ConnectionFailed(e.to_string())))?;
        }

        // 8. Validate checksum (BEFORE deserialization — blocks tampered data)
        validate_payload_checksum(&payload, header.checksum).map_err(|pe| {
            ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
        })?;

        // 9. Deserialize payload (bincode, allocation-bounded)
        let msg: P2PMessage = bounded_deserialize(&payload).map_err(|e| {
            ReadStop::Failed(NetworkError::Serialization(format!(
                "[Protocol] {} deserialize failed: {}",
                cmd, e
            )))
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
        let msg_size = payload_size_estimate(&msg);
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
            //
            // PuzzleChallenge is allowed before the handshake completes, so
            // this arm runs for a stranger. Solving unconditionally inverted
            // the puzzle's whole purpose — the peer that wants the connection
            // is supposed to pay — and because `solve` hashes the challenge
            // once per iteration it turned one 4 MiB message into ~16 GiB of
            // SHA-256 at 800 messages/s per peer.
            //
            // We owe a solution in exactly one case: we dialled out, the
            // challenge arrived too late for the handshake window (slow peer),
            // and we have not already answered one on this connection.
            P2PMessage::PuzzleChallenge { challenge } => {
                if !should_solve_puzzle(
                    session.protocol.is_outbound,
                    session.puzzles_solved,
                    &challenge,
                ) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        10,
                        "unexpected puzzle challenge",
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                let sol = match ConnectionPuzzle::solve(&challenge) {
                    Some(s) => s,
                    None => {
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            10,
                            "puzzle challenge exceeded the solver bound",
                            BanCategory::Malformed,
                        );
                        return Ok(());
                    }
                };
                session.puzzles_solved = session.puzzles_solved.saturating_add(1);
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
                                    if q.len() >= MAX_PENDING_TX_QUEUE {
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
                                    let mut q = PENDING_BLOCKS.write();
                                    if q.len() >= MAX_NETWORK_PENDING_BLOCKS {
                                        false
                                    } else {
                                        let mut m = PEER_PENDING.lock();
                                        let entry = m.entry(peer.to_string()).or_insert((0, 0));
                                        if entry.1 >= MAX_PENDING_BLOCKS_PER_PEER {
                                            false
                                        } else {
                                            // `push` refuses a block THIS peer
                                            // already has queued — the path had
                                            // no duplicate check at all, so one
                                            // peer could fill its whole quota
                                            // with copies of one block. A copy
                                            // from another peer is a separate
                                            // entry and is kept: it is the only
                                            // copy left once this peer goes.
                                            // Charge only for what was stored.
                                            if q.push(peer, block) {
                                                entry.1 += 1;
                                            }
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
                if let Err(pe) = validate_inv_count(items.len()) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                for item in items {
                    if let Err(pe) = validate_inv_item(&item.kind, &item.hash) {
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            pe.ban_score as u64,
                            &pe.message,
                            BanCategory::Malformed,
                        );
                        return Ok(());
                    }
                }
                // Request only what we are not already holding, once each, and
                // never more than one peer could queue for us. Without the
                // filter a peer can re-announce what we already hold and make us
                // download it again; with a filter that walked the queue per
                // item, the announcement itself was the attack.
                let needed = {
                    let pending = PENDING_BLOCKS.read();
                    inv_items_to_request(items, |hash| pending.contains(hash))
                };
                if !needed.is_empty() {
                    let get_data = P2PMessage::GetData { items: needed };
                    let bytes = Self::write_message(writer, &get_data, magic)?;
                    session.record_bytes_sent(bytes);
                }
            }

            // ── GetData: validate item list and serve requested data ────
            P2PMessage::GetData { ref items } => {
                if let Err(pe) = validate_inv_count(items.len()) {
                    DOS_GUARD.add_ban_score_cat(
                        peer,
                        pe.ban_score as u64,
                        &pe.message,
                        BanCategory::Malformed,
                    );
                    return Ok(());
                }
                for item in items {
                    if let Err(pe) = validate_inv_item(&item.kind, &item.hash) {
                        DOS_GUARD.add_ban_score_cat(
                            peer,
                            pe.ban_score as u64,
                            &pe.message,
                            BanCategory::Malformed,
                        );
                        return Ok(());
                    }
                }
                // Serve requested data by forwarding to per-peer targeted queue.
                // The peer's connection thread drains targeted messages and
                // writes them to the socket, so we never touch the TcpStream
                // directly. Block serving needs block_store access, which this
                // layer lacks, so the hashes are queued for the daemon event
                // loop; TX serving needs the mempool, which it also lacks.
                //
                // Both outcomes are counted and reported once per message rather
                // than logged per item: the log macros build their event and all
                // its fields BEFORE the level is consulted, so a per-item debug
                // line is thousands of discarded allocations per message even
                // with debug logging switched off.
                let mut wanted_blocks: Vec<String> = Vec::with_capacity(items.len());
                let mut tx_requests = 0usize;
                for item in items {
                    // The validator above accepts only "block" and "tx".
                    if item.kind == "block" {
                        wanted_blocks.push(item.hash.clone());
                    } else {
                        tx_requests += 1;
                    }
                }
                if tx_requests > 0 {
                    slog_debug!("p2p", "getdata_tx_unserved", peer => peer, count => tx_requests);
                }
                push_block_requests(peer, wanted_blocks);
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
                // 2000 outbound GetBlock requests in one message. Bounded to the
                // per-peer pending-block quota: that is one full served Headers
                // range, and asking for more than we could queue from this peer
                // only guarantees the surplus is dropped and re-requested. Big
                // enough that IBD backfill isn't throttled to a crawl — a node
                // catching up a tall chain needs the served range in a few
                // round-trips, not 64 at a time (W3).
                //
                // The pending-queue filter runs ONCE, under one lock, before
                // anything is written. It used to take that lock per hash,
                // interleaved with the socket writes, and walk the whole queue
                // on each of up to 2,000 hashes.
                let requests = {
                    let pending = PENDING_BLOCKS.read();
                    blocks_to_request(hashes, MAX_PENDING_BLOCKS_PER_PEER as usize, |hash| {
                        pending.contains(hash)
                    })
                };
                for hash in requests {
                    let req = P2PMessage::GetBlock {
                        hash: hash.to_string(),
                    };
                    let bytes = Self::write_message(writer, &req, magic)?;
                    session.record_bytes_sent(bytes);
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
            // The outbound cap lives inside spawn_outbound, so this startup
            // pass needs no budget of its own.
            let _ = Self::spawn_outbound(addr, magic, known_peers.clone(), Arc::clone(&self.peers));
        }
    }

    /// Dial one peer in its own thread, tracking the live connection in
    /// CONNECTED_OUTBOUND so it is neither double-dialed nor left un-redialed.
    /// Skips peers already connected; frees the slot when the connection ends so
    /// the reconnect loop can re-dial. This is the unit of auto-reconnect.
    ///
    /// Reports whether a dial was actually started, so a caller can budget
    /// DIALS rather than candidates. This is also the one choke point for the
    /// outbound slot cap: enforcing it here covers every caller.
    fn spawn_outbound(
        addr: String,
        magic: [u8; 4],
        peers_snapshot: Vec<String>,
        peers: Arc<PeerManager>,
    ) -> bool {
        // Never dial our own IP (identified via the identity-nonce self-check).
        // The seed list contains this node's own address; without this the node
        // wastes every dial re-connecting to itself instead of to real peers.
        if is_self_addr(&addr) {
            return false;
        }
        // Anti-eclipse: keep OUTBOUND links spread across /16 subnets so an
        // attacker owning one subnet can't occupy every outbound slot and
        // control our view of the chain. Whitelisted trusted seeds are exempt
        // (a node must always be able to reach its configured seeds); the limit
        // therefore constrains only untrusted peers.
        let whitelisted = crate::service::network::dos_guard::is_whitelisted(&addr);
        if !whitelisted && outbound_subnet_would_saturate(&addr) {
            slog_debug!("p2p", "outbound_subnet_diversity_skip", addr => &addr);
            return false;
        }
        // Reserve the slot up front (atomic check-and-insert) so two callers
        // can't both dial the same peer, and refuse past the outbound budget in
        // the same critical section so the count cannot be raced.
        {
            let mut set = CONNECTED_OUTBOUND.lock();
            if set.contains(&addr) {
                return false;
            }
            if outbound_slots_full(set.len(), whitelisted) {
                slog_debug!("p2p", "outbound_slots_full", addr => &addr, in_use => set.len());
                return false;
            }
            set.insert(addr.clone());
        }
        LAST_DIAL.lock().insert(addr.clone(), Instant::now());
        thread::spawn(move || {
            // Owns the slot from here: released when this closure returns AND
            // when it unwinds, which the statement at the end could not do.
            let _slot = OutboundSlot { addr: addr.clone() };
            match connect_with_timeout(&addr) {
                Ok(stream) => {
                    slog_info!("p2p", "outbound_connected", addr => &addr);
                    if let Err(e) =
                        Self::handle_peer_connection(stream, true, magic, peers_snapshot, peers)
                    {
                        slog_info!("p2p", "peer_connection_ended", addr => &addr, reason => &e.to_string());
                    }
                }
                Err(e) => {
                    slog_warn!("p2p", "outbound_connect_failed", addr => &addr, error => &e.to_string());
                }
            }
        });
        true
    }

    /// Background maintenance: every 10s, re-dial any known peer that has no live
    /// outbound connection. Without this a node stays isolated after a restart,
    /// a dropped connection, or a transient refusal — which is exactly why forked
    /// nodes never reconverged. Runs for the life of the process.
    ///
    /// Dials are budgeted by the OUTBOUND DEFICIT, not by the size of the peer
    /// store, and the budget is spent over a ROTATING window. This loop used to
    /// call `spawn_outbound` for every stored peer on every tick — up to
    /// `MAX_STORED_PEERS` = 16,384 of them, each an OS thread parked in an untimed
    /// `connect` — while its sibling `connect_to_peers` had capped itself at
    /// `MAX_PEERS` all along. A handshaked peer fills that store with
    /// routable-looking dead addresses in about 17 `Addr` messages, and the store
    /// is RocksDB-backed, so a restart did not clear it.
    fn spawn_reconnect_loop(&self) {
        let peers = Arc::clone(&self.peers);
        let magic = self.network_magic;
        // Where the next cycle's dial window starts. Survives across cycles so
        // the front of the store cannot monopolise the budget.
        let mut cursor = 0usize;
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(10));
            let known_snapshot = peers.get_addr_list_limited(100);
            let known = peers.get_peers();

            // Seeds first, and never gated by the deficit: they bypass the
            // outbound cap, so a budget that stopped the scan before reaching
            // one would be how a node loses contact with its own seeds.
            for addr in known
                .iter()
                .filter(|a| crate::service::network::dos_guard::is_whitelisted(a))
            {
                if reconnect_due(&peers, addr) {
                    let _ = Self::spawn_outbound(
                        addr.clone(),
                        magic,
                        known_snapshot.clone(),
                        Arc::clone(&peers),
                    );
                }
            }

            // Then everyone else, up to the deficit. A slot is held from the
            // moment a dial starts, so this bounds live connections plus dials
            // in flight — and therefore dial threads — at MAX_PEERS.
            let deficit = MAX_PEERS.saturating_sub(CONNECTED_OUTBOUND.lock().len());
            let (picked, next) = dial_window(known.len(), cursor, deficit, |i| {
                reconnect_due(&peers, &known[i])
            });
            cursor = next;
            for i in picked {
                let _ = Self::spawn_outbound(
                    known[i].clone(),
                    magic,
                    known_snapshot.clone(),
                    Arc::clone(&peers),
                );
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
            sweep_targeted_expired();
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
    // ── F12: the inbound accounting must survive every exit path ──────────
    #[test]
    fn inbound_slot_releases_the_pending_count_when_the_thread_panics() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // The real leak: the old code decremented with a plain statement placed
        // AFTER handle_peer_connection returned, so an unwinding panic skipped
        // it and the slot was lost for the life of the process.
        let pending = Arc::new(AtomicUsize::new(0));
        pending.fetch_add(1, Ordering::AcqRel);
        let slot = InboundSlot::new(&pending, "203.0.113.7".to_string());
        assert_eq!(pending.load(Ordering::SeqCst), 1);

        let joined = thread::spawn(move || {
            let _slot = slot;
            panic!("connection handler blew up");
        })
        .join();
        assert!(joined.is_err(), "the thread must actually have panicked");
        assert_eq!(
            pending.load(Ordering::SeqCst),
            0,
            "a panicking connection thread must still release its pending slot"
        );
    }

    #[test]
    fn inbound_slot_releases_on_an_ordinary_early_return() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pending = Arc::new(AtomicUsize::new(0));
        pending.fetch_add(1, Ordering::AcqRel);
        {
            let _slot = InboundSlot::new(&pending, "203.0.113.8".to_string());
            assert_eq!(pending.load(Ordering::SeqCst), 1);
        }
        assert_eq!(pending.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pending_cap_never_refuses_a_whitelisted_seed() {
        // Below the cap nobody is refused.
        assert!(!pending_cap_rejects(0, false));
        assert!(!pending_cap_rejects(MAX_PENDING_CONNECTIONS - 1, false));
        // At and above it, an ordinary peer is refused...
        assert!(pending_cap_rejects(MAX_PENDING_CONNECTIONS, false));
        assert!(pending_cap_rejects(MAX_PENDING_CONNECTIONS + 10_000, false));
        // ...but a trusted seed never is. This is the property whose absence
        // left two followers unable to accept the miner for 76 days.
        assert!(!pending_cap_rejects(MAX_PENDING_CONNECTIONS, true));
        assert!(!pending_cap_rejects(usize::MAX, true));
    }

    #[test]
    fn inbound_throttle_never_refuses_a_whitelisted_seed() {
        // An ordinary peer is refused once its OWN arrivals pass the per-IP
        // budget...
        assert!(!inbound_throttle_rejects(false, MAX_INBOUND_PER_SEC, 1, 1));
        assert!(inbound_throttle_rejects(false, MAX_INBOUND_PER_SEC + 1, 1, 1));
        // ...or once its /16 does...
        assert!(!inbound_throttle_rejects(
            false,
            1,
            MAX_INBOUND_PER_SEC_PER_SUBNET,
            1
        ));
        assert!(inbound_throttle_rejects(
            false,
            1,
            MAX_INBOUND_PER_SEC_PER_SUBNET + 1,
            1
        ));
        // ...or once total arrivals pass the global backstop.
        assert!(!inbound_throttle_rejects(
            false,
            1,
            1,
            MAX_INBOUND_GLOBAL_PER_SEC
        ));
        assert!(inbound_throttle_rejects(
            false,
            1,
            1,
            MAX_INBOUND_GLOBAL_PER_SEC + 1
        ));
        // A trusted seed is refused by none of the three. This is the property
        // whose absence let 11 connects/sec from one host lock a node out of
        // its own seeds — the gate ran before the address was even resolved,
        // so it could not tell a seed from a stranger.
        assert!(!inbound_throttle_rejects(
            true,
            u32::MAX,
            u32::MAX,
            u32::MAX
        ));
        assert!(!inbound_throttle_rejects(
            true,
            MAX_INBOUND_PER_SEC + 1,
            1,
            1
        ));
    }

    #[test]
    fn one_source_cannot_spend_the_whole_inbound_budget() {
        // The budgets must widen strictly outwards, or the narrower one is
        // decorative and a single host (or /16) can starve every other peer.
        const {
            assert!(
                MAX_INBOUND_PER_SEC < MAX_INBOUND_PER_SEC_PER_SUBNET
                    && MAX_INBOUND_PER_SEC_PER_SUBNET < MAX_INBOUND_GLOBAL_PER_SEC,
                "per-IP < per-/16 < global, or a single source can exhaust the budget above it"
            )
        };
        // Walk one flooder's arrivals: it is cut off at its own budget, and
        // nothing else in the window is.
        for n in 1..=MAX_INBOUND_GLOBAL_PER_SEC {
            assert_eq!(
                inbound_throttle_rejects(false, n, n, n),
                n > MAX_INBOUND_PER_SEC,
                "arrival {} from a single source",
                n
            );
        }
        // An honest peer arriving in the same window has per_ip == 1 and is
        // still accepted, even with the global budget fully spent by others.
        // The old gate was one global counter, so the flooder's 11th arrival
        // refused this peer too.
        assert!(!inbound_throttle_rejects(
            false,
            1,
            1,
            MAX_INBOUND_GLOBAL_PER_SEC
        ));
        // And an attacker spread over one /16 is cut off by the subnet budget
        // before it can spend the global one.
        assert!(inbound_throttle_rejects(
            false,
            1,
            MAX_INBOUND_PER_SEC_PER_SUBNET + 1,
            MAX_INBOUND_PER_SEC_PER_SUBNET + 1
        ));
    }

    #[test]
    fn arrival_counting_is_per_source_and_bounded() {
        let mut arrivals: HashMap<String, u32> = HashMap::new();
        // Per source: each IP carries its own count, and the ephemeral port is
        // not part of the key, so rolling ports shares one budget.
        assert_eq!(count_arrival(&mut arrivals, "203.0.113.1"), 1);
        assert_eq!(count_arrival(&mut arrivals, "203.0.113.1"), 2);
        assert_eq!(count_arrival(&mut arrivals, "203.0.113.2"), 1);

        // The map never grows past the tracking bound, however many distinct
        // sources arrive in one window.
        for i in 0..(MAX_THROTTLE_TRACKED_IPS as u32 + 500) {
            count_arrival(&mut arrivals, &format!("198.51.{}.{}", i / 250, i % 250));
        }
        assert_eq!(
            arrivals.len(),
            MAX_THROTTLE_TRACKED_IPS,
            "the per-window map must stay bounded under an IP-rolling flood"
        );

        // A source the full table cannot track reports 0, so the global
        // backstop judges it. A full table must never be what locks an honest
        // peer out.
        let untracked = count_arrival(&mut arrivals, "192.0.2.254");
        assert_eq!(untracked, 0);
        assert!(!inbound_throttle_rejects(false, untracked, 1, 1));
    }

    #[test]
    fn puzzle_is_solved_only_where_the_protocol_asks_for_it() {
        let good = ConnectionPuzzle::generate_challenge().challenge;

        // The one legitimate case: we dialled out and have not answered yet.
        assert!(should_solve_puzzle(true, 0, &good));

        // Inbound: we are the challenger. A challenge from the peer that
        // connected TO us inverts the puzzle — it would have us pay for a
        // stranger's connection attempt.
        assert!(!should_solve_puzzle(false, 0, &good));

        // One puzzle per connection; repeats are free work for the peer.
        assert!(!should_solve_puzzle(true, 1, &good));
        assert!(!should_solve_puzzle(true, u32::MAX, &good));

        // The amplifier: `solve` hashes the whole challenge once per
        // iteration (~4096 iterations), so an oversized challenge turns one
        // message into gigabytes of SHA-256. Shape is checked before solving.
        assert!(!should_solve_puzzle(true, 0, &"a".repeat(4 * 1024 * 1024)));
        assert!(!should_solve_puzzle(true, 0, ""));
        assert!(!should_solve_puzzle(true, 0, &"0".repeat(63)));
        assert!(!should_solve_puzzle(true, 0, &"0".repeat(65)));
        assert!(!should_solve_puzzle(true, 0, &"z".repeat(64)));
    }

    use super::*;
    use crate::service::network::p2p::peer_manager::MAX_PEERS_PER_IP;

    #[test]
    fn inbound_per_ip_cap_enforced_and_released() {
        // Unique IP so this test does not race the global map with others.
        let ip = "203.0.113.77";
        // Up to the cap: each registration is within-limit.
        for _ in 0..MAX_PEERS_PER_IP {
            assert!(register_inbound_ip(ip), "within cap must be within-limit");
        }
        // The next reports OVER the cap. It still incremented (always-increment
        // semantics), so the rejecting caller releases it immediately — as the
        // accept loop does for a non-whitelisted peer.
        assert!(!register_inbound_ip(ip), "over cap must report over-limit");
        release_inbound_ip(ip);
        // Releasing a live slot lets a new connection register within the cap.
        release_inbound_ip(ip);
        assert!(register_inbound_ip(ip), "slot freed after release");
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

    // ── Sweep-3 #1: no pre-handshake read may outlive its deadline ────────

    /// A peer that hands over exactly one byte per recv, forever — the shape of
    /// the slowloris. `SO_RCVTIMEO` never fires against it, because every recv
    /// makes progress.
    struct DripReader {
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Read for DripReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            thread::sleep(Duration::from_millis(1));
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = 0x42;
            Ok(1)
        }
    }

    // ── Sweep-3 #3: the reconnect loop may not dial the whole store ──────

    #[test]
    fn the_outbound_cap_holds_dials_at_max_peers_but_never_a_seed() {
        // Below the cap nobody is refused.
        assert!(!outbound_slots_full(0, false));
        assert!(!outbound_slots_full(MAX_PEERS - 1, false));
        // At and above it an ordinary peer is refused. `in_use` counts dials
        // still in flight, so this is what bounds the THREAD count: the loop
        // used to spawn one per stored peer, up to MAX_STORED_PEERS.
        assert!(outbound_slots_full(MAX_PEERS, false));
        assert!(outbound_slots_full(usize::MAX, false));
        assert!(
            MAX_PEERS * 100
                < crate::service::network::p2p::peer_manager::MAX_STORED_PEERS as usize,
            "the cap must be far below what the store can hold, or it bounds nothing"
        );
        // A trusted seed is never refused: a node must always be able to reach
        // its configured seeds.
        assert!(!outbound_slots_full(MAX_PEERS, true));
        assert!(!outbound_slots_full(usize::MAX, true));
    }

    #[test]
    fn the_dial_window_reaches_every_stored_peer_despite_a_flooder() {
        // 300 stored addresses, 64 dials a cycle: a budgeted loop that always
        // started at the front would spend every cycle on the first 64, which
        // a peer that gossips addresses gets to choose (the store is returned
        // in lexicographic key order).
        const LEN: usize = 300;
        const DEFICIT: usize = MAX_PEERS;
        let mut cursor = 0usize;
        let mut ever: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // ceil(300/64) = 5 cycles must cover all of it.
        for _ in 0..5 {
            let (picked, next) = dial_window(LEN, cursor, DEFICIT, |_| true);
            assert_eq!(picked.len(), DEFICIT);
            for i in picked {
                ever.insert(i);
            }
            cursor = next;
        }
        assert_eq!(
            ever.len(),
            LEN,
            "every stored peer must be reached; missed {}",
            LEN - ever.len()
        );

        // Frozen at the front, the same 64 are picked forever — the starvation
        // the rotation exists to prevent.
        let mut frozen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for _ in 0..5 {
            for i in dial_window(LEN, 0, DEFICIT, |_| true).0 {
                frozen.insert(i);
            }
        }
        assert_eq!(frozen.len(), DEFICIT);
    }

    #[test]
    fn the_dial_window_is_total_and_cannot_spin() {
        // Nothing due: one pass, no picks, and the cursor still advances so the
        // next cycle looks elsewhere.
        let (picked, next) = dial_window(10, 0, 4, |_| false);
        assert!(picked.is_empty());
        assert_eq!(next, 0, "a full pass of 10 from 0 wraps back to 0");
        // Only one entry due, repeatedly picked without exhausting the walk.
        let (picked, _) = dial_window(10, 0, 4, |i| i == 7);
        assert_eq!(picked, vec![7]);
        // Degenerate inputs: an empty store, a zero budget, a cursor past the end.
        assert_eq!(dial_window(0, 5, 4, |_| true), (Vec::new(), 5));
        assert_eq!(dial_window(10, 3, 0, |_| true), (Vec::new(), 3));
        let (picked, _) = dial_window(4, 99, 2, |_| true);
        assert_eq!(picked, vec![3, 0], "a cursor past the end wraps, not panics");
    }

    // ── the targeted queue: bounded per peer, and nothing outlives its peer ──

    fn targeted_block(bytes: usize) -> P2PMessage {
        P2PMessage::Block {
            data: vec![0u8; bytes],
        }
    }

    fn targeted_ping(nonce: u64) -> P2PMessage {
        P2PMessage::Ping { nonce }
    }

    #[test]
    fn a_targeted_drain_moves_one_peers_messages_and_leaves_the_rest_alone() {
        // The drain used to walk the whole 10,000-entry queue and deep-CLONE
        // every match under the global lock — up to 2 MiB per block — although
        // the entry was removed in the same pass. Keyed by peer it is one
        // remove that moves.
        let mut q = TargetedQueue::new();
        q.push("a:1", targeted_ping(1), false);
        q.push("b:1", targeted_ping(2), false);
        q.push("a:1", targeted_ping(3), false);
        assert_eq!(q.len(), 3);

        let mine = q.take_for("a:1");
        assert_eq!(mine.len(), 2, "both of a's messages, oldest first");
        assert!(matches!(mine[0], P2PMessage::Ping { nonce: 1 }));
        assert!(matches!(mine[1], P2PMessage::Ping { nonce: 3 }));
        assert_eq!(q.len(), 1, "b's message is untouched");
        assert_eq!(q.take_for("b:1").len(), 1);
        assert_eq!(q.len(), 0);
        assert_eq!(q.bytes(), 0, "the totals must come back to zero");
    }

    #[test]
    fn one_peer_cannot_fill_the_targeted_queue_for_everyone() {
        // No per-peer cap existed, and an overflow dropped the ARRIVING
        // message — which belongs to whichever peer is behaving, not to the one
        // that filled the queue.
        let mut q = TargetedQueue::new();
        for i in 0..(MAX_TARGETED_PER_PEER + 10) {
            q.push("flooder:1", targeted_ping(i as u64), false);
        }
        assert_eq!(
            q.len(),
            MAX_TARGETED_PER_PEER,
            "one peer is held to its own share"
        );

        // A quiet peer still gets in, and keeps its message.
        q.push("quiet:1", targeted_ping(999), false);
        let mine = q.take_for("quiet:1");
        assert_eq!(mine.len(), 1, "the arriving message must not be the victim");
        assert!(matches!(mine[0], P2PMessage::Ping { nonce: 999 }));

        // And what the flooder lost was its OLDEST, not its newest.
        let flood = q.take_for("flooder:1");
        assert!(matches!(flood[0], P2PMessage::Ping { nonce: 10 }));
    }

    #[test]
    fn a_peers_targeted_bytes_are_bounded_and_one_block_always_fits() {
        // The queue had NO byte term at all, while its entries hold blocks of
        // up to MAX_BLOCK_BYTES — and nothing else in the process bounds what
        // we send: check_bandwidth counts inbound only.
        let mut q = TargetedQueue::new();
        let one_mib = 1024 * 1024;
        for _ in 0..32 {
            q.push("heavy:1", targeted_block(one_mib), false);
        }
        assert!(
            q.bytes() <= MAX_TARGETED_BYTES_PER_PEER,
            "a peer's queued bytes must stay inside its share, got {}",
            q.bytes()
        );

        // A single maximum-size block is never refused, however full we are.
        let mut q = TargetedQueue::new();
        q.push(
            "heavy:1",
            targeted_block(crate::service::network::dos_guard::MAX_BLOCK_BYTES),
            false,
        );
        assert_eq!(q.take_for("heavy:1").len(), 1);
    }

    #[test]
    fn a_global_overflow_is_charged_to_the_peer_holding_the_most() {
        let mut q = TargetedQueue::new();
        let one_mib = 1024 * 1024;
        // Fill the global byte budget with heavy peers.
        let mut peer = 0;
        while q.bytes() + one_mib <= MAX_TARGETED_BYTES {
            q.push(&format!("heavy{peer}:1"), targeted_block(one_mib), false);
            peer = (peer + 1) % 8;
        }
        let before = q.bytes();
        // A light peer arriving must get in, and the bytes must not grow past
        // the budget.
        q.push("light:1", targeted_block(one_mib), false);
        assert!(
            q.bytes() <= MAX_TARGETED_BYTES,
            "the global byte budget must hold, was {before} now {}",
            q.bytes()
        );
        assert_eq!(
            q.take_for("light:1").len(),
            1,
            "the arriving message is never the victim"
        );
    }

    #[test]
    fn an_undelivered_targeted_message_does_not_outlive_its_peer() {
        // THE TERMINAL DEFECT: the only removers are a peer's own flush and its
        // cleanup, and the daemon can enqueue for a peer AFTER its cleanup ran,
        // because the drain and the cleanup are separate critical sections. So
        // such an entry was immortal, and enough of them refuse every future
        // targeted message for the life of the process — block serving, header
        // serving and stem relay all dead.
        let mut q = TargetedQueue::new();
        q.push("ghost:51234", targeted_block(1024), false);
        q.push("ghost:51235", targeted_ping(1), false);
        assert_eq!(q.len(), 2);

        assert_eq!(
            q.sweep_expired(Duration::from_secs(3_600)),
            0,
            "a message queued moments ago is not expired"
        );
        assert_eq!(q.len(), 2);

        assert_eq!(q.sweep_expired(Duration::ZERO), 2, "both must be reaped");
        assert_eq!(q.len(), 0);
        assert_eq!(q.bytes(), 0, "and the totals with them");
        assert!(
            q.take_for("ghost:51234").is_empty(),
            "the peer's entry itself must be gone, not left empty"
        );
    }

    #[test]
    fn a_requeued_targeted_message_keeps_its_place_at_the_front() {
        // A write failure puts the message back; it must be retried BEFORE
        // whatever was queued behind it, or ordering is lost. The old requeue
        // also bypassed every cap, so the global limit was not a hard limit.
        let mut q = TargetedQueue::new();
        q.push("a:1", targeted_ping(1), false);
        q.push("a:1", targeted_ping(2), false);
        q.push("a:1", targeted_ping(9), true);
        let mine = q.take_for("a:1");
        assert!(matches!(mine[0], P2PMessage::Ping { nonce: 9 }));
        assert!(matches!(mine[1], P2PMessage::Ping { nonce: 1 }));
        assert!(matches!(mine[2], P2PMessage::Ping { nonce: 2 }));
    }

    #[test]
    fn the_payload_estimate_is_the_one_the_rate_limiter_uses() {
        // Two implementations of "how big is this message" drift, and a byte
        // budget that disagrees with the rate limiter about what a message
        // costs is worse than no budget.
        assert_eq!(payload_size_estimate(&targeted_block(4096)), 4096);
        assert_eq!(
            payload_size_estimate(&P2PMessage::Headers {
                hashes: vec!["ab".repeat(32), "cd".repeat(32)]
            }),
            128
        );
        assert!(
            payload_size_estimate(&targeted_ping(1)) > 0,
            "a fixed-size message still costs something"
        );
    }

    // ── #5: the pending-block queue is tested, not walked ─────────────────

    fn pending_test_block(hash: &str) -> Block {
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                Vec::new(),
                String::new(),
                0,
                0,
                1,
                0,
            ),
            body: BlockBody {
                transactions: Vec::new(),
            },
        }
    }

    fn assert_index_matches_queue(q: &PendingBlocks) {
        let counted: u32 = q.hashes.values().sum();
        assert_eq!(
            q.queue.len() as u32,
            counted,
            "the hash counts drifted from the queue"
        );
        let owned_pairs: usize = q.owned.values().map(|h| h.len()).sum();
        assert_eq!(
            owned_pairs,
            q.queue.len(),
            "the per-peer ownership drifted from the queue"
        );
        for (peer, b) in &q.queue {
            assert!(
                q.contains(&b.header.hash),
                "a queued hash is missing from the counts: {}",
                b.header.hash
            );
            assert!(
                q.owns(peer, &b.header.hash),
                "a queued entry is missing from its peer's ownership: {peer}"
            );
        }
    }

    #[test]
    fn the_pending_block_index_matches_the_queue_through_every_mutation() {
        // The index is only trustworthy if it cannot drift, so drive every
        // mutation the queue has and check the two halves after each one. A
        // phantom entry would make us refuse to request that block ever again.
        let mut q = PendingBlocks::new();

        assert!(q.push("peer_a", pending_test_block("aa")));
        assert!(q.push("peer_b", pending_test_block("bb")));
        assert_eq!(q.len(), 2);
        assert_index_matches_queue(&q);

        assert!(
            !q.push("peer_a", pending_test_block("aa")),
            "the SAME peer sending it twice is refused, so no quota is charged"
        );
        assert_eq!(q.len(), 2);
        assert_index_matches_queue(&q);

        assert!(
            q.push("peer_c", pending_test_block("aa")),
            "ANOTHER peer's copy is its own entry: it is the only copy left \
             once peer_a disconnects"
        );
        assert_eq!(q.len(), 3);
        assert_index_matches_queue(&q);

        q.prepend(vec![("peer_d".to_string(), pending_test_block("cc"))]);
        assert_eq!(
            q.queue[0].1.header.hash, "cc",
            "requeued work goes to the front"
        );
        assert_index_matches_queue(&q);

        assert_eq!(q.retain_other_peers("peer_a"), 1);
        assert!(
            q.contains("aa"),
            "peer_c's copy must survive peer_a leaving"
        );
        assert!(q.contains("bb") && q.contains("cc"));
        assert_index_matches_queue(&q);

        assert_eq!(q.retain_other_peers("peer_c"), 1);
        assert!(
            !q.contains("aa"),
            "and with the last copy gone the hash leaves the index"
        );
        assert_index_matches_queue(&q);

        let taken = q.take();
        assert_eq!(taken.len(), 2);
        assert_eq!(q.len(), 0);
        assert!(!q.contains("bb"), "the indexes must empty with the queue");
        assert_index_matches_queue(&q);
    }

    #[test]
    fn a_block_survives_the_disconnect_of_the_peer_that_delivered_it_first() {
        // The regression that keys the dedup per peer. The entry's peer is also
        // what `retain_other_peers` deletes by, so deduplicating on the hash
        // alone made the FIRST deliverer's disconnect destroy the only copy of a
        // block that several peers had handed us — and closing a socket costs a
        // peer nothing and accrues no ban score.
        let mut q = PendingBlocks::new();
        assert!(q.push("first:1", pending_test_block("ab")));
        assert!(q.push("second:2", pending_test_block("ab")));
        assert!(q.push("third:3", pending_test_block("ab")));
        assert_eq!(q.len(), 3, "one entry per peer that delivered it");

        assert_eq!(q.retain_other_peers("first:1"), 1);
        assert!(q.contains("ab"), "two copies still remain");
        assert_eq!(q.retain_other_peers("second:2"), 1);
        assert!(q.contains("ab"), "one copy still remains");
        assert_eq!(q.retain_other_peers("third:3"), 1);
        assert!(!q.contains("ab"), "and only now is the block gone");
        assert_index_matches_queue(&q);
    }

    #[test]
    fn one_peer_cannot_fill_its_quota_with_copies_of_one_block() {
        // What the dedup is actually for: the network path had no duplicate
        // check at all, so one peer could spend its whole 512-slot quota on
        // copies of a single block.
        let mut q = PendingBlocks::new();
        assert!(q.push("flooder:9", pending_test_block("cd")));
        for _ in 0..16 {
            assert!(
                !q.push("flooder:9", pending_test_block("cd")),
                "a repeat from the same peer is refused, and charges no quota"
            );
        }
        assert_eq!(q.len(), 1);
        assert_index_matches_queue(&q);
    }

    #[test]
    fn a_requeue_offers_only_blocks_the_queue_can_really_store() {
        let mut q = PendingBlocks::new();
        assert!(q.push("peer_a", pending_test_block("aa")));

        // peer_a's own copy of "aa" is in the queue already, and peer_x offers
        // "bb" twice inside one batch. peer_x's copy of "aa" is NOT a
        // duplicate: it is a separate entry, and the only one left if peer_a
        // disconnects before the drain.
        let batch = vec![
            ("peer_a".to_string(), pending_test_block("aa")),
            ("peer_x".to_string(), pending_test_block("aa")),
            ("peer_x".to_string(), pending_test_block("bb")),
            ("peer_x".to_string(), pending_test_block("bb")),
        ];
        let (admitted, dropped) = q.admissible_for_requeue(batch, 8);
        assert_eq!(
            admitted
                .iter()
                .map(|(p, b)| (p.as_str(), b.header.hash.as_str()))
                .collect::<Vec<_>>(),
            vec![("peer_x", "aa"), ("peer_x", "bb")],
            "only what will really be stored may be admitted — the caller \
             charges a per-peer count for exactly this list"
        );
        assert_eq!(dropped, 2);

        // Space left is honoured before anything else.
        let (admitted, dropped) = q.admissible_for_requeue(
            vec![
                ("peer_x".to_string(), pending_test_block("dd")),
                ("peer_x".to_string(), pending_test_block("ee")),
            ],
            1,
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(dropped, 1);

        // And what was admitted really does go in, index included.
        q.prepend(admitted);
        assert!(q.contains("dd"));
        assert_index_matches_queue(&q);
    }

    #[test]
    fn an_announcement_is_requested_once_each_and_only_for_what_is_not_queued() {
        let inv = |kind: &str, hash: &str| InvItem {
            kind: kind.to_string(),
            hash: hash.to_string(),
        };
        let items = vec![
            inv("block", "aa"),
            inv("block", "aa"),
            inv("block", "queued"),
            inv("tx", "bb"),
            inv("block", "cc"),
        ];
        let got = inv_items_to_request(&items, |h| h == "queued");
        assert_eq!(
            got.iter()
                .map(|i| (i.kind.as_str(), i.hash.as_str()))
                .collect::<Vec<_>>(),
            vec![("block", "aa"), ("tx", "bb"), ("block", "cc")],
            "order kept, each hash asked for once, queued hashes skipped"
        );
    }

    #[test]
    fn a_repeated_hash_is_tested_against_the_shared_queue_once() {
        // The membership test is the one thing that touches the shared queue
        // under its lock, so the repeat filter has to run FIRST: an
        // announcement of 500 copies of one hash must cost one lookup there.
        let items: Vec<InvItem> = (0..500)
            .map(|_| InvItem {
                kind: "block".to_string(),
                hash: "ab".repeat(32),
            })
            .collect();
        let lookups = std::cell::Cell::new(0usize);
        let got = inv_items_to_request(&items, |_| {
            lookups.set(lookups.get() + 1);
            false
        });
        assert_eq!(got.len(), 1, "500 copies of one hash is one request");
        assert_eq!(lookups.get(), 1, "and one test against the pending queue");
    }

    #[test]
    fn an_announcement_cannot_ask_for_more_than_one_peer_could_queue() {
        assert!(
            MAX_INV_ITEMS_REQUESTED <= MAX_PENDING_BLOCKS_PER_PEER as usize
                && MAX_INV_ITEMS_REQUESTED <= MAX_PENDING_TXS_PER_PEER as usize,
            "the cap must not exceed either per-peer quota, or the surplus is \
             dropped on arrival and re-requested for nothing"
        );
        let items: Vec<InvItem> = (0..MAX_INV_PER_MSG)
            .map(|i| InvItem {
                kind: "block".to_string(),
                hash: format!("{:064x}", i),
            })
            .collect();
        let got = inv_items_to_request(&items, |_| false);
        assert_eq!(
            got.len(),
            MAX_INV_ITEMS_REQUESTED,
            "a full wire-sized announcement is bounded, not answered in full"
        );
    }

    #[test]
    fn a_headers_reply_becomes_bounded_deduplicated_block_requests() {
        let hashes: Vec<String> = vec![
            "aa".into(),
            String::new(),
            "aa".into(),
            "queued".into(),
            "bb".into(),
            "cc".into(),
        ];
        assert_eq!(
            blocks_to_request(&hashes, 2, |h| h == "queued"),
            vec!["aa", "bb"],
            "empties, repeats and queued hashes drop out, and the limit binds"
        );
        assert_eq!(
            blocks_to_request(&hashes, 64, |_| false),
            vec!["aa", "queued", "bb", "cc"],
            "with nothing queued, every distinct hash is requested once"
        );
        assert!(
            blocks_to_request(&hashes, 0, |_| false).is_empty(),
            "a zero limit requests nothing rather than spinning"
        );
    }

    // ── #4: the outbound cursor is owned, and holds one lock at a time ─────

    #[test]
    fn an_outbound_cursor_is_seeded_once_and_released_on_drop() {
        // The map is a process global and the suite runs in parallel, so every
        // assertion here is about this one key.
        let peer = "203.0.113.41:11001";
        {
            let _cursor = OutboundCursor::seed(peer, 77);
            assert_eq!(
                PEER_LAST_OUTBOUND.lock().get(peer).copied(),
                Some(77),
                "the cursor must start at the sequence it was handed"
            );
            // Seeding again must leave a live cursor alone: overwriting it
            // either rewinds a connected peer and re-sends what it already has,
            // or jumps it forward and drops what it has not.
            let _again = OutboundCursor::seed(peer, 5);
            assert_eq!(PEER_LAST_OUTBOUND.lock().get(peer).copied(), Some(77));
        }
        assert!(
            !PEER_LAST_OUTBOUND.lock().contains_key(peer),
            "the cursor must not outlive the connection that seeded it"
        );
    }

    #[test]
    fn an_outbound_cursor_is_released_even_when_the_peer_thread_panics() {
        // The leak: the only remover ran after the main loop, so an unwinding
        // panic — or any of the sixteen early returns before the loop — left
        // the entry behind for the life of the process, pinning the broadcast
        // queue's pruning cursor with it.
        let peer = "203.0.113.42:11002".to_string();
        let moved = peer.clone();
        let joined = thread::spawn(move || {
            let _cursor = OutboundCursor::seed(&moved, 9);
            assert!(PEER_LAST_OUTBOUND.lock().contains_key(&moved));
            panic!("handshake blew up");
        })
        .join();
        assert!(joined.is_err(), "the thread must have panicked");
        assert!(
            !PEER_LAST_OUTBOUND.lock().contains_key(&peer),
            "a panicking peer thread must still hand the cursor back"
        );
    }

    #[test]
    fn neither_side_of_the_cursor_inversion_holds_one_lock_to_wait_on_the_other() {
        // The inversion: seeding a cursor read the broadcast queue's sequence
        // from INSIDE the cursor lock (cursors -> queue), while the drain held
        // the queue and then took the cursor map (queue -> cursors). Two
        // parking_lot mutexes with no timeout: when the two met, the accept
        // path, every peer's flush and the daemon's own push_outbound wedged
        // together until a restart.
        //
        // Both halves are checked HERE, in sequence, and deliberately not as
        // two tests: each half holds exactly what the other waits for, so run
        // in parallel they would starve each other and whichever polled would
        // lose.

        // Half one: with the queue held by someone else, seeding must still
        // finish — it is handed the sequence instead of reading it.
        {
            let queue = OUTBOUND_MSGS.lock();
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = thread::spawn(move || {
                let cursor = OutboundCursor::seed("203.0.113.43:11003", 3);
                let _ = tx.send(());
                drop(cursor);
            });
            let seeded = rx.recv_timeout(Duration::from_secs(5));
            // Released before the join, so a regression fails this test rather
            // than hanging the suite.
            drop(queue);
            handle.join().expect("the seeding thread must not panic");
            assert!(
                seeded.is_ok(),
                "seeding a cursor blocked while the broadcast queue was held"
            );
        }

        // Half two: with the cursor map held, a drain must be waiting on the
        // CURSORS and not sitting on the queue — so the queue is observably
        // free. The ready signal only narrows the start-up window, so a
        // regression could still slip through as a pass on a loaded machine;
        // that is the safe direction, and it never goes red spuriously.
        let cursors = PEER_LAST_OUTBOUND.lock();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = ready_tx.send(());
            drain_outbound_since(0)
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the drain thread must start");
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut queue_was_free = false;
        while Instant::now() < deadline {
            if OUTBOUND_MSGS.try_lock().is_some() {
                queue_was_free = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        drop(cursors);
        let _ = handle.join();
        assert!(
            queue_was_free,
            "the broadcast queue stayed locked while the drain waited on cursors"
        );
    }

    #[test]
    fn the_prune_cutoff_takes_the_later_of_the_acks_and_the_hard_retain() {
        // Nothing connected: nothing has been consumed, and a young queue is
        // inside the hard window, so nothing is pruned.
        assert_eq!(prune_cutoff(None, 10), 0);
        // Every peer has consumed up to 5 and the queue is young: prune to 5.
        assert_eq!(prune_cutoff(Some(5), 10), 5);
        // A cursor pinned low — by a leaked entry, or a retained laggard — must
        // not freeze pruning: the hard retain takes over. This is the backstop
        // that kept the leak from being an unbounded QUEUE as well as an
        // unbounded map.
        assert_eq!(prune_cutoff(Some(5), 10_000), 10_000 - 4_096);
        // A fleet that is ahead of the hard window prunes by the acks.
        assert_eq!(prune_cutoff(Some(9_000), 10_000), 9_000);
    }

    #[test]
    fn an_outbound_slot_is_released_even_when_the_dial_thread_panics() {
        // The slot is reserved BEFORE the dial thread starts and used to be
        // released by a plain statement at the end, so an unwinding panic kept
        // the address marked connected forever. Harmless while dials were
        // unbounded; with the cap above it is a lockout.
        let addr = "203.0.113.151:19333".to_string();
        CONNECTED_OUTBOUND.lock().insert(addr.clone());
        assert!(CONNECTED_OUTBOUND.lock().contains(&addr));

        let moved = addr.clone();
        let joined = thread::spawn(move || {
            let _slot = OutboundSlot { addr: moved };
            panic!("connect blew up");
        })
        .join();
        assert!(joined.is_err(), "the thread must actually have panicked");
        assert!(
            !CONNECTED_OUTBOUND.lock().contains(&addr),
            "a panicking dial thread must still release its outbound slot"
        );
    }

    #[test]
    fn an_outbound_slot_is_released_on_an_ordinary_return() {
        let addr = "203.0.113.152:19333".to_string();
        CONNECTED_OUTBOUND.lock().insert(addr.clone());
        {
            let _slot = OutboundSlot { addr: addr.clone() };
            assert!(CONNECTED_OUTBOUND.lock().contains(&addr));
        }
        assert!(!CONNECTED_OUTBOUND.lock().contains(&addr));
    }

    #[test]
    fn a_bounded_dial_resolves_a_stored_address_and_rejects_garbage() {
        // The happy path: every stored address is "ip:port" (is_routable_peer_addr
        // requires it), so this resolves with no DNS and connects.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
        let target = listener.local_addr().expect("local addr").to_string();
        let stream = connect_with_timeout(&target).expect("a bounded dial must still connect");
        assert_eq!(
            stream.peer_addr().expect("peer addr").to_string(),
            target
        );

        // An address that cannot even be parsed fails immediately, without a
        // DNS lookup and without waiting out the connect timeout.
        let err = connect_with_timeout("not-an-address").expect_err("must not resolve");
        assert!(
            !err.to_string().is_empty(),
            "the unresolvable arm must report why"
        );

        // The timeout really does reach `connect_timeout`: it rejects a zero
        // duration, so an unbounded `connect` would have SUCCEEDED here against
        // the live listener above. This is the only thing that distinguishes a
        // bounded dial from an unbounded one without waiting out a real
        // SYN-retry window.
        assert!(
            connect_within(&target, Duration::ZERO).is_err(),
            "the timeout must be passed through to connect_timeout"
        );
    }

    // ── Sweep-3 #2: one peer may not own the header-serve queue ──────────

    #[test]
    fn header_requests_are_quotaed_per_peer_but_never_for_a_seed() {
        // Below the quota nobody is refused.
        assert!(!header_request_rejects(false, 0, 0));
        assert!(!header_request_rejects(
            false,
            MAX_HEADER_REQUESTS_PER_IP - 1,
            0
        ));
        // At the quota an ordinary peer is refused...
        assert!(header_request_rejects(false, MAX_HEADER_REQUESTS_PER_IP, 0));
        assert!(header_request_rejects(false, usize::MAX, 0));
        // ...but a trusted seed catching up is not.
        assert!(!header_request_rejects(true, usize::MAX, 0));
        // The global cap, however, binds EVERYONE including a seed: it bounds
        // our own memory, and a refusal here only delays that peer's next sync
        // round — it cannot lock anyone out the way an accept gate can.
        assert!(header_request_rejects(true, 0, MAX_HEADER_REQUEST_QUEUE));
        assert!(header_request_rejects(false, 0, MAX_HEADER_REQUEST_QUEUE));
        assert!(!header_request_rejects(
            true,
            0,
            MAX_HEADER_REQUEST_QUEUE - 1
        ));
        // Strangers are refused at the stranger cap, leaving the rest for
        // seeds. One cap for everyone let a sustained flood refuse the fleet's
        // own seeds at push time.
        assert!(header_request_rejects(false, 0, HEADER_QUEUE_STRANGER_CAP));
        assert!(!header_request_rejects(true, 0, HEADER_QUEUE_STRANGER_CAP));
        const {
            assert!(
                HEADER_QUEUE_STRANGER_CAP < MAX_HEADER_REQUEST_QUEUE,
                "no capacity is reserved for seeds"
            )
        };

        // The quota must never clip an honest peer's startup tip sweep:
        // request_headers_sync asks once per published DAG tip and that list is
        // truncated to MAX_PARENTS, so a tighter quota drops most of a sweep
        // whose whole purpose is not missing DAG branches. Compile-time, so
        // lowering either constant fails the build rather than a test run.
        const {
            assert!(
                MAX_HEADER_REQUESTS_PER_IP
                    >= crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS,
                "the header-request quota would clip the per-tip sync sweep"
            )
        };
    }

    #[test]
    fn one_peer_cannot_fill_the_block_queue_and_a_seed_keeps_its_room() {
        // Uses the real globals, so it owns the block-request queue for its
        // duration: it is the only test that touches PENDING_BLOCK_REQUESTS.
        let flooder = "203.0.113.61:40001";
        // Same host, another socket: the share is per IP, so this shares the
        // flooder's rather than doubling it.
        let flooder_second_socket = "203.0.113.61:40002";
        let honest = "198.51.100.62:40002";
        let _ = drain_block_requests(); // start from a known-empty queue

        // One legal GetData carries up to MAX_INV_PER_MSG hashes, which used to
        // fill all 5,000 entries by itself.
        let flood: Vec<String> = (0..MAX_INV_PER_MSG).map(|i| format!("{:064x}", i)).collect();
        push_block_requests(flooder, flood);
        let more: Vec<String> = (0..MAX_BLOCK_REQUESTS_PER_IP)
            .map(|i| format!("{:064x}", i + MAX_INV_PER_MSG))
            .collect();
        push_block_requests(flooder_second_socket, more);
        // An honest peer asking afterwards must still be queued.
        push_block_request(honest, &format!("{:064x}", 999_999));

        let queued = drain_block_requests();
        let flooder_queued = queued
            .iter()
            .filter(|(p, _)| p == flooder || p == flooder_second_socket)
            .count();
        let honest_queued = queued.iter().filter(|(p, _)| p == honest).count();
        assert_eq!(
            flooder_queued, MAX_BLOCK_REQUESTS_PER_IP,
            "one HOST must hold at most its share across all of its sockets"
        );
        assert_eq!(
            honest_queued, 1,
            "and a peer asking after the flood must still get in"
        );
        assert!(
            queued.len() < MAX_BLOCK_REQUEST_QUEUE,
            "the queue must not have been filled at all"
        );

        // The share is per drain WINDOW, so the drain above must have reopened
        // it: a counter that outlived the requests it counted would lock the
        // flooder out for ever, which is the stale-counter failure the header
        // queue avoids by clearing the map wholesale.
        push_block_request(flooder, &format!("{:064x}", 1_000_000));
        let after = drain_block_requests();
        assert_eq!(
            after.iter().filter(|(p, _)| p == flooder).count(),
            1,
            "the per-host share must reopen once the queue is drained"
        );
    }

    #[test]
    fn a_spent_block_serve_budget_defers_the_remainder_instead_of_dropping_it() {
        // The defect this fixes: the un-served remainder of a pass was a local
        // Vec that simply went out of scope. The requester has no in-flight
        // ledger and no retry for an unanswered GetBlock, so a dropped request
        // is only re-asked on its next GetHeaders round — which turned a
        // per-pass budget into a hard ceiling on sync throughput.
        let peer = "203.0.113.71:40001";
        let _ = drain_block_requests();

        push_block_requests(
            peer,
            (0..4).map(|i| format!("{:064x}", i)).collect::<Vec<_>>(),
        );
        let taken = drain_block_requests();
        assert_eq!(taken.len(), 4);

        // A pass serves the first two and defers the rest.
        let deferred: Vec<(String, String)> = taken[2..].to_vec();
        // New work arrives before the requeue, as it would in the live loop.
        push_block_request(peer, &format!("{:064x}", 99));
        requeue_block_requests(deferred);

        let next = drain_block_requests();
        assert_eq!(next.len(), 3, "nothing may be lost");
        assert_eq!(
            next[0].1,
            format!("{:064x}", 2),
            "deferred work must come back at the FRONT, or it starves behind \
             whatever arrived while the pass was running"
        );
        assert_eq!(next[1].1, format!("{:064x}", 3));

        // And the deferred requests are charged to the new window, so being
        // deferred cannot let a host hold more than its share.
        let _ = drain_block_requests();
        push_block_requests(
            peer,
            (0..MAX_BLOCK_REQUESTS_PER_IP)
                .map(|i| format!("{:064x}", i))
                .collect::<Vec<_>>(),
        );
        let full = drain_block_requests();
        requeue_block_requests(full);
        push_block_request(peer, &format!("{:064x}", 123_456));
        let after = drain_block_requests();
        assert_eq!(
            after.len(),
            MAX_BLOCK_REQUESTS_PER_IP,
            "a deferred host is still held to its share in the new window"
        );
    }

    #[test]
    fn the_block_queue_reserves_room_only_a_seed_can_reach() {
        // A stranger is cut off at the stranger cap; a whitelisted seed is
        // bounded only by the global cap. Counted, never refused.
        assert!(!block_request_rejects(false, 0, 0));
        assert!(block_request_rejects(
            false,
            MAX_BLOCK_REQUESTS_PER_IP,
            0
        ));
        assert!(block_request_rejects(false, 0, BLOCK_QUEUE_STRANGER_CAP));
        assert!(
            !block_request_rejects(true, MAX_BLOCK_REQUESTS_PER_IP * 9, BLOCK_QUEUE_STRANGER_CAP),
            "a seed is past both stranger bounds and must still be accepted"
        );
        assert!(
            block_request_rejects(true, 0, MAX_BLOCK_REQUEST_QUEUE),
            "but not past the global cap"
        );
        const {
            assert!(
                BLOCK_QUEUE_STRANGER_CAP < MAX_BLOCK_REQUEST_QUEUE,
                "there must be room a stranger cannot take"
            )
        };
    }

    #[test]
    fn one_peer_cannot_fill_the_header_queue_and_the_window_reopens() {
        // Uses the real globals, so it owns the queue for its duration: it is
        // the only test that touches PENDING_HEADER_REQUESTS.
        let flooder = "203.0.113.41:40001";
        // Same host, another socket: the quota is per IP, so this shares the
        // flooder's share instead of doubling it.
        let flooder_second_socket = "203.0.113.41:40002";
        let honest = "198.51.100.42:40002";
        let _ = drain_header_requests(); // start from a known-empty queue

        // The flooder asks far past its quota. At the guard's 800 tok/s it can
        // really do this; the old code accepted 2,000 of them.
        for i in 0..(MAX_HEADER_REQUESTS_PER_IP * 4) {
            push_header_request(flooder, &format!("{:064x}", i), 512);
        }
        // Opening a second connection from the same host must not buy a second
        // share — the port is the attacker's to choose.
        for i in 0..MAX_HEADER_REQUESTS_PER_IP {
            push_header_request(flooder_second_socket, &format!("{:064x}", i), 512);
        }
        // An honest peer asking once afterwards must still be queued.
        push_header_request(honest, &format!("{:064x}", 999), 512);

        let queued = drain_header_requests();
        let flooder_queued = queued
            .iter()
            .filter(|(p, _, _)| p == flooder || p == flooder_second_socket)
            .count();
        let honest_queued = queued.iter().filter(|(p, _, _)| p == honest).count();
        assert_eq!(
            flooder_queued, MAX_HEADER_REQUESTS_PER_IP,
            "one HOST must hold at most its quota across all its sockets"
        );
        assert_eq!(
            honest_queued, 1,
            "the honest peer's request must survive the flood"
        );

        // The drain opened a new window: the same peer may ask again. Without
        // the clear, a flooder would be locked out of header sync for the life
        // of the process.
        push_header_request(flooder, &format!("{:064x}", 1234), 512);
        let after = drain_header_requests();
        assert_eq!(
            after.len(),
            1,
            "the per-peer window must reopen on every drain"
        );
    }

    #[test]
    fn a_drip_cannot_outlive_the_pre_handshake_deadline() {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Instant::now();
        let mut reader = BufReader::new(DeadlineReader::new(
            DripReader {
                reads: Arc::clone(&reads),
            },
            started + Duration::from_millis(50),
        ));

        // 4 KiB at one byte per millisecond is over four seconds of looping,
        // and the real drip can hold the loop for as long as it likes:
        // read_exact fails only when ONE recv returns nothing.
        let mut buf = [0u8; 4096];
        let err = reader
            .read_exact(&mut buf)
            .expect_err("the deadline must end the read");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), DEADLINE_ERROR_TEXT);
        // Evidence that the DEADLINE ended this, and not something else.
        // Deliberately not a count of recvs per unit time: the drip sleeps 1 ms
        // but Windows' timer granularity is ~15.6 ms, and under the full suite's
        // parallelism a 50 ms budget fits as few as 8 recvs.
        let recvs = reads.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            recvs >= 2,
            "the loop must have iterated, not failed on its first recv"
        );
        assert!(
            recvs < buf.len(),
            "{} recvs for {} bytes — the read COMPLETED, so no deadline was needed",
            recvs,
            buf.len()
        );
        // Loose upper bound on wall clock: reading the whole buffer at one
        // sleeping byte per recv takes seconds, so this also cannot have run to
        // completion.
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the read must end at the deadline, not after the whole 4 KiB: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_disarmed_reader_lets_a_slow_honest_read_finish() {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut reader = BufReader::new(DeadlineReader::new(
            DripReader {
                reads: Arc::clone(&reads),
            },
            Instant::now(), // already spent
        ));
        let mut one = [0u8; 1];
        assert!(
            reader.read_exact(&mut one).is_err(),
            "a spent deadline must refuse to read at all"
        );

        // Disarmed, the same drip completes. This is what keeps an established
        // follower's slow bulk transfer alive during IBD.
        reader.get_mut().disarm();
        let mut buf = [0u8; 16];
        reader
            .read_exact(&mut buf)
            .expect("a disarmed reader must not time out");
        assert!(buf.iter().all(|b| *b == 0x42));
    }

    #[test]
    fn the_deadline_error_is_fatal_not_an_idle_poll() {
        // The classifier decides whether the connection loop keeps waiting or
        // ends. A spent deadline must land on "ends" — classified as transient
        // it would spin the loop on an error that can never clear.
        let deadline_err =
            std::io::Error::new(std::io::ErrorKind::TimedOut, DEADLINE_ERROR_TEXT);
        let wrapped = NetworkError::ConnectionFailed(deadline_err.to_string());
        assert!(!is_transient_read_timeout(&wrapped.to_string().to_lowercase()));

        // ...and every real idle-poll expiry must still be transient, or the
        // node drops every peer every 100 ms. The last two are Windows'
        // WSAETIMEDOUT text, which that platform returns for an SO_RCVTIMEO
        // expiry instead of EWOULDBLOCK.
        for m in [
            "resource temporarily unavailable (os error 11)",
            "operation timed out",
            "a non-blocking socket operation could not be completed immediately (os error 10035)",
            "the semaphore timeout period has expired. (os error 10060)",
            "a connection attempt failed because the connected party did not properly respond",
        ] {
            assert!(is_transient_read_timeout(m), "must stay transient: {}", m);
        }
    }

    #[test]
    fn an_unhandshaked_peer_cannot_reach_the_bulk_payload_bound() {
        use crate::service::network::p2p::protocol::payload_size_bounds;
        // The widest payload any command allowed before the handshake may
        // declare: Version, 1 KiB plus bincode's 4-byte enum tag.
        const MAX_PRE_HANDSHAKE_PAYLOAD: usize = 1028;

        let fresh = ProtocolSession::new(false, DEFAULT_BPS);
        assert!(!fresh.is_established());

        let mut refused = 0usize;
        let mut widest = 0usize;
        for b in 0u8..=u8::MAX {
            let Some(cmd) = CommandId::from_byte(b) else {
                continue;
            };
            if fresh.check_command_allowed(cmd).is_err() {
                refused += 1;
                continue;
            }
            widest = widest.max(payload_size_bounds(cmd).1);
        }

        assert_eq!(
            widest, MAX_PRE_HANDSHAKE_PAYLOAD,
            "a command allowed before the handshake moved the pre-handshake \
             allocation ceiling"
        );
        // Not vacuous: the bulk commands are the ones refused, and the ceiling
        // is three orders of magnitude under what one of them could declare.
        assert!(fresh.check_command_allowed(CommandId::Block).is_err());
        assert!(fresh.check_command_allowed(CommandId::Tx).is_err());
        assert!(fresh.check_command_allowed(CommandId::ShadowTx).is_err());
        assert!(refused >= 10, "only {} commands refused", refused);
        assert!(widest * 1_000 < MAX_MESSAGE_SIZE);
        // ...while the handshake's own commands still pass, so an honest peer
        // can complete it.
        assert!(fresh.check_command_allowed(CommandId::PuzzleSolution).is_ok());
        assert!(fresh.check_command_allowed(CommandId::Version).is_ok());
    }
}
