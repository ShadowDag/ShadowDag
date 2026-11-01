// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
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
    DEFAULT_BPS, HANDSHAKE_TIMEOUT_SECS, MAX_ADDR_PER_MSG, MAX_INV_PER_MSG, MAX_MESSAGE_SIZE,
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
/// Max concurrent inbound connections — pre-handshake AND established.
///
/// Named for the pre-handshake pool it was long believed to bound, which it is
/// not: the `InboundSlot` holding one of these is moved into the connection's
/// own thread and dropped only when `handle_peer_connection` returns, so the
/// count falls when the CONNECTION ends, not when its handshake completes.
/// Nothing else bounds established inbound connections — there is no inbound
/// analogue of `MAX_PEERS`, which caps the outbound dial set — so this single
/// constant is the entire inbound capacity, and the 76-day lockout was that
/// capacity leaking, not a pending pool's.
const MAX_PENDING_CONNECTIONS: usize = 64;
/// Max inbound arrivals per second from one /16 subnet. The per-IP budget alone
/// is bypassed by an attacker who owns a whole /16 — every address passes its
/// own budget — which is the same bypass that puts `MAX_INBOUND_PER_SUBNET`
/// beside `MAX_PEERS_PER_IP` for live connections. Three attempts per second per
/// live slot the subnet is allowed to hold.
const MAX_INBOUND_PER_SEC_PER_SUBNET: u32 = MAX_INBOUND_PER_SUBNET * 3;
/// Backstop on TOTAL inbound arrivals per second, so a flood spread across many
/// subnets still cannot spin the accept thread without bound. Tied to
/// `MAX_PENDING_CONNECTIONS`: the whole inbound population may be asked to turn
/// over at most once per second.
const MAX_INBOUND_GLOBAL_PER_SEC: u32 = MAX_PENDING_CONNECTIONS as u32;

/// The three arrival budgets must widen strictly outwards, or the narrower one
/// is decorative and a single host (or /16) can starve every other peer.
///
/// This bound was asserted inside a `#[test]` body, so it held for `cargo test`
/// and bound nothing in a release build of the daemon: re-deriving either end —
/// `MAX_INBOUND_GLOBAL_PER_SEC` takes its value from a constant whose name says
/// "pending", and `MAX_INBOUND_PER_SEC_PER_SUBNET` from one that says "subnet" —
/// could invert the order and still ship.
const _: () = assert!(
    MAX_INBOUND_PER_SEC < MAX_INBOUND_PER_SEC_PER_SUBNET
        && MAX_INBOUND_PER_SEC_PER_SUBNET < MAX_INBOUND_GLOBAL_PER_SEC,
    "per-IP < per-/16 < global, or a single source can exhaust the budget above it"
);
/// Distinct keys (source IPs, and separately /16s) tracked within one throttle
/// window, bounding each per-window map against a flood that rolls addresses.
const MAX_THROTTLE_TRACKED_IPS: usize = 4_096;
const ACCEPTOR_PUZZLE_STEP: Duration = Duration::from_secs(4);
const DIALER_PUZZLE_STEP: Duration = Duration::from_secs(8);
const VERSION_EXCHANGE_DEADLINE: Duration = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1);
const _: () = assert!(
    ACCEPTOR_PUZZLE_STEP.as_secs() < HANDSHAKE_TIMEOUT_SECS
        && DIALER_PUZZLE_STEP.as_secs() < HANDSHAKE_TIMEOUT_SECS,
    "the puzzle step must leave time for the Version exchange"
);

#[derive(Clone, Copy)]
struct HandshakeBudget {
    puzzle_step: Duration,
    version_exchange: Duration,
}

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
/// Addresses one connection may have us PROCESS before it has to wait, and the
/// rate at which the allowance comes back.
///
/// Bitcoin Core's numbers: MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000 and
/// MAX_ADDR_RATE_PER_SECOND = 0.1 — a thousand addresses at once, then one
/// every ten seconds. There was no bound on PROCESSING here at all: COST_ADDR
/// is ONE token for a message carrying MAX_ADDR_PER_MSG = 1,000 addresses, so
/// at BUCKET_REFILL_RATE a peer could offer eight hundred thousand addresses a
/// second — each one a routability parse, and past the queue a RocksDB write
/// under the peer store's global mutex. Cheap in and expensive out is the shape
/// that produced the GetHeaders amplifier and the puzzle amplifier.
///
/// The allowance is per CONNECTION, as it is upstream, not per host: a
/// reconnect resets the burst, and what bounds THAT is the arrival throttle and
/// MAX_PEERS_PER_IP, not this. Keeping it in the session also means it cannot
/// leak — it dies with the connection, where a global map would need a cap and
/// a sweep of its own.
const ADDR_TOKEN_BURST: usize = 1_000;
const ADDR_TOKENS_PER_SEC: f64 = 0.1;
const _: () = assert!(
    ADDR_TOKEN_BURST >= MAX_ADDR_PER_MSG,
    "one full Addr message must fit the burst, or an honest peer's first reply is clipped"
);

/// Addresses waiting for the daemon to feed them to the peer store. Was an
/// unnamed literal beside the push that enforced it.
const MAX_RECEIVED_ADDRS: usize = 4_096;

/// Addresses one GetAddr is answered with. Was an unnamed literal beside the
/// `take` that enforced it. Well below MAX_ADDR_PER_MSG so the reply always
/// passes the receiver's own validation — including a receiver running this
/// code, whose ADDR_TOKEN_BURST must also cover it.
const MAX_GETADDR_REPLY: usize = 100;
const _: () = assert!(
    MAX_GETADDR_REPLY <= MAX_ADDR_PER_MSG && MAX_GETADDR_REPLY <= ADDR_TOKEN_BURST,
    "our own reply must fit both the receiver's per-message cap and its address allowance"
);

/// Keepalive ping interval (seconds) — detect dead connections.
const KEEPALIVE_INTERVAL_SECS: u64 = 60;
/// Max time without pong before disconnecting (seconds).
const PONG_TIMEOUT_SECS: u64 = 120;

/// Entries the broadcast queue may hold. Was an unnamed literal beside the
/// eviction that enforced it.
const MAX_OUTBOUND_ENTRIES: usize = 10_000;

/// Bytes the broadcast queue may hold.
///
/// It had no byte term at all, while an entry holds a relayed block or
/// transaction. The hard retain below keeps OUTBOUND_HARD_RETAIN entries
/// whatever peers have acknowledged, so with max-size blocks the FLOOR of the
/// queue was already in the gigabytes, and the ceiling of 10,000 entries put it
/// near twenty.
const MAX_OUTBOUND_BYTES: usize = 64 * 1024 * 1024;

/// Messages kept regardless of what every peer has acknowledged. The backstop
/// for a pinned or stale cursor: a queue that stops pruning slows every flush
/// and finally wedges sync when it fills.
///
/// This floor is in ENTRIES and MAX_OUTBOUND_BYTES is in bytes, so the byte
/// budget can and does bind below it: at MAX_BLOCK_BYTES per entry the budget
/// holds 32, not 4,096. That is the point of a byte bound and it cannot stall
/// pruning — it only ever prunes MORE — but it does mean a laggard's window is
/// measured in bytes rather than messages, and it recovers through header-sync
/// as the newest-wins policy already assumes. Two independent reviewers read
/// the 128x gap as a defect, so it is stated here.
const OUTBOUND_HARD_RETAIN: u64 = 4_096;

/// How often the queue may report that it is evicting.
///
/// One line per eviction was one BLOCKING stderr write per broadcast, taken
/// while holding the lock every peer's flush waits on: `emit` ends in
/// `eprintln!` and Rust's stderr is unbuffered. Once the byte ceiling binds —
/// which with max-size blocks is at 32 entries — that fires on every push, so
/// the log volume becomes a throughput tax exactly when the node is busiest.
/// The accept loop throttles its own refusal log the same way and for the same
/// reason.
const OUTBOUND_WARN_INTERVAL: Duration = Duration::from_secs(1);

/// A block is the largest thing any push site produces — a Tx is capped at
/// MAX_TX_BYTES and an Inv at MAX_INV_PER_MSG small items — so this is what
/// guarantees no single message can exceed the whole budget. If one could, the
/// eviction loop would drain the queue for every peer to make room for it. The
/// invariant is checked here instead of guarded at runtime, because a branch
/// that cannot be reached is worse than none: it reads as load-bearing.
const _: () = assert!(
    MAX_OUTBOUND_BYTES > crate::service::network::dos_guard::MAX_BLOCK_BYTES * 2,
    "a maximum-size block must always fit, with room for what follows it"
);
const _: () = assert!(
    OUTBOUND_HARD_RETAIN < MAX_OUTBOUND_ENTRIES as u64,
    "the hard retain must bind below the entry cap, or ack-based pruning never contributes"
);

/// The broadcast queue. Each peer tracks its own `last_outbound_seq`, so every
/// peer receives every message that is still here when it flushes.
///
/// Entries hold an `Arc` because the SAME message goes to every peer. The queue
/// used to hold the message itself and every flush CLONED up to
/// OUTBOUND_FLUSH_BATCH of them while the global lock was held — one 2 MiB
/// block in flight to 128 peers was 128 deep copies, made one after another
/// behind the lock that every push and every other flush waits on. The Arc
/// makes a flush cost eight bytes per message, and makes the byte bound mean
/// what it says: one copy of the payload, counted once.
struct OutboundQueue {
    /// Newest sequence handed out. Keeps counting when entries are evicted,
    /// because peers' cursors are compared against it.
    seq: u64,
    /// Sorted ascending by sequence: pushes go to the back and both eviction
    /// and pruning take from the front, which is what lets `since` binary-search.
    msgs: std::collections::VecDeque<(u64, usize, Arc<P2PMessage>)>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    /// Evictions not yet reported, and when the last report went out. Carried
    /// rather than dropped, so a throttled line reports a count and not just
    /// the one eviction that happened to be due.
    dropped_since_warn: usize,
    last_warn: Option<Instant>,
}

impl OutboundQueue {
    fn new() -> Self {
        Self::with_limits(MAX_OUTBOUND_ENTRIES, MAX_OUTBOUND_BYTES)
    }

    /// The limits are fields, not constants read inline, so a test can drive
    /// the eviction logic without allocating the real budget. Six tests filling
    /// 64 MiB put a few hundred megabytes of churn through the allocator while
    /// the rest of the suite runs in parallel, and that is enough to deschedule
    /// another test's thread past a 50 ms deadline. One test pins `new()` to the
    /// real constants so the cheap ones cannot drift away from them.
    fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            seq: 0,
            msgs: std::collections::VecDeque::with_capacity(256),
            bytes: 0,
            max_entries,
            max_bytes,
            dropped_since_warn: 0,
            last_warn: None,
        }
    }

    fn pop_front(&mut self) {
        if let Some((_, size, _)) = self.msgs.pop_front() {
            self.bytes = self.bytes.saturating_sub(size);
        }
    }

    /// Queue one broadcast. Returns `Some((dropped, queued_bytes))` when a
    /// report is due, for the CALLER to log once it has released this queue's
    /// lock — see OUTBOUND_WARN_INTERVAL for why that matters.
    ///
    /// Newest-wins: an overflow drops the OLDEST entry, never the arriving one.
    /// Stale gossip is worthless to live peers, which backfill through
    /// header-sync, while the arriving message may be the GetHeaders that
    /// drives a sync — dropping those wedged IBD entirely.
    fn push(&mut self, msg: P2PMessage) -> Option<(usize, usize)> {
        let size = payload_size_estimate(&msg);
        let mut dropped = 0usize;
        while !self.msgs.is_empty()
            && (self.msgs.len() >= self.max_entries || self.bytes + size > self.max_bytes)
        {
            self.pop_front();
            dropped += 1;
        }
        self.seq += 1;
        self.bytes += size;
        self.msgs.push_back((self.seq, size, Arc::new(msg)));

        if dropped == 0 {
            return None;
        }
        self.dropped_since_warn = self.dropped_since_warn.saturating_add(dropped);
        if self
            .last_warn
            .is_some_and(|t| t.elapsed() < OUTBOUND_WARN_INTERVAL)
        {
            return None;
        }
        self.last_warn = Some(Instant::now());
        Some((std::mem::take(&mut self.dropped_since_warn), self.bytes))
    }

    /// At most `batch` entries after `since`, as Arc clones.
    ///
    /// The deque is sorted by sequence, so the starting point is a binary
    /// search rather than a walk: the old filter scanned from the front on
    /// every flush of every peer, which for a peer at the tip meant reading the
    /// whole queue to find nothing.
    fn since(&self, since: u64, batch: usize) -> Vec<(u64, Arc<P2PMessage>)> {
        let start = self.msgs.partition_point(|(seq, _, _)| *seq <= since);
        self.msgs
            .range(start..)
            .take(batch)
            .map(|(seq, _, msg)| (*seq, Arc::clone(msg)))
            .collect()
    }

    /// Drop everything at or below `cutoff`, returning how many went.
    fn prune(&mut self, cutoff: u64) -> usize {
        let mut dropped = 0usize;
        while self.msgs.front().is_some_and(|(seq, _, _)| *seq <= cutoff) {
            self.pop_front();
            dropped += 1;
        }
        dropped
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.msgs.len()
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.bytes
    }
}

static OUTBOUND_MSGS: Lazy<Arc<PlMutex<OutboundQueue>>> =
    Lazy::new(|| Arc::new(PlMutex::new(OutboundQueue::new())));

/// Estimated payload bytes of a message: the heap data, not the stack enum.
///
/// `size_of_val` measures only the discriminant and inline fields, missing the
/// `Vec<u8>`/`String` contents that dominate a real message. Extracted so the
/// DoS guard's accounting and the targeted queue's byte budget share ONE
/// estimate — two implementations of the same notion drift, and a byte budget
/// that disagrees with the rate limiter about what a message costs is worse
/// than no budget.
///
/// It is EXACT for the variants that carry the bytes — Block, Tx, ShadowTx,
/// OnionTx are their payload's length — and an undercount for the container
/// variants, where it counts the string contents but not the per-`String`
/// header or the `Vec` itself: an Inv of 5,000 items is short by about 240 KiB
/// of allocator overhead. Those variants are small and bounded by their own
/// item caps, and the bound exists for the megabyte payloads, so the estimate
/// is tight exactly where it has to be.
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
/// reprocessing once the missing ancestor arrives.
static ORPHAN_BLOCKS: Lazy<Arc<PlMutex<OrphanPool>>> =
    Lazy::new(|| Arc::new(PlMutex::new(OrphanPool::new())));

/// Orphan entries across all peers.
const MAX_ORPHAN_BLOCKS: usize = 5_000;
/// Orphans ONE peer may hold.
///
/// A backward fork walk buffers one orphan per level until the ancestor
/// arrives, and `orphan_worth_resolving` admits orphans within `FINALITY_DEPTH`
/// of the tip — so a per-peer cap below that would make the pool refuse exactly
/// the heal it exists to serve. Deeper gaps are header-sync's job, by that
/// function's own reasoning, not this pool's.
const MAX_ORPHANS_PER_PEER: usize =
    crate::engine::consensus::reorg::FINALITY_DEPTH as usize;
/// Bytes ONE peer may hold — the same share the targeted queue gives a peer.
const MAX_ORPHAN_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
/// Bytes across all peers.
///
/// The pool had NO byte term at all, only the entry count above, while
/// `payload_size_bounds(CommandId::Block)` admits a payload up to
/// `MAX_MESSAGE_SIZE` — so 5,000 entries was tens of gigabytes of memory whose
/// size the sender chooses, held until each parent arrives or the sender leaves.
const MAX_ORPHAN_BYTES: usize = 64 * 1024 * 1024;
const _: () = assert!(
    MAX_ORPHANS_PER_PEER <= MAX_ORPHAN_BLOCKS
        && MAX_ORPHAN_BYTES_PER_PEER <= MAX_ORPHAN_BYTES,
    "a peer's own orphan quota must fit inside the global one"
);
const _: () = assert!(
    MAX_ORPHAN_BYTES / MAX_ORPHAN_BYTES_PER_PEER >= 8,
    "several peers must be able to hold a full share at once, or one heal starves the rest"
);

struct PeerOrphans {
    /// (block hash, measured bytes, block) in arrival order.
    blocks: std::collections::VecDeque<(String, usize, Block)>,
    bytes: usize,
}

/// Orphans held per SENDER, bounded per peer and in total, by entries AND bytes.
///
/// This was a flat `Vec<(String, Block)>`: a linear dedup scan over up to 5,000
/// entries per push, `remove(0)` eviction, a deep `clone` of every match when a
/// parent arrived, an O(n) retain to drop a departed peer — and no byte term.
/// The shape here, including charging a global overflow to the peer holding the
/// most bytes, is `TargetedQueue`'s, which already solved the same problem for
/// the send side in this file.
struct OrphanPool {
    by_peer: HashMap<String, PeerOrphans>,
    entries: usize,
    bytes: usize,
}

impl OrphanPool {
    fn new() -> Self {
        Self {
            by_peer: HashMap::new(),
            entries: 0,
            bytes: 0,
        }
    }

    /// Both accessors exist for the accounting invariant the tests drive; the
    /// pool's own logic reads the fields directly, so production carries neither.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop one peer's oldest orphan. Returns false when it had none.
    fn drop_oldest_for(&mut self, peer: &str) -> bool {
        let Some(po) = self.by_peer.get_mut(peer) else {
            return false;
        };
        match po.blocks.pop_front() {
            Some((_, size, _)) => {
                po.bytes = po.bytes.saturating_sub(size);
                self.entries = self.entries.saturating_sub(1);
                self.bytes = self.bytes.saturating_sub(size);
                if po.blocks.is_empty() {
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

    /// The peer holding the most bytes — the one to charge a global overflow to,
    /// so a flooder cannot evict the orphans another peer is healing a fork with.
    fn heaviest_peer(&self) -> Option<String> {
        self.by_peer
            .iter()
            .max_by_key(|(_, po)| po.bytes)
            .map(|(p, _)| p.clone())
    }

    /// Buffer `block` from `peer`, making room by evicting the backlog of
    /// whoever is responsible for the overflow.
    ///
    /// Deduplicated per SENDER, not by hash alone: `remove_peer` deletes this
    /// pool by peer, so a hash-wide key made the first sender's disconnect
    /// destroy the only copy of a block several peers had handed us, and the
    /// ancestor we had already broadcast GetBlock for arrived to find nothing
    /// waiting on it. `PendingBlocks::retain_other_peers` states the same lesson
    /// for the queue these blocks are drained from.
    fn push(&mut self, peer: &str, block: Block) {
        let hash = block.header.hash.clone();
        if self
            .by_peer
            .get(peer)
            .is_some_and(|po| po.blocks.iter().any(|(h, _, _)| *h == hash))
        {
            return;
        }
        let size = bincode::serialized_size(&block).unwrap_or(0) as usize;
        // That peer's own quota first.
        loop {
            let (n, b) = self
                .by_peer
                .get(peer)
                .map_or((0, 0), |po| (po.blocks.len(), po.bytes));
            if n == 0 || (n < MAX_ORPHANS_PER_PEER && b + size <= MAX_ORPHAN_BYTES_PER_PEER) {
                break;
            }
            if !self.drop_oldest_for(peer) {
                break;
            }
        }
        // Then the global budget, charged to whoever holds the most.
        while self.entries >= MAX_ORPHAN_BLOCKS || self.bytes + size > MAX_ORPHAN_BYTES {
            let Some(victim) = self.heaviest_peer() else {
                break;
            };
            if !self.drop_oldest_for(&victim) {
                break;
            }
        }
        let po = self.by_peer.entry(peer.to_string()).or_insert(PeerOrphans {
            blocks: std::collections::VecDeque::new(),
            bytes: 0,
        });
        po.blocks.push_back((hash, size, block));
        po.bytes = po.bytes.saturating_add(size);
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
    }

    /// Remove and return every buffered orphan listing `parent_hash` among its
    /// parents. The block is MOVED out, not cloned: the flat-Vec retain this
    /// replaces deep-copied each match while holding the pool's lock.
    fn take_for_parent(&mut self, parent_hash: &str) -> Vec<(String, Block)> {
        let mut ready: Vec<(String, Block)> = Vec::new();
        let (mut freed_entries, mut freed_bytes) = (0usize, 0usize);
        for (peer, po) in self.by_peer.iter_mut() {
            let mut keep = std::collections::VecDeque::with_capacity(po.blocks.len());
            while let Some((hash, size, block)) = po.blocks.pop_front() {
                if block.header.parents.iter().any(|p| p == parent_hash) {
                    po.bytes = po.bytes.saturating_sub(size);
                    freed_entries = freed_entries.saturating_add(1);
                    freed_bytes = freed_bytes.saturating_add(size);
                    ready.push((peer.clone(), block));
                } else {
                    keep.push_back((hash, size, block));
                }
            }
            po.blocks = keep;
        }
        self.entries = self.entries.saturating_sub(freed_entries);
        self.bytes = self.bytes.saturating_sub(freed_bytes);
        self.by_peer.retain(|_, po| !po.blocks.is_empty());
        ready
    }

    /// Drop everything a departed peer sent. O(1) in the pool's size; the Vec
    /// this replaces scanned every entry.
    fn remove_peer(&mut self, peer: &str) -> usize {
        match self.by_peer.remove(peer) {
            Some(po) => {
                let n = po.blocks.len();
                self.entries = self.entries.saturating_sub(n);
                self.bytes = self.bytes.saturating_sub(po.bytes);
                n
            }
            None => 0,
        }
    }
}

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
    //
    // Both systems are asked. peer_manager's is PERSISTENT and has no
    // production writer, so on its own this gate always answered false and the
    // loop kept dialling hosts the live guard had banned — every message from
    // which we then drop, for a dial budget that is deliberately scarce. The
    // live check is a host-keyed pure read, so it is affordable per candidate;
    // whitelisted seeds answer false, so our own seeds are never refused.
    if peers.is_banned(addr) || DOS_GUARD.is_banned(addr) {
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
/// from a reaper) unwinds `fill_buf` -> `poll_frame` ->
/// `handle_peer_connection` through the ordinary error path, so
/// `InboundSlot::drop` releases the pending slot and both anti-eclipse
/// registrations on the way out.
///
/// `set_deadline` moves it from one handshake step to the next, and `disarm`
/// drops it once the handshake completes: an established
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

    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
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
/// (10060), which that platform returns for an `SO_RCVTIMEO` expiry.
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

/// How far a payload buffer may grow ahead of the bytes that have actually
/// arrived. Bitcoin Core's V1 transport uses the same bound, added after its
/// 2024 receive-buffer disclosure: a peer that declares a large payload and then
/// sends nothing must not be able to make us allocate the declared size.
const PAYLOAD_LOOKAHEAD: usize = 256 * 1024;

/// Read buffer per connection. One recv can then hold several small frames,
/// and a large payload arrives in large steps.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Error text for a poll interval that delivered no byte. It must classify as
/// transient, exactly like the socket timeout it stands for.
const IDLE_POLL_TEXT: &str = "read timed out: no byte arrived within one poll interval";

/// A frame decoded off the wire: the message, its command, and the bytes it took.
type Frame = (P2PMessage, CommandId, usize);

enum DecodeStage {
    Header {
        buf: [u8; WIRE_HEADER_SIZE],
        filled: usize,
    },
    Payload {
        cmd: CommandId,
        checksum: [u8; 4],
        declared: usize,
        buf: Vec<u8>,
    },
}

/// Turns the byte stream into frames, keeping a partial frame across reads.
///
/// `read_message` used to call `read_exact` for the header and the payload under
/// the 100 ms poll timeout, and std's `read_exact` returns on the first error
/// with the bytes it had already taken gone. So a frame whose bytes stopped for
/// more than 100 ms mid-way — one lost packet does that over a real link, where
/// the minimum TCP retransmission timeout is 200 ms — was cut, and the next
/// read took a "header" from the middle of it. The shape here is Bitcoin Core's
/// V1 transport: a state machine fed whatever bytes arrived.
///
/// `feed` never consumes a byte past the one that completes a message. The next
/// header is therefore always gated in a later call, under the handshake state
/// the caller has moved to by then — exactly as each header was gated in its own
/// `read_message` call before.
struct FrameDecoder {
    stage: DecodeStage,
}

impl FrameDecoder {
    fn new() -> Self {
        Self {
            stage: DecodeStage::Header {
                buf: [0; WIRE_HEADER_SIZE],
                filled: 0,
            },
        }
    }

    /// Consume as much of `input` as belongs to the current frame and report how
    /// much, plus the frame if this call completed one. The gates run in the
    /// order `read_message` ran them, and that order is the scoring rule: only
    /// `check_command_allowed` scores, so a header that fails `validate_header`
    /// first is never scored, and a forbidden command is scored before its size
    /// is looked at.
    fn feed(
        &mut self,
        input: &[u8],
        magic: [u8; 4],
        protocol: &ProtocolSession,
    ) -> Result<(usize, Option<Frame>), ReadStop> {
        let mut used = 0;
        if let DecodeStage::Header { buf, filled } = &mut self.stage {
            let take = (WIRE_HEADER_SIZE - *filled).min(input.len());
            buf[*filled..*filled + take].copy_from_slice(&input[..take]);
            *filled += take;
            used += take;
            if *filled < WIRE_HEADER_SIZE {
                return Ok((used, None));
            }
            let header = WireHeader::decode(buf);
            let cmd = validate_header(&header, magic).map_err(|pe| {
                ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
            })?;
            if let Err(pe) = protocol.check_command_allowed(cmd) {
                return Err(ReadStop::Premature {
                    cmd,
                    reason: pe.message,
                    ban_score: pe.ban_score as u64,
                });
            }
            let declared = header.payload_len as usize;
            validate_payload_size(cmd, declared).map_err(|pe| {
                ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
            })?;
            self.stage = DecodeStage::Payload {
                cmd,
                checksum: header.checksum,
                declared,
                buf: Vec::new(),
            };
        }

        let DecodeStage::Payload {
            cmd,
            checksum,
            declared,
            buf,
        } = &mut self.stage
        else {
            unreachable!("the header stage either returned or moved to the payload stage");
        };
        let rest = &input[used..];
        let take = (*declared - buf.len()).min(rest.len());
        if take > 0 {
            let want = buf.len() + take;
            if buf.capacity() < want {
                let target = want.saturating_add(PAYLOAD_LOOKAHEAD).min(*declared);
                buf.reserve_exact(target - buf.len());
            }
            buf.extend_from_slice(&rest[..take]);
            used += take;
        }
        if buf.len() < *declared {
            return Ok((used, None));
        }

        let cmd = *cmd;
        let checksum = *checksum;
        let payload = std::mem::take(buf);
        self.stage = DecodeStage::Header {
            buf: [0; WIRE_HEADER_SIZE],
            filled: 0,
        };
        validate_payload_checksum(&payload, checksum).map_err(|pe| {
            ReadStop::Failed(NetworkError::Serialization(format!("[Protocol] {}", pe)))
        })?;
        let msg: P2PMessage = bounded_deserialize(&payload).map_err(|e| {
            ReadStop::Failed(NetworkError::Serialization(format!(
                "[Protocol] {} deserialize failed: {}",
                cmd, e
            )))
        })?;
        Ok((used, Some((msg, cmd, WIRE_HEADER_SIZE + payload.len()))))
    }
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
        let dropped = ORPHAN_BLOCKS.lock().remove_peer(peer_id);
        if dropped > 0 {
            slog_warn!("p2p", "cleanup_dropped_orphans", peer => peer_id, dropped => dropped);
        }
    }
    {
        let mut q = PENDING_HEADER_REQUESTS.lock();
        q.retain(|(target, _, _)| target != peer_id);
    }
    {
        let mut p = PEER_PENDING.lock();
        p.remove(peer_id);
    }
    // The outbound cursor is NOT removed here: `OutboundCursor` owns it from the
    // start of relay until the session drops, on every exit path, panics included.
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
/// missing ancestor arrives. Bounded (drops oldest).
///
/// Deduplicated per SENDER, not by hash alone. With a hash-wide key the second
/// peer to gossip an orphan was turned away with nothing stored for it, while
/// `cleanup_peer_state` deletes this pool BY PEER — so the first sender's
/// disconnect took the only copy of a block several peers had handed us, and the
/// ancestor we had already broadcast GetBlock for arrived to find nothing
/// waiting on it. `PendingBlocks::retain_other_peers` states the same lesson for
/// the queue these blocks were drained from; this pool had not learned it.
pub fn buffer_orphan(peer_id: &str, block: Block) {
    ORPHAN_BLOCKS.lock().push(peer_id, block);
}

/// Remove and return buffered orphans that list `parent_hash` among their
/// parents. Called after a block is accepted: those orphans may now be
/// processable (re-queue them; still-missing parents re-buffer + re-request).
pub fn take_orphans_for_parent(parent_hash: &str) -> Vec<(String, Block)> {
    ORPHAN_BLOCKS.lock().take_for_parent(parent_hash)
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

/// The host a peer address belongs to: "1.2.3.4:9333", "[::1]:9333", "::1".
///
/// Delegates to `dos_guard::host_key` so the accept gates, the per-host queue
/// quotas, the daemon's serve fairness and the ban records cannot disagree
/// about what one host is. Three separate implementations of this existed and
/// each handled a bare IPv6 literal differently.
pub fn extract_ban_ip(addr: &str) -> String {
    crate::service::network::dos_guard::host_key(addr).to_string()
}

/// Whether the live DoS guard has this host banned.
///
/// Public because the operator's RPC peer view reported `banned` out of
/// `peer_manager`'s persistent store, which nothing in production writes, so it
/// answered false for every host this guard had banned.
pub fn is_peer_banned(addr: &str) -> bool {
    DOS_GUARD.is_banned(addr)
}

/// The live ban record for a host, for the operator's peer view.
pub fn peer_ban_info(addr: &str) -> Option<crate::service::network::dos_guard::BanInfo> {
    DOS_GUARD.get_ban_info(addr)
}

/// Every host the live guard has banned right now. Bounded by MAX_BAN_RECORDS.
pub fn banned_peers() -> Vec<(String, crate::service::network::dos_guard::BanInfo)> {
    DOS_GUARD.banned_peers()
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
///
/// One call, because the guard now keys reputation on the host itself. This
/// used to score the ip:port key and then the IP separately so a reconnect on
/// a fresh port could not start from zero; with the key normalised inside the
/// guard, the second call is the same record again and would double every
/// penalty.
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
    // The lock is released before the log line, because the line is a blocking
    // write to a stderr the whole process shares.
    let report = OUTBOUND_MSGS.lock().push(msg);
    if let Some((dropped, queued_bytes)) = report {
        slog_warn!("p2p", "outbound_queue_full",
            dropped => dropped,
            queued_bytes => queued_bytes);
    }
}

/// The current global broadcast sequence number. A freshly-connected peer must
/// start its outbound cursor HERE (not at 0) so it only receives FUTURE
/// broadcasts — the historical backlog is delivered via header-sync / IBD, never
/// replayed through the broadcast queue. Without this, a new peer's cursor of 0
/// against a high global counter is misread as thousands of seqs of "outbound
/// lag" and the peer is wrongly disconnected as slow the instant it connects,
/// which prevents a lagging node from ever catching up (chain never converges).
fn current_outbound_seq() -> u64 {
    OUTBOUND_MSGS.lock().seq
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
/// connection's DELIVERY cursor is read AFTER its entry is seeded (both at the
/// start of relay, in `flush_outbound`), so the delivery
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
    let hard = max_seq.saturating_sub(OUTBOUND_HARD_RETAIN);
    min_ack.unwrap_or(0).max(hard)
}

/// Get outbound messages that this peer hasn't sent yet.
/// Each peer tracks its own `last_outbound_seq` to ensure ALL peers
/// receive ALL broadcast messages (not just the first to drain).
/// Also prunes old messages that all peers have had time to read.
fn drain_outbound_since(since: u64) -> (Vec<(u64, Arc<P2PMessage>)>, u64) {
    // Oldest messages a flush hands one peer in one call. Bounds the per-flush
    // cost (the cursor advances incrementally; the next flush continues), so
    // one slow peer's flush can no longer walk a huge backlog.
    const OUTBOUND_FLUSH_BATCH: usize = 512;
    // Before the queue is locked, so this function holds one lock at a time.
    let min_ack = min_outbound_ack();
    let mut q = OUTBOUND_MSGS.lock();
    let new_msgs = q.since(since, OUTBOUND_FLUSH_BATCH);
    let max_seq = q.seq;
    let cutoff = prune_cutoff(min_ack, max_seq);
    if cutoff > 0 {
        let dropped = q.prune(cutoff);
        if dropped > 0 {
            slog_debug!("p2p", "outbound_queue_pruned",
                dropped => dropped,
                cutoff_seq => cutoff,
                min_ack_seq => min_ack.unwrap_or(0));
        }
    }
    (new_msgs, max_seq)
}

/// Owns one peer's outbound-broadcast cursor for as long as it is relayed to.
/// Held by the connection's session, created when relay starts after the
/// handshake.
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
    /// Count of unsupported-message violations (unimplemented protocol commands).
    /// Repeated abuse is treated as malformed/malicious behavior and disconnects.
    unsupported_msg_violations: u32,
    /// Last outbound broadcast sequence number sent to this peer.
    /// Used to ensure every peer gets every broadcast message.
    last_outbound_seq: u64,
    /// Address-processing allowance left for this connection, and when it was
    /// last refilled. See ADDR_TOKEN_BURST.
    addr_tokens: f64,
    addr_tokens_at: Instant,
    /// This peer's broadcast cursor, created by the first flush after the
    /// handshake and dropped with the session on every exit path, panics
    /// included. A connection still in its handshake therefore has no entry in
    /// `PEER_LAST_OUTBOUND` and cannot hold back the queue's pruning: the
    /// cursor used to be seeded at connect, and once relay waits for the
    /// handshake, a seeded cursor that cannot advance would pin the minimum.
    relay_cursor: Option<OutboundCursor>,
    /// Whether this connection has already been answered a GetAddr.
    ///
    /// GetAddr is not in `token_cost`'s match, so it costs COST_MSG_DEFAULT = 1:
    /// a 13-byte request for a ~2.5 KiB reply, about 190x, repeatable at
    /// BUCKET_REFILL_RATE a second. That is megabytes a second of OUR upstream
    /// per peer, written synchronously from the peer's own thread. Bitcoin Core
    /// answers it once per connection for exactly this reason.
    getaddr_answered: bool,
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
            unsupported_msg_violations: 0,
            // Overwritten when relay starts in flush_outbound, and nothing
            // reads it before then. It still starts at the CURRENT global seq,
            // not 0: a new peer only needs future broadcasts (backlog comes via
            // sync), and starting at 0 made the outbound-lag check see the whole
            // global counter as "lag" and disconnect the peer as slow on its
            // first flush — which stalled convergence for any node behind the
            // broadcast counter.
            last_outbound_seq: current_outbound_seq(),
            addr_tokens: ADDR_TOKEN_BURST as f64,
            addr_tokens_at: Instant::now(),
            relay_cursor: None,
            getaddr_answered: false,
        }
    }

    /// Take up to `wanted` address-processing tokens and return how many were
    /// granted. A trusted seed is exempt, exactly as upstream exempts a peer
    /// holding the Addr permission: the fleet's own seeds must be able to hand
    /// a lagging node a full address book.
    fn take_addr_tokens(&mut self, wanted: usize, whitelisted: bool) -> usize {
        if whitelisted {
            return wanted;
        }
        let elapsed = self.addr_tokens_at.elapsed().as_secs_f64();
        self.addr_tokens =
            (self.addr_tokens + elapsed * ADDR_TOKENS_PER_SEC).min(ADDR_TOKEN_BURST as f64);
        self.addr_tokens_at = Instant::now();
        let granted = (self.addr_tokens.floor() as usize).min(wanted);
        self.addr_tokens -= granted as f64;
        granted
    }

    /// The prefix of `peers` this connection's allowance admits, and how many
    /// it refuses.
    ///
    /// Spending and admitting are ONE call deliberately. The handler first took
    /// a budget and decremented it per address, and a negative control that
    /// deleted that decrement went unnoticed — the handler lives inside
    /// `dispatch_message`, which no unit test can drive without a live socket.
    /// Here there is no separate counter to forget.
    fn admit_addresses<'a>(
        &mut self,
        peers: &'a [String],
        whitelisted: bool,
    ) -> (&'a [String], usize) {
        let granted = self.take_addr_tokens(peers.len(), whitelisted);
        (&peers[..granted], peers.len() - granted)
    }

    /// Whether to answer a GetAddr on this connection, consuming the single
    /// allowance if so.
    ///
    /// Deciding and spending are ONE call, for the reason `admit_addresses`
    /// gives: the caller is inside `dispatch_message` and no unit test can
    /// reach it, so a separate flag to set would be a flag to forget.
    ///
    /// Two rules, both Bitcoin Core's. Once per connection, because the reply
    /// is ~190x the request and costs the asker one token. And never on a
    /// connection WE dialled: we chose that peer, so it has no business asking
    /// for our address book, and upstream ignores GETADDR from outbound peers
    /// for the same reason.
    fn admit_getaddr(&mut self) -> bool {
        if self.protocol.is_outbound || self.getaddr_answered {
            return false;
        }
        self.getaddr_answered = true;
        true
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
        let budget = HandshakeBudget {
            puzzle_step: if outbound {
                DIALER_PUZZLE_STEP
            } else {
                ACCEPTOR_PUZZLE_STEP
            },
            version_exchange: VERSION_EXCHANGE_DEADLINE,
        };
        Self::handle_peer_connection_within(stream, outbound, magic, known_peers, peers, budget)
    }

    fn handle_peer_connection_within(
        stream: TcpStream,
        outbound: bool,
        magic: [u8; 4],
        known_peers: Vec<String>,
        peers: Arc<PeerManager>,
        budget: HandshakeBudget,
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

        // The read timeout above bounds one recv; this bounds each handshake
        // step. Disarmed in the main loop the moment the handshake completes.
        let connected_at = Instant::now();
        let mut reader = BufReader::with_capacity(
            READ_BUFFER_BYTES,
            DeadlineReader::new(&stream, connected_at + budget.puzzle_step),
        );
        // One decoder for the whole connection, so a frame that arrives in the
        // same read as the one before it survives the hand-over from the puzzle
        // phase to the main loop.
        let mut decoder = FrameDecoder::new();
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
            let first = Self::read_step(&mut reader, &mut decoder, magic, &session.protocol);
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
            let first = Self::read_step(&mut reader, &mut decoder, magic, &session.protocol);
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
                Ok((_, cmd, _)) => {
                    return Err(NetworkError::ConnectionFailed(format!(
                        "Expected PuzzleChallenge from {}, got {}",
                        peer_str, cmd
                    )));
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
        }
        reader
            .get_mut()
            .set_deadline(connected_at + budget.version_exchange);

        // ── Send our Version (after puzzle phase) ──────────────────────────
        let bytes = Self::send_version(&mut writer, 0, magic)?;
        session.record_bytes_sent(bytes);
        session
            .protocol
            .sent_version()
            .map_err(|e| NetworkError::ConnectionFailed(format!("protocol state error: {}", e)))?;

        // ── Main message loop ──────────────────────────────────────────────
        loop {
            let next = Self::read_message(&mut reader, &mut decoder, magic, &session.protocol);
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
        // Nothing is relayed before the handshake completes. A peer that has
        // our Version but not yet our VerAck scores anything outside the
        // handshake commands 50 and closes, and this flush runs after every
        // dispatched message and on every idle tick of the main loop, which a
        // connection enters as soon as our Version is sent. Bitcoin Core's
        // SendMessages sends nothing past the version message until the
        // handshake is complete, and Kaspa launches its flows only after the
        // ready exchange.
        if !session.is_established() {
            return true;
        }
        // Relay starts here, once. The order is the one min_outbound_ack's
        // safety argument rests on: the sequence is read BEFORE the cursor lock
        // is taken, the entry is seeded, and the delivery cursor is read only
        // AFTER the entry exists, so it is never below the seeded value and no
        // prune reaches past it before this peer reads it, short of the hard
        // retain.
        if session.relay_cursor.is_none() {
            let seeded_at = current_outbound_seq();
            session.relay_cursor = Some(OutboundCursor::seed(peer_str, seeded_at));
            session.last_outbound_seq = current_outbound_seq();
        }
        let (outbound, global_seq) = drain_outbound_since(session.last_outbound_seq);
        if !outbound.is_empty() {
            // Lag is measured against the GLOBAL newest seq, not the (batched)
            // returned slice, so capping the flush batch doesn't mask real lag.
            let lag = global_seq.saturating_sub(session.last_outbound_seq);
            if lag > MAX_OUTBOUND_LAG_SEQS
                && !crate::service::network::dos_guard::is_whitelisted(peer_str)
            {
                DOS_GUARD.add_ban_score_cat(
                    peer_str,
                    25,
                    "excessive outbound lag; disconnecting slow peer",
                    BanCategory::Resource,
                );
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
        decoder: &mut FrameDecoder,
        magic: [u8; 4],
        protocol: &ProtocolSession,
    ) -> Result<Frame, ReadStop> {
        match Self::poll_frame(reader, decoder, magic, protocol)? {
            Some(frame) => Ok(frame),
            None => Err(ReadStop::Failed(NetworkError::ConnectionFailed(
                IDLE_POLL_TEXT.to_string(),
            ))),
        }
    }

    /// Wait out idle polls until a frame arrives or the reader's deadline ends
    /// the step.
    fn read_step(
        reader: &mut BufReader<DeadlineReader<&TcpStream>>,
        decoder: &mut FrameDecoder,
        magic: [u8; 4],
        protocol: &ProtocolSession,
    ) -> Result<Frame, ReadStop> {
        debug_assert!(reader.get_ref().deadline.is_some());
        loop {
            if let Some(frame) = Self::poll_frame(reader, decoder, magic, protocol)? {
                return Ok(frame);
            }
        }
    }

    /// Feed whatever bytes are buffered or arrive into `decoder` until a frame
    /// completes. `Ok(None)` means exactly what an idle tick has always meant: no
    /// byte arrived within one poll interval. A partial frame is kept for the next
    /// call rather than discarded.
    ///
    /// The timeout is recognised by `is_transient_read_timeout`, never by
    /// `ErrorKind`: the pre-handshake deadline error is also `TimedOut`, and it
    /// must stay fatal.
    fn poll_frame(
        reader: &mut BufReader<DeadlineReader<&TcpStream>>,
        decoder: &mut FrameDecoder,
        magic: [u8; 4],
        protocol: &ProtocolSession,
    ) -> Result<Option<Frame>, ReadStop> {
        loop {
            let available = match reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let text = e.to_string();
                    if is_transient_read_timeout(&text.to_lowercase()) {
                        return Ok(None);
                    }
                    return Err(ReadStop::Failed(NetworkError::ConnectionFailed(text)));
                }
            };
            if available.is_empty() {
                return Err(ReadStop::Failed(NetworkError::ConnectionFailed(
                    "connection closed by peer".to_string(),
                )));
            }
            let (used, frame) = decoder.feed(available, magic, protocol)?;
            // A decoder that takes nothing from a non-empty buffer and yields no
            // frame would spin here for ever: fill_buf hands back the same bytes
            // without a syscall, so neither the poll timeout nor the deadline
            // could ever fire.
            if used == 0 && frame.is_none() {
                return Err(ReadStop::Failed(NetworkError::ConnectionFailed(
                    "frame decoder made no progress".to_string(),
                )));
            }
            reader.consume(used);
            if let Some(frame) = frame {
                return Ok(Some(frame));
            }
        }
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
            // A connection's one puzzle is exchanged before the main loop, so a
            // challenge here is never solved.
            P2PMessage::PuzzleChallenge { .. } => {
                DOS_GUARD.add_ban_score_cat(
                    peer,
                    10,
                    "unexpected puzzle challenge",
                    BanCategory::Malformed,
                );
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
                // `&id[..16]` could land mid-UTF-8 and panic the peer thread.
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
                // Ignored rather than refused, and not scored: asking twice is
                // wasteful, not malicious, and upstream treats it the same way.
                if session.admit_getaddr() {
                    let addrs: Vec<String> =
                        known_peers.iter().take(MAX_GETADDR_REPLY).cloned().collect();
                    let response = P2PMessage::Addr { peers: addrs };
                    let bytes = Self::write_message(writer, &response, magic)?;
                    session.record_bytes_sent(bytes);
                } else {
                    slog_debug!("p2p", "getaddr_ignored",
                        addr => peer, outbound => session.protocol.is_outbound);
                }
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
                    // An address costs an allowance token whether or not it
                    // turns out to be routable: the work is the examination, and
                    // garbage is already scored below. Over-rate addresses are
                    // DROPPED and not punished, as upstream does — an honest
                    // peer with a big address book is not an attacker.
                    let whitelisted = crate::service::network::dos_guard::is_whitelisted(peer);
                    let (admitted, rate_limited) = session.admit_addresses(peers, whitelisted);
                    let mut q = RECEIVED_ADDRS.lock();
                    let mut rejected = 0u32;
                    for addr in admitted {
                        if !is_routable_peer_addr(addr) {
                            rejected = rejected.saturating_add(1);
                            continue;
                        }
                        if q.len() < MAX_RECEIVED_ADDRS {
                            q.push(addr.clone());
                        }
                    }
                    drop(q);
                    if rate_limited > 0 {
                        slog_debug!("p2p", "addr_rate_limited",
                            addr => peer, dropped => rate_limited);
                    }
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
        // The widen-strictly-outwards bound is asserted at the constants
        // themselves, so it fails a release build and not merely this test.
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
    fn maintenance_decays_then_evicts_in_one_round() {
        // The pass is composed decay-THEN-evict so a peer that has served out
        // its penalty is dropped from the table the same tick. It used to be
        // handed two records that were ALREADY at score 0, created as a side
        // effect of ASKING whether they were banned — so it never exercised the
        // decay at all, and the moment asking stopped creating records it had
        // nothing to evict and failed on its own setup.
        let g = DosGuard::new();
        g.add_ban_score_cat("198.51.100.21", 10, "minor", BanCategory::Resource);
        g.add_ban_score_cat("198.51.100.22", 10, "minor", BanCategory::Resource);
        assert_eq!(g.stats().tracked_peers, 2);

        // Ten minutes of decay owed on one of them: Resource sheds 5 a minute,
        // so its 10 points are gone and the evict half of the same round must
        // see a cleared record.
        assert!(g.backdate_decay("198.51.100.21", 600));
        maintain_dos_guard(&g);

        assert_eq!(
            g.stats().tracked_peers,
            1,
            "a record whose score decayed to 0 must go in the same round"
        );
        assert!(g.get_ban_info("198.51.100.21").is_none());
        assert!(
            g.get_ban_info("198.51.100.22").is_some(),
            "and one that still owes score must stay"
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

    // ── the broadcast queue: one copy, bounded in bytes ───────────────────

    fn broadcast_block(bytes: usize) -> P2PMessage {
        P2PMessage::Block {
            data: vec![0u8; bytes],
        }
    }

    #[test]
    fn the_broadcast_queue_uses_the_real_limits() {
        // The behaviour tests below run on small limits so they allocate
        // nothing; this is what keeps them honest about the real ones.
        let q = OutboundQueue::new();
        assert_eq!(q.max_entries, MAX_OUTBOUND_ENTRIES);
        assert_eq!(q.max_bytes, MAX_OUTBOUND_BYTES);
    }

    #[test]
    fn the_broadcast_queue_is_bounded_in_bytes_not_just_entries() {
        // It had no byte term at all, while entries hold relayed blocks and
        // transactions — and prune_cutoff keeps OUTBOUND_HARD_RETAIN entries
        // whatever peers have acknowledged, so the FLOOR was in the gigabytes.
        // Entry cap high, byte cap low: only the byte term can be doing this.
        let mut q = OutboundQueue::with_limits(1_000, 8 * 1024);
        for _ in 0..40 {
            q.push(broadcast_block(1024));
        }
        assert!(
            q.bytes() <= 8 * 1024,
            "queued bytes must stay inside the budget, got {}",
            q.bytes()
        );
        assert!(
            q.len() < 40,
            "the byte budget must have evicted, not just the entry cap"
        );

        // A single maximum-size block is never refused by the REAL budget,
        // however full we are — the invariant the const assert pins.
        let mut q = OutboundQueue::new();
        q.push(broadcast_block(
            crate::service::network::dos_guard::MAX_BLOCK_BYTES,
        ));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn a_broadcast_overflow_drops_the_oldest_not_the_arriving_message() {
        // Newest-wins: stale gossip is worthless to live peers, which backfill
        // through header-sync, while the arriving message may be the GetHeaders
        // that drives a sync — dropping those wedged IBD entirely.
        // Byte cap high, entry cap low: only the entry term can be doing this.
        let entries = 8usize;
        let mut q = OutboundQueue::with_limits(entries, 1 << 20);
        for i in 0..(entries + 5) {
            q.push(P2PMessage::Ping { nonce: i as u64 });
        }
        assert_eq!(q.len(), entries, "the entry cap must hold");

        let all = q.since(0, entries);
        assert!(
            matches!(*all[0].1, P2PMessage::Ping { nonce: 5 }),
            "the five oldest went, not the five newest"
        );
        assert!(matches!(
            *all[all.len() - 1].1,
            P2PMessage::Ping { nonce } if nonce == (entries + 4) as u64
        ));
    }

    #[test]
    fn a_flush_hands_out_a_handle_not_a_copy_of_the_payload() {
        // THE REAL EXPOSURE: the drain cloned up to OUTBOUND_FLUSH_BATCH
        // messages while the GLOBAL lock was held, per peer per flush. The same
        // message goes to every peer, so one 2 MiB block in flight to 128 peers
        // was 128 deep copies made one after another behind the lock that every
        // push and every other flush waits on.
        let mut q = OutboundQueue::new();
        q.push(broadcast_block(1024));
        let first = q.since(0, 512);
        let second = q.since(0, 512);
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert!(
            Arc::ptr_eq(&first[0].1, &second[0].1),
            "two flushes of one message must share it, not copy it"
        );
    }

    #[test]
    fn the_overflow_report_is_due_at_most_once_per_interval() {
        // The warning used to be emitted inside this queue's lock, once per
        // eviction. `emit` ends in `eprintln!` and Rust's stderr is unbuffered,
        // so that is a blocking syscall per broadcast, taken while holding the
        // lock every peer's flush waits on — and with max-size blocks the byte
        // ceiling binds at 32 entries, so it would fire on every push.
        let mut q = OutboundQueue::with_limits(2, 1 << 20);
        assert!(q.push(P2PMessage::Ping { nonce: 1 }).is_none());
        assert!(q.push(P2PMessage::Ping { nonce: 2 }).is_none());

        // The first eviction after a quiet period reports.
        let first = q.push(P2PMessage::Ping { nonce: 3 });
        assert_eq!(first, Some((1, q.bytes())), "one eviction, reported");

        // Everything inside the interval is silent, and the count is CARRIED
        // rather than lost, so the throttled line is a rate and not one event.
        for i in 4..20u64 {
            assert!(q.push(P2PMessage::Ping { nonce: i }).is_none(), "i={i}");
        }
        assert_eq!(
            q.dropped_since_warn, 16,
            "the unreported evictions must accumulate"
        );

        // And they must come OUT in the next line, which is the whole point of
        // carrying them: a throttled report is a rate, not the one eviction
        // that happened to be due. A control that reported only the current
        // push's count passed everything above, because nothing here took a
        // SECOND report — the interval is a whole second and this test runs in
        // microseconds. Clearing `last_warn` is how it gets one without a
        // sleep, the same reason the TTL and the two limits are parameters.
        q.last_warn = None;
        let second = q.push(P2PMessage::Ping { nonce: 20 });
        assert_eq!(
            second,
            Some((17, q.bytes())),
            "the sixteen carried, plus this push's own eviction"
        );
        assert_eq!(
            q.dropped_since_warn, 0,
            "and reporting them clears the carry"
        );
    }

    #[test]
    fn a_cursor_finds_its_place_without_walking_the_queue() {
        // `since` binary-searches, which is only valid because the deque stays
        // sorted by sequence: pushes go to the back, and both eviction and
        // pruning take from the front.
        let mut q = OutboundQueue::new();
        for i in 0..50u64 {
            q.push(P2PMessage::Ping { nonce: i });
        }
        assert_eq!(q.since(50, 512).len(), 0, "a peer at the tip gets nothing");
        let tail = q.since(49, 512);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].0, 50, "sequences are 1-based");

        let batch = q.since(10, 512);
        assert_eq!(batch.len(), 40);
        assert_eq!(batch[0].0, 11, "the first entry AFTER the cursor");
        assert!(
            batch.windows(2).all(|w| w[0].0 < w[1].0),
            "and in sequence order"
        );

        // Bounded per flush, so one slow peer cannot walk a huge backlog.
        assert_eq!(q.since(0, 7).len(), 7);
    }

    #[test]
    fn pruning_keeps_the_byte_total_honest() {
        let mut q = OutboundQueue::new();
        for _ in 0..10 {
            q.push(broadcast_block(1000));
        }
        let ten = q.bytes();
        assert_eq!(q.prune(4), 4, "everything at or below the cutoff goes");
        assert_eq!(q.len(), 6);
        assert_eq!(
            q.bytes(),
            ten / 10 * 6,
            "the byte total must come down with the entries"
        );
        assert_eq!(q.prune(0), 0, "a cutoff below the front drops nothing");
        q.prune(u64::MAX);
        assert_eq!(q.len(), 0);
        assert_eq!(q.bytes(), 0, "and back to zero when it empties");

        // Pruning must not roll the counter back either: a cursor ahead of it
        // reads as thousands of seqs of lag and gets the peer disconnected.
        // Eviction is covered by its own test; prune runs on EVERY flush.
        assert_eq!(q.seq, 10, "an emptied queue has still issued ten sequences");
        q.push(broadcast_block(1000));
        assert_eq!(q.seq, 11, "and the next push continues from there");
        assert_eq!(q.since(10, 512).len(), 1);
    }

    #[test]
    fn the_sequence_keeps_counting_when_entries_are_evicted() {
        // Peers' cursors are compared against the newest sequence, so it must
        // not be rolled back by an eviction: a cursor ahead of the counter
        // reads as thousands of seqs of lag and gets the peer disconnected.
        let mut q = OutboundQueue::with_limits(4, 1 << 20);
        for _ in 0..100 {
            q.push(broadcast_block(64));
        }
        assert_eq!(q.seq, 100, "a hundred pushes is a hundred sequences");
        assert!(q.len() < 100, "most of them were evicted");
        assert_eq!(
            q.since(q.seq, 512).len(),
            0,
            "and nothing sits past the newest sequence"
        );
    }

    // ── GetAddr is answered once per connection, and never when we dialled ─

    #[test]
    fn getaddr_is_answered_once_per_inbound_connection_and_never_outbound() {
        // GetAddr is absent from `token_cost`'s match, so it falls to
        // COST_MSG_DEFAULT = 1: a 13-byte request for a MAX_GETADDR_REPLY
        // answer of ~2.5 KiB, about 190x, repeatable at BUCKET_REFILL_RATE a
        // second. Megabytes a second of OUR upstream per peer, written
        // synchronously from the peer's own thread.
        let mut inbound = ConnectionSession::new("192.0.2.90:9333".parse().unwrap(), false);
        assert!(inbound.admit_getaddr(), "a peer that dialled us is answered");
        assert!(
            !inbound.admit_getaddr(),
            "and only once — this is the amplifier"
        );
        assert!(!inbound.admit_getaddr(), "the allowance does not come back");

        // We send GetAddr at exactly one site, in the handshake-completion arm,
        // so one answer per connection cannot cost us our own refresh.
        let mut outbound = ConnectionSession::new("192.0.2.91:9333".parse().unwrap(), true);
        assert!(
            !outbound.admit_getaddr(),
            "we chose this peer; it has no business asking for our address book"
        );
        assert!(
            !outbound.getaddr_answered,
            "and being refused for direction must not spend the allowance, \
             or the rule would depend on which check ran first"
        );
    }

    #[test]
    fn our_getaddr_reply_fits_what_the_receiver_will_accept() {
        // Including a receiver running this code: the reply must pass
        // validate_addr_list's per-message cap AND fit the address allowance,
        // or we would rate-limit our own honest answer. Both bounds are held
        // by the const assert at MAX_GETADDR_REPLY, which is compile-time and
        // needs no test; what needs one is the runtime consequence.
        let mut s = ConnectionSession::new("192.0.2.92:9333".parse().unwrap(), false);
        assert_eq!(
            s.take_addr_tokens(MAX_GETADDR_REPLY, false),
            MAX_GETADDR_REPLY,
            "a fresh connection admits a full reply from us in one message"
        );
    }

    // ── address processing has a rate, not just a per-message cap ─────────

    #[test]
    fn address_processing_is_rate_limited_after_the_first_burst() {
        // There was no bound on PROCESSING: COST_ADDR is ONE token for a
        // message carrying MAX_ADDR_PER_MSG = 1,000 addresses, so at
        // BUCKET_REFILL_RATE a peer could offer eight hundred thousand
        // addresses a second — each a routability parse and, past the queue, a
        // RocksDB write under the peer store's global mutex.
        let mut s = ConnectionSession::new("192.0.2.80:9333".parse().unwrap(), false);

        // The whole burst is there at once, which is what lets an honest peer
        // answer a GetAddr in one message.
        assert_eq!(
            s.take_addr_tokens(MAX_ADDR_PER_MSG, false),
            MAX_ADDR_PER_MSG
        );
        // And then nothing: at 0.1 a second the next token is ten seconds away.
        assert_eq!(s.take_addr_tokens(MAX_ADDR_PER_MSG, false), 0);

        // A short allowance grants what it has rather than refusing outright,
        // so a peer just over the line still gets most of its message through.
        s.addr_tokens = 4.0;
        assert_eq!(s.take_addr_tokens(10, false), 4);
        assert_eq!(s.take_addr_tokens(1, false), 0);

        // The rate itself: a hundred seconds owed buys ten tokens, not a full
        // burst. Backdated rather than slept, for the same reason the TTL and
        // the queue limits are parameters.
        s.addr_tokens = 0.0;
        s.addr_tokens_at = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .expect("the process has been up longer than that");
        assert_eq!(s.take_addr_tokens(50, false), 10);

        // A trusted seed is exempt and spends nothing: the fleet's own seeds
        // must be able to hand a lagging node a full address book.
        s.addr_tokens = 0.0;
        assert_eq!(s.take_addr_tokens(5_000, true), 5_000);
        assert_eq!(s.addr_tokens, 0.0, "and it cost them nothing");
    }

    #[test]
    fn an_addr_message_is_admitted_only_as_far_as_the_allowance_reaches() {
        // The allowance is SPENT by admitting, in one call, because the handler
        // that used to spend it per address cannot be unit-tested — it is
        // inside dispatch_message — and a control that deleted the spend went
        // unnoticed.
        let mut s = ConnectionSession::new("192.0.2.81:9333".parse().unwrap(), false);
        let list: Vec<String> = (0..10).map(|i| format!("203.0.113.{i}:9333")).collect();

        s.addr_tokens = 4.0;
        let (admitted, refused) = s.admit_addresses(&list, false);
        assert_eq!(admitted.len(), 4, "only as far as the allowance reaches");
        assert_eq!(refused, 6, "and the rest are refused, not silently kept");
        assert_eq!(admitted[0], list[0], "the prefix, in order");
        assert_eq!(admitted[3], list[3]);

        // The allowance is gone, so the next message of the same size is all
        // refused — which is what proves admitting SPENT it.
        let (admitted, refused) = s.admit_addresses(&list, false);
        assert!(admitted.is_empty());
        assert_eq!(refused, list.len());

        // A trusted seed is admitted whole.
        let (admitted, refused) = s.admit_addresses(&list, true);
        assert_eq!(admitted.len(), list.len());
        assert_eq!(refused, 0);
    }

    // ── the dial loop must ask the system that actually bans ──────────────

    #[test]
    fn the_dial_loop_will_not_dial_a_host_the_guard_has_banned() {
        // "Never dial a banned peer" asked peer_manager's PERSISTENT ban store,
        // which has no production writer — add_penalty and ban_peer are called
        // only from tests — so the gate always answered false and the loop kept
        // dialling hosts the live guard had banned, spending a dial budget that
        // 39f9d09 made deliberately scarce on connections whose every message
        // we then drop. Asking the live guard is affordable only because that
        // check is now a host-keyed pure READ.
        let path = "/tmp/p2p_reconnect_ban";
        let _ = std::fs::remove_dir_all(path);
        let pm = PeerManager::open(path).expect("peer store");

        let addr = "192.0.2.70:9333";
        assert!(reconnect_due(&pm, addr), "an unknown host is dialable");

        report_bad_peer_cat(
            addr,
            crate::service::network::dos_guard::BAN_SCORE_AUTOBAN,
            "invalid PoW",
            BanCategory::Malicious,
        );
        assert!(
            !reconnect_due(&pm, addr),
            "a host the live guard has banned must not be dialled"
        );
        assert!(
            !reconnect_due(&pm, "192.0.2.70:41122"),
            "nor on another of its ports — the ban belongs to the host"
        );
        // And the operator can see it, which is the other half of the same
        // defect: the RPC view read the same empty store.
        assert!(is_peer_banned("192.0.2.70:1"));
        assert!(banned_peers().iter().any(|(h, _)| h == "192.0.2.70"));
    }

    // ── the ban key is the host, so one offence must score once ───────────

    #[test]
    fn one_offence_scores_once_now_that_the_key_is_the_host() {
        // report_bad_peer used to score the `ip:port` key and then the IP
        // separately, so a reconnect on a fresh ephemeral port could not start
        // from zero. With the key normalised inside the guard both calls land
        // on the SAME record, and the second would double every penalty: a
        // 50-point offence would autoban on the first strike instead of the
        // second, and the eight pre-handshake arms scored 100 twice. Uses a
        // documentation-range address of its own, because DOS_GUARD is global.
        let peer = "192.0.2.50:51234";
        report_bad_peer(peer, 40, "bad block");
        assert_eq!(DOS_GUARD.get_ban_score(peer), 40, "40 points, scored once");

        report_bad_peer_cat(peer, 40, "bad tx", BanCategory::Malformed);
        assert_eq!(DOS_GUARD.get_ban_score(peer), 80);
        assert!(
            !DOS_GUARD.is_banned(peer),
            "two 40-point strikes are still under the autoban threshold"
        );

        // And the record is the host's, so the ban the third strike earns
        // cannot be shed by reconnecting from another port.
        report_bad_peer(peer, 40, "bad block");
        assert!(DOS_GUARD.is_banned("192.0.2.50:7777"));
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

    // ── the orphan pool keeps a block its first sender abandoned ───────

    fn orphan_test_block(hash: &str, parent: &str) -> Block {
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                vec![parent.to_string()],
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

    #[test]
    fn an_orphan_outlives_the_disconnect_of_the_peer_that_sent_it_first() {
        // `buffer_orphan` deduplicated on the HASH alone, so the second peer to
        // gossip an orphan was turned away with nothing stored for it, while
        // `cleanup_peer_state` deletes by PEER — so the first sender leaving took
        // the only copy. `PendingBlocks::retain_other_peers` states this exact
        // lesson for the queue one pool over: a hash-wide dedup makes one peer's
        // disconnect destroy a block several peers had handed us.
        let parent = "orphan_parent_outlives";
        let child = "orphan_child_outlives";
        buffer_orphan("orphan_peer_a", orphan_test_block(child, parent));
        buffer_orphan("orphan_peer_b", orphan_test_block(child, parent));

        cleanup_peer_state("orphan_peer_a");

        let ready = take_orphans_for_parent(parent);
        assert_eq!(
            ready.len(),
            1,
            "peer_b handed us this block too, so it must still be here"
        );
        assert_eq!(ready[0].1.header.hash, child);
        assert_eq!(ready[0].0, "orphan_peer_b", "attributed to who still has it");
        assert!(
            take_orphans_for_parent(parent).is_empty(),
            "and taking it removes it"
        );
    }

    #[test]
    fn one_sender_cannot_buffer_the_same_orphan_twice() {
        // Per-sender keying must not become no keying: a peer that repeats an
        // orphan would otherwise multiply its own footprint in a pool bounded
        // only by entry count, and evict other peers' orphans to do it.
        let parent = "orphan_parent_once";
        let child = "orphan_child_once";
        buffer_orphan("orphan_peer_c", orphan_test_block(child, parent));
        buffer_orphan("orphan_peer_c", orphan_test_block(child, parent));
        buffer_orphan("orphan_peer_c", orphan_test_block(child, parent));
        assert_eq!(
            take_orphans_for_parent(parent).len(),
            1,
            "one sender, one copy"
        );
    }

    fn sized_orphan(hash: &str, parent: &str, pad: usize) -> Block {
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                vec![parent.to_string()],
                "p".repeat(pad),
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

    fn assert_orphan_accounting(pool: &OrphanPool) {
        let entries: usize = pool.by_peer.values().map(|po| po.blocks.len()).sum();
        assert_eq!(entries, pool.len(), "the entry count drifted from the pool");
        let bytes: usize = pool.by_peer.values().map(|po| po.bytes).sum();
        assert_eq!(bytes, pool.bytes(), "the byte count drifted from the pool");
        for (peer, po) in &pool.by_peer {
            assert!(!po.blocks.is_empty(), "an empty peer row was left behind: {peer}");
            let own: usize = po.blocks.iter().map(|(_, size, _)| *size).sum();
            assert_eq!(own, po.bytes, "{peer}'s own byte total drifted");
        }
    }

    #[test]
    fn the_orphan_pool_accounting_survives_every_mutation() {
        // Two running totals and a per-peer total, all mutated on four paths. A
        // drifted count would either refuse orphans the pool has room for or
        // never evict at all, and neither shows up as a wrong block.
        let mut pool = OrphanPool::new();
        assert_orphan_accounting(&pool);

        pool.push("a", sized_orphan("h1", "p1", 16));
        pool.push("a", sized_orphan("h2", "p2", 32));
        pool.push("b", sized_orphan("h3", "p1", 64));
        assert_eq!(pool.len(), 3);
        assert_orphan_accounting(&pool);

        // A repeat from the same sender is refused and changes nothing.
        pool.push("a", sized_orphan("h1", "p1", 16));
        assert_eq!(pool.len(), 3, "a sender's repeat is not stored twice");
        assert_orphan_accounting(&pool);

        // Taking by parent frees both totals.
        let ready = pool.take_for_parent("p1");
        assert_eq!(ready.len(), 2, "a's h1 and b's h3 both list p1");
        assert_eq!(pool.len(), 1);
        assert_orphan_accounting(&pool);

        // Dropping a departed peer frees what it held, and only that.
        pool.push("b", sized_orphan("h4", "p9", 128));
        assert_eq!(pool.remove_peer("a"), 1);
        assert_eq!(pool.remove_peer("a"), 0, "removing twice is not a double free");
        assert_orphan_accounting(&pool);
        assert_eq!(pool.len(), 1, "b's own orphan is untouched");

        pool.drop_oldest_for("b");
        assert_eq!(pool.len(), 0);
        assert!(pool.by_peer.is_empty(), "the last entry takes its row with it");
        assert_orphan_accounting(&pool);
    }

    #[test]
    fn a_peer_may_buffer_a_whole_fork_heal_walk_of_orphans() {
        // The bound that must NOT bite. A backward walk buffers one orphan per
        // level until the ancestor arrives, and orphan_worth_resolving admits
        // orphans within FINALITY_DEPTH of the tip — so a per-peer cap below
        // that would make this pool refuse precisely the heal it exists for.
        let depth = crate::engine::consensus::reorg::FINALITY_DEPTH as usize;
        let mut pool = OrphanPool::new();
        for i in 0..depth {
            pool.push("healer", sized_orphan(&format!("h{i}"), &format!("p{i}"), 8));
        }
        assert_eq!(pool.len(), depth, "every level of the walk is still buffered");
        assert_orphan_accounting(&pool);
        // And the level that would exceed it costs the OLDEST, not the newest:
        // dropping the arrival would stall the walk at its deepest point.
        pool.push("healer", sized_orphan("h_last", "p_last", 8));
        assert_eq!(pool.len(), depth);
        assert!(
            !pool.take_for_parent("p_last").is_empty(),
            "the newest arrival is kept"
        );
        assert!(
            pool.take_for_parent("p0").is_empty(),
            "and the oldest is what made room"
        );
    }

    #[test]
    fn a_peer_cannot_spend_more_orphan_bytes_than_its_own_quota() {
        // Entry count alone bounded nothing: a Block payload is admitted up to
        // MAX_MESSAGE_SIZE, so the old 5,000-entry cap was tens of gigabytes.
        let mut pool = OrphanPool::new();
        let chunk = 1024 * 1024;
        for i in 0..(MAX_ORPHAN_BYTES_PER_PEER / chunk + 2) {
            pool.push("fat", sized_orphan(&format!("f{i}"), &format!("fp{i}"), chunk));
        }
        assert!(
            pool.bytes() <= MAX_ORPHAN_BYTES_PER_PEER,
            "one peer held {} bytes, over its {} quota",
            pool.bytes(),
            MAX_ORPHAN_BYTES_PER_PEER
        );
        assert!(pool.len() > 0, "but it is not emptied either");
        assert_orphan_accounting(&pool);
    }

    #[test]
    fn a_global_orphan_overflow_is_charged_to_the_peer_holding_the_most() {
        // The property that keeps this from becoming a weapon: a flooder that
        // fills the pool must lose its OWN backlog, never the orphans another
        // peer is healing a fork with.
        let mut pool = OrphanPool::new();
        // One honest peer with a small, real heal in progress.
        pool.push("honest", sized_orphan("honest_1", "honest_parent", 8));
        // Fill to EXACTLY the global entry budget from peers that each stay
        // inside their own quota, the first padded so it is the heaviest. Going
        // one over here instead would make the fill itself charge that peer —
        // which is the mechanism working, but it destroys the precondition.
        let per = MAX_ORPHANS_PER_PEER;
        let mut placed = pool.len();
        let mut p = 0;
        while placed < MAX_ORPHAN_BLOCKS {
            let pad = if p == 0 { 4096 } else { 8 };
            let take = per.min(MAX_ORPHAN_BLOCKS - placed);
            for i in 0..take {
                pool.push(&format!("flood{p}"), sized_orphan(&format!("g{p}_{i}"), &format!("gp{p}_{i}"), pad));
            }
            placed += take;
            p += 1;
        }
        assert_eq!(pool.len(), MAX_ORPHAN_BLOCKS, "filled to the cap, not past it");
        assert_eq!(pool.heaviest_peer().as_deref(), Some("flood0"), "the padded peer holds the most");
        let before = pool.by_peer["flood0"].blocks.len();
        pool.push("newcomer", sized_orphan("new_1", "new_parent", 8));
        assert!(
            pool.by_peer["flood0"].blocks.len() < before,
            "the overflow was charged to the heaviest holder"
        );
        assert!(
            !pool.take_for_parent("honest_parent").is_empty(),
            "and the honest peer's orphan was never touched"
        );
        assert!(pool.len() <= MAX_ORPHAN_BLOCKS, "the global entry cap holds");
        assert!(pool.bytes() <= MAX_ORPHAN_BYTES, "the global byte cap holds");
        assert_orphan_accounting(&pool);
    }

    #[test]
    fn one_sender_may_buffer_different_orphans() {
        // The key is (sender, hash), and it needs BOTH halves. Without the hash
        // a peer's first orphan would block every later one it sent, which is
        // how a node stops healing the fork it is actively downloading — and no
        // other test here notices, because each uses one orphan per sender.
        let p1 = "orphan_parent_many_1";
        let p2 = "orphan_parent_many_2";
        buffer_orphan("orphan_peer_d", orphan_test_block("orphan_child_many_1", p1));
        buffer_orphan("orphan_peer_d", orphan_test_block("orphan_child_many_2", p2));
        assert_eq!(take_orphans_for_parent(p1).len(), 1, "the first is kept");
        assert_eq!(take_orphans_for_parent(p2).len(), 1, "and so is the second");
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

    // ── the handshake must survive a real round-trip time ─────────────────

    use std::net::Ipv4Addr;

    /// Forwards one direction of a TCP stream, holding every chunk for `delay`.
    fn pump_with_delay(mut from: TcpStream, mut to: TcpStream, delay: Duration) {
        use std::io::{Read, Write};
        thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                match from.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = to.shutdown(std::net::Shutdown::Write);
                        break;
                    }
                    Ok(n) => {
                        thread::sleep(delay);
                        if to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    fn connect_from(source: Ipv4Addr, to: SocketAddr) -> TcpStream {
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .expect("socket");
        sock.bind(&SocketAddr::from((source, 0)).into())
            .expect("bind a loopback source");
        sock.connect(&to.into()).expect("connect");
        sock.into()
    }

    fn test_store(tag: &str) -> (Arc<PeerManager>, std::path::PathBuf) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "shadowdag_test_hs_{}_{}_{}",
            tag,
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let pm = Arc::new(PeerManager::new(dir.to_str().unwrap()).expect("peer store"));
        (pm, dir)
    }

    fn score_of(host: Ipv4Addr) -> u64 {
        let host = host.to_string();
        assert!(!crate::service::network::dos_guard::is_whitelisted(&host));
        DOS_GUARD.get_ban_score(&host)
    }

    fn foreign_version() -> P2PMessage {
        let vp = build_version_payload("ShadowDAG/test", 0, DEFAULT_BPS);
        P2PMessage::Version {
            version: vp.version,
            height: vp.height,
            timestamp: vp.timestamp,
            user_agent: vp.user_agent,
            bps: vp.bps,
            chain_id: vp.chain_id,
            services: vp.services,
            nonce: vp.nonce ^ 1,
        }
    }

    fn ended_on_the_deadline(outcome: &Result<(), NetworkError>) -> bool {
        matches!(outcome, Err(e) if e.to_string().contains(DEADLINE_ERROR_TEXT))
    }

    /// Run `f` on its own thread, so a connection that never ends fails the
    /// test at `recv_timeout` instead of hanging the suite.
    fn spawn_bounded<T: Send + 'static>(
        f: impl FnOnce() -> T + Send + 'static,
    ) -> std::sync::mpsc::Receiver<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx
    }

    const SHORT_STEP: Duration = Duration::from_millis(600);

    fn short_puzzle_step() -> HandshakeBudget {
        HandshakeBudget {
            puzzle_step: SHORT_STEP,
            version_exchange: VERSION_EXCHANGE_DEADLINE,
        }
    }

    fn read_challenge(client: &TcpStream) -> String {
        use crate::service::network::p2p::protocol::HandshakeState;
        client.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut reader = BufReader::new(DeadlineReader::new(client, Instant::now() + Duration::from_secs(10)));
        let mut dec = FrameDecoder::new();
        let gate = session_in(HandshakeState::Init);
        loop {
            match P2P::poll_frame(&mut reader, &mut dec, NetworkParams::REGTEST_MAGIC, &gate) {
                Ok(Some((P2PMessage::PuzzleChallenge { challenge }, _, _))) => return challenge,
                Ok(Some((_, cmd, _))) => panic!("expected a challenge, got {cmd}"),
                Ok(None) => {}
                Err(_) => panic!("no challenge arrived"),
            }
        }
    }

    fn solution_to(challenge: &str) -> Vec<u8> {
        let sol = ConnectionPuzzle::solve(challenge).expect("solvable");
        wire_frame(
            NetworkParams::REGTEST_MAGIC,
            &P2PMessage::PuzzleSolution {
                challenge: sol.challenge,
                nonce: sol.nonce,
                hash: sol.hash,
            },
        )
    }

    /// One connection at production budgets through a proxy that adds
    /// `one_way` in each direction, connects to the acceptor only after
    /// `one_way` so the dialer waits a full round trip for its challenge, and
    /// reaches the acceptor from `dialer_host`. Returns how each side ended and
    /// the score the acceptor gave that host.
    ///
    /// Both ends share this process's identity nonce, so the first Version
    /// either reads ends the connection as a self-connection inside the main
    /// loop, which returns Ok(()). Only a failure before the main loop returns
    /// an error, so Ok(()) on both sides means both completed the puzzle phase
    /// and sent their Version.
    fn puzzle_phase_across(one_way: Duration, dialer_host: Ipv4Addr) -> (String, String, u64) {
        let (acc_pm, acc_dir) = test_store("acc");
        let (dial_pm, dial_dir) = test_store("dial");
        let magic = NetworkParams::REGTEST_MAGIC;

        let acceptor = TcpListener::bind("127.0.0.1:0").expect("bind acceptor");
        let acceptor_addr = acceptor.local_addr().expect("acceptor addr");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");

        thread::spawn(move || {
            if let Ok((client, _)) = proxy.accept() {
                thread::sleep(one_way);
                let server = connect_from(dialer_host, acceptor_addr);
                let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                pump_with_delay(client, server, one_way);
                pump_with_delay(s2, c2, one_way);
            }
        });

        let as_text = |r: Result<(), NetworkError>| match r {
            Ok(()) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let acc = spawn_bounded(move || {
            let (stream, _) = acceptor.accept().expect("accept");
            as_text(P2P::handle_peer_connection(stream, false, magic, Vec::new(), acc_pm))
        });
        let dial = spawn_bounded(move || match TcpStream::connect(proxy_addr) {
            Ok(stream) => as_text(P2P::handle_peer_connection(stream, true, magic, Vec::new(), dial_pm)),
            Err(e) => format!("connect: {e}"),
        });

        let acceptor_outcome = acc
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| "still connected after 20 s".to_string());
        let dialer_outcome = dial
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| "still connected after 20 s".to_string());
        let score = score_of(dialer_host);
        SELF_ADDRS.lock().remove("127.0.0.1");
        SELF_ADDRS.lock().remove(&dialer_host.to_string());
        let _ = std::fs::remove_dir_all(&acc_dir);
        let _ = std::fs::remove_dir_all(&dial_dir);
        (acceptor_outcome, dialer_outcome, score)
    }

    fn assert_puzzle_phase_completes(one_way: Duration, dialer_host: Ipv4Addr) {
        let (acceptor, dialer, score) = puzzle_phase_across(one_way, dialer_host);
        assert_eq!(acceptor, "ok", "{one_way:?} each way: the acceptor ended: {acceptor}");
        assert_eq!(dialer, "ok", "{one_way:?} each way: the dialer ended: {dialer}");
        assert_eq!(score, 0, "{one_way:?} each way: the acceptor scored the dialer");
    }

    #[test]
    fn the_puzzle_phase_completes_across_a_local_link() {
        assert_puzzle_phase_completes(Duration::ZERO, Ipv4Addr::new(127, 0, 0, 61));
    }

    #[test]
    fn the_puzzle_phase_completes_across_an_intercontinental_round_trip() {
        assert_puzzle_phase_completes(Duration::from_millis(75), Ipv4Addr::new(127, 0, 0, 62));
    }

    #[test]
    fn the_puzzle_phase_completes_across_a_300_ms_round_trip() {
        assert_puzzle_phase_completes(Duration::from_millis(150), Ipv4Addr::new(127, 0, 0, 63));
    }

    #[test]
    fn an_acceptor_waits_out_its_step_for_a_silent_dialer_and_closes_unscored() {
        use crate::service::network::p2p::protocol::HandshakeState;
        let host = Ipv4Addr::new(127, 0, 0, 64);
        let (pm, dir) = test_store("silent_dialer");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let done = spawn_bounded(move || {
            let started = Instant::now();
            let r = P2P::handle_peer_connection_within(
                stream,
                false,
                NetworkParams::REGTEST_MAGIC,
                Vec::new(),
                pm,
                short_puzzle_step(),
            );
            (r, started.elapsed())
        });
        let got = read_frames(&client, &session_in(HandshakeState::Init), Duration::from_secs(10), |_| false)
            .unwrap_or_else(|e| panic!("{e}"));
        let (outcome, elapsed) = done.recv_timeout(Duration::from_secs(10)).expect("the step never ended");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ended_on_the_deadline(&outcome), "{outcome:?}");
        assert!(elapsed >= SHORT_STEP, "closed after {elapsed:?}, before its step ran out");
        let cmds: Vec<CommandId> = got.iter().map(|(c, _)| *c).collect();
        assert_eq!(cmds, vec![CommandId::PuzzleChallenge], "only the challenge may be written");
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn a_trickling_dialer_is_cut_at_the_step_not_carried_by_its_bytes() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        let host = Ipv4Addr::new(127, 0, 0, 65);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("trickle");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let frame = wire_frame(
            magic,
            &P2PMessage::PuzzleSolution {
                challenge: "0".repeat(64),
                nonce: 0,
                hash: "0".repeat(64),
            },
        );
        let stop = Arc::new(AtomicBool::new(false));
        let stop_writer = Arc::clone(&stop);
        let trickle = thread::spawn(move || {
            for b in frame {
                if stop_writer.load(Ordering::Relaxed) || (&client).write_all(&[b]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let done = spawn_bounded(move || {
            let started = Instant::now();
            let r = P2P::handle_peer_connection_within(stream, false, magic, Vec::new(), pm, short_puzzle_step());
            (r, started.elapsed())
        });
        let result = done.recv_timeout(Duration::from_secs(20));
        stop.store(true, Ordering::Relaxed);
        trickle.join().ok();
        let _ = std::fs::remove_dir_all(&dir);
        let (outcome, elapsed) = result.expect("the step never ended");
        assert!(ended_on_the_deadline(&outcome), "{outcome:?}");
        assert!(elapsed < Duration::from_secs(3), "a byte every 50 ms held the step for {elapsed:?}");
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn a_dialer_whose_acceptor_stays_silent_closes_unscored_having_sent_nothing() {
        use std::io::Read;
        let host = Ipv4Addr::new(127, 0, 0, 66);
        let (pm, dir) = test_store("silent_acceptor");
        let listener = TcpListener::bind((host, 0)).expect("bind");
        let dial = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (theirs, _) = listener.accept().expect("accept");
        let done = spawn_bounded(move || {
            let started = Instant::now();
            let r = P2P::handle_peer_connection_within(
                dial,
                true,
                NetworkParams::REGTEST_MAGIC,
                Vec::new(),
                pm,
                short_puzzle_step(),
            );
            (r, started.elapsed())
        });
        theirs.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut sent = Vec::new();
        let _ = (&theirs).read_to_end(&mut sent);
        let (outcome, elapsed) = done.recv_timeout(Duration::from_secs(10)).expect("the step never ended");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ended_on_the_deadline(&outcome), "{outcome:?}");
        assert!(elapsed >= SHORT_STEP, "gave up after {elapsed:?}, before its step ran out");
        assert!(sent.is_empty(), "wrote {} bytes to a peer that never challenged it", sent.len());
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn a_dialer_sent_another_handshake_command_first_closes_unscored_without_answering() {
        use std::io::{Read, Write};
        let magic = NetworkParams::REGTEST_MAGIC;
        let cases = [
            (Ipv4Addr::new(127, 0, 0, 71), foreign_version()),
            (Ipv4Addr::new(127, 0, 0, 74), P2PMessage::VerAck),
            (
                Ipv4Addr::new(127, 0, 0, 75),
                P2PMessage::PuzzleSolution {
                    challenge: "0".repeat(64),
                    nonce: 0,
                    hash: "0".repeat(64),
                },
            ),
            (Ipv4Addr::new(127, 0, 0, 76), P2PMessage::Reject { reason: "busy".to_string() }),
        ];
        for (host, first) in cases {
            let cmd = P2P::msg_to_command_id(&first);
            let (pm, dir) = test_store("no_challenge");
            let listener = TcpListener::bind((host, 0)).expect("bind");
            let dial = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
            let (theirs, _) = listener.accept().expect("accept");
            (&theirs).write_all(&wire_frame(magic, &first)).unwrap();
            let done = spawn_bounded(move || P2P::handle_peer_connection(dial, true, magic, Vec::new(), pm));
            theirs.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut sent = Vec::new();
            let _ = (&theirs).read_to_end(&mut sent);
            let outcome = done.recv_timeout(Duration::from_secs(10)).expect("the dialer never ended");
            let _ = std::fs::remove_dir_all(&dir);
            let text = format!("{outcome:?}");
            assert!(text.contains("Expected PuzzleChallenge"), "{cmd}: {text}");
            assert!(sent.is_empty(), "{cmd}: answered a peer that skipped the puzzle with {} bytes", sent.len());
            assert_eq!(score_of(host), 0, "{cmd}");
        }
    }

    #[test]
    fn an_acceptor_sent_another_handshake_command_instead_of_a_solution_closes_unscored() {
        use std::io::Write;
        let magic = NetworkParams::REGTEST_MAGIC;
        let cases = [
            (Ipv4Addr::new(127, 0, 0, 67), foreign_version()),
            (Ipv4Addr::new(127, 0, 0, 77), P2PMessage::VerAck),
            (
                Ipv4Addr::new(127, 0, 0, 78),
                P2PMessage::PuzzleChallenge {
                    challenge: ConnectionPuzzle::generate_challenge().challenge,
                },
            ),
            (Ipv4Addr::new(127, 0, 0, 79), P2PMessage::Reject { reason: "busy".to_string() }),
        ];
        for (host, sent_instead) in cases {
            let cmd = P2P::msg_to_command_id(&sent_instead);
            let (pm, dir) = test_store("no_solution");
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let client = connect_from(host, listener.local_addr().expect("addr"));
            let (stream, _) = listener.accept().expect("accept");
            let done = spawn_bounded(move || P2P::handle_peer_connection(stream, false, magic, Vec::new(), pm));
            thread::sleep(Duration::from_millis(100));
            (&client).write_all(&wire_frame(magic, &sent_instead)).unwrap();
            let outcome = done.recv_timeout(Duration::from_secs(10)).expect("the acceptor never ended");
            drop(client);
            let _ = std::fs::remove_dir_all(&dir);
            let text = format!("{outcome:?}");
            assert!(text.contains("Expected PuzzleSolution"), "{cmd}: {text}");
            assert_eq!(score_of(host), 0, "{cmd}");
        }
    }

    #[test]
    fn an_invalid_solution_still_scores_100() {
        use std::io::Write;
        let host = Ipv4Addr::new(127, 0, 0, 80);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("invalid_solution");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let done = spawn_bounded(move || P2P::handle_peer_connection(stream, false, magic, Vec::new(), pm));
        let challenge = read_challenge(&client);
        let sol = ConnectionPuzzle::solve(&challenge).expect("solvable");
        let forged = P2PMessage::PuzzleSolution {
            challenge: sol.challenge,
            nonce: sol.nonce.wrapping_add(1),
            hash: sol.hash,
        };
        (&client).write_all(&wire_frame(magic, &forged)).unwrap();
        let outcome = done.recv_timeout(Duration::from_secs(10)).expect("the acceptor never ended");
        drop(client);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(format!("{outcome:?}").contains("Invalid puzzle solution"), "{outcome:?}");
        assert_eq!(score_of(host), 100);
    }

    #[test]
    fn a_solution_and_a_version_in_one_write_are_both_answered() {
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        let host = Ipv4Addr::new(127, 0, 0, 68);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("coalesced");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let done = spawn_bounded(move || P2P::handle_peer_connection(stream, false, magic, Vec::new(), pm));
        let mut both = solution_to(&read_challenge(&client));
        both.extend(wire_frame(magic, &foreign_version()));
        (&client).write_all(&both).unwrap();
        let got = read_frames(&client, &session_in(HandshakeState::AwaitVersion), Duration::from_secs(5), |f| {
            f.iter().any(|(c, _)| *c == CommandId::VerAck)
        });
        drop(client);
        let _ = done.recv_timeout(Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.iter().any(|(c, _)| *c == CommandId::VerAck),
            "the coalesced Version went unanswered: {got:?}"
        );
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn an_acceptor_past_its_puzzle_step_still_completes_the_version_exchange() {
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        let host = Ipv4Addr::new(127, 0, 0, 72);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("acceptor_past_step");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let started = Instant::now();
        let done = spawn_bounded(move || {
            P2P::handle_peer_connection_within(stream, false, magic, Vec::new(), pm, short_puzzle_step())
        });
        (&client).write_all(&solution_to(&read_challenge(&client))).unwrap();
        let mut version_sent = false;
        let got = read_frames(&client, &session_in(HandshakeState::AwaitVersion), Duration::from_secs(20), |f| {
            if !version_sent && started.elapsed() >= SHORT_STEP * 3 {
                (&client).write_all(&wire_frame(magic, &foreign_version())).unwrap();
                version_sent = true;
            }
            f.iter().any(|(c, _)| *c == CommandId::VerAck)
        });
        drop(client);
        let _ = done.recv_timeout(Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("{e}"));
        assert!(version_sent, "the acceptor closed before the Version was due: {got:?}");
        assert!(
            got.iter().any(|(c, _)| *c == CommandId::VerAck),
            "the acceptor did not answer a Version that came after its puzzle step: {got:?}"
        );
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn a_peer_trickling_its_version_is_cut_at_the_version_exchange_deadline() {
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        let host = Ipv4Addr::new(127, 0, 0, 73);
        let magic = NetworkParams::REGTEST_MAGIC;
        let budget = HandshakeBudget {
            puzzle_step: SHORT_STEP,
            version_exchange: Duration::from_millis(1500),
        };
        let (pm, dir) = test_store("version_trickle");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = connect_from(host, listener.local_addr().expect("addr"));
        let (stream, _) = listener.accept().expect("accept");
        let started = Instant::now();
        let done = spawn_bounded(move || P2P::handle_peer_connection_within(stream, false, magic, Vec::new(), pm, budget));
        (&client).write_all(&solution_to(&read_challenge(&client))).unwrap();
        let version = wire_frame(magic, &foreign_version());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_writer = Arc::clone(&stop);
        let writer = client.try_clone().expect("clone");
        let trickle = thread::spawn(move || {
            for b in version {
                if stop_writer.load(Ordering::Relaxed) || (&writer).write_all(&[b]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(60));
            }
        });
        let got = read_frames(&client, &session_in(HandshakeState::AwaitVersion), Duration::from_secs(15), |_| false);
        let ended_after = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        trickle.join().ok();
        drop(client);
        let _ = done.recv_timeout(Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !got.iter().any(|(c, _)| *c == CommandId::VerAck),
            "a Version trickled past the deadline was answered: {got:?}"
        );
        assert!(
            ended_after < Duration::from_millis(3500),
            "a byte every 60 ms held the Version exchange for {ended_after:?}"
        );
        assert_eq!(score_of(host), 0);
    }

    #[test]
    fn a_challenge_that_arrives_after_the_puzzle_phase_is_never_solved() {
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        let host = Ipv4Addr::new(127, 0, 0, 69);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("late_challenge");
        let listener = TcpListener::bind((host, 0)).expect("bind");
        let dial = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let done = spawn_bounded(move || P2P::handle_peer_connection(dial, true, magic, Vec::new(), pm));
        let (theirs, _) = listener.accept().expect("accept");
        let challenge = || P2PMessage::PuzzleChallenge {
            challenge: ConnectionPuzzle::generate_challenge().challenge,
        };
        (&theirs).write_all(&wire_frame(magic, &challenge())).unwrap();
        let mut second_sent: Option<Instant> = None;
        let got = read_frames(&theirs, &session_in(HandshakeState::AwaitVersion), Duration::from_secs(20), |f| {
            match second_sent {
                Some(t) => t.elapsed() >= Duration::from_millis(500),
                None if f.iter().any(|(c, _)| *c == CommandId::Version) => {
                    (&theirs).write_all(&wire_frame(magic, &challenge())).unwrap();
                    second_sent = Some(Instant::now());
                    false
                }
                None => false,
            }
        });
        drop(theirs);
        let _ = done.recv_timeout(Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("{e}"));
        assert!(second_sent.is_some(), "the dialer never sent its Version: {got:?}");
        let solutions = got.iter().filter(|(c, _)| *c == CommandId::PuzzleSolution).count();
        assert_eq!(solutions, 1, "a challenge after the puzzle phase was solved: {got:?}");
        assert_eq!(score_of(host), 10);
    }

    #[test]
    fn a_dialer_past_its_puzzle_step_still_completes_the_version_exchange() {
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        let host = Ipv4Addr::new(127, 0, 0, 70);
        let magic = NetworkParams::REGTEST_MAGIC;
        let (pm, dir) = test_store("past_step");
        let listener = TcpListener::bind((host, 0)).expect("bind");
        let dial = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let started = Instant::now();
        let done = spawn_bounded(move || {
            P2P::handle_peer_connection_within(dial, true, magic, Vec::new(), pm, short_puzzle_step())
        });
        let (theirs, _) = listener.accept().expect("accept");
        (&theirs)
            .write_all(&wire_frame(
                magic,
                &P2PMessage::PuzzleChallenge {
                    challenge: ConnectionPuzzle::generate_challenge().challenge,
                },
            ))
            .unwrap();
        let mut version_sent = false;
        let got = read_frames(&theirs, &session_in(HandshakeState::AwaitVersion), Duration::from_secs(20), |f| {
            if !version_sent
                && started.elapsed() >= SHORT_STEP * 3
                && f.iter().any(|(c, _)| *c == CommandId::Version)
            {
                (&theirs).write_all(&wire_frame(magic, &foreign_version())).unwrap();
                version_sent = true;
            }
            f.iter().any(|(c, _)| *c == CommandId::VerAck)
        });
        drop(theirs);
        let _ = done.recv_timeout(Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("{e}"));
        assert!(version_sent, "the dialer never sent its Version: {got:?}");
        assert!(
            got.iter().any(|(c, _)| *c == CommandId::VerAck),
            "the dialer did not answer a Version that came after its puzzle step: {got:?}"
        );
        assert_eq!(score_of(host), 0);
    }

    /// Write one frame split at `split`, with `pause` between the halves, and
    /// read it the way the main loop does: `read_message` under the 100 ms
    /// SO_RCVTIMEO, retried on a transient timeout. Returns the nonce read back,
    /// or what went wrong.
    fn read_split_frame(split: usize, pause: Duration) -> Result<u64, String> {
        use std::io::Write;
        let magic = NetworkParams::REGTEST_MAGIC;
        let nonce = 0x5AD0_C0DE_u64;
        let payload = bincode::serialize(&P2PMessage::Ping { nonce }).unwrap();
        let mut frame = WireHeader::for_payload(magic, CommandId::Ping as u8, &payload).encode().to_vec();
        frame.extend_from_slice(&payload);
        assert!(split > 0 && split < frame.len(), "the split must fall inside the frame");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let writer = thread::spawn(move || {
            let mut out = TcpStream::connect(addr).expect("connect");
            out.set_nodelay(true).ok();
            out.write_all(&frame[..split]).unwrap();
            out.flush().unwrap();
            thread::sleep(pause);
            out.write_all(&frame[split..]).unwrap();
            out.flush().unwrap();
            thread::sleep(Duration::from_secs(1));
        });

        let (stream, _) = listener.accept().expect("accept");
        stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut reader = BufReader::new(DeadlineReader::new(
            &stream,
            Instant::now() + Duration::from_secs(10),
        ));
        let mut proto = ProtocolSession::new(false, 10);
        proto.state = crate::service::network::p2p::protocol::HandshakeState::Established;

        // One decoder for the whole read, as the connection has: the point is
        // that a frame interrupted by a pause is resumed, not restarted.
        let mut decoder = FrameDecoder::new();
        let started = Instant::now();
        let result = loop {
            match P2P::read_message(&mut reader, &mut decoder, magic, &proto) {
                Ok((P2PMessage::Ping { nonce: n }, _, _)) => break Ok(n),
                Ok((_, cmd, _)) => break Err(format!("read the wrong message: {cmd}")),
                Err(ReadStop::Failed(e)) if is_transient_read_timeout(&e.to_string().to_lowercase()) => {
                    if started.elapsed() > Duration::from_secs(3) {
                        break Err("no message within 3 s".to_string());
                    }
                }
                Err(ReadStop::Failed(e)) => break Err(format!("stream desynchronised: {e}")),
                Err(ReadStop::Premature { reason, .. }) => break Err(format!("premature: {reason}")),
            }
        };
        writer.join().ok();
        result
    }

    // ── no relay before the handshake ────────────────────────────────────

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let ours = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (theirs, _) = listener.accept().expect("accept");
        (ours, theirs)
    }

    /// The frames that arrive on `stream`, decoded under `proto`'s gate, until
    /// `done` holds or `window` has passed: each frame's command, and the nonce
    /// when it is a Ping. Polls at least once, so a stalled test thread cannot
    /// return before reading what is already buffered. A frame the gate refuses
    /// ends the read as an Err naming its command.
    fn read_frames(
        stream: &TcpStream,
        proto: &ProtocolSession,
        window: Duration,
        mut done: impl FnMut(&[(CommandId, Option<u64>)]) -> bool,
    ) -> Result<Vec<(CommandId, Option<u64>)>, String> {
        stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut reader = BufReader::new(DeadlineReader::new(stream, Instant::now() + Duration::from_secs(60)));
        let mut dec = FrameDecoder::new();
        let end = Instant::now() + window;
        let mut out = Vec::new();
        loop {
            match P2P::poll_frame(&mut reader, &mut dec, NetworkParams::REGTEST_MAGIC, proto) {
                Ok(Some((P2PMessage::Ping { nonce }, cmd, _))) => out.push((cmd, Some(nonce))),
                Ok(Some((_, cmd, _))) => out.push((cmd, None)),
                Ok(None) => {}
                Err(ReadStop::Premature { cmd, .. }) => return Err(format!("the gate refused {cmd}")),
                Err(ReadStop::Failed(_)) => break,
            }
            if done(&out) || Instant::now() >= end {
                break;
            }
        }
        Ok(out)
    }

    fn pings(frames: &[(CommandId, Option<u64>)]) -> Vec<u64> {
        frames.iter().filter_map(|(_, n)| *n).collect()
    }

    fn has_ping(frames: &[(CommandId, Option<u64>)], nonce: u64) -> bool {
        frames.iter().any(|(_, n)| *n == Some(nonce))
    }

    fn established_connection_session(peer: &str) -> ConnectionSession {
        let mut session = ConnectionSession::new(peer.parse().unwrap(), false);
        session.protocol.state = crate::service::network::p2p::protocol::HandshakeState::Established;
        session
    }

    #[test]
    fn a_session_still_in_its_handshake_is_relayed_nothing_and_holds_no_cursor() {
        // The two states the main loop flushes in before VerAck: our Version
        // sent, and the peer's Version answered. A peer in either scores
        // anything outside the handshake commands 50 Malicious and closes. The
        // broadcast is pushed after the session's creation, so a gate around the
        // cursor alone would still deliver it, and the targeted message is
        // written by any flush that runs at all.
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        for (i, state) in [HandshakeState::AwaitVersion, HandshakeState::AwaitPeerVerAck]
            .into_iter()
            .enumerate()
        {
            let (ours, theirs) = socket_pair();
            let peer = format!("203.0.113.51:{}", 12001 + i);
            let mut session = ConnectionSession::new(peer.parse().unwrap(), false);
            session.protocol.state = state;
            push_outbound(P2PMessage::Ping { nonce: 0x51_0000_0001 + i as u64 });
            push_outbound_to_peer(&peer, P2PMessage::Ping { nonce: 0x51_0000_0011 + i as u64 });
            let mut writer = BufWriter::new(&ours);
            assert!(P2P::flush_outbound(&mut writer, &peer, &mut session, NetworkParams::REGTEST_MAGIC));
            writer.flush().unwrap();
            assert!(session.relay_cursor.is_none(), "no cursor in {state:?}");
            assert!(
                !PEER_LAST_OUTBOUND.lock().contains_key(&peer),
                "a peer still in its handshake must not be in the pruning minimum"
            );
            let got = read_frames(&theirs, &established_session(), Duration::from_millis(300), |_| false)
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(got.is_empty(), "nothing at all may be written in {state:?}: {got:?}");
            assert_eq!(
                drain_targeted_for(&peer).len(),
                1,
                "a message targeted at a peer in its handshake must wait for it, not be dropped"
            );
        }
    }

    #[test]
    fn relay_starts_after_the_handshake_with_only_what_comes_next() {
        // Only future broadcasts, the same rule the cursor has always started
        // under: the backlog reaches a new peer through its own sync.
        use std::io::Write;
        let (ours, theirs) = socket_pair();
        let peer = "203.0.113.52:12002";
        {
            let mut session = established_connection_session(peer);
            let mut writer = BufWriter::new(&ours);
            push_outbound(P2PMessage::Ping { nonce: 0x52_0000_000A });
            assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
            assert!(PEER_LAST_OUTBOUND.lock().contains_key(peer), "relay starts on the first established flush");
            push_outbound(P2PMessage::Ping { nonce: 0x52_0000_000B });
            assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
            writer.flush().unwrap();
            // One writer in sequence order, so a replayed A would arrive before B.
            let got = read_frames(&theirs, &established_session(), Duration::from_secs(5), |f| {
                has_ping(f, 0x52_0000_000B)
            })
            .unwrap_or_else(|e| panic!("{e}"));
            assert!(!has_ping(&got, 0x52_0000_000A), "a broadcast from before relay started was replayed");
            assert!(has_ping(&got, 0x52_0000_000B), "a broadcast pushed after relay started was lost");
        }
        assert!(
            !PEER_LAST_OUTBOUND.lock().contains_key(peer),
            "the cursor goes with the session"
        );
    }

    #[test]
    fn every_broadcast_between_flushes_of_an_established_peer_is_delivered() {
        // Relay must start ONCE. Restarting it on every flush would move the
        // cursor past whatever was pushed since the previous flush, so a peer
        // that keeps sending would silently miss blocks, transactions and the
        // GetHeaders that drives its own sync.
        use std::io::Write;
        let (ours, theirs) = socket_pair();
        let peer = "203.0.113.53:12003";
        let mut session = established_connection_session(peer);
        let mut writer = BufWriter::new(&ours);
        assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
        push_outbound(P2PMessage::Ping { nonce: 0x53_0000_000C });
        assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
        push_outbound(P2PMessage::Ping { nonce: 0x53_0000_000D });
        assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
        writer.flush().unwrap();
        let got = read_frames(&theirs, &established_session(), Duration::from_secs(5), |f| {
            has_ping(f, 0x53_0000_000C) && has_ping(f, 0x53_0000_000D)
        })
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            has_ping(&got, 0x53_0000_000C) && has_ping(&got, 0x53_0000_000D),
            "got {:?}",
            pings(&got)
        );
    }

    #[test]
    fn a_relayed_peer_rejoins_the_pruning_minimum_when_another_connection_drops_its_entry() {
        // Two live connections can share one peer string, and the first to
        // close removes the shared entry. The survivor's next flush must put it
        // back, or the survivor stays outside the pruning minimum until
        // something else seeds that key, and other peers' drains prune
        // broadcasts it has not been sent.
        let (ours, _theirs) = socket_pair();
        let peer = "203.0.113.54:12004";
        let mut session = established_connection_session(peer);
        let other = OutboundCursor::seed(peer, current_outbound_seq());
        let mut writer = BufWriter::new(&ours);
        assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
        drop(other);
        assert!(!PEER_LAST_OUTBOUND.lock().contains_key(peer));
        assert!(P2P::flush_outbound(&mut writer, peer, &mut session, NetworkParams::REGTEST_MAGIC));
        assert!(
            PEER_LAST_OUTBOUND.lock().contains_key(peer),
            "the surviving connection was left out of the pruning minimum"
        );
    }

    #[test]
    fn a_connection_still_in_its_handshake_does_not_hold_back_pruning() {
        // The pruning minimum is taken over every entry in PEER_LAST_OUTBOUND. A
        // cursor seeded at connect, for a peer that cannot be relayed to until
        // its handshake completes, cannot advance either: every connection kept
        // in its handshake would hold back the broadcast queue's pruning until
        // its deadline, the profile of the leak 964f55b closed. This covers the
        // acceptor up to its puzzle read; the dialer test covers the main loop.
        let dir = std::env::temp_dir().join(format!("shadowdag_test_relaygate_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pm = Arc::new(PeerManager::new(dir.to_str().unwrap()).expect("peer store"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let key = client.local_addr().expect("client addr").to_string();
        let (stream, _) = listener.accept().expect("accept");
        let worker = thread::spawn(move || {
            let _ = P2P::handle_peer_connection(stream, false, NetworkParams::REGTEST_MAGIC, Vec::new(), pm);
        });
        let end = Instant::now() + Duration::from_millis(300);
        let mut seen = false;
        while Instant::now() < end && !worker.is_finished() {
            if PEER_LAST_OUTBOUND.lock().contains_key(&key) {
                seen = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        drop(client);
        worker.join().ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!seen, "a connection in its handshake took a place in the pruning minimum");
    }

    #[test]
    fn a_dialled_peer_kept_in_its_handshake_is_relayed_nothing() {
        // The window the gate exists for, through the production path: our
        // dialer has solved the puzzle and sent its Version, the main loop is
        // running its idle flushes, and the peer never answers. The peer reads
        // under the gate a peer in that state applies, so anything relayed is
        // refused and named rather than silently read.
        use crate::service::network::p2p::protocol::HandshakeState;
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("shadowdag_test_relaygate_dial_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pm = Arc::new(PeerManager::new(dir.to_str().unwrap()).expect("peer store"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let key = listener.local_addr().expect("addr").to_string();
        let dial = TcpStream::connect(&key).expect("connect");
        let worker = thread::spawn(move || {
            let _ = P2P::handle_peer_connection(dial, true, NetworkParams::REGTEST_MAGIC, Vec::new(), pm);
        });
        let (theirs, _) = listener.accept().expect("accept");
        let challenge = ConnectionPuzzle::generate_challenge();
        (&theirs)
            .write_all(&wire_frame(
                NetworkParams::REGTEST_MAGIC,
                &P2PMessage::PuzzleChallenge { challenge: challenge.challenge.clone() },
            ))
            .unwrap();
        let mut held_since: Option<Instant> = None;
        let mut cursor_seen = false;
        let got = read_frames(&theirs, &session_in(HandshakeState::Init), Duration::from_secs(20), |f| {
            if PEER_LAST_OUTBOUND.lock().contains_key(&key) {
                cursor_seen = true;
            }
            let since = held_since;
            match since {
                Some(t) => t.elapsed() >= Duration::from_millis(400),
                None if f.iter().any(|(c, _)| *c == CommandId::Version) => {
                    held_since = Some(Instant::now());
                    push_outbound(P2PMessage::Ping { nonce: 0x55_0000_000E });
                    push_outbound_to_peer(&key, P2PMessage::Ping { nonce: 0x55_0000_000F });
                    false
                }
                None => false,
            }
        });
        let held = drain_targeted_for(&key);
        drop(theirs);
        worker.join().ok();
        let _ = std::fs::remove_dir_all(&dir);
        let got = got.unwrap_or_else(|e| panic!("relayed to a peer in its handshake: {e}"));
        assert!(held_since.is_some(), "the dialer never sent its Version: {got:?}");
        assert!(!cursor_seen, "a connection in its handshake took a place in the pruning minimum");
        assert_eq!(held.len(), 1, "a message targeted at a peer in its handshake must wait for it");
    }

    // ── the frame decoder ─────────────────────────────────────────────────

    fn wire_frame(magic: [u8; 4], msg: &P2PMessage) -> Vec<u8> {
        let payload = bincode::serialize(msg).unwrap();
        let cmd = P2P::msg_to_command_id(msg) as u8;
        let mut frame = WireHeader::for_payload(magic, cmd, &payload).encode().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    fn session_in(state: crate::service::network::p2p::protocol::HandshakeState) -> ProtocolSession {
        let mut p = ProtocolSession::new(false, 10);
        p.state = state;
        p
    }

    fn established_session() -> ProtocolSession {
        session_in(crate::service::network::p2p::protocol::HandshakeState::Established)
    }

    /// Feed `input` in the given chunk sizes and collect every frame, checking
    /// after each call that the decoder made progress and that the payload
    /// buffer never ran further ahead of the data than the look-ahead allows.
    fn feed_in_chunks(
        input: &[u8],
        chunks: &mut dyn Iterator<Item = usize>,
        proto: &ProtocolSession,
    ) -> Result<Vec<Frame>, ReadStop> {
        let magic = NetworkParams::REGTEST_MAGIC;
        let mut dec = FrameDecoder::new();
        let mut frames = Vec::new();
        let mut at = 0;
        let mut turns = 0usize;
        while at < input.len() {
            turns += 1;
            assert!(turns <= input.len() + 16, "the decoder stopped making progress");
            let n = chunks.next().unwrap_or(1).max(1).min(input.len() - at);
            let mut slice = &input[at..at + n];
            while !slice.is_empty() {
                let (used, frame) = dec.feed(slice, magic, proto)?;
                assert!(
                    used > 0 || frame.is_some(),
                    "feed took nothing from {} bytes and returned no frame",
                    slice.len()
                );
                if let DecodeStage::Payload { declared, buf, .. } = &dec.stage {
                    assert!(
                        buf.capacity() <= (buf.len() + PAYLOAD_LOOKAHEAD).min(*declared),
                        "payload buffer at {} of {} bytes ran {} ahead",
                        buf.len(),
                        declared,
                        buf.capacity() - buf.len()
                    );
                }
                slice = &slice[used..];
                at += used;
                if let Some(f) = frame {
                    frames.push(f);
                }
            }
        }
        Ok(frames)
    }

    fn frame_identity(f: &Frame) -> (CommandId, usize, Vec<u8>) {
        (f.1, f.2, bincode::serialize(&f.0).unwrap())
    }

    #[test]
    fn the_decoder_reads_a_stream_byte_by_byte_exactly_as_it_reads_it_whole() {
        let magic = NetworkParams::REGTEST_MAGIC;
        let msgs = vec![
            P2PMessage::Ping { nonce: 7 },
            P2PMessage::Pong { nonce: 8 },
            P2PMessage::Addr { peers: vec!["198.51.100.7:19333".to_string(); 40] },
            P2PMessage::GetBlock { hash: "ab".repeat(32) },
            P2PMessage::Block { data: (0..5000u32).map(|i| (i * 31) as u8).collect() },
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            stream.extend(wire_frame(magic, m));
        }
        let proto = established_session();
        let whole = feed_in_chunks(&stream, &mut std::iter::repeat(stream.len()), &proto)
            .unwrap_or_else(|_| panic!("whole stream failed"));
        let single = feed_in_chunks(&stream, &mut std::iter::repeat(1), &proto)
            .unwrap_or_else(|_| panic!("byte-by-byte stream failed"));
        assert_eq!(whole.len(), msgs.len());
        assert_eq!(
            whole.iter().map(frame_identity).collect::<Vec<_>>(),
            single.iter().map(frame_identity).collect::<Vec<_>>(),
            "how the bytes are split must not change what is read"
        );
    }

    #[test]
    fn a_large_block_in_random_chunks_is_read_intact_without_overallocating() {
        // 1.5 MiB: six look-ahead steps. Chunk sizes from a small LCG, 1 B to
        // 64 KiB, so every boundary lands somewhere different.
        let magic = NetworkParams::REGTEST_MAGIC;
        let data: Vec<u8> = (0..1_572_864u32).map(|i| (i ^ (i >> 7)) as u8).collect();
        let stream = wire_frame(magic, &P2PMessage::Block { data: data.clone() });
        let mut state = 0x2545_F491_u64;
        let mut chunks = std::iter::from_fn(move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Some(1 + (state >> 33) as usize % 65_536)
        });
        let frames = feed_in_chunks(&stream, &mut chunks, &established_session())
            .unwrap_or_else(|_| panic!("the large block failed to decode"));
        assert_eq!(frames.len(), 1);
        match &frames[0].0 {
            P2PMessage::Block { data: got } => assert!(got == &data, "the block came back altered"),
            _ => panic!("decoded the wrong message"),
        }
    }

    #[test]
    fn a_declared_payload_is_not_allocated_before_it_arrives() {
        // Bitcoin Core's 2024 receive-buffer disclosure: a peer that declares
        // 4 MiB and sends one byte must not cost us 4 MiB.
        let magic = NetworkParams::REGTEST_MAGIC;
        let header = WireHeader {
            magic,
            command_id: CommandId::Block as u8,
            payload_len: MAX_MESSAGE_SIZE as u32,
            checksum: [0; 4],
        }
        .encode();
        let mut dec = FrameDecoder::new();
        let mut input = header.to_vec();
        input.push(0);
        let (used, frame) = dec
            .feed(&input, magic, &established_session())
            .unwrap_or_else(|_| panic!("a valid header was refused"));
        assert_eq!(used, input.len());
        assert!(frame.is_none());
        match &dec.stage {
            DecodeStage::Payload { buf, .. } => assert!(
                buf.capacity() <= 1 + PAYLOAD_LOOKAHEAD,
                "allocated {} bytes for 1 byte of payload",
                buf.capacity()
            ),
            _ => panic!("the decoder should be inside the payload"),
        }
    }

    #[test]
    fn feed_never_consumes_past_the_message_it_completes() {
        // The next header must be gated under the state the caller moves to
        // after dispatching this message. VerAck is what completes the
        // handshake, and GetAddr is refused before it: consuming GetAddr's
        // header in the same call would gate it under the old state and score
        // an honest peer 50.
        use crate::service::network::p2p::protocol::HandshakeState;
        let magic = NetworkParams::REGTEST_MAGIC;
        let verack = wire_frame(magic, &P2PMessage::VerAck);
        let getaddr = wire_frame(magic, &P2PMessage::GetAddr);
        let mut input = verack.clone();
        input.extend_from_slice(&getaddr);

        let mut dec = FrameDecoder::new();
        let before = session_in(HandshakeState::AwaitPeerVerAck);
        let (used, frame) = dec
            .feed(&input, magic, &before)
            .unwrap_or_else(|_| panic!("VerAck was refused"));
        assert_eq!(used, verack.len(), "consumed past the end of the VerAck frame");
        assert!(matches!(frame, Some((P2PMessage::VerAck, _, _))));

        let after = established_session();
        let (used, frame) = dec
            .feed(&input[verack.len()..], magic, &after)
            .unwrap_or_else(|_| panic!("GetAddr was refused once established"));
        assert_eq!(used, getaddr.len());
        assert!(matches!(frame, Some((P2PMessage::GetAddr, _, _))));
    }

    #[derive(Debug, PartialEq)]
    enum Outcome {
        Read(CommandId),
        Failed,
        Premature(u64),
    }

    /// The gate sequence `read_message` ran before the decoder existed, on a
    /// complete frame: validate_header, check_command_allowed,
    /// validate_payload_size, checksum, deserialize.
    fn reference_outcome(frame: &[u8], magic: [u8; 4], proto: &ProtocolSession) -> Outcome {
        let mut hdr = [0u8; WIRE_HEADER_SIZE];
        hdr.copy_from_slice(&frame[..WIRE_HEADER_SIZE]);
        let header = WireHeader::decode(&hdr);
        let Ok(cmd) = validate_header(&header, magic) else { return Outcome::Failed };
        if let Err(pe) = proto.check_command_allowed(cmd) {
            return Outcome::Premature(pe.ban_score as u64);
        }
        if validate_payload_size(cmd, header.payload_len as usize).is_err() {
            return Outcome::Failed;
        }
        let payload = &frame[WIRE_HEADER_SIZE..];
        if payload.len() < header.payload_len as usize {
            return Outcome::Failed;
        }
        let payload = &payload[..header.payload_len as usize];
        if validate_payload_checksum(payload, header.checksum).is_err() {
            return Outcome::Failed;
        }
        match bounded_deserialize::<P2PMessage>(payload) {
            Ok(_) => Outcome::Read(cmd),
            Err(_) => Outcome::Failed,
        }
    }

    fn decoder_outcome(frame: &[u8], magic: [u8; 4], proto: &ProtocolSession) -> Outcome {
        let mut dec = FrameDecoder::new();
        let mut slice = frame;
        loop {
            match dec.feed(slice, magic, proto) {
                Ok((_, Some((_, cmd, _)))) => return Outcome::Read(cmd),
                Ok((used, None)) => {
                    if used >= slice.len() {
                        return Outcome::Failed; // ran out of input: the frame was short
                    }
                    slice = &slice[used..];
                }
                Err(ReadStop::Failed(_)) => return Outcome::Failed,
                Err(ReadStop::Premature { ban_score, .. }) => return Outcome::Premature(ban_score),
            }
        }
    }

    #[test]
    fn the_decoder_gates_and_scores_exactly_as_read_message_did() {
        // Only check_command_allowed's score is ever applied, so the ORDER of
        // the gates is the scoring rule. Compare against the old sequence.
        use crate::service::network::p2p::protocol::HandshakeState;
        let magic = NetworkParams::REGTEST_MAGIC;
        let raw = |m: [u8; 4], cmd: u8, len: u32, payload: &[u8], good_sum: bool| {
            let mut h = WireHeader { magic: m, command_id: cmd, payload_len: len, checksum: [0; 4] };
            if good_sum {
                h.checksum = WireHeader::for_payload(m, cmd, payload).checksum;
            }
            let mut f = h.encode().to_vec();
            f.extend_from_slice(payload);
            f
        };
        let ping = bincode::serialize(&P2PMessage::Ping { nonce: 1 }).unwrap();
        let version = vec![0u8; 2000];
        let init = session_in(HandshakeState::Init);
        let est = established_session();
        let cases: Vec<(&str, Vec<u8>, &ProtocolSession)> = vec![
            ("pre-handshake Block over the wire maximum", raw(magic, CommandId::Block as u8, (MAX_MESSAGE_SIZE + 1) as u32, &[], false), &init),
            ("pre-handshake Block with an empty payload", raw(magic, CommandId::Block as u8, 0, &[], false), &init),
            ("pre-handshake Ping", raw(magic, CommandId::Ping as u8, ping.len() as u32, &ping, true), &init),
            ("pre-handshake Ping declaring 100 bytes", raw(magic, CommandId::Ping as u8, 100, &[0; 100], true), &init),
            ("Version after the handshake", raw(magic, CommandId::Version as u8, 2000, &version, true), &est),
            ("wrong magic", raw([1, 2, 3, 4], CommandId::Ping as u8, ping.len() as u32, &ping, true), &est),
            ("unknown command", raw(magic, 0xEE, ping.len() as u32, &ping, true), &est),
            ("payload shorter than the command allows", raw(magic, CommandId::Ping as u8, 2, &[0, 0], true), &est),
            ("bad checksum", raw(magic, CommandId::Ping as u8, ping.len() as u32, &ping, false), &est),
            ("undeserialisable payload", raw(magic, CommandId::Ping as u8, 12, &[0xFF; 12], true), &est),
            ("a good Ping", raw(magic, CommandId::Ping as u8, ping.len() as u32, &ping, true), &est),
        ];
        for (name, frame, proto) in cases {
            assert_eq!(
                decoder_outcome(&frame, magic, proto),
                reference_outcome(&frame, magic, proto),
                "{name}"
            );
        }
    }

    #[test]
    fn a_frame_cut_off_by_the_peer_closing_is_a_failure_not_a_wait() {
        use std::io::Write;
        let magic = NetworkParams::REGTEST_MAGIC;
        let frame = wire_frame(magic, &P2PMessage::Ping { nonce: 9 });
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let writer = thread::spawn(move || {
            let mut out = TcpStream::connect(addr).expect("connect");
            out.write_all(&frame[..10]).unwrap();
        });
        let (stream, _) = listener.accept().expect("accept");
        writer.join().ok();
        stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut reader = BufReader::new(DeadlineReader::new(&stream, Instant::now() + Duration::from_secs(5)));
        let mut dec = FrameDecoder::new();
        let proto = established_session();
        let started = Instant::now();
        let result = loop {
            match P2P::poll_frame(&mut reader, &mut dec, magic, &proto) {
                Ok(None) if started.elapsed() < Duration::from_secs(3) => continue,
                other => break other,
            }
        };
        assert!(
            matches!(result, Err(ReadStop::Failed(_))),
            "a peer that hangs up mid-frame must end the read"
        );
    }

    #[test]
    fn a_spent_deadline_ends_the_read_through_the_decoder_too() {
        // The deadline error is ErrorKind::TimedOut, the same kind as an idle
        // poll. poll_frame must classify it by its text, as before, or the
        // pre-handshake deadline would turn into an idle tick for ever.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let _client = TcpStream::connect(addr).expect("connect");
        let (stream, _) = listener.accept().expect("accept");
        stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut reader = BufReader::new(DeadlineReader::new(&stream, Instant::now()));
        let mut dec = FrameDecoder::new();
        let result = P2P::poll_frame(&mut reader, &mut dec, NetworkParams::REGTEST_MAGIC, &established_session());
        assert!(
            matches!(result, Err(ReadStop::Failed(_))),
            "a spent deadline must be fatal, not an idle poll"
        );
    }

    #[test]
    fn a_frame_split_by_a_retransmission_pause_is_read_intact() {
        // A frame whose bytes stop arriving for longer than the 100 ms poll —
        // which one lost packet does over a real link, where the minimum TCP
        // retransmission timeout is 200 ms — used to lose the bytes read_exact
        // had already consumed. The main loop treats the timeout as an idle tick
        // and starts a fresh 13-byte header in the middle of the old frame.
        // Split inside the header, then inside the payload.
        for split in [7, WIRE_HEADER_SIZE + 5] {
            let got = read_split_frame(split, Duration::from_millis(250));
            assert_eq!(got, Ok(0x5AD0_C0DE), "split at byte {split}");
        }
    }

    #[test]
    fn a_frame_that_arrives_whole_is_read_intact() {
        // The control for the split test: same harness, no pause.
        assert_eq!(read_split_frame(7, Duration::ZERO), Ok(0x5AD0_C0DE));
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
    fn the_deadline_fires_only_once_it_has_passed() {
        // The two halves the drip test cannot assert without a clock: an armed
        // reader whose deadline is already behind it refuses the FIRST read, and
        // an armed reader whose deadline is ahead of it does not interfere at
        // all. Together they rule out a guard that fires early — which would
        // otherwise look exactly like the deadline working.
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut past = DeadlineReader::new(
            DripReader {
                reads: Arc::clone(&reads),
            },
            Instant::now(),
        );
        let mut one = [0u8; 1];
        let err = past
            .read(&mut one)
            .expect_err("a deadline already behind us must refuse the read");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), DEADLINE_ERROR_TEXT);
        assert_eq!(
            reads.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "and must refuse it without reaching the socket"
        );

        // A deadline far enough ahead that no scheduler can reach it: the read
        // must complete untouched. `repeat` never sleeps, so this is instant.
        let mut future = DeadlineReader::new(
            std::io::repeat(0x42),
            Instant::now() + Duration::from_secs(3_600),
        );
        let mut buf = [0u8; 4096];
        future
            .read_exact(&mut buf)
            .expect("an armed deadline must not interfere before it passes");
        assert!(buf.iter().all(|b| *b == 0x42));

        // And a disarmed reader is out of the way for good, which is what the
        // established connection relies on.
        future.disarm();
        future.read_exact(&mut buf).expect("disarmed must not fire");
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
        // Evidence that the DEADLINE ended this, and not something else. NOT a
        // lower bound on the recv count: that needed two recvs inside the 50 ms
        // budget while the drip's 1 ms sleep is ~15.6 ms on Windows, a margin of
        // three quanta, so one deschedule under the full suite's parallelism
        // turned it red. `the_deadline_fires_only_once_it_has_passed` below
        // proves the same thing without a clock.
        let recvs = reads.load(std::sync::atomic::Ordering::Relaxed);
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
