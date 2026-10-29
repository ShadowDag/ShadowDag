// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::NetworkError;
use crate::service::network::dos_guard::BanCategory;
use crate::{slog_error, slog_warn};
use rocksdb::{Direction, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BAN_DURATION_SECS: u64 = 86_400;
pub const BAN_DURATION_SEVERE_SECS: u64 = 7 * 86_400;
pub const AUTO_BAN_THRESHOLD: u64 = 100;
pub const SCORE_DECAY_INTERVAL: u64 = 3_600;
pub const MAX_ADDR_CACHE_SIZE: usize = 4_096;
pub const MAX_GETADDR_RESPONSE: usize = 200;
pub const MAX_PEERS_PER_IP: u32 = 3;
pub const PEER_HEALTH_TIMEOUT_SECS: u64 = 300;
/// Hard cap on persisted peer records (anti-DoS: bounds the `peer:` keyspace so
/// an attacker flooding valid-but-distinct addresses cannot grow the DB without
/// bound). Counted via the `meta:peer_count` key (NOT under `peer:`).
pub const MAX_STORED_PEERS: u64 = 16_384;
/// Meta key holding the live count of `peer:` records. Deliberately outside the
/// `peer:` prefix so it is never counted/iterated as a peer.
const PEER_COUNT_KEY: &[u8] = b"meta:peer_count";
/// Records examined while looking for one to evict, per admitted address once
/// the store is at capacity.
///
/// Small on purpose. An eviction happens once per admitted address once the
/// store is saturated, and at `MAX_ADDR_PER_MSG` = 1,000 addresses per Addr
/// message, a sample of k is k thousand record reads per message — a scoring
/// sample large enough to choose a GOOD victim would cost more than the full
/// scan this same change removes. So the victim is the next record in a
/// rotating walk: O(1) in the normal case, whole-store coverage over time, and
/// impossible to starve or to target by gossiping low-sorting addresses.
///
/// Not one, though: the budget has to absorb a run of whitelisted records at
/// the cursor without failing an insert that thousands of evictable records
/// could have satisfied.
const EVICT_SCAN_LIMIT: usize = 16;

/// How recent a handshake must be before a tried record is protected outright.
/// Bitcoin Core's ADDRMAN_REPLACEMENT (src/addrman.h): "How recent a successful
/// connection should be before we allow an address to be evicted from tried".
///
/// This is also why there is no separate one-minute guard like the one
/// IsTerrible opens with. Bitcoin needs that override because IsTerrible has
/// several independent clauses that could each fire on a freshly tried record;
/// here there is exactly ONE path to evicting a tried record and it is gated on
/// this window, so a record handshaked moments ago is already protected. A
/// grace constant beside this one would be a branch that cannot change an
/// outcome — a negative control caught it as such.
const TRIED_REPLACEMENT_SECS: u64 = 4 * 3_600;

const PFX_BAN: &str = "ban:";
const PFX_PENALTY: &str = "penalty:";
/// Legacy parallel address table. NOTHING READS IT any more: the advertise
/// and discovery paths were moved onto `peer:`, which is the table the live
/// Addr ingest actually fills. Its writers (`store_addr`, `add_addr_batch`) are
/// still called by `bootstrap_for_network` and by the never-constructed
/// `PeerDiscovery`, so removing the prefix means gutting that module too —
/// left for its own change rather than done halfway here.
const PFX_ADDR: &str = "addr:";
const PFX_PEER: &str = "peer:";
const PFX_LAST_SEEN: &str = "seen:";
const PFX_CONN_COUNT: &str = "conn:";
const PFX_LATENCY: &str = "latency:";
const PFX_HEIGHT: &str = "height:";
const PFX_BAN_COUNT: &str = "bancnt:";
const PFX_BAN_CAT: &str = "bancat:";
/// When we last completed a handshake with this address.
///
/// Its own prefix rather than a `PeerRecord` field: the record is bincode, which
/// is not self-describing, so adding a field makes every record already on disk
/// fail to deserialize — and the readers here swallow that with `.ok()`, so a
/// live peer DB would go silently half-blind. `seen:`, `height:` and `latency:`
/// are kept beside the record for the same reason.
const PFX_TRIED: &str = "tried:";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr: String,
    pub port: u16,
    pub first_seen: u64,
    pub last_seen: u64,
    pub services: u64,
    pub user_agent: String,
    pub best_height: u64,
    pub latency_ms: u64,
    pub ban_score: u64,
    pub is_banned: bool,
    pub ban_until: u64,
    pub inbound: bool,
    pub version: u32,
}

impl PeerRecord {
    pub fn new(addr: &str, port: u16) -> Self {
        let now = unix_now();
        Self {
            addr: addr.to_string(),
            port,
            first_seen: now,
            last_seen: now,
            services: 0,
            user_agent: String::new(),
            best_height: 0,
            latency_ms: 9999,
            ban_score: 0,
            is_banned: false,
            ban_until: 0,
            inbound: false,
            version: 1,
        }
    }

    pub fn is_active(&self) -> bool {
        // `now - self.last_seen` was an unsigned subtraction. `last_seen` is
        // only ever written as `unix_now()`, so a remote peer cannot poison it,
        // but a backwards clock step — an NTP correction, a restored VM
        // snapshot — makes it exceed `now`: a panic in debug, and in release a
        // wrap to a huge number, which read as inactive and silently dropped
        // the peer.
        //
        // `is_banned` is a stored field that nothing ever sets to true, so that
        // half of this predicate is inert. It is left alone deliberately: the
        // record is bincode'd into RocksDB with a `version: 1`, so removing a
        // field would stop existing peer stores deserialising. The live ban
        // state is in the DoS guard, and the readers that matter ask it.
        let now = unix_now();
        !self.is_banned && now.saturating_sub(self.last_seen) < PEER_HEALTH_TIMEOUT_SECS
    }

    pub fn health_score(&self) -> i64 {
        let latency_penalty = (self.latency_ms / 100) as i64;
        let ban_penalty = self.ban_score as i64 * 2;
        100_i64 - latency_penalty - ban_penalty
    }
}

static PEER_MANAGER_INSTANCE: OnceLock<Arc<PeerManager>> = OnceLock::new();

pub struct PeerManager {
    db: Arc<Mutex<DB>>,
    addr_cache: Arc<Mutex<Vec<String>>>,
    /// Where the next capacity eviction resumes its walk of `peer:`.
    ///
    /// A fixed start would evict the same lexicographically-first records over
    /// and over while the rest of the store sat untouched, and whoever gossips
    /// low-sorting addresses gets to choose which records those are.
    evict_cursor: Arc<Mutex<Vec<u8>>>,
    _network_path: String,
    network: crate::config::node::node_config::NetworkMode,
}

impl PeerManager {
    pub fn global(path: &str) -> Result<Arc<Self>, NetworkError> {
        // Fast path: already initialised.
        if let Some(pm) = PEER_MANAGER_INSTANCE.get() {
            // Warn if caller requests a different path than what was initialised.
            // OnceLock returns the same instance regardless of path after first init,
            // which silently ignores the new path. This makes the mismatch visible.
            if pm._network_path != path {
                slog_error!("p2p", "peer_manager_path_mismatch_singleton_already_bound",
                    requested => path,
                    active => &pm._network_path,
                    hint => "OnceLock returns the existing instance — the requested path is ignored. \
                             This is a configuration bug: all callers must agree on the peer DB path."
                );
            }
            return Ok(pm.clone());
        }

        // Try primary path, then fallback, then temp.
        // WARNING: falling back to a different DB path means ALL peer reputation
        // data (ban scores, penalty history, connection counts) starts fresh.
        // There is no automatic migration between DB paths.
        let pm = Self::open(path).or_else(|e| {
            slog_warn!("p2p", "peer_db_open_failed", path => path, error => &e.to_string());
            let fallback = format!("{}_fallback", path);
            slog_warn!("p2p", "peer_db_fallback_reputation_reset",
                primary_path => path,
                fallback_path => &fallback,
                impact => "All peer reputation state (bans, penalties, latency history) will be fresh. \
                           Previously banned peers will be unbanned."
            );
            Self::open(&fallback)
        }).or_else(|e| {
            slog_warn!("p2p", "peer_db_fallback_failed", error => &e.to_string());
            let temp = std::env::temp_dir().join(format!("shadowdag_peer_emergency_{}", std::process::id()));
            slog_error!("p2p", "peer_db_emergency_fallback_reputation_reset",
                temp_path => &temp.to_string_lossy().to_string(),
                impact => "Using emergency temp DB — ALL peer reputation is lost. \
                           Node is vulnerable to previously-banned peers until reputation rebuilds."
            );
            Self::open(temp.to_str().unwrap_or("/tmp/shadowdag_peer_emergency"))
        })?;

        let arc = Arc::new(pm);
        // Another thread may have raced us — that's fine, use whichever won.
        let _ = PEER_MANAGER_INSTANCE.set(arc.clone());
        Ok(PEER_MANAGER_INSTANCE.get().cloned().unwrap_or(arc))
    }

    pub fn open(path: &str) -> Result<Self, NetworkError> {
        Self::open_for_network(path, crate::config::node::node_config::NetworkMode::Mainnet)
    }

    /// Open with explicit network mode so bootstrap seeds match the network.
    pub fn open_for_network(
        path: &str,
        network: crate::config::node::node_config::NetworkMode,
    ) -> Result<Self, NetworkError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(32 * 1024 * 1024);
        opts.set_max_open_files(64);
        let db = DB::open(&opts, Path::new(path)).map_err(|e| {
            NetworkError::Storage(crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })
        })?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            addr_cache: Arc::new(Mutex::new(Vec::new())),
            evict_cursor: Arc::new(Mutex::new(Vec::new())),
            _network_path: path.to_string(),
            network,
        })
    }

    pub fn new(path: &str) -> Option<Self> {
        match Self::open(path) {
            Ok(mgr) => Some(mgr),
            Err(e) => {
                slog_error!("p2p", "peer_manager_open_failed", path => path, error => &e.to_string());
                None
            }
        }
    }

    pub fn new_default() -> Result<Self, NetworkError> {
        let base = crate::config::node::node_config::NetworkMode::base_data_dir();
        let primary = base.join("peers");
        let fallback = base.join("peers_fallback");
        let temp =
            std::env::temp_dir().join(format!("shadowdag_peer_emergency_{}", std::process::id()));

        let paths = [
            primary.to_string_lossy().to_string(),
            fallback.to_string_lossy().to_string(),
            temp.to_string_lossy().to_string(),
        ];

        let mut last_err = None;
        for p in &paths {
            match Self::open(p) {
                Ok(pm) => return Ok(pm),
                Err(e) => {
                    slog_warn!("p2p", "peer_db_open_failed", path => p.as_str(), error => &e.to_string());
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| NetworkError::Other("all peer DB paths exhausted".to_string())))
    }

    /// Create a PeerManager with a unique temp path (for tests).
    /// Create a temporary PeerManager for testing.
    /// Returns a fallback in-memory default if DB creation fails.
    #[cfg(test)]
    pub fn new_temp() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/shadowdag_peer_test_{}_{}", std::process::id(), id);
        Self::open(&path)
            .or_else(|_| Self::new_default())
            .expect("new_temp: cannot open any DB for testing")
    }

    pub fn new_default_path(path: &str) -> Result<Self, NetworkError> {
        Self::open(path)
            .or_else(|e| {
                slog_warn!("p2p", "peer_db_open_failed", path => path, error => &e.to_string());
                let fallback = format!("{}_fallback", path);
                Self::open(&fallback)
            })
            .or_else(|e| {
                slog_warn!("p2p", "peer_db_fallback_failed", error => &e.to_string());
                let temp = std::env::temp_dir()
                    .join(format!("shadowdag_peer_emergency_{}", std::process::id()));
                Self::open(temp.to_str().unwrap_or("/tmp/shadowdag_peer_emergency"))
            })
    }

    fn lock_db(&self) -> std::sync::MutexGuard<'_, DB> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Iterate exactly one key prefix: seek to it, stop at its end.
    ///
    /// Every reader here used `IteratorMode::Start` with a `starts_with` filter,
    /// which walks the WHOLE database and discards what does not match — while
    /// holding the process-global DB mutex. `addr:` sorts first of the ten
    /// prefixes, so the one reader that had a `take` limit never reached it
    /// (only the configured seeds are ever written there) and scanned
    /// everything, once per inbound TCP connection.
    fn prefix_iter<'a>(
        db: &'a DB,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a {
        db.iterator(IteratorMode::From(prefix, Direction::Forward))
            .filter_map(|r| r.ok())
            .take_while(move |(k, _)| k.starts_with(prefix))
    }

    /// Ban check against an ALREADY-LOCKED db, read-only.
    ///
    /// `is_banned` also deletes an expired record, which cannot be done from
    /// inside a read loop over the same database.
    fn is_banned_inner(db: &DB, addr: &str) -> bool {
        match db.get(format!("{}{}", PFX_BAN, addr).as_bytes()) {
            Ok(Some(data)) if data.len() == 8 => {
                let until = <[u8; 8]>::try_from(&data[..8])
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);
                unix_now() < until
            }
            // Corrupted record: fail CLOSED, exactly as `is_banned` does.
            Ok(Some(_)) => true,
            _ => false,
        }
    }

    pub fn add_peer(&self, addr: &str) -> Result<(), NetworkError> {
        let port = addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9333);
        self.add_peer_record(PeerRecord::new(addr, port))
    }

    /// Live count of persisted `peer:` records, via the `meta:peer_count` key.
    /// Lazily initialised (once) by iterating the `peer:` prefix if the key is
    /// absent. Takes the held DB guard to avoid re-locking.
    fn stored_peer_count_inner(db: &DB) -> u64 {
        if let Ok(Some(v)) = db.get(PEER_COUNT_KEY) {
            if v.len() == 8 {
                return u64::from_le_bytes(v[..8].try_into().unwrap_or([0u8; 8]));
            }
        }
        // Lazy init: count existing peer records once, then persist the count.
        let n = Self::prefix_iter(db, PFX_PEER.as_bytes()).count() as u64;
        let _ = db.put(PEER_COUNT_KEY, n.to_le_bytes());
        n
    }

    pub fn add_peer_record(&self, record: PeerRecord) -> Result<(), NetworkError> {
        if Self::extract_ip(&record.addr)
            .parse::<std::net::IpAddr>()
            .is_err()
        {
            return Err(NetworkError::ConnectionFailed(format!(
                "peer address is not a resolved IP: {}",
                record.addr
            )));
        }
        if self.is_banned(&record.addr) {
            return Err(NetworkError::PeerBanned(record.addr.clone()));
        }

        let ip = Self::extract_ip(&record.addr);

        let data =
            bincode::serialize(&record).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let db = self.lock_db();

        // Per-IP cap read + all writes under ONE lock hold, so the check-then-write
        // is atomic: concurrent adds for the same IP can no longer both pass the cap
        // and each persist count+1 (which exceeded MAX_PEERS_PER_IP and corrupted
        // the counter).
        let count = Self::conn_count_for_ip_inner(&db, ip);
        if count >= MAX_PEERS_PER_IP {
            return Err(NetworkError::ConnectionFailed(format!(
                "IP {} already has {} connections",
                ip, count
            )));
        }

        let already_exists = db
            .get(format!("{}{}", PFX_PEER, record.addr).as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false);

        // Anti-DoS: bound the total number of persisted peer records. Only NEW
        // peers grow the store, so the cap is checked for those only.
        //
        // The cap used to be a REFUSAL, and nothing in the process ever removes
        // a `peer:` record — `remove_peer` has no production caller, nothing
        // ages a record out, and the store is RocksDB-backed. So the first
        // peer to claim all MAX_STORED_PEERS slots froze the store for the life
        // of the data directory: every later address was refused, including the
        // configured seeds, since `bootstrap_for_network` admits them through
        // this same function. At MAX_ADDR_PER_MSG = 1,000 that cost one peer
        // about 17 messages.
        let whitelisted = crate::service::network::dos_guard::is_whitelisted(ip);
        let stored = Self::stored_peer_count_inner(&db);
        let mut batch = WriteBatch::default();
        let mut evicted = false;
        // Set when the victim is on the SAME IP as the address being admitted.
        // Then one record leaves and one arrives on that IP, so its count must
        // not move at all: staging a decrement and an increment for one key in
        // one batch keeps only the second, which ratcheted the count upward and
        // refused an IP that was under the real limit.
        let mut victim_shares_ip = false;
        if !already_exists && stored >= MAX_STORED_PEERS && !whitelisted {
            match Self::evict_candidate_inner(&db, &self.evict_cursor) {
                Some(victim) => {
                    Self::stage_peer_delete(&mut batch, &victim);
                    if Self::extract_ip(&victim) == ip {
                        victim_shares_ip = true;
                    } else {
                        Self::stage_conn_decrement(&db, &mut batch, Self::extract_ip(&victim));
                    }
                    evicted = true;
                }
                None => {
                    return Err(NetworkError::ConnectionFailed(format!(
                        "peer store at capacity ({} records) and nothing evictable",
                        MAX_STORED_PEERS
                    )));
                }
            }
        }

        let key = format!("{}{}", PFX_PEER, record.addr);
        batch.put(key.as_bytes(), &data);
        batch.put(
            format!("{}{}", PFX_LAST_SEEN, record.addr).as_bytes(),
            unix_now().to_le_bytes(),
        );
        // Only increment conn_count + the global peer count if this is a NEW peer
        if !already_exists {
            let next = if victim_shares_ip { count } else { count + 1 };
            batch.put(
                format!("{}{}", PFX_CONN_COUNT, ip).as_bytes(),
                next.to_le_bytes(),
            );
            // One in, one out leaves the count where it was. A whitelisted
            // address admitted over the cap raises it: counted, never refused,
            // and bounded by how many addresses are whitelisted.
            if !evicted {
                batch.put(PEER_COUNT_KEY, stored.saturating_add(1).to_le_bytes());
            }
        }
        db.write(batch).map_err(|e| {
            NetworkError::Storage(crate::errors::StorageError::WriteFailed(e.to_string()))
        })
    }

    /// Stage the deletion of one peer record and all of its satellite keys.
    ///
    /// The single place that knows which keys make up a peer, so an eviction
    /// and a `remove_peer` cannot drift apart and leave a `seen:`/`height:`/
    /// `latency:`/`tried:` key orphaned behind a deleted `peer:`. (0460ef4
    /// claimed the two shared this list when they were in fact two parallel
    /// copies; `remove_peer` now really does call it.)
    fn stage_peer_delete(batch: &mut WriteBatch, addr: &str) {
        batch.delete(format!("{}{}", PFX_PEER, addr).as_bytes());
        batch.delete(format!("{}{}", PFX_LAST_SEEN, addr).as_bytes());
        batch.delete(format!("{}{}", PFX_HEIGHT, addr).as_bytes());
        batch.delete(format!("{}{}", PFX_LATENCY, addr).as_bytes());
        batch.delete(format!("{}{}", PFX_TRIED, addr).as_bytes());
    }

    /// Stage the per-IP connection count going DOWN by one, DELETING the key
    /// when it reaches zero.
    ///
    /// Writing a zero leaves a live key behind for ever. That was harmless
    /// while nothing ever removed a peer record, because then a `conn:` key
    /// existed only for an IP with a live record and the whole keyspace was
    /// bounded by MAX_STORED_PEERS. Once the cap started EVICTING, the number
    /// of IPs that have ever been admitted became unbounded, and a zero left
    /// behind per IP made the cap stop bounding the keyspace it exists for.
    fn stage_conn_decrement(db: &DB, batch: &mut WriteBatch, ip: &str) {
        let key = format!("{}{}", PFX_CONN_COUNT, ip);
        match Self::conn_count_for_ip_inner(db, ip) {
            0 => {}
            1 => batch.delete(key.as_bytes()),
            n => batch.put(key.as_bytes(), (n - 1).to_le_bytes()),
        }
    }

    /// The next evictable `peer:` record, walking the prefix from a rotating
    /// cursor so coverage is eventual and no key can be starved or targeted.
    ///
    /// Ranked rather than blind, which is what `tried:` bought:
    /// - a whitelisted address is never evicted — removing a configured seed is
    ///   the lockout this whole line of work exists to undo;
    /// - an UNTRIED record is taken first, so an attacker's gossip can only ever
    ///   displace other unverified gossip, never a peer we have talked to;
    /// - a tried record is a last resort, and only once its handshake is older
    ///   than `TRIED_REPLACEMENT_SECS`, so a peer we are handshaking right now
    ///   cannot be deleted by a burst of gossiped addresses arriving on this
    ///   same path, and the store still cannot freeze if it ever fills
    ///   entirely with tried peers.
    fn evict_candidate_inner(db: &DB, cursor: &Arc<Mutex<Vec<u8>>>) -> Option<String> {
        let prefix = PFX_PEER.as_bytes();
        let now = unix_now();
        let mut stale_tried: Option<String> = None;
        let mut cur = cursor.lock().unwrap_or_else(|e| e.into_inner());
        // Two passes at most: from the cursor to the end of the prefix, then
        // from the start of the prefix back round to it.
        for pass in 0..2 {
            let from: Vec<u8> = if pass == 0 && cur.starts_with(prefix) {
                cur.clone()
            } else {
                prefix.to_vec()
            };
            let mut examined = 0usize;
            for (n, (k, _)) in db
                .iterator(IteratorMode::From(&from, Direction::Forward))
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(prefix))
                .take(EVICT_SCAN_LIMIT)
                .enumerate()
            {
                examined = n + 1;
                let Some(addr) = std::str::from_utf8(&k)
                    .ok()
                    .map(|s| s[PFX_PEER.len()..].to_string())
                else {
                    continue;
                };
                // Resume after this key next time, whether or not it is taken.
                let mut next = k.to_vec();
                next.push(0);
                *cur = next;
                if crate::service::network::dos_guard::is_whitelisted(Self::extract_ip(&addr)) {
                    continue;
                }
                match Self::tried_at_inner(db, &addr) {
                    None => return Some(addr),
                    Some(at) => {
                        if now.saturating_sub(at) > TRIED_REPLACEMENT_SECS
                            && stale_tried.is_none()
                        {
                            stale_tried = Some(addr);
                        }
                    }
                }
            }
            if pass == 0 {
                if examined < EVICT_SCAN_LIMIT {
                    // The prefix ended: wrap to the front for the second pass.
                    *cur = prefix.to_vec();
                } else {
                    // The SCAN BUDGET ended, not the prefix. Keep the cursor
                    // where it is so the next call carries on from here.
                    // Throwing it back to the front pinned the walk to the
                    // first EVICT_SCAN_LIMIT records — the opposite of the
                    // rotation this exists for, and enough low-sorting
                    // protected records would then freeze the store again.
                    break;
                }
            }
        }
        // No unverified record came up in the budget: fall back to the oldest
        // handshake we saw, if it is past the replacement window.
        stale_tried
    }

    pub fn remove_peer(&self, addr: &str) -> Result<(), NetworkError> {
        let db = self.lock_db();
        // Existence check + per-IP count read + the writes all happen under ONE lock
        // hold, so two concurrent removes of the same addr can no longer both pass
        // the check and each decrement meta:peer_count (drifting it below truth) — B4-L04.
        let exists = db
            .get(format!("{}{}", PFX_PEER, addr).as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false);
        if !exists {
            return Ok(()); // Nothing to remove
        }
        let mut batch = WriteBatch::default();
        Self::stage_peer_delete(&mut batch, addr);
        Self::stage_conn_decrement(&db, &mut batch, Self::extract_ip(addr));
        // Keep the global peer count in step (peer_exists was true above, so a
        // record is actually being removed).
        let stored = Self::stored_peer_count_inner(&db);
        batch.put(PEER_COUNT_KEY, stored.saturating_sub(1).to_le_bytes());
        db.write(batch).map_err(|e| {
            NetworkError::Storage(crate::errors::StorageError::WriteFailed(e.to_string()))
        })
    }

    pub fn peer_exists(&self, addr: &str) -> bool {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_PEER, addr).as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    pub fn get_peer(&self, addr: &str) -> Option<PeerRecord> {
        let db = self.lock_db();
        match db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            Ok(None) => None,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "get_peer", error => &e.to_string());
                None
            }
        }
    }

    pub fn update_peer_height(&self, addr: &str, height: u64) {
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_HEIGHT, addr).as_bytes(),
            height.to_le_bytes(),
        );
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.best_height = height;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "update_peer_height", error => &e.to_string());
        }
    }

    pub fn update_peer_latency(&self, addr: &str, latency_ms: u64) {
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_LATENCY, addr).as_bytes(),
            latency_ms.to_le_bytes(),
        );
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.latency_ms = latency_ms;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "update_peer_latency", error => &e.to_string());
        }
    }

    /// Record that a handshake with this address completed.
    ///
    /// ONLY for an OUTBOUND dial. The caller passes the address it dialled,
    /// which is the key the store holds the record under, so the mark lands on
    /// a real record and refreshes its `last_seen` — the only thing in the
    /// process that does, which is what makes `PeerRecord::is_active()` mean
    /// anything at all.
    ///
    /// An INBOUND connection must NOT be marked: its address carries the peer's
    /// ephemeral source port, so no record exists under that key. Marking it
    /// wrote an orphan into two prefixes that have no cap and no deleter, at up
    /// to 128 permanent keys a second, while telling the eviction ranking
    /// nothing it could use. We do not learn an inbound peer's listening
    /// address, so there is nothing valid to record.
    pub fn mark_tried(&self, addr: &str) {
        let now = unix_now();
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_TRIED, addr).as_bytes(),
            now.to_le_bytes(),
        );
        batch.put(
            format!("{}{}", PFX_LAST_SEEN, addr).as_bytes(),
            now.to_le_bytes(),
        );
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.last_seen = now;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "mark_tried", error => &e.to_string());
        }
    }

    /// When we last completed a handshake with `addr`, if ever.
    fn tried_at_inner(db: &DB, addr: &str) -> Option<u64> {
        db.get(format!("{}{}", PFX_TRIED, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| d.get(..8).and_then(|s| s.try_into().ok()))
            .map(u64::from_le_bytes)
    }

    /// Whether we have ever completed a handshake with `addr`.
    pub fn is_tried(&self, addr: &str) -> bool {
        let db = self.lock_db();
        Self::tried_at_inner(&db, addr).is_some()
    }

    pub fn touch_peer(&self, addr: &str) {
        let now = unix_now();
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_LAST_SEEN, addr).as_bytes(),
            now.to_le_bytes(),
        );
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.last_seen = now;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "touch_peer", error => &e.to_string());
        }
    }

    pub fn get_peers(&self) -> Vec<String> {
        let db = self.lock_db();
        Self::prefix_iter(&db, PFX_PEER.as_bytes())
            .filter_map(|(k, _)| {
                let s = std::str::from_utf8(&k).ok()?;
                Some(s[PFX_PEER.len()..].to_string())
            })
            .collect()
    }

    pub fn get_peer_records(&self) -> Vec<PeerRecord> {
        let db = self.lock_db();
        Self::prefix_iter(&db, PFX_PEER.as_bytes())
            .filter_map(|(_, v)| bincode::deserialize::<PeerRecord>(&v).ok())
            .collect()
    }

    pub fn get_best_peers(&self, limit: usize) -> Vec<PeerRecord> {
        let mut peers = self.get_peer_records();
        peers.retain(|p| !self.is_banned(&p.addr) && p.is_active());
        peers.sort_by(|a, b| {
            b.health_score()
                .cmp(&a.health_score())
                .then_with(|| b.best_height.cmp(&a.best_height))
                .then_with(|| a.addr.cmp(&b.addr))
        });
        peers.truncate(limit);
        peers
    }

    /// Number of persisted peer records.
    ///
    /// Reads the `meta:peer_count` key rather than walking and allocating a
    /// String for every record to then throw them away: the two agree by
    /// construction, which `peer_count_meta_tracks_add_and_remove` pins.
    pub fn count(&self) -> usize {
        self.stored_peer_count() as usize
    }

    /// Live persisted-peer count from the `meta:peer_count` key (O(1) after lazy
    /// init). Used by the `MAX_STORED_PEERS` anti-DoS cap.
    pub fn stored_peer_count(&self) -> u64 {
        let db = self.lock_db();
        Self::stored_peer_count_inner(&db)
    }

    pub fn ban_peer(&self, addr: &str, duration_secs: u64, _reason: &str) {
        let until = unix_now() + duration_secs;
        let db = self.lock_db();
        // Increment persistent ban count (survives restarts)
        let ban_count = self.read_ban_count_inner(&db, addr).saturating_add(1);
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_BAN, addr).as_bytes(),
            until.to_le_bytes(),
        );
        batch.put(
            format!("{}{}", PFX_BAN_COUNT, addr).as_bytes(),
            ban_count.to_le_bytes(),
        );
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "ban_peer", error => &e.to_string());
        }
    }

    /// Ban with category-aware escalating duration.
    /// Uses persistent ban_count to compute exponentially increasing durations.
    pub fn ban_peer_categorized(&self, addr: &str, category: BanCategory, reason: &str) {
        let db = self.lock_db();
        let ban_count = self.read_ban_count_inner(&db, addr);
        let base = category.base_ban_duration();
        let exponent = ban_count.min(4); // cap shift at 4 (×16)
        let multiplier = 1u64 << exponent;
        let duration = base.saturating_mul(multiplier).min(30 * 86_400); // cap 30d
        let until = unix_now() + duration;
        let new_count = ban_count.saturating_add(1);
        let mut batch = WriteBatch::default();
        batch.put(
            format!("{}{}", PFX_BAN, addr).as_bytes(),
            until.to_le_bytes(),
        );
        batch.put(
            format!("{}{}", PFX_BAN_COUNT, addr).as_bytes(),
            new_count.to_le_bytes(),
        );
        batch.put(
            format!("{}{}", PFX_BAN_CAT, addr).as_bytes(),
            [category as u8],
        );
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "ban_peer_categorized", error => &e.to_string());
        }
        slog_warn!("p2p", "peer_banned", addr => addr, duration_secs => duration, ban_count => new_count, category => &format!("{:?}", category), reason => reason);
    }

    /// Read persistent ban count (must hold db lock already).
    fn read_ban_count_inner(&self, db: &DB, addr: &str) -> u32 {
        db.get(format!("{}{}", PFX_BAN_COUNT, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| {
                d.get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
            })
            .unwrap_or(0)
    }

    /// Get persistent ban count for a peer (survives restarts).
    pub fn get_ban_count(&self, addr: &str) -> u32 {
        let db = self.lock_db();
        self.read_ban_count_inner(&db, addr)
    }

    pub fn unban_peer(&self, addr: &str) {
        let db = self.lock_db();
        let _ = db.delete(format!("{}{}", PFX_BAN, addr).as_bytes());
    }

    pub fn is_banned(&self, addr: &str) -> bool {
        let db = self.lock_db();
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_BAN, addr).as_bytes()) {
            // Strict: exactly 8 bytes → u64 timestamp.
            // Corrupted/short data → treat as banned (fail-closed, not fail-open).
            // Returning false on corrupt data would let attackers evade bans.
            match <[u8; 8]>::try_from(&data[..data.len().min(8)]) {
                Ok(bytes) if data.len() == 8 => {
                    let until = u64::from_le_bytes(bytes);
                    if unix_now() < until {
                        return true;
                    }
                    // Cleanup expired ban
                    let _ = db.delete(format!("{}{}", PFX_BAN, addr).as_bytes());
                }
                _ => {
                    // Corrupted ban record — fail closed: treat as banned.
                    // Operator can fix by unbanning explicitly.
                    slog_warn!("p2p", "corrupted_ban_record", addr => addr, bytes => data.len());
                    return true;
                }
            }
        }
        false
    }

    pub fn get_ban_expiry(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_BAN, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| {
                if d.len() >= 8 {
                    d[..8].try_into().ok().map(u64::from_le_bytes)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    pub fn add_penalty(&self, addr: &str, points: u64, reason: &str) {
        self.add_penalty_categorized(addr, points, reason, BanCategory::Malformed)
    }

    /// Add penalty with offense category — triggers category-aware escalating ban
    /// when score reaches AUTO_BAN_THRESHOLD.
    pub fn add_penalty_categorized(
        &self,
        addr: &str,
        points: u64,
        reason: &str,
        category: BanCategory,
    ) {
        let current = self.get_penalty(addr);
        let new_score = current.saturating_add(points);
        {
            let db = self.lock_db();
            let _ = db.put(
                format!("{}{}", PFX_PENALTY, addr).as_bytes(),
                new_score.to_le_bytes(),
            );
        }
        if new_score >= AUTO_BAN_THRESHOLD {
            self.ban_peer_categorized(addr, category, reason);
        }
    }

    pub fn get_penalty(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_PENALTY, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| {
                d.get(..8)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes)
            })
            .unwrap_or(0)
    }

    /// Decay all penalty scores. Category-aware: Resource decays 5×/call,
    /// Malformed 2×/call, Malicious 1×/call. Removes entries that reach 0.
    pub fn decay_penalties(&self) {
        let db = self.lock_db();
        let prefix = PFX_PENALTY.as_bytes();
        let entries: Vec<(Vec<u8>, u64, String)> = Self::prefix_iter(&db, prefix)
            .filter_map(|(k, v)| {
                let score = v
                    .get(..8)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes)?;
                let addr = std::str::from_utf8(&k[prefix.len()..]).ok()?.to_string();
                Some((k.to_vec(), score, addr))
            })
            .collect();
        let mut batch = WriteBatch::default();
        for (key, score, addr) in entries {
            // Look up category for this peer to get the right decay rate
            let cat_byte = db
                .get(format!("{}{}", PFX_BAN_CAT, addr).as_bytes())
                .ok()
                .flatten()
                .and_then(|d| d.first().copied())
                .unwrap_or(1); // default = Malformed
            let decay_rate = match cat_byte {
                0 => 5u64, // Resource
                2 => 1,    // Malicious
                _ => 2,    // Malformed (default)
            };
            let new_score = score.saturating_sub(decay_rate);
            if new_score == 0 {
                batch.delete(&key);
            } else {
                batch.put(&key, new_score.to_le_bytes());
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "decay_penalties", error => &e.to_string());
        }
    }

    pub fn store_addr(&self, addr: &str) {
        let db = self.lock_db();
        if let Err(e) = db.put(
            format!("{}{}", PFX_ADDR, addr).as_bytes(),
            unix_now().to_le_bytes(),
        ) {
            slog_error!("p2p", "peer_manager_write_failed", op => "store_addr", error => &e.to_string());
        }
        drop(db);
        self.evict_addr_cache_if_full();
        let mut cache = self.addr_cache.lock().unwrap_or_else(|e| e.into_inner());
        if !cache.contains(&addr.to_string()) {
            cache.push(addr.to_string());
        }
    }

    pub fn add_addr_batch(&self, addrs: &[String]) {
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        let now = unix_now().to_le_bytes();
        for addr in addrs {
            batch.put(format!("{}{}", PFX_ADDR, addr).as_bytes(), now);
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "add_addr_batch", error => &e.to_string());
        }
    }

    pub fn get_addr_list(&self) -> Vec<String> {
        self.get_addr_list_limited(MAX_GETADDR_RESPONSE)
    }

    /// Addresses to advertise in an Addr reply: the peers we have actually
    /// dialled and handshaked.
    ///
    /// Served from `tried:`. Two earlier shapes were both wrong. It first read
    /// `addr:`, which only `bootstrap_for_network` writes, so we took addresses
    /// in and advertised nothing but our own seeds — no peer could learn about
    /// any other peer through us. 0460ef4 moved it to `peer:`, which the live
    /// ingest does fill, but took the records in RocksDB key order: a peer
    /// gossiping addresses in 0.0.0.0/8 sorts below every real address and so
    /// chose the entire contents of every Addr message we sent, which is worse
    /// than advertising nothing — it made us an amplifier for addresses of the
    /// attacker's choosing.
    ///
    /// `tried:` cannot be entered by gossip: only a completed outbound
    /// handshake writes it, so every address here is one we reached ourselves.
    /// Iterating that prefix is also bounded by the number of real peers rather
    /// than by the whole store, which is why this needs no scan limit.
    ///
    /// Banned addresses are still filtered: handing a peer an address we have
    /// ourselves banned wastes its dial budget on something we know is bad.
    pub fn get_addr_list_limited(&self, max: usize) -> Vec<String> {
        let db = self.lock_db();
        let cap = max.min(MAX_GETADDR_RESPONSE);
        let mut addrs: Vec<String> = Self::prefix_iter(&db, PFX_TRIED.as_bytes())
            .filter_map(|(k, _)| {
                let s = std::str::from_utf8(&k).ok()?;
                Some(s[PFX_TRIED.len()..].to_string())
            })
            .filter(|addr| !Self::is_banned_inner(&db, addr))
            .take(cap)
            .collect();
        addrs.sort();
        addrs
    }

    pub fn addr_cache_size(&self) -> usize {
        self.addr_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn evict_addr_cache_if_full(&self) {
        let mut cache = self.addr_cache.lock().unwrap_or_else(|e| e.into_inner());
        while cache.len() >= MAX_ADDR_CACHE_SIZE {
            cache.remove(0);
        }
    }

    /// Read the per-IP connection count from an ALREADY-LOCKED db, so the caller
    /// can keep the cap check and the write in one lock hold (no TOCTOU).
    fn conn_count_for_ip_inner(db: &DB, ip: &str) -> u32 {
        match db.get(format!("{}{}", PFX_CONN_COUNT, ip).as_bytes()) {
            Ok(Some(data)) => data
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0),
            Ok(None) => 0,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "conn_count_for_ip", error => &e.to_string());
                0
            }
        }
    }

    pub fn has_enough_peers(&self, min: usize) -> bool {
        self.count() >= min
    }

    pub fn get_peer_height(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        match db.get(format!("{}{}", PFX_HEIGHT, addr).as_bytes()) {
            Ok(Some(data)) => data
                .get(..8)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0),
            Ok(None) => 0,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "get_peer_height", error => &e.to_string());
                0
            }
        }
    }

    /// Read the stored latency for a peer (stored separately from PeerRecord).
    /// This method mirrors the pattern of get_peer_height for use in tests.
    #[cfg(test)]
    pub fn get_peer_latency_ms(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_LATENCY, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| {
                d.get(..8)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes)
            })
            .unwrap_or(9999)
    }

    pub fn best_peer_height(&self) -> u64 {
        let db = self.lock_db();
        Self::prefix_iter(&db, PFX_HEIGHT.as_bytes())
            .filter_map(|(_, v)| {
                v.get(..8)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes)
            })
            .max()
            .unwrap_or(0)
    }

    pub fn stats(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        map.insert("total_peers".to_string(), self.count() as u64);
        map.insert("best_height".to_string(), self.best_peer_height());
        map
    }

    pub fn bootstrap_for_network(&self, network: &crate::config::node::node_config::NetworkMode) {
        use crate::config::network::bootstrap_nodes::BootstrapNodes;
        let seeds: Vec<String> = match network {
            crate::config::node::node_config::NetworkMode::Mainnet => BootstrapNodes::mainnet()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            crate::config::node::node_config::NetworkMode::Testnet => BootstrapNodes::testnet()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            crate::config::node::node_config::NetworkMode::Regtest => BootstrapNodes::localhost()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        };
        for addr in &seeds {
            if !self.peer_exists(addr) {
                let _ = self.add_peer(addr);
            }
        }
        self.add_addr_batch(&seeds);
    }

    pub fn discover_peers(&self) -> Vec<String> {
        self.get_addr_list()
    }

    pub fn bootstrap(&self) {
        self.bootstrap_for_network(&self.network);
    }

    pub fn bootstrap_with_seeds(&self, seeds: &[&str]) {
        let owned: Vec<String> = seeds.iter().map(|s| s.to_string()).collect();
        for addr in &owned {
            if !self.peer_exists(addr) {
                let _ = self.add_peer(addr);
            }
        }
        self.add_addr_batch(&owned);
    }

    /// Extract IP address from addr string, handling both IPv4 and IPv6.
    /// Formats: "1.2.3.4:9333", "[::1]:9333", "::1"
    /// The host this address belongs to. Delegates to `dos_guard::host_key` so
    /// the per-host connection count, the ban records and the accept gates
    /// cannot disagree about which host a peer is.
    fn extract_ip(addr: &str) -> &str {
        crate::service::network::dos_guard::host_key(addr)
    }
}

impl crate::domain::traits::sync_peers::SyncPeers for PeerManager {
    fn get_peers(&self) -> Vec<String> {
        self.get_peers()
    }
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

    fn tmp(label: &str) -> String {
        format!("/tmp/pm_test_{}", label)
    }

    #[test]
    fn a_record_stamped_in_the_future_does_not_underflow() {
        // `last_seen` is only ever written as unix_now(), so this needs a
        // BACKWARDS clock step — an NTP correction or a restored VM snapshot —
        // not a remote peer. The subtraction was unsigned: a panic in debug and
        // in release a wrap to a huge number, which read as inactive and
        // silently dropped the peer.
        let mut rec = PeerRecord::new("198.51.100.30:9333", 9333);
        rec.last_seen = unix_now() + 3_600;
        assert!(
            rec.is_active(),
            "a record stamped in the future was seen very recently"
        );

        // And the ordinary paths still work either side of the timeout.
        rec.last_seen = unix_now();
        assert!(rec.is_active());
        rec.last_seen = unix_now().saturating_sub(PEER_HEALTH_TIMEOUT_SECS + 1);
        assert!(!rec.is_active(), "a stale record is not active");
    }

    #[test]
    fn add_and_remove_peer() {
        let path = tmp("add_rm");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("1.2.3.4:9333").is_ok());
        assert!(pm.peer_exists("1.2.3.4:9333"));
        assert!(pm.remove_peer("1.2.3.4:9333").is_ok());
        assert!(!pm.peer_exists("1.2.3.4:9333"));
    }

    // B4-M01: the per-IP connection cap must be enforced (the fix makes the
    // count-read + write atomic; a true concurrent race is not unit-testable, but
    // this guards the cap logic itself).
    #[test]
    fn per_ip_connection_cap_enforced() {
        let path = tmp("per_ip_cap");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        // Same IP, distinct ports: exactly MAX_PEERS_PER_IP accepted, then rejected.
        assert!(pm.add_peer("5.5.5.5:1").is_ok());
        assert!(pm.add_peer("5.5.5.5:2").is_ok());
        assert!(pm.add_peer("5.5.5.5:3").is_ok());
        assert!(
            pm.add_peer("5.5.5.5:4").is_err(),
            "4th connection from one IP must exceed MAX_PEERS_PER_IP"
        );
    }

    #[test]
    fn peer_count_meta_tracks_add_and_remove() {
        let path = tmp("peer_count");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        // Distinct IPs so the per-IP cap (3) doesn't interfere.
        assert!(pm.add_peer("1.0.0.1:9333").is_ok());
        assert!(pm.add_peer("1.0.0.2:9333").is_ok());
        assert!(pm.add_peer("1.0.0.3:9333").is_ok());
        assert_eq!(pm.count(), 3);
        // The meta counter (which enforces MAX_STORED_PEERS) matches ground truth.
        assert_eq!(pm.stored_peer_count(), 3);
        // Re-adding an existing peer must NOT double-count.
        assert!(pm.add_peer("1.0.0.1:9333").is_ok());
        assert_eq!(pm.stored_peer_count(), 3);
        // Removal decrements.
        pm.remove_peer("1.0.0.2:9333").unwrap();
        assert_eq!(pm.count(), 2);
        assert_eq!(pm.stored_peer_count(), 2);
    }

    #[test]
    fn ban_blocks_add() {
        let path = tmp("ban");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.ban_peer("evil:9333", 9999, "spam");
        assert!(pm.is_banned("evil:9333"));
        assert!(pm.add_peer("evil:9333").is_err());
    }

    #[test]
    fn auto_ban_on_penalty() {
        let path = tmp("auto_ban");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        for _ in 0..AUTO_BAN_THRESHOLD {
            pm.add_penalty("bad:9333", 1, "test");
        }
        assert!(pm.is_banned("bad:9333"));
    }

    #[test]
    fn ban_expiry_returns_future_timestamp() {
        let path = tmp("ban_exp");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.ban_peer("x:9333", 3600, "test");
        assert!(pm.get_ban_expiry("x:9333") > 0);
    }

    /// Present a full store without writing 16,384 records: the cap is read
    /// from `meta:peer_count`, so seeding that key is what `add_peer_record`
    /// actually consults.
    fn declare_store_full(pm: &PeerManager) {
        let db = pm.lock_db();
        db.put(PEER_COUNT_KEY, MAX_STORED_PEERS.to_le_bytes()).unwrap();
    }

    #[test]
    fn a_full_store_evicts_instead_of_freezing_forever() {
        // The defect: the cap was a refusal, and nothing in the process ever
        // removes a `peer:` record, so the first peer to claim every slot froze
        // the store for the life of the data directory — every later address
        // refused, the configured seeds included.
        let path = tmp("evict_not_freeze");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        for i in 1..=4 {
            assert!(pm.add_peer(&format!("9.0.0.{}:9333", i)).is_ok());
        }
        declare_store_full(&pm);

        // A new address is still admitted, and the store does not grow.
        assert!(
            pm.add_peer("9.9.9.9:9333").is_ok(),
            "a full store must evict, not refuse for ever"
        );
        assert!(pm.peer_exists("9.9.9.9:9333"));
        assert_eq!(
            pm.stored_peer_count(),
            MAX_STORED_PEERS,
            "one in, one out: the count must not grow past the cap"
        );
        // Exactly one of the originals is gone.
        let gone: Vec<u32> = (1..=4)
            .filter(|i| !pm.peer_exists(&format!("9.0.0.{}:9333", i)))
            .collect();
        assert_eq!(gone.len(), 1, "exactly one record should have been evicted");

        // And its satellite keys went with it. A per-IP count left behind
        // ratchets upward on every evict-and-readd cycle until the per-IP cap
        // refuses that address for good — the same shape as the inbound-slot
        // lockout.
        let db = pm.lock_db();
        assert_eq!(
            PeerManager::conn_count_for_ip_inner(&db, &format!("9.0.0.{}", gone[0])),
            0,
            "the evicted record's per-IP connection count must come back down"
        );
    }

    #[test]
    fn a_whitelisted_address_is_never_refused_and_never_evicted() {
        // The seeds are the whole point: the old refusal locked them out of our
        // own store, so eviction must never choose one and the cap must never
        // refuse one.
        let path = tmp("evict_whitelist");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        crate::service::network::dos_guard::whitelist_peer("9.1.0.7");
        assert!(pm.add_peer("9.1.0.7:9333").is_ok());
        for i in 20..26 {
            assert!(pm.add_peer(&format!("9.1.1.{}:9333", i)).is_ok());
        }
        declare_store_full(&pm);

        // A stranger is admitted by evicting an ORDINARY record, repeatedly...
        for i in 30..40 {
            assert!(
                pm.add_peer(&format!("9.2.0.{}:9333", i)).is_ok(),
                "a full store must evict an ordinary record rather than refuse"
            );
        }
        // ...and the whitelisted record is never the one that goes, however
        // many times the rotating walk passes over it.
        assert!(
            pm.peer_exists("9.1.0.7:9333"),
            "a whitelisted address must never be the eviction victim"
        );

        // And a whitelisted address is admitted over the cap even with nothing
        // at all to evict: counted, never refused. A stranger in that same
        // store IS refused — which is the honest fallback, and still strictly
        // better than the old unconditional refusal.
        let only = tmp("evict_whitelist_only");
        let _ = fs::remove_dir_all(&only);
        let pm2 = PeerManager::open(&only).unwrap();
        crate::service::network::dos_guard::whitelist_peer("9.1.0.9");
        declare_store_full(&pm2);
        assert!(
            pm2.add_peer("9.1.0.9:9333").is_ok(),
            "a whitelisted address must be admitted over the cap"
        );
        assert!(
            pm2.add_peer("9.1.0.250:9333").is_err(),
            "with nothing evictable a stranger is refused — but only then"
        );
    }

    /// Backdate a handshake: `mark_tried` always stamps now, and the windows
    /// under test are hours wide.
    fn set_tried_age(pm: &PeerManager, addr: &str, secs_ago: u64) {
        let db = pm.lock_db();
        let t = unix_now().saturating_sub(secs_ago);
        db.put(
            format!("{}{}", PFX_TRIED, addr).as_bytes(),
            t.to_le_bytes(),
        )
        .unwrap();
    }

    /// Age a record's `last_seen`. Needed because `add_peer` stamps now, and
    /// the window under test is `PEER_HEALTH_TIMEOUT_SECS` wide.
    fn backdate_last_seen(pm: &PeerManager, addr: &str, secs_ago: u64) {
        let db = pm.lock_db();
        let key = format!("{}{}", PFX_PEER, addr);
        let data = db.get(key.as_bytes()).unwrap().expect("record must exist");
        let mut rec: PeerRecord = bincode::deserialize(&data).unwrap();
        rec.last_seen = unix_now().saturating_sub(secs_ago);
        db.put(key.as_bytes(), bincode::serialize(&rec).unwrap())
            .unwrap();
    }

    #[test]
    fn mark_tried_records_the_handshake_and_revives_is_active() {
        // `seen:` was written once at insert and never refreshed — the three
        // writers that would have refreshed it have no production caller — so
        // every peer read as inactive 300 s after it was stored.
        let path = tmp("mark_tried");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("9.6.0.1:9333").is_ok());
        assert!(!pm.is_tried("9.6.0.1:9333"), "not tried until we shake hands");

        // Age it past the health timeout: a record inserted moments ago is
        // active either way, so without this the assertion below cannot tell
        // whether the handshake refreshed anything.
        backdate_last_seen(&pm, "9.6.0.1:9333", PEER_HEALTH_TIMEOUT_SECS + 60);
        assert!(
            !pm.get_peer("9.6.0.1:9333").unwrap().is_active(),
            "a record last seen past the timeout must read as inactive"
        );

        pm.mark_tried("9.6.0.1:9333");
        assert!(pm.is_tried("9.6.0.1:9333"));
        assert!(
            pm.get_peer("9.6.0.1:9333").unwrap().is_active(),
            "a handshake must refresh last_seen, or is_active means nothing"
        );
    }

    #[test]
    fn eviction_takes_unverified_gossip_before_a_peer_we_have_talked_to() {
        // The property that makes the cap anti-eclipse rather than merely
        // unblocked: an attacker's gossip can only ever displace other
        // unverified gossip, never a peer we have actually reached.
        let path = tmp("evict_prefers_untried");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("9.7.0.1:9333").is_ok());
        pm.mark_tried("9.7.0.1:9333");
        set_tried_age(&pm, "9.7.0.1:9333", 10 * 3_600); // old enough to be a last resort
        for i in 2..=5 {
            assert!(pm.add_peer(&format!("9.7.0.{}:9333", i)).is_ok());
        }

        let db = pm.lock_db();
        let mut victims = Vec::new();
        for _ in 0..4 {
            victims.push(
                PeerManager::evict_candidate_inner(&db, &pm.evict_cursor)
                    .expect("four unverified records are available"),
            );
        }
        assert!(
            !victims.contains(&"9.7.0.1:9333".to_string()),
            "the peer we handshaked must not go while unverified records remain: {victims:?}"
        );
        assert_eq!(
            victims.iter().collect::<std::collections::HashSet<_>>().len(),
            4,
            "and the four unverified ones each come up once"
        );
    }

    #[test]
    fn a_handshake_from_moments_ago_is_never_the_victim() {
        // Eviction runs on the Addr ingest path, so a burst of gossiped
        // addresses must not be able to delete the peer we are shaking hands
        // with right now. Bitcoin Core's IsTerrible opens with the same guard.
        let path = tmp("evict_grace");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("9.8.0.1:9333").is_ok());
        pm.mark_tried("9.8.0.1:9333");

        let db = pm.lock_db();
        assert!(
            PeerManager::evict_candidate_inner(&db, &pm.evict_cursor).is_none(),
            "the only record was handshaked moments ago, so nothing is evictable"
        );
    }

    #[test]
    fn a_store_full_of_tried_peers_still_does_not_freeze() {
        // The other half of protecting tried records: if they were untouchable
        // for ever, a store that filled with them would be the original freeze
        // again. Past the replacement window they are a last resort.
        let path = tmp("evict_all_tried");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        for i in 1..=3 {
            let addr = format!("9.9.0.{}:9333", i);
            assert!(pm.add_peer(&addr).is_ok());
            pm.mark_tried(&addr);
            set_tried_age(&pm, &addr, TRIED_REPLACEMENT_SECS + 3_600);
        }
        {
            let db = pm.lock_db();
            assert!(
                PeerManager::evict_candidate_inner(&db, &pm.evict_cursor).is_some(),
                "a stale handshake must be evictable rather than freezing the store"
            );
        }

        // And the tried key goes with the record, so a re-added address does
        // not inherit a handshake it never had.
        declare_store_full(&pm);
        assert!(pm.add_peer("9.9.9.1:9333").is_ok());
        let gone: Vec<u32> = (1..=3)
            .filter(|i| !pm.peer_exists(&format!("9.9.0.{}:9333", i)))
            .collect();
        assert_eq!(gone.len(), 1);
        assert!(
            !pm.is_tried(&format!("9.9.0.{}:9333", gone[0])),
            "the evicted record's tried marker must be gone too"
        );
    }

    fn conn_key_exists(pm: &PeerManager, ip: &str) -> bool {
        let db = pm.lock_db();
        db.get(format!("{}{}", PFX_CONN_COUNT, ip).as_bytes())
            .unwrap()
            .is_some()
    }

    #[test]
    fn an_evicted_ips_last_record_takes_its_conn_key_with_it() {
        // The key used to be REWRITTEN to zero rather than deleted. That was
        // harmless while nothing removed peer records — a conn: key existed
        // only for an IP with a live record, so the keyspace was bounded by
        // MAX_STORED_PEERS. Once the cap started evicting, the number of IPs
        // that have ever been admitted became unbounded, and one zero left
        // behind per IP meant the cap no longer bounded the keyspace it exists
        // for.
        let path = tmp("conn_key_deleted");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("9.10.0.1:9333").is_ok());
        assert!(conn_key_exists(&pm, "9.10.0.1"));
        declare_store_full(&pm);

        // Admitting a different IP evicts that record, which was its IP's last.
        assert!(pm.add_peer("9.11.0.1:9333").is_ok());
        assert!(
            !pm.peer_exists("9.10.0.1:9333"),
            "the only other record must have been the victim"
        );
        assert!(
            !conn_key_exists(&pm, "9.10.0.1"),
            "an evicted IP's last record must take its conn: key with it, not \
             leave a zero behind for ever"
        );

        // And remove_peer behaves the same way.
        assert!(conn_key_exists(&pm, "9.11.0.1"));
        pm.remove_peer("9.11.0.1:9333").unwrap();
        assert!(!conn_key_exists(&pm, "9.11.0.1"));
    }

    #[test]
    fn an_eviction_on_the_same_ip_does_not_ratchet_its_count() {
        // One record leaves and one arrives on the same IP, so its count must
        // not move. Staging a decrement and an increment for ONE key in one
        // batch keeps only the second, which ratcheted the count upward until
        // that IP was refused while under the real limit.
        let path = tmp("conn_same_ip");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        // The store holds only this IP's records, so the victim must share it.
        assert!(pm.add_peer("9.12.0.1:1").is_ok());
        assert!(pm.add_peer("9.12.0.1:2").is_ok());
        {
            let db = pm.lock_db();
            assert_eq!(PeerManager::conn_count_for_ip_inner(&db, "9.12.0.1"), 2);
        }
        declare_store_full(&pm);

        assert!(pm.add_peer("9.12.0.1:3").is_ok());
        {
            let db = pm.lock_db();
            assert_eq!(
                PeerManager::conn_count_for_ip_inner(&db, "9.12.0.1"),
                2,
                "two records in, one evicted, one admitted: the count must stay"
            );
        }
        // So the IP is still under its cap and its next address is admitted.
        assert!(
            pm.add_peer("9.12.0.1:4").is_ok(),
            "a ratcheted count would refuse this while the IP is under the limit"
        );
    }

    #[test]
    fn the_rotation_cursor_survives_a_spent_scan_budget() {
        // The cursor used to be thrown back to the front of the prefix after
        // pass 0 even when pass 0 ended because the SCAN BUDGET ran out rather
        // than because the prefix did. That pinned the walk to the first
        // EVICT_SCAN_LIMIT records — the opposite of the rotation it exists for
        // — and enough low-sorting protected records would freeze the store
        // again, which is the defect the eviction was written to undo.
        let path = tmp("cursor_budget");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        // A run of protected records at the FRONT, longer than TWO scan
        // budgets. Two matters: with the cursor thrown back to the front after
        // pass 0, pass 1 re-walks [0, LIMIT) and advances the cursor to LIMIT
        // again, so pass 0 is permanently confined to [LIMIT, 2*LIMIT) and
        // nothing beyond 2*LIMIT is ever examined. A protected run shorter than
        // that is reachable either way, which is why a first version of this
        // test passed against the defect.
        // "9.20.*" sorts before "9.21.*".
        for i in 1..=(EVICT_SCAN_LIMIT * 2 + 8) {
            let ip = format!("9.20.0.{}", i);
            crate::service::network::dos_guard::whitelist_peer(&ip);
            assert!(pm.add_peer(&format!("{}:9333", ip)).is_ok());
        }
        // Evictable records behind them.
        for i in 1..=3 {
            assert!(pm.add_peer(&format!("9.21.0.{}:9333", i)).is_ok());
        }

        // The first call spends its budget on the protected run and finds
        // nothing; the walk must CARRY ON from there rather than restart, so a
        // later call reaches the evictable records.
        let db = pm.lock_db();
        let mut found = None;
        for _ in 0..8 {
            if let Some(v) = PeerManager::evict_candidate_inner(&db, &pm.evict_cursor) {
                found = Some(v);
                break;
            }
        }
        let victim = found.expect(
            "the walk must get past a protected run longer than its scan budget",
        );
        assert!(
            victim.starts_with("9.21.0."),
            "and the victim must be one of the evictable records, got {victim}"
        );
    }

    #[test]
    fn the_eviction_walk_rotates_over_the_whole_store() {
        // A fixed start would evict the same lexicographically-first records
        // for ever while the rest sat untouched — and whoever gossips
        // low-sorting addresses would choose which ones those are.
        let path = tmp("evict_rotates");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        for i in 1..=5 {
            assert!(pm.add_peer(&format!("9.3.0.{}:9333", i)).is_ok());
        }
        let db = pm.lock_db();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let victim = PeerManager::evict_candidate_inner(&db, &pm.evict_cursor)
                .expect("a store with records must offer a victim");
            seen.insert(victim);
        }
        assert_eq!(seen.len(), 5, "five calls must name all five records once");
        // And it wraps rather than returning None at the end.
        assert!(PeerManager::evict_candidate_inner(&db, &pm.evict_cursor).is_some());
    }

    #[test]
    fn only_addresses_we_have_dialled_are_advertised() {
        // Two earlier shapes were both wrong. The reply first came from `addr:`,
        // which only bootstrap writes, so gossip was ONE-WAY and we advertised
        // nothing but our own seeds. 0460ef4 moved it to `peer:` in RocksDB key
        // order, which was worse: a peer gossiping addresses in 0.0.0.0/8 sorts
        // below every real address and so chose the whole contents of every
        // Addr message we sent, making us an amplifier for addresses of its
        // choosing.
        let path = tmp("addr_reply");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(
            pm.get_addr_list_limited(10).is_empty(),
            "a fresh store has nothing to advertise"
        );

        // Gossiped addresses are ingested but NOT advertisable: this is the
        // property that makes the reply unchooseable by a peer.
        assert!(pm.add_peer("0.0.0.1:9333").is_ok());
        assert!(pm.add_peer("0.0.0.2:9333").is_ok());
        assert!(
            pm.get_addr_list_limited(10).is_empty(),
            "an address we have only been TOLD about must not be advertised, \
             however low it sorts"
        );

        // One we dialled and handshaked is.
        assert!(pm.add_peer("9.4.0.1:9333").is_ok());
        pm.mark_tried("9.4.0.1:9333");
        assert_eq!(
            pm.get_addr_list_limited(10),
            vec!["9.4.0.1:9333".to_string()],
            "a peer we reached ourselves is worth telling others about"
        );

        // A banned address is not handed on, even if we once reached it: it
        // would waste the asker's dial budget on something we have judged.
        pm.add_peer("9.4.0.2:9333").unwrap();
        pm.mark_tried("9.4.0.2:9333");
        pm.ban_peer("9.4.0.1:9333", 3_600, "test");
        assert_eq!(
            pm.get_addr_list_limited(10),
            vec!["9.4.0.2:9333".to_string()],
            "a banned address must not be advertised"
        );
        // And the cap binds.
        assert!(pm.get_addr_list_limited(1).len() <= 1);
    }

    #[test]
    fn the_o1_count_agrees_with_walking_the_records() {
        // `count()` now reads `meta:peer_count` instead of walking every record
        // and allocating a String per key to then discard them. The two must
        // not be able to drift apart silently.
        let path = tmp("count_agrees");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert_eq!(pm.count(), pm.get_peers().len());
        for i in 1..=6 {
            assert!(pm.add_peer(&format!("9.5.0.{}:9333", i)).is_ok());
        }
        assert_eq!(pm.count(), 6);
        assert_eq!(pm.count(), pm.get_peers().len());
        pm.remove_peer("9.5.0.3:9333").unwrap();
        assert_eq!(pm.count(), 5);
        assert_eq!(pm.count(), pm.get_peers().len());
    }

    #[test]
    fn bootstrap_adds_mainnet_seeds() {
        let path = tmp("bootstrap");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.bootstrap();
        assert!(pm.count() > 0);
    }
}
