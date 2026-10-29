// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::types::hash::log_prefix;
use crate::errors::NetworkError;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── Trusted-peer whitelist ─────────────────────────────────────────────────
/// Process-global set of trusted peer IPs (the operator's own seed / `--connect`
/// nodes). Whitelisted peers are NEVER rate-limited or banned.
///
/// The seed nodes must be able to serve each other an unbounded IBD backlog when
/// one falls behind. DoS heuristics (rate limits, outbound-lag scoring, etc.)
/// otherwise ban the very peer helping a lagging node catch up — and a Resource
/// ban lasts an hour — which permanently stalls convergence (observed live:
/// followers stuck thousands of blocks behind the miner). This is the standard
/// "whitelisted / trusted peer" model (cf. Bitcoin `-whitelist`): trust is
/// operator-configured, so these peers bypass the DoS layer entirely.
static WHITELIST: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

/// The host a peer key belongs to: `ip:port`, `[ipv6]:port` and a bare address
/// all collapse onto the bare address.
///
/// Reputation, whitelisting and per-host connection counting all mean "which
/// host is this", and all three key on this one function. There were three
/// implementations of it before (here, `p2p::extract_ban_ip`,
/// `peer_manager::extract_ip`) and they disagreed, which only became
/// load-bearing once ban records were keyed by host: a key the attacker can
/// choose is a key the attacker can use to start over.
///
/// A bare IPv6 literal is the case the old splitters got wrong. All three cut
/// on the LAST colon, so `2001:db8::1` became `2001:db8:` — shared by every
/// address in that prefix, so one offender would have banned all of them — and
/// `::1` became `:`, so whitelisting an IPv6 seed by its bare address never
/// matched the bracketed form a socket reports.
///
/// Splitting on the FIRST colon is what makes the unbracketed case safe, and
/// the only reason it works: with two or more colons the suffix contains one,
/// so it can never pass the all-digits port test, and the address is returned
/// whole. An explicit multi-colon guard here was unreachable — a negative
/// control confirmed no test could tell whether it was present.
pub fn host_key(peer: &str) -> &str {
    if let Some(rest) = peer.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end]; // IPv6 literal inside brackets
        }
    }
    match peer.split_once(':') {
        Some((ip, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => ip,
        _ => peer,
    }
}

/// Add a trusted peer IP to the whitelist. Accepts `ip` or `ip:port`.
pub fn whitelist_peer(addr: &str) {
    let ip = host_key(addr);
    if !ip.is_empty() {
        WHITELIST
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ip.to_string());
    }
}

/// True if the peer's IP is whitelisted (a trusted seed / `--connect` node).
pub fn is_whitelisted(peer: &str) -> bool {
    let ip = host_key(peer);
    WHITELIST
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains(ip)
}

// ── Token bucket tuning ────────────────────────────────────────────────
// At 32 BPS: legitimate traffic ≈ 32 blocks/sec × 8 tok + TX relay + INV
// ≈ 400–600 tok/sec.  Refill must exceed this with headroom for bursts.
// At 10 BPS: ~120 tok/sec steady → plenty of room.
// Capacity = 5 sec burst buffer at max refill rate.
pub const BUCKET_REFILL_RATE: f64 = 800.0;
pub const BUCKET_CAPACITY: f64 = 4_000.0;

// ── Per-message token costs ────────────────────────────────────────────
// Tuned so at 32 BPS, block relay alone = 32 × 8 = 256 tok/sec
// (well within 800/sec refill).  Previous COST_BLOCK=20 caused
// false-positive rate-limiting at high BPS.
pub const COST_MSG_DEFAULT: f64 = 1.0;
pub const COST_TX: f64 = 3.0;
pub const COST_BLOCK: f64 = 8.0;
pub const COST_GETDATA: f64 = 2.0;
/// An Inv is what makes us emit a GetData, so it cannot be the cheaper of the
/// two. It sat at the floor beside Ping while being the most expensive message
/// to process per byte: every announced hash is tested against the pending
/// block queue, and the ones we want are written straight back out as a request.
pub const COST_INV: f64 = COST_GETDATA;
pub const COST_ADDR: f64 = 1.0;
pub const COST_HEADERS: f64 = 3.0;
pub const COST_GETBLOCKS: f64 = 5.0;
/// GetHeaders is the costliest request per byte in the protocol: 29 bytes in
/// (an empty from_hash is legitimate — a fresh node asks that way), up to 512
/// `get_block_hashes_at_height` prefix iterators of walking, and 36,889 bytes
/// out. It was not in the match below, so it fell to COST_MSG_DEFAULT and one
/// peer could ask 800 times a second. Priced with GetBlocks, which serves
/// strictly less work: one stored block, one lookup.
pub const COST_GETHEADERS: f64 = 5.0;
pub const COST_MEMPOOL: f64 = 10.0;

pub const BAN_SCORE_AUTOBAN: u64 = 100;
pub const BAN_SCORE_SEVERE: u64 = 50;
pub const BAN_SCORE_MINOR: u64 = 10;
pub const BAN_DURATION_SECS: u64 = 86_400;
pub const BAN_DURATION_SEVERE: u64 = 604_800;
pub const BAN_DECAY_PER_MINUTE: u64 = 1;

/// Maximum bytes retained in a ban record's accumulated reason.
///
/// `reason` is only cleared when a ban EXPIRES, and a peer can offend
/// indefinitely without ever being banned by staying under
/// BAN_SCORE_AUTOBAN at a rate the category decay absorbs. An uncapped
/// `push_str` therefore grows for the lifetime of the process, per peer key,
/// and the string is cloned into `BanInfo` and logged. The newest evidence is
/// the useful part, so the cap keeps the tail.
pub const MAX_BAN_REASON_LEN: usize = 512;

/// Ceiling on hosts tracked for reputation.
///
/// Records are keyed by host, so this counts hosts that have offended since the
/// last eviction pass rather than sockets — but a botnet is a real set of
/// hosts, and each record carries a reason string of up to MAX_BAN_REASON_LEN,
/// so the table still needs a bound of its own.
pub const MAX_BAN_RECORDS: usize = 16_384;

/// Ceiling on live rate-limiter buckets. These are keyed per CONNECTION, and
/// the sweep only drops a bucket once it has refilled, so a connect-and-drop
/// loop can hold one per attempt until it does.
pub const MAX_BUCKET_RECORDS: usize = 8_192;

/// How many records an insert at a ceiling may examine to find a victim. An
/// unbounded scan would make every message at the ceiling cost O(table), which
/// is the amplifier shape this layer has already been bitten by once.
const EVICT_SCAN_LIMIT: usize = 32;

// ── Offense categories ─────────────────────────────────────────────────
/// Categorise offenses so decay, ban duration, and repeat-offender
/// multipliers scale appropriately for each threat class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BanCategory {
    /// Resource / rate abuse: token bucket exhaustion, bandwidth flooding,
    /// queue quota exceeded, slow responses. Often transient.
    /// Fastest decay, shortest bans.
    Resource = 0,
    /// Structural / parsing errors: bad deserialization, oversized payload,
    /// invalid checksums, malformed fields. Could be buggy client or attack.
    /// Moderate decay and ban duration.
    Malformed = 1,
    /// Proven protocol / consensus violation: invalid PoW, wrong network
    /// magic, cycle injection, duplicate handshake, incompatible version.
    /// Slowest decay, longest bans, highest repeat multiplier.
    Malicious = 2,
}

impl BanCategory {
    /// Per-minute score decay rate for each category.
    ///   Malicious:  1 pt/min → 100 min to clear threshold (keep evidence long)
    ///   Malformed:  2 pt/min →  50 min to clear
    ///   Resource:   5 pt/min →  20 min to clear (transient issues forgiven quickly)
    pub const fn decay_per_minute(&self) -> u64 {
        match self {
            BanCategory::Malicious => 1,
            BanCategory::Malformed => 2,
            BanCategory::Resource => 5,
        }
    }

    /// Base ban duration (seconds) before repeat-offender escalation.
    ///   Malicious:  24 hours
    ///   Malformed:   6 hours
    ///   Resource:    1 hour
    pub const fn base_ban_duration(&self) -> u64 {
        match self {
            BanCategory::Malicious => 86_400,
            BanCategory::Malformed => 21_600,
            BanCategory::Resource => 3_600,
        }
    }

    /// Severity rank for ordering (higher = worse).
    const fn severity(&self) -> u8 {
        match self {
            BanCategory::Resource => 0,
            BanCategory::Malformed => 1,
            BanCategory::Malicious => 2,
        }
    }

    /// Return the more severe of two categories.
    pub fn escalate(self, other: BanCategory) -> BanCategory {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

pub const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TX_BYTES: usize = 100_000;
pub const MAX_HEADERS_PER_MSG: usize = 2_000;
pub const MAX_INV_PER_MSG: usize = 5_000;
pub const MAX_ADDR_PER_MSG: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MsgType {
    Version,
    VerAck,
    Ping,
    Pong,
    Inv,
    GetData,
    Block,
    Tx,
    Headers,
    GetHeaders,
    GetBlocks,
    Addr,
    GetAddr,
    Mempool,
    Reject,
    Unknown,
}

impl MsgType {
    pub fn token_cost(&self) -> f64 {
        match self {
            MsgType::Tx => COST_TX,
            MsgType::Block => COST_BLOCK,
            MsgType::GetData => COST_GETDATA,
            MsgType::Inv => COST_INV,
            MsgType::Addr => COST_ADDR,
            MsgType::Headers => COST_HEADERS,
            MsgType::GetHeaders => COST_GETHEADERS,
            MsgType::GetBlocks => COST_GETBLOCKS,
            MsgType::Mempool => COST_MEMPOOL,
            _ => COST_MSG_DEFAULT,
        }
    }

    pub fn max_size(&self) -> Option<usize> {
        match self {
            MsgType::Block => Some(MAX_BLOCK_BYTES),
            MsgType::Tx => Some(MAX_TX_BYTES),
            _ => Some(MAX_MSG_BYTES),
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: BUCKET_CAPACITY,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * BUCKET_REFILL_RATE).min(BUCKET_CAPACITY);
        self.last_refill = Instant::now();
    }

    /// A bucket refilled to capacity carries no state worth keeping: a peer
    /// returning to a fresh bucket and a peer returning to this one are
    /// indistinguishable. This is the test that actually means "inactive".
    fn is_full(&mut self) -> bool {
        self.refill();
        self.tokens >= BUCKET_CAPACITY
    }

    fn consume(&mut self, cost: f64) -> bool {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct BanRecord {
    score: u64,
    banned: bool,
    ban_until: u64,
    last_decay: u64,
    reason: String,
    /// How many times this peer has been auto-banned. Persists across ban
    /// expirations so repeat offenders get escalating penalties.
    ban_count: u32,
    /// Highest-severity category seen during the current scoring cycle.
    /// Drives decay rate and ban duration selection.
    worst_category: BanCategory,
}

impl BanRecord {
    fn new() -> Self {
        Self {
            score: 0,
            banned: false,
            ban_until: 0,
            last_decay: unix_now(),
            reason: String::new(),
            ban_count: 0,
            worst_category: BanCategory::Resource,
        }
    }

    /// Add score points with a category tag.
    ///
    /// - The category is escalated (worst wins) so a peer that starts with
    ///   rate-limit offenses and then sends a malicious block gets Malicious
    ///   decay and ban duration.
    /// - Repeat offenders get a score **multiplier**: 2× on 2nd ban cycle,
    ///   4× on 3rd, capped at 8×. This means a peer that was banned twice
    ///   before reaches the threshold in fewer offenses.
    fn add_score(&mut self, points: u64, reason: &str, category: BanCategory) -> bool {
        // Escalate worst category
        self.worst_category = self.worst_category.escalate(category);

        // Repeat-offender multiplier: 1× first time, 2× after 1 ban, 4× after 2, cap 8×
        let multiplier = 1u64 << self.ban_count.min(3); // 1, 2, 4, 8
        let effective = points.saturating_mul(multiplier);

        self.score = self.score.saturating_add(effective);
        self.append_reason(reason);

        if self.score >= BAN_SCORE_AUTOBAN && !self.banned {
            self.banned = true;
            self.ban_count = self.ban_count.saturating_add(1);
            self.ban_until = unix_now() + self.compute_ban_duration();
            return true;
        }
        false
    }

    /// Append an offense reason, keeping the newest evidence and bounding the
    /// total at MAX_BAN_REASON_LEN. Truncation is done on a char boundary in
    /// both directions, so a multi-byte reason can never panic here.
    fn append_reason(&mut self, reason: &str) {
        let piece = log_prefix(reason, MAX_BAN_REASON_LEN);
        if !self.reason.is_empty() {
            self.reason.push_str("; ");
        }
        self.reason.push_str(piece);
        if self.reason.len() > MAX_BAN_REASON_LEN {
            let mut cut = self.reason.len() - MAX_BAN_REASON_LEN;
            while cut < self.reason.len() && !self.reason.is_char_boundary(cut) {
                cut += 1;
            }
            self.reason.drain(..cut);
        }
    }

    /// Compute ban duration based on category severity and repeat count.
    ///
    /// Formula: base_duration × 2^(ban_count - 1), capped at 30 days.
    ///
    /// Examples (Malicious, base 24h):
    ///   1st ban → 24h,  2nd → 48h,  3rd → 96h,  4th → 8 days,  5th+ → 16 days (cap 30d)
    /// Examples (Resource, base 1h):
    ///   1st ban → 1h,   2nd → 2h,   3rd → 4h,   4th → 8h,      5th+ → 16h
    fn compute_ban_duration(&self) -> u64 {
        let base = self.worst_category.base_ban_duration();
        let exponent = self.ban_count.saturating_sub(1).min(4); // cap shift at 4 (×16)
        let multiplier = 1u64 << exponent;
        let duration = base.saturating_mul(multiplier);
        duration.min(30 * 86_400) // absolute cap: 30 days
    }

    /// Category-aware decay: different offense types decay at different rates.
    ///
    /// - Resource offenses (rate limits) decay 5× faster than malicious ones,
    ///   because transient congestion shouldn't linger.
    /// - Malicious scores decay slowly to keep the evidence window open.
    /// - On ban expiry, score resets but ban_count is PRESERVED — so the next
    ///   offense cycle will trigger faster/longer bans.
    fn decay(&mut self) {
        let now = unix_now();
        let minutes = (now.saturating_sub(self.last_decay)) / 60;
        if minutes > 0 {
            let rate = self.worst_category.decay_per_minute();
            self.score = self.score.saturating_sub(minutes.saturating_mul(rate));
            self.last_decay = now;
        }

        // Ban expired — reset score and category for next cycle,
        // but keep ban_count for repeat-offender escalation.
        if self.banned && now >= self.ban_until {
            self.banned = false;
            self.score = 0;
            self.worst_category = BanCategory::Resource;
            self.reason.clear();
        }
    }

    /// Whether the ban is active right now, without touching the record.
    ///
    /// `decay()` is what CLEARS an expired ban; it is not needed to answer the
    /// question. Asking used to need the WRITE lock and created a record for
    /// whatever key it was handed, so every inbound connection both serialised
    /// on a writer and grew the table by asking about itself.
    fn ban_active(&self) -> bool {
        self.banned && unix_now() < self.ban_until
    }
}

/// Free one slot in the reputation table, examining at most EVICT_SCAN_LIMIT
/// records. Prefers a record whose ban is not active (lowest score first), and
/// falls back to the active ban that expires soonest.
///
/// It evicts rather than refusing on purpose: refusing at the ceiling would
/// mean a full table can no longer ban anyone new, which hands whoever filled
/// it an immunity for everybody.
fn evict_one_ban(bans: &mut HashMap<String, BanRecord>) -> bool {
    let victim = bans
        .iter()
        .take(EVICT_SCAN_LIMIT)
        .min_by_key(|(_, r)| {
            let active = r.ban_active();
            (u8::from(active), if active { r.ban_until } else { r.score })
        })
        .map(|(k, _)| k.clone());
    match victim {
        Some(k) => {
            bans.remove(&k);
            true
        }
        None => false,
    }
}

struct GlobalLimits {
    tx_count_per_sec: u64,
    block_count_per_sec: u64,
    last_reset: u64,
}

impl GlobalLimits {
    fn new() -> Self {
        Self {
            tx_count_per_sec: 0,
            block_count_per_sec: 0,
            last_reset: unix_now(),
        }
    }

    fn tick(&mut self) {
        let now = unix_now();
        if now > self.last_reset {
            self.tx_count_per_sec = 0;
            self.block_count_per_sec = 0;
            self.last_reset = now;
        }
    }

    fn check_tx(&mut self, limit: u64) -> bool {
        self.tick();
        if self.tx_count_per_sec < limit {
            self.tx_count_per_sec += 1;
            true
        } else {
            false
        }
    }

    fn check_block(&mut self, limit: u64) -> bool {
        self.tick();
        if self.block_count_per_sec < limit {
            self.block_count_per_sec += 1;
            true
        } else {
            false
        }
    }
}

pub struct DosGuard {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    bans: Arc<RwLock<HashMap<String, BanRecord>>>,
    global: Arc<Mutex<GlobalLimits>>,
    max_tx_per_s: u64,
    max_blk_per_s: u64,
}

impl DosGuard {
    pub fn new() -> Self {
        // Defaults tuned for 32 BPS (ultra mode):
        //   - 32 BPS × 10K tx/block = 320K max TPS → global TX limit 50K/sec
        //     gives ~6× headroom over single-node relay duty
        //   - 32 BPS × 4 (DAG width) = 128 blocks/sec max → 200 limit
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            bans: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(Mutex::new(GlobalLimits::new())),
            max_tx_per_s: 50_000,
            max_blk_per_s: 200,
        }
    }

    pub fn with_limits(max_tx_per_s: u64, max_blk_per_s: u64) -> Self {
        let mut g = Self::new();
        g.max_tx_per_s = max_tx_per_s;
        g.max_blk_per_s = max_blk_per_s;
        g
    }

    pub fn check(&self, peer: &str, msg_type: &MsgType, msg_size: usize) -> DosVerdict {
        // Trusted seeds bypass the DoS layer entirely (see WHITELIST) so they can
        // serve each other an unbounded IBD backlog without being throttled/banned.
        if is_whitelisted(peer) {
            return DosVerdict::Allow;
        }
        if self.is_banned(peer) {
            return DosVerdict::BanActive;
        }

        if let Some(max) = msg_type.max_size() {
            if msg_size > max {
                self.add_ban_score_cat(
                    peer,
                    BAN_SCORE_SEVERE,
                    "oversized message",
                    BanCategory::Malformed,
                );
                return DosVerdict::OversizedMessage {
                    allowed: max,
                    got: msg_size,
                };
            }
        }

        match msg_type {
            MsgType::Tx => {
                if !self
                    .global
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .check_tx(self.max_tx_per_s)
                {
                    return DosVerdict::GlobalRateLimited;
                }
            }
            MsgType::Block => {
                if !self
                    .global
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .check_block(self.max_blk_per_s)
                {
                    return DosVerdict::GlobalRateLimited;
                }
            }
            _ => {}
        }

        let cost = msg_type.token_cost();
        let allowed = {
            let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            if !buckets.contains_key(peer) && buckets.len() >= MAX_BUCKET_RECORDS {
                // Drop the most-refilled bucket we can find in a bounded scan.
                // Refusing instead would rate-limit every NEW peer the moment
                // the table filled — the lockout shape, not a rate limit.
                let victim = buckets
                    .iter()
                    .take(EVICT_SCAN_LIMIT)
                    .max_by(|(_, a), (_, b)| {
                        a.tokens
                            .partial_cmp(&b.tokens)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(k, _)| k.clone());
                if let Some(k) = victim {
                    buckets.remove(&k);
                }
            }
            let bucket = buckets
                .entry(peer.to_string())
                .or_insert_with(TokenBucket::new);
            bucket.consume(cost)
        };
        if !allowed {
            // Throttle only — do NOT accrue ban score on a token-bucket overflow.
            // An overflow just means the peer sent VALID messages faster than our
            // steady refill — exactly what happens when a peer serves us a block
            // backlog during catch-up (sync). Dropping the excess message is
            // sufficient flow control. Banning here banned the very peer helping
            // us sync: 10 overflows × BAN_SCORE_MINOR = autoban, which stalled
            // convergence permanently (a lagging node could never catch up to a
            // busy/mining peer). Genuine abuse is still banned via the oversized /
            // malformed / invalid-PoW / lifecycle paths, and the bandwidth cap +
            // pong timeout bound a pure flooder whose messages are all dropped.
            return DosVerdict::RateLimited {
                peer: peer.to_string(),
            };
        }

        DosVerdict::Allow
    }

    /// Add ban score with explicit offense category.
    ///
    /// The category controls:
    ///   - **Decay rate**: Malicious decays slowly, Resource decays fast
    ///   - **Ban duration**: Malicious → 24h base, Resource → 1h base
    ///   - **Repeat multiplier**: Score × 2^ban_count (cap 8×)
    pub fn add_ban_score_cat(
        &self,
        peer: &str,
        points: u64,
        reason: &str,
        category: BanCategory,
    ) -> bool {
        // Never accrue ban score against a trusted seed — this is the single
        // choke-point for ALL ban paths (block rejection, outbound lag,
        // lifecycle, oversized, etc.), so one guard here exempts them everywhere.
        if is_whitelisted(peer) {
            return false;
        }
        let key = host_key(peer);
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        if !bans.contains_key(key) && bans.len() >= MAX_BAN_RECORDS && !evict_one_ban(&mut bans) {
            return false;
        }
        let rec = bans.entry(key.to_string()).or_insert_with(BanRecord::new);
        // Scoring must see a current record. `decay()` is what clears an
        // EXPIRED ban's leftover score, and it used to run here only by
        // accident: `check()` asked `is_banned` first, and that asked the
        // record, which decayed it. Now that asking is a pure read, a peer
        // whose ban had just run out would otherwise be re-banned by its first
        // minor offence, on a score it had already served out. The paths that
        // never went through `check()` — report_bad_peer and the lifecycle
        // arms — never got the decay at all.
        rec.decay();
        let banned = rec.add_score(points, reason, category);

        // Metrics
        let m = crate::telemetry::metrics::registry::global();
        m.counter("dos.score_added").inc();
        if banned {
            m.counter("dos.peers_banned").inc();
            m.gauge("dos.currently_banned").inc();
        }

        banned
    }

    /// Add ban score (backward-compatible, defaults to Malformed category).
    pub fn add_ban_score(&self, peer: &str, points: u64, reason: &str) -> bool {
        self.add_ban_score_cat(peer, points, reason, BanCategory::Malformed)
    }

    pub fn ban_peer(&self, peer: &str, duration_secs: u64, reason: &str) {
        // add_ban_score_cat exempts trusted seeds; the direct path must too, or
        // the one guard meant to cover every ban path covers all but the
        // bluntest.
        if is_whitelisted(peer) {
            return;
        }
        let key = host_key(peer);
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        if !bans.contains_key(key) && bans.len() >= MAX_BAN_RECORDS && !evict_one_ban(&mut bans) {
            return;
        }
        let rec = bans.entry(key.to_string()).or_insert_with(BanRecord::new);
        rec.banned = true;
        rec.ban_until = unix_now() + duration_secs;
        rec.reason = log_prefix(reason, MAX_BAN_REASON_LEN).to_string();
    }

    pub fn unban_peer(&self, peer: &str) {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        if let Some(rec) = bans.get_mut(host_key(peer)) {
            rec.banned = false;
            rec.score = 0;
            rec.ban_until = 0;
            rec.worst_category = BanCategory::Resource;
            rec.reason.clear();
        }
    }

    pub fn is_banned(&self, peer: &str) -> bool {
        // Trusted seeds are never considered banned (belt-and-suspenders: bans
        // are already never accrued for them via add_ban_score_cat, but a stale
        // pre-whitelist record must not linger as active).
        if is_whitelisted(peer) {
            return false;
        }
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        bans.get(host_key(peer)).is_some_and(|r| r.ban_active())
    }

    pub fn get_ban_score(&self, peer: &str) -> u64 {
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        bans.get(host_key(peer)).map(|r| r.score).unwrap_or(0)
    }

    /// Get detailed ban info for diagnostics / RPC.
    pub fn get_ban_info(&self, peer: &str) -> Option<BanInfo> {
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        bans.get(host_key(peer)).map(|r| BanInfo {
            score: r.score,
            banned: r.banned,
            ban_until: r.ban_until,
            ban_count: r.ban_count,
            worst_category: r.worst_category,
            reason: r.reason.clone(),
        })
    }

    /// Owe a record `secs` more seconds of decay than it has had, so a test can
    /// observe decay without waiting out real minutes.
    ///
    /// Test-only seam: the decay rate is per-MINUTE, so there is no other way to
    /// exercise the composed decay-then-evict pass, and the pass existing in
    /// that order is the whole point of `maintain_dos_guard`.
    #[cfg(test)]
    pub(crate) fn backdate_decay(&self, peer: &str, secs: u64) -> bool {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        match bans.get_mut(host_key(peer)) {
            Some(rec) => {
                rec.last_decay = rec.last_decay.saturating_sub(secs);
                true
            }
            None => false,
        }
    }

    pub fn tick_decay(&self) {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        for rec in bans.values_mut() {
            rec.decay();
        }
    }

    pub fn evict_inactive(&self) {
        {
            let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
            bans.retain(|_, r| r.banned || r.score > 0);
        }
        // Buckets are keyed per connection and reputation per host, so the old
        // `bans.contains_key` test would drop nearly every bucket now. It was
        // also the only place in this file that held both locks at once.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, b| !b.is_full());
    }

    pub fn stats(&self) -> DosStats {
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        let banned_count = bans.values().filter(|r| r.banned).count();
        DosStats {
            tracked_peers: bans.len(),
            currently_banned: banned_count,
        }
    }

    pub fn check_block_size(&self, size: usize) -> Result<(), NetworkError> {
        if size > MAX_BLOCK_BYTES {
            Err(NetworkError::DosGuard(format!(
                "Block too large: {} > {}",
                size, MAX_BLOCK_BYTES
            )))
        } else {
            Ok(())
        }
    }

    pub fn check_tx_size(&self, size: usize) -> Result<(), NetworkError> {
        if size > MAX_TX_BYTES {
            Err(NetworkError::DosGuard(format!(
                "Tx too large: {} > {}",
                size, MAX_TX_BYTES
            )))
        } else {
            Ok(())
        }
    }
}

impl Default for DosGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum DosVerdict {
    Allow,
    BanActive,
    RateLimited { peer: String },
    GlobalRateLimited,
    OversizedMessage { allowed: usize, got: usize },
}

impl DosVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, DosVerdict::Allow)
    }
}

#[derive(Debug)]
pub struct DosStats {
    pub tracked_peers: usize,
    pub currently_banned: usize,
}

/// Public snapshot of a peer's ban state (for RPC / diagnostics).
#[derive(Debug, Clone)]
pub struct BanInfo {
    pub score: u64,
    pub banned: bool,
    pub ban_until: u64,
    pub ban_count: u32,
    pub worst_category: BanCategory,
    pub reason: String,
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

    #[test]
    fn ban_reason_stays_bounded_under_sustained_offenses() {
        // The leak: `reason` is cleared only when a ban EXPIRES, and a peer
        // can offend forever without ever being banned by keeping its score
        // under BAN_SCORE_AUTOBAN at a rate the decay absorbs. Before the cap
        // this string grew for the lifetime of the process, per peer key.
        let g = DosGuard::new();
        for i in 0..5_000 {
            g.add_ban_score_cat(
                "noisy",
                0,
                &format!("offense number {}", i),
                BanCategory::Resource,
            );
        }
        let info = g.get_ban_info("noisy").expect("record exists");
        assert!(
            info.reason.len() <= MAX_BAN_REASON_LEN,
            "reason grew to {} bytes, cap is {}",
            info.reason.len(),
            MAX_BAN_REASON_LEN
        );
        assert!(
            info.reason.ends_with("offense number 4999"),
            "the newest evidence must survive truncation: {:?}",
            info.reason
        );
    }

    #[test]
    fn ban_reason_cap_is_char_boundary_safe() {
        // Truncating a multi-byte reason by byte offset would panic on a
        // char boundary; both directions go through the boundary walk.
        let g = DosGuard::new();
        for _ in 0..200 {
            g.add_ban_score_cat("unicode", 0, "رسالة غير صالحة", BanCategory::Malformed);
        }
        g.add_ban_score_cat("unicode", 0, &"ع".repeat(600), BanCategory::Malformed);
        let info = g.get_ban_info("unicode").expect("record exists");
        assert!(info.reason.len() <= MAX_BAN_REASON_LEN);
    }

    #[test]
    fn manual_ban_reason_is_bounded() {
        let g = DosGuard::new();
        g.ban_peer("evil", 9999, &"x".repeat(MAX_BAN_REASON_LEN * 4));
        let info = g.get_ban_info("evil").expect("record exists");
        assert!(
            info.reason.len() <= MAX_BAN_REASON_LEN,
            "ban_peer stored {} bytes",
            info.reason.len()
        );
    }

    #[test]
    fn allow_normal_message() {
        let g = DosGuard::new();
        let v = g.check("1.2.3.4", &MsgType::Ping, 64);
        assert!(v.is_allowed());
    }

    #[test]
    fn oversized_message_rejected() {
        let g = DosGuard::new();
        let v = g.check("1.2.3.4", &MsgType::Block, MAX_BLOCK_BYTES + 1);
        assert!(matches!(v, DosVerdict::OversizedMessage { .. }));
    }

    #[test]
    fn manual_ban() {
        let g = DosGuard::new();
        g.ban_peer("evil", 9999, "spam");
        assert!(g.is_banned("evil"));
        let v = g.check("evil", &MsgType::Ping, 10);
        assert!(matches!(v, DosVerdict::BanActive));
    }

    #[test]
    fn auto_ban_on_score() {
        let g = DosGuard::new();
        let banned = g.add_ban_score("peer", BAN_SCORE_AUTOBAN, "test");
        assert!(banned);
        assert!(g.is_banned("peer"));
    }

    #[test]
    fn rate_limit_exhausted() {
        let g = DosGuard::new();

        // Bucket capacity = 4000, COST_BLOCK = 8 → 500 blocks to drain
        // Plus some refill during loop, so send 600 to ensure exhaustion
        for _ in 0..600 {
            let _ = g.check("spammer", &MsgType::Block, 100);
        }
        let v = g.check("spammer", &MsgType::Block, 100);

        assert!(!v.is_allowed() || g.is_banned("spammer"));
    }

    #[test]
    fn unban_works() {
        let g = DosGuard::new();
        g.ban_peer("peer2", 9999, "test");
        assert!(g.is_banned("peer2"));
        g.unban_peer("peer2");
        assert!(!g.is_banned("peer2"));
    }

    #[test]
    fn global_tx_rate_limit() {
        let g = DosGuard::with_limits(5, 100); // Only 5 TX/sec allowed
        for _ in 0..5 {
            assert!(g.check("peer_g1", &MsgType::Tx, 100).is_allowed());
        }
        // 6th TX in same second should be globally rate limited
        let v = g.check("peer_g2", &MsgType::Tx, 100);
        assert!(matches!(v, DosVerdict::GlobalRateLimited));
    }

    #[test]
    fn global_block_rate_limit() {
        let g = DosGuard::with_limits(10_000, 3); // Only 3 blocks/sec
        for _ in 0..3 {
            assert!(g.check("peer_b1", &MsgType::Block, 100).is_allowed());
        }
        let v = g.check("peer_b2", &MsgType::Block, 100);
        assert!(matches!(v, DosVerdict::GlobalRateLimited));
    }

    #[test]
    fn tx_oversized_rejected() {
        let g = DosGuard::new();
        let v = g.check("peer_tx", &MsgType::Tx, MAX_TX_BYTES + 1);
        assert!(matches!(v, DosVerdict::OversizedMessage { .. }));
    }

    #[test]
    fn per_peer_rate_limit_throttles_without_banning() {
        // Exhausting the per-peer token bucket (e.g. a peer serving us a block
        // backlog during catch-up) must THROTTLE (RateLimited) but NEVER ban:
        // banning the peer that helps us sync stalls convergence. Use Inv (no
        // global cap) so we hit the per-peer bucket path.
        let g = DosGuard::new();
        let peer = "203.0.113.50:19333";
        let mut throttled = false;
        for _ in 0..((BUCKET_CAPACITY as usize) + 3000) {
            if matches!(g.check(peer, &MsgType::Inv, 100), DosVerdict::RateLimited { .. }) {
                throttled = true;
            }
        }
        assert!(throttled, "sustained high rate must eventually throttle");
        assert!(
            !g.is_banned(peer),
            "throttling must NOT ban a peer (banning a sync peer stalls convergence)"
        );
    }

    #[test]
    fn ban_score_accumulates() {
        let g = DosGuard::new();
        g.add_ban_score("badpeer", 30, "offense 1");
        assert!(!g.is_banned("badpeer"));
        assert_eq!(g.get_ban_score("badpeer"), 30);
        g.add_ban_score("badpeer", 30, "offense 2");
        assert!(!g.is_banned("badpeer"));
        g.add_ban_score("badpeer", 50, "offense 3"); // total=110 > 100
        assert!(g.is_banned("badpeer"));
    }

    #[test]
    fn categorized_ban_malicious() {
        let g = DosGuard::new();
        // Malicious offense → instant ban at 100 pts
        let banned = g.add_ban_score_cat("attacker", 100, "invalid PoW", BanCategory::Malicious);
        assert!(banned);
        assert!(g.is_banned("attacker"));
        let info = g.get_ban_info("attacker").unwrap();
        assert_eq!(info.worst_category, BanCategory::Malicious);
        assert_eq!(info.ban_count, 1);
        // Malicious base duration = 24h, 1st ban → 24h
        assert!(info.ban_until > unix_now());
        assert!(info.ban_until <= unix_now() + 86_400 + 2);
    }

    #[test]
    fn categorized_ban_resource() {
        let g = DosGuard::new();
        // Resource offenses accumulate
        for i in 0..10 {
            g.add_ban_score_cat(
                "ratelimited",
                10,
                &format!("rate #{}", i),
                BanCategory::Resource,
            );
        }
        assert!(g.is_banned("ratelimited"));
        let info = g.get_ban_info("ratelimited").unwrap();
        assert_eq!(info.worst_category, BanCategory::Resource);
        // Resource base = 1h, 1st ban → 1h
        assert!(info.ban_until <= unix_now() + 3_600 + 2);
    }

    #[test]
    fn category_escalation() {
        let g = DosGuard::new();
        // Start with resource, escalate to malicious
        g.add_ban_score_cat("peer", 30, "rate limit", BanCategory::Resource);
        g.add_ban_score_cat("peer", 30, "bad format", BanCategory::Malformed);
        g.add_ban_score_cat("peer", 50, "invalid PoW", BanCategory::Malicious);
        assert!(g.is_banned("peer"));
        let info = g.get_ban_info("peer").unwrap();
        // Worst category should be Malicious (not Resource)
        assert_eq!(info.worst_category, BanCategory::Malicious);
    }

    #[test]
    fn repeat_offender_multiplier() {
        let g = DosGuard::new();
        // First ban cycle: 50 + 50 = 100 → ban
        g.add_ban_score_cat("repeat", 50, "first", BanCategory::Malformed);
        g.add_ban_score_cat("repeat", 50, "first2", BanCategory::Malformed);
        assert!(g.is_banned("repeat"));

        // Simulate ban expiry by manually resetting
        {
            let mut bans = g.bans.write().unwrap();
            let rec = bans.get_mut("repeat").unwrap();
            rec.banned = false;
            rec.score = 0;
            rec.worst_category = BanCategory::Resource;
            rec.reason.clear();
            // ban_count stays at 1
        }
        assert!(!g.is_banned("repeat"));

        // Second cycle: multiplier = 2×, so 50 pts becomes 100 → instant ban
        let banned = g.add_ban_score_cat("repeat", 50, "second", BanCategory::Malformed);
        assert!(
            banned,
            "repeat offender should ban faster with 2× multiplier"
        );
        let info = g.get_ban_info("repeat").unwrap();
        assert_eq!(info.ban_count, 2);
    }

    #[test]
    fn repeat_offender_ban_duration_escalates() {
        let g = DosGuard::new();

        // 1st ban (Malformed, base 6h) → 6h
        g.add_ban_score_cat("esc", 100, "ban1", BanCategory::Malformed);
        let info1 = g.get_ban_info("esc").unwrap();
        let dur1 = info1.ban_until - unix_now();
        // 6h = 21600 ± tolerance
        assert!(
            (21_598..=21_602).contains(&dur1),
            "1st ban should be ~6h, got {}s",
            dur1
        );

        // Simulate expiry, keep ban_count=1
        {
            let mut bans = g.bans.write().unwrap();
            let rec = bans.get_mut("esc").unwrap();
            rec.banned = false;
            rec.score = 0;
            rec.worst_category = BanCategory::Resource;
            rec.reason.clear();
        }

        // 2nd ban (Malformed) → 6h × 2 = 12h
        // With 2× multiplier, 50 pts → 100 effective
        g.add_ban_score_cat("esc", 50, "ban2", BanCategory::Malformed);
        let info2 = g.get_ban_info("esc").unwrap();
        assert_eq!(info2.ban_count, 2);
        let dur2 = info2.ban_until - unix_now();
        // 12h = 43200
        assert!(
            (43_198..=43_202).contains(&dur2),
            "2nd ban should be ~12h, got {}s",
            dur2
        );
    }

    #[test]
    fn unban_resets_category_and_score() {
        let g = DosGuard::new();
        // Ban with malicious category
        g.add_ban_score_cat("unbanned", 100, "invalid PoW", BanCategory::Malicious);
        assert!(g.is_banned("unbanned"));
        let info = g.get_ban_info("unbanned").unwrap();
        assert_eq!(info.worst_category, BanCategory::Malicious);

        // Unban
        g.unban_peer("unbanned");
        assert!(!g.is_banned("unbanned"));

        // Verify full reset: score=0, category back to Resource
        let info = g.get_ban_info("unbanned").unwrap();
        assert_eq!(info.score, 0);
        assert_eq!(info.worst_category, BanCategory::Resource);
        assert!(info.reason.is_empty());

        // Next offense should be judged as fresh (Resource category),
        // not escalated to Malicious from the previous cycle
        g.add_ban_score_cat("unbanned", 30, "rate limit", BanCategory::Resource);
        let info = g.get_ban_info("unbanned").unwrap();
        assert_eq!(info.worst_category, BanCategory::Resource);
    }

    #[test]
    fn different_msg_types_have_different_costs() {
        assert!(MsgType::Block.token_cost() > MsgType::Tx.token_cost());
        assert!(MsgType::Tx.token_cost() > MsgType::Ping.token_cost());
        assert!(MsgType::Mempool.token_cost() > MsgType::Addr.token_cost());
    }

    #[test]
    fn whitelisted_seed_is_never_rate_limited_or_banned() {
        // A trusted seed must bypass the DoS layer so it can serve unbounded IBD
        // backfill to a lagging peer without being throttled/banned (the live
        // convergence failure). Uses a documentation-range IP unique to this test.
        let g = DosGuard::new();
        whitelist_peer("203.0.113.200"); // add by bare IP
        // A flood of severe ban score is a no-op for a whitelisted IP...
        for _ in 0..50 {
            g.add_ban_score_cat(
                "203.0.113.200:19333",
                BAN_SCORE_AUTOBAN,
                "flood",
                BanCategory::Resource,
            );
        }
        assert!(
            !g.is_banned("203.0.113.200:19333"),
            "whitelisted seed must never be banned"
        );
        // ...and the match is by IP, so an ephemeral inbound port is also exempt.
        assert!(!g.is_banned("203.0.113.200:41122"));
        assert!(matches!(
            g.check("203.0.113.200:19333", &MsgType::Block, 100),
            DosVerdict::Allow
        ));
        // A different, non-whitelisted peer still bans normally (guard is scoped).
        for _ in 0..50 {
            g.add_ban_score_cat(
                "198.51.100.9:19333",
                BAN_SCORE_AUTOBAN,
                "flood",
                BanCategory::Malicious,
            );
        }
        assert!(
            g.is_banned("198.51.100.9:19333"),
            "non-whitelisted peer must still ban"
        );
    }

    #[test]
    fn evict_inactive_cleans_up() {
        let g = DosGuard::new();
        // A ban CHECK no longer creates a record, so this pass has to be given
        // something to evict or it proves nothing: it used to assert 0 tracked
        // peers, which is now true before the pass even runs.
        g.check("198.51.100.11:1", &MsgType::Ping, 10);
        assert_eq!(
            g.stats().tracked_peers,
            0,
            "asking about a peer must not track it"
        );

        g.add_ban_score("198.51.100.12", 10, "minor");
        g.add_ban_score("198.51.100.13", BAN_SCORE_AUTOBAN, "severe");
        g.unban_peer("198.51.100.13"); // cleared: score 0 and not banned
        assert_eq!(g.stats().tracked_peers, 2);

        g.evict_inactive();
        assert_eq!(g.stats().tracked_peers, 1, "only the cleared record goes");
        assert!(g.get_ban_info("198.51.100.12").is_some());
        assert!(g.get_ban_info("198.51.100.13").is_none());
    }

    #[test]
    fn inv_costs_at_least_as_much_as_the_getdata_it_provokes() {
        let inv = MsgType::Inv.token_cost();
        assert!(
            inv >= MsgType::GetData.token_cost(),
            "an Inv makes us send a GetData, so it must not be cheaper than one"
        );
        assert!(
            inv > COST_MSG_DEFAULT,
            "an Inv is not a floor-cost message: every announced hash is tested \
             against the pending queue, and answered with a request of its own size"
        );
    }

    #[test]
    fn getheaders_costs_more_than_the_default_message() {
        // GetHeaders was absent from token_cost, so it fell to the default and
        // one peer could ask BUCKET_REFILL_RATE times a second — each ask
        // costing up to 512 prefix iterators and a 36,889-byte reply for 29
        // bytes in. It must cost at least as much as GetBlocks, which serves
        // strictly less: one stored block.
        let cost = MsgType::GetHeaders.token_cost();
        assert!(
            cost > COST_MSG_DEFAULT,
            "GetHeaders must not be priced at the default: {}",
            cost
        );
        assert!(cost >= COST_GETBLOCKS);
        // The rate that price implies, against an honest peer that asks once
        // per 6 s sync interval: still two orders of magnitude of headroom.
        let per_sec = BUCKET_REFILL_RATE / cost;
        assert!(per_sec <= 160.0, "{} GetHeaders/sec is still too cheap", per_sec);
        assert!(per_sec >= 20.0, "{} GetHeaders/sec would throttle honest sync", per_sec);
    }

    #[test]
    fn stats_reports_correctly() {
        let g = DosGuard::new();
        g.ban_peer("banned1", 9999, "test");
        g.ban_peer("banned2", 9999, "test");
        g.add_ban_score("scored", 10, "minor");
        let stats = g.stats();
        assert_eq!(stats.currently_banned, 2);
        assert!(stats.tracked_peers >= 2);
    }

    // ── the ban key: the host, not the socket ─────────────────────────────

    #[test]
    fn a_ban_follows_the_host_not_the_socket() {
        // THE DEFECT: the accept gate checked the IP-only key while ~26 scoring
        // sites inside dispatch_message scored the attacker-chosen `ip:port`,
        // so the whole post-handshake ban mechanism cost one new source port to
        // bypass — and each evaded cycle left a 24h record keyed on the port it
        // had already abandoned.
        let g = DosGuard::new();
        g.add_ban_score_cat(
            "192.0.2.10:51234",
            BAN_SCORE_AUTOBAN,
            "invalid PoW",
            BanCategory::Malicious,
        );
        assert!(g.is_banned("192.0.2.10:51234"));
        assert!(
            g.is_banned("192.0.2.10:7777"),
            "a fresh source port must not be a fresh reputation"
        );
        assert!(g.is_banned("192.0.2.10"), "and neither must the bare address");
        assert!(
            !g.is_banned("192.0.2.11:51234"),
            "but a different host is a different host"
        );
        assert_eq!(
            g.stats().tracked_peers,
            1,
            "one host, one record — not one per port it tried"
        );
    }

    #[test]
    fn a_bare_ipv6_literal_is_its_own_host() {
        // All three old splitters cut on the LAST colon, so `2001:db8::1`
        // became `2001:db8:` — one key shared by every address in the prefix,
        // which would have let one offender ban all of them — and `::1` became
        // `:`, so whitelisting an IPv6 seed by its bare address never matched
        // the bracketed form a socket reports.
        assert_eq!(host_key("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_key("[2001:db8::1]:9333"), "2001:db8::1");
        assert_eq!(host_key("::1"), "::1");
        assert_eq!(host_key("[::1]:9333"), "::1");
        assert_eq!(host_key("1.2.3.4:9333"), "1.2.3.4");
        assert_eq!(host_key("1.2.3.4"), "1.2.3.4");
        // A non-numeric suffix is not a port, so it is part of the name.
        assert_eq!(host_key("some-seed:name"), "some-seed:name");

        let g = DosGuard::new();
        g.add_ban_score_cat(
            "[2001:db8::1]:9333",
            BAN_SCORE_AUTOBAN,
            "invalid PoW",
            BanCategory::Malicious,
        );
        assert!(g.is_banned("2001:db8::1"));
        assert!(
            !g.is_banned("2001:db8::2"),
            "a neighbour in the same prefix must not be banned with it"
        );
    }

    #[test]
    fn asking_whether_a_peer_is_banned_does_not_create_a_record() {
        // `is_banned` took the WRITE lock and did
        // `bans.entry(peer).or_insert_with(BanRecord::new)`, so every inbound
        // connection both serialised on a writer and grew the table by asking
        // about itself.
        let g = DosGuard::new();
        for port in 0..200u16 {
            assert!(!g.is_banned(&format!("192.0.2.20:{}", port)));
        }
        assert_eq!(
            g.stats().tracked_peers,
            0,
            "a query must not be a write"
        );
        assert!(g.get_ban_info("192.0.2.20:1").is_none());
    }

    #[test]
    fn a_served_out_ban_does_not_make_the_next_offence_instant() {
        // `decay()` is what clears an expired ban's leftover score, and it used
        // to run on the scoring path only by accident: `check()` asked
        // `is_banned` first, and that asked the record, which decayed it. With
        // asking made a pure read, the decay has to be explicit or a peer whose
        // ban had just run out would be re-banned by its first minor offence,
        // on a score it had already served.
        let g = DosGuard::new();
        let peer = "192.0.2.30:1";
        assert!(g.add_ban_score_cat(peer, BAN_SCORE_AUTOBAN, "severe", BanCategory::Malformed));
        {
            // Run the ban out without waiting for it.
            let mut bans = g.bans.write().unwrap();
            let rec = bans.get_mut(host_key(peer)).unwrap();
            rec.ban_until = unix_now().saturating_sub(1);
        }
        assert!(!g.is_banned(peer), "the ban has expired");

        let banned_again = g.add_ban_score_cat(peer, 10, "minor", BanCategory::Resource);
        assert!(
            !banned_again,
            "a 10-point offence must not re-ban a peer that served its time"
        );
        // ban_count is 1, so the repeat multiplier doubles the 10 to 20 — and
        // nothing of the old 100 is left.
        assert_eq!(g.get_ban_score(peer), 20);
    }

    // ── both tables have a ceiling, and neither can lock anyone out ───────

    #[test]
    fn the_reputation_table_has_a_ceiling_it_cannot_be_pushed_past() {
        let g = DosGuard::new();
        for i in 0..(MAX_BAN_RECORDS + 500) {
            g.add_ban_score_cat(
                &format!("198.18.{}.{}", i / 256, i % 256),
                10,
                "minor",
                BanCategory::Resource,
            );
        }
        assert_eq!(
            g.stats().tracked_peers,
            MAX_BAN_RECORDS,
            "the table must stop growing at the ceiling"
        );
        // And a full table must still be able to ban someone new: refusing
        // instead of evicting would hand whoever filled it an immunity for
        // everybody.
        g.add_ban_score_cat(
            "203.0.113.77:1",
            BAN_SCORE_AUTOBAN,
            "invalid PoW",
            BanCategory::Malicious,
        );
        assert!(
            g.is_banned("203.0.113.77:9999"),
            "a full table must not stop us banning a new offender"
        );
        assert_eq!(g.stats().tracked_peers, MAX_BAN_RECORDS);
    }

    #[test]
    fn the_bucket_table_has_a_ceiling_and_still_admits_a_new_peer() {
        let g = DosGuard::new();
        for i in 0..(MAX_BUCKET_RECORDS + 200) {
            // Inv has no global per-second limit, so every call reaches the
            // bucket stage and creates a bucket.
            g.check(&format!("198.18.{}.{}:9333", i / 256, i % 256), &MsgType::Inv, 100);
        }
        let live = g.buckets.lock().unwrap().len();
        assert!(
            live <= MAX_BUCKET_RECORDS,
            "buckets must stop growing at the ceiling, got {}",
            live
        );
        assert!(
            matches!(
                g.check("203.0.113.88:9333", &MsgType::Inv, 100),
                DosVerdict::Allow
            ),
            "a full bucket table must not rate-limit every new peer"
        );
    }

    #[test]
    fn the_bucket_sweep_keeps_a_drained_bucket_and_drops_a_refilled_one() {
        // The sweep used to be `buckets.retain(|k, _| bans.contains_key(k))`.
        // Buckets are keyed per connection and reputation is now keyed per
        // host, so that test would drop nearly every bucket. A bucket that has
        // refilled to capacity is the one that carries no state worth keeping.
        let g = DosGuard::new();
        g.check("192.0.2.40:1", &MsgType::Inv, 100); // 2 of 4000 tokens spent
        for _ in 0..1_500 {
            g.check("192.0.2.41:1", &MsgType::Inv, 100); // 3000 tokens spent
        }
        assert_eq!(g.buckets.lock().unwrap().len(), 2);

        // Long enough for the first to refill its 2 tokens (800/s) and nowhere
        // near enough for the second to refill 3000.
        std::thread::sleep(std::time::Duration::from_millis(50));
        g.evict_inactive();

        let buckets = g.buckets.lock().unwrap();
        assert!(
            !buckets.contains_key("192.0.2.40:1"),
            "a refilled bucket holds nothing worth keeping"
        );
        assert!(
            buckets.contains_key("192.0.2.41:1"),
            "a drained bucket must survive the sweep, or the rate limit resets"
        );
    }

    #[test]
    fn banning_a_whitelisted_peer_directly_is_a_no_op() {
        // `add_ban_score_cat` is documented as the single choke point that
        // exempts trusted seeds, and `ban_peer` walked straight past it.
        whitelist_peer("203.0.113.210");
        let g = DosGuard::new();
        g.ban_peer("203.0.113.210:9333", 86_400, "manual");
        assert!(
            !g.is_banned("203.0.113.210:9333"),
            "a trusted seed must not be bannable by the direct path either"
        );
        assert_eq!(g.stats().tracked_peers, 0, "and must leave no record");
    }
}
