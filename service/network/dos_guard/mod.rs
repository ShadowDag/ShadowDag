// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use crate::errors::NetworkError;

// ── Token bucket tuning ────────────────────────────────────────────────
// At 32 BPS: legitimate traffic ≈ 32 blocks/sec × 8 tok + TX relay + INV
// ≈ 400–600 tok/sec.  Refill must exceed this with headroom for bursts.
// At 10 BPS: ~120 tok/sec steady → plenty of room.
// Capacity = 5 sec burst buffer at max refill rate.
pub const BUCKET_REFILL_RATE:     f64 = 800.0;
pub const BUCKET_CAPACITY:        f64 = 4_000.0;

// ── Per-message token costs ────────────────────────────────────────────
// Tuned so at 32 BPS, block relay alone = 32 × 8 = 256 tok/sec
// (well within 800/sec refill).  Previous COST_BLOCK=20 caused
// false-positive rate-limiting at high BPS.
pub const COST_MSG_DEFAULT:       f64 = 1.0;
pub const COST_TX:                f64 = 3.0;
pub const COST_BLOCK:             f64 = 8.0;
pub const COST_GETDATA:           f64 = 2.0;
pub const COST_INV:               f64 = 1.0;
pub const COST_ADDR:              f64 = 1.0;
pub const COST_HEADERS:           f64 = 3.0;
pub const COST_GETBLOCKS:         f64 = 5.0;
pub const COST_MEMPOOL:           f64 = 10.0;

pub const BAN_SCORE_AUTOBAN:      u64 = 100;
pub const BAN_SCORE_SEVERE:       u64 = 50;
pub const BAN_SCORE_MINOR:        u64 = 10;
pub const BAN_DURATION_SECS:      u64 = 86_400;
pub const BAN_DURATION_SEVERE:    u64 = 604_800;
pub const BAN_DECAY_PER_MINUTE:   u64 = 1;

// ── Offense categories ─────────────────────────────────────────────────
/// Categorise offenses so decay, ban duration, and repeat-offender
/// multipliers scale appropriately for each threat class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BanCategory {
    /// Resource / rate abuse: token bucket exhaustion, bandwidth flooding,
    /// queue quota exceeded, slow responses. Often transient.
    /// Fastest decay, shortest bans.
    Resource  = 0,
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
            BanCategory::Resource  => 5,
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
            BanCategory::Resource  => 3_600,
        }
    }

    /// Severity rank for ordering (higher = worse).
    const fn severity(&self) -> u8 {
        match self {
            BanCategory::Resource  => 0,
            BanCategory::Malformed => 1,
            BanCategory::Malicious => 2,
        }
    }

    /// Return the more severe of two categories.
    pub fn escalate(self, other: BanCategory) -> BanCategory {
        if other.severity() > self.severity() { other } else { self }
    }
}

pub const MAX_MSG_BYTES:          usize = 4 * 1024 * 1024;
pub const MAX_BLOCK_BYTES:        usize = 2 * 1024 * 1024;
pub const MAX_TX_BYTES:           usize = 100_000;
pub const MAX_HEADERS_PER_MSG:    usize = 2_000;
pub const MAX_INV_PER_MSG:        usize = 5_000;
pub const MAX_ADDR_PER_MSG:       usize = 1_000;

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
            MsgType::Tx         => COST_TX,
            MsgType::Block      => COST_BLOCK,
            MsgType::GetData    => COST_GETDATA,
            MsgType::Inv        => COST_INV,
            MsgType::Addr       => COST_ADDR,
            MsgType::Headers    => COST_HEADERS,
            MsgType::GetBlocks  => COST_GETBLOCKS,
            MsgType::Mempool    => COST_MEMPOOL,
            _                   => COST_MSG_DEFAULT,
        }
    }

    pub fn max_size(&self) -> Option<usize> {
        match self {
            MsgType::Block   => Some(MAX_BLOCK_BYTES),
            MsgType::Tx      => Some(MAX_TX_BYTES),
            _                => Some(MAX_MSG_BYTES),
        }
    }
}

struct TokenBucket {
    tokens:      f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self { tokens: BUCKET_CAPACITY, last_refill: Instant::now() }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * BUCKET_REFILL_RATE).min(BUCKET_CAPACITY);
        self.last_refill = Instant::now();
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
    score:           u64,
    banned:          bool,
    ban_until:       u64,
    last_decay:      u64,
    reason:          String,
    /// How many times this peer has been auto-banned. Persists across ban
    /// expirations so repeat offenders get escalating penalties.
    ban_count:       u32,
    /// Highest-severity category seen during the current scoring cycle.
    /// Drives decay rate and ban duration selection.
    worst_category:  BanCategory,
}

impl BanRecord {
    fn new() -> Self {
        Self {
            score: 0, banned: false, ban_until: 0,
            last_decay: unix_now(), reason: String::new(),
            ban_count: 0, worst_category: BanCategory::Resource,
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
        let effective  = points.saturating_mul(multiplier);

        self.score = self.score.saturating_add(effective);
        if !self.reason.is_empty() { self.reason.push_str("; "); }
        self.reason.push_str(reason);

        if self.score >= BAN_SCORE_AUTOBAN && !self.banned {
            self.banned    = true;
            self.ban_count = self.ban_count.saturating_add(1);
            self.ban_until = unix_now() + self.compute_ban_duration();
            return true;
        }
        false
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
            self.score  = 0;
            self.worst_category = BanCategory::Resource;
            self.reason.clear();
        }
    }

    fn is_banned(&mut self) -> bool {
        self.decay();
        self.banned && unix_now() < self.ban_until
    }
}

struct GlobalLimits {
    tx_count_per_sec: u64,
    block_count_per_sec: u64,
    last_reset: u64,
}

impl GlobalLimits {
    fn new() -> Self { Self { tx_count_per_sec: 0, block_count_per_sec: 0, last_reset: unix_now() } }

    fn tick(&mut self) {
        let now = unix_now();
        if now > self.last_reset {
            self.tx_count_per_sec    = 0;
            self.block_count_per_sec = 0;
            self.last_reset          = now;
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
    buckets:       Arc<Mutex<HashMap<String, TokenBucket>>>,
    bans:          Arc<RwLock<HashMap<String, BanRecord>>>,
    global:        Arc<Mutex<GlobalLimits>>,
    max_tx_per_s:  u64,
    max_blk_per_s: u64,
}

impl DosGuard {
    pub fn new() -> Self {
        // Defaults tuned for 32 BPS (ultra mode):
        //   - 32 BPS × 10K tx/block = 320K max TPS → global TX limit 50K/sec
        //     gives ~6× headroom over single-node relay duty
        //   - 32 BPS × 4 (DAG width) = 128 blocks/sec max → 200 limit
        Self {
            buckets:       Arc::new(Mutex::new(HashMap::new())),
            bans:          Arc::new(RwLock::new(HashMap::new())),
            global:        Arc::new(Mutex::new(GlobalLimits::new())),
            max_tx_per_s:  50_000,
            max_blk_per_s: 200,
        }
    }

    pub fn with_limits(max_tx_per_s: u64, max_blk_per_s: u64) -> Self {
        let mut g = Self::new();
        g.max_tx_per_s  = max_tx_per_s;
        g.max_blk_per_s = max_blk_per_s;
        g
    }

    pub fn check(&self, peer: &str, msg_type: &MsgType, msg_size: usize) -> DosVerdict {
        if self.is_banned(peer) {
            return DosVerdict::BanActive;
        }

        if let Some(max) = msg_type.max_size() {
            if msg_size > max {
                self.add_ban_score_cat(peer, BAN_SCORE_SEVERE, "oversized message", BanCategory::Malformed);
                return DosVerdict::OversizedMessage { allowed: max, got: msg_size };
            }
        }

        match msg_type {
            MsgType::Tx => {
                if !self.global.lock().unwrap_or_else(|e| e.into_inner()).check_tx(self.max_tx_per_s) {
                    return DosVerdict::GlobalRateLimited;
                }
            }
            MsgType::Block => {
                if !self.global.lock().unwrap_or_else(|e| e.into_inner()).check_block(self.max_blk_per_s) {
                    return DosVerdict::GlobalRateLimited;
                }
            }
            _ => {}
        }

        let cost = msg_type.token_cost();
        let allowed = {
            let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            let bucket = buckets.entry(peer.to_string()).or_insert_with(TokenBucket::new);
            bucket.consume(cost)
        };
        if !allowed {
            self.add_ban_score_cat(peer, BAN_SCORE_MINOR, "rate exceeded", BanCategory::Resource);
            return DosVerdict::RateLimited { peer: peer.to_string() };
        }

        DosVerdict::Allow
    }

    /// Add ban score with explicit offense category.
    ///
    /// The category controls:
    ///   - **Decay rate**: Malicious decays slowly, Resource decays fast
    ///   - **Ban duration**: Malicious → 24h base, Resource → 1h base
    ///   - **Repeat multiplier**: Score × 2^ban_count (cap 8×)
    pub fn add_ban_score_cat(&self, peer: &str, points: u64, reason: &str, category: BanCategory) -> bool {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        let rec = bans.entry(peer.to_string()).or_insert_with(BanRecord::new);
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
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        let rec = bans.entry(peer.to_string()).or_insert_with(BanRecord::new);
        rec.banned    = true;
        rec.ban_until = unix_now() + duration_secs;
        rec.reason    = reason.to_string();
    }

    pub fn unban_peer(&self, peer: &str) {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        if let Some(rec) = bans.get_mut(peer) {
            rec.banned         = false;
            rec.score          = 0;
            rec.ban_until      = 0;
            rec.worst_category = BanCategory::Resource;
            rec.reason.clear();
        }
    }

    pub fn is_banned(&self, peer: &str) -> bool {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        bans.entry(peer.to_string())
            .or_insert_with(BanRecord::new)
            .is_banned()
    }

    pub fn get_ban_score(&self, peer: &str) -> u64 {
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        bans.get(peer).map(|r| r.score).unwrap_or(0)
    }

    /// Get detailed ban info for diagnostics / RPC.
    pub fn get_ban_info(&self, peer: &str) -> Option<BanInfo> {
        let bans = self.bans.read().unwrap_or_else(|e| e.into_inner());
        bans.get(peer).map(|r| BanInfo {
            score:          r.score,
            banned:         r.banned,
            ban_until:      r.ban_until,
            ban_count:      r.ban_count,
            worst_category: r.worst_category,
            reason:         r.reason.clone(),
        })
    }

    pub fn tick_decay(&self) {
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        for rec in bans.values_mut() {
            rec.decay();
        }
    }

    pub fn evict_inactive(&self) {
        let mut bans    = self.bans.write().unwrap_or_else(|e| e.into_inner());
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        bans.retain(|_, r| r.banned || r.score > 0);

        buckets.retain(|k, _| bans.contains_key(k.as_str()));
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
            Err(NetworkError::DosGuard(format!("Block too large: {} > {}", size, MAX_BLOCK_BYTES)))
        } else {
            Ok(())
        }
    }

    pub fn check_tx_size(&self, size: usize) -> Result<(), NetworkError> {
        if size > MAX_TX_BYTES {
            Err(NetworkError::DosGuard(format!("Tx too large: {} > {}", size, MAX_TX_BYTES)))
        } else {
            Ok(())
        }
    }
}

impl Default for DosGuard {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub enum DosVerdict {
    Allow,
    BanActive,
    RateLimited  { peer: String },
    GlobalRateLimited,
    OversizedMessage { allowed: usize, got: usize },
}

impl DosVerdict {
    pub fn is_allowed(&self) -> bool { matches!(self, DosVerdict::Allow) }
}

#[derive(Debug)]
pub struct DosStats {
    pub tracked_peers:    usize,
    pub currently_banned: usize,
}

/// Public snapshot of a peer's ban state (for RPC / diagnostics).
#[derive(Debug, Clone)]
pub struct BanInfo {
    pub score:          u64,
    pub banned:         bool,
    pub ban_until:      u64,
    pub ban_count:      u32,
    pub worst_category: BanCategory,
    pub reason:         String,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            g.add_ban_score_cat("ratelimited", 10, &format!("rate #{}", i), BanCategory::Resource);
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
        assert!(banned, "repeat offender should ban faster with 2× multiplier");
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
        assert!(dur1 <= 21_602 && dur1 >= 21_598, "1st ban should be ~6h, got {}s", dur1);

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
        assert!(dur2 <= 43_202 && dur2 >= 43_198, "2nd ban should be ~12h, got {}s", dur2);
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
    fn evict_inactive_cleans_up() {
        let g = DosGuard::new();
        // Create some entries
        g.check("active_peer", &MsgType::Ping, 10);
        g.check("another_peer", &MsgType::Ping, 10);
        // Evict: all are score=0, not banned → should be cleaned
        g.evict_inactive();
        let stats = g.stats();
        assert_eq!(stats.tracked_peers, 0);
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
}
