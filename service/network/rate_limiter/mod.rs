// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MSG_RATE_PER_SEC: u64 = 200;

pub const INV_RATE_PER_SEC: u64 = 100;

pub const TX_RATE_PER_SEC: u64 = 50;

/// Block rate limit — MUST scale with BPS.
/// At 1 BPS: 60 * 2 = 120/min (2x headroom)
/// At 10 BPS: 600 * 2 = 1200/min
/// At 32 BPS: 1920 * 2 = 3840/min
/// Default uses 32 BPS max for compatibility.
pub const BLOCK_RATE_PER_MIN: u64 = 3840;

pub const BURST_SIZE: f64 = 20.0;

#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u64) -> Self {
        let cap = BURST_SIZE.max(rate_per_sec as f64 * 0.1);
        Self {
            tokens: cap,
            capacity: cap,
            refill_rate: rate_per_sec as f64,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn try_consume_n(&mut self, n: u64) -> bool {
        self.refill();
        let needed = n as f64;
        if self.tokens >= needed {
            self.tokens -= needed;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = Instant::now();
    }

    pub fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

pub struct PeerRateLimits {
    pub msg_bucket: TokenBucket,
    pub inv_bucket: TokenBucket,
    pub tx_bucket: TokenBucket,
    pub block_bucket: TokenBucket,
    pub last_active: Instant,
}

impl Default for PeerRateLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRateLimits {
    pub fn new() -> Self {
        Self {
            msg_bucket: TokenBucket::new(MSG_RATE_PER_SEC),
            inv_bucket: TokenBucket::new(INV_RATE_PER_SEC),
            tx_bucket: TokenBucket::new(TX_RATE_PER_SEC),
            block_bucket: TokenBucket::new(BLOCK_RATE_PER_MIN / 60 + 1),
            last_active: Instant::now(),
        }
    }

    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    pub fn is_idle_for(&self, secs: u64) -> bool {
        self.last_active.elapsed() > Duration::from_secs(secs)
    }
}

pub struct RateLimiter {
    limits: HashMap<String, PeerRateLimits>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
        }
    }

    fn entry(&mut self, peer: &str) -> &mut PeerRateLimits {
        self.limits.entry(peer.to_string()).or_default()
    }

    pub fn allow_message(&mut self, peer: &str) -> bool {
        let e = self.entry(peer);
        e.touch();
        e.msg_bucket.try_consume()
    }

    pub fn allow_inv(&mut self, peer: &str) -> bool {
        let e = self.entry(peer);
        e.touch();
        e.inv_bucket.try_consume()
    }

    pub fn allow_transaction(&mut self, peer: &str) -> bool {
        let e = self.entry(peer);
        e.touch();
        e.tx_bucket.try_consume()
    }

    pub fn allow_block(&mut self, peer: &str) -> bool {
        let e = self.entry(peer);
        e.touch();
        e.block_bucket.try_consume()
    }

    pub fn prune_idle(&mut self, idle_secs: u64) {
        self.limits.retain(|_, v| !v.is_idle_for(idle_secs));
    }

    pub fn peer_count(&self) -> usize {
        self.limits.len()
    }

    pub fn remove_peer(&mut self, peer: &str) {
        self.limits.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_initial_burst() {
        let mut bucket = TokenBucket::new(10);

        assert!(bucket.try_consume());
    }

    #[test]
    fn token_bucket_denies_after_exhaustion() {
        let mut bucket = TokenBucket::new(1);

        while bucket.try_consume() {}

        assert!(!bucket.try_consume());
    }

    #[test]
    fn rate_limiter_allows_message() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow_message("peer1"));
    }

    #[test]
    fn rate_limiter_allows_transaction() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow_transaction("peer1"));
    }

    #[test]
    fn prune_idle_removes_inactive() {
        let mut rl = RateLimiter::new();
        rl.allow_message("peer1");

        rl.prune_idle(u64::MAX);
        assert_eq!(rl.peer_count(), 1);
    }

    #[test]
    fn remove_peer_works() {
        let mut rl = RateLimiter::new();
        rl.allow_message("peer1");
        rl.remove_peer("peer1");
        assert_eq!(rl.peer_count(), 0);
    }

    #[test]
    fn separate_buckets_per_peer() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow_message("peer_a"));
        assert!(rl.allow_message("peer_b"));
    }
}
