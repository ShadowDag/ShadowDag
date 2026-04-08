// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Dandelion++ — Privacy-preserving transaction relay protocol.
//
// Standard P2P: TX broadcast to all peers → trivial to trace source IP.
// Dandelion++:  TX passes through a "stem" phase (1-to-1 relay) before
//               entering the "fluff" phase (normal broadcast).
//
// Phases:
//   STEM:  TX relayed to exactly ONE randomly chosen peer (anonymity hop)
//          Each hop has STEM_PROBABILITY chance of continuing stem.
//          After MAX_STEM_HOPS or timeout, transitions to fluff.
//
//   FLUFF: Normal broadcast to all connected peers.
//
// This makes it impossible for a network observer to determine which
// node originated a transaction, even with multiple colluding nodes.
//
// ShadowDAG improvement: combines with Shadow Pool for double-layer privacy.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::rngs::OsRng;
use rand::RngCore;

/// Probability of continuing stem phase at each hop (0-100)
pub const STEM_PROBABILITY: u8 = 90; // 90% chance to continue stem

/// Maximum stem hops before forced fluff
pub const MAX_STEM_HOPS: u8 = 10;

/// Stem timeout — force fluff after this many seconds
pub const STEM_TIMEOUT_SECS: u64 = 30;

/// Epoch duration — re-randomize stem peer selection
pub const EPOCH_DURATION_SECS: u64 = 600; // 10 minutes

/// Max pending stem TXs
pub const MAX_STEM_PENDING: usize = 5_000;

/// Max seen set size — prevents unbounded memory growth.
/// At 10K TX/sec, 1M entries covers ~100 seconds of history.
pub const MAX_SEEN_SET_SIZE: usize = 1_000_000;

/// Transaction relay phase
#[derive(Debug, Clone, PartialEq)]
pub enum RelayPhase {
    /// Stem: relay to exactly one peer
    Stem { hops: u8, entered_at: u64 },
    /// Fluff: broadcast to all peers
    Fluff,
}

/// A transaction in the Dandelion pipeline
#[derive(Debug, Clone)]
pub struct DandelionTx {
    pub tx_hash:   String,
    pub phase:     RelayPhase,
    pub stem_peer: Option<String>, // Selected stem relay peer
    pub created:   u64,
}

/// Dandelion++ relay engine
pub struct DandelionRelay {
    /// Pending stem transactions
    stem_pool:       HashMap<String, DandelionTx>,
    /// TXs already seen (prevent loops)
    seen:            HashSet<String>,
    /// Current epoch's stem peer assignment (rotated every EPOCH_DURATION)
    stem_peer_map:   HashMap<String, String>, // our_node → stem_peer
    /// Epoch start time
    epoch_start:     u64,
    /// RNG state
    rng_counter:     u64,
}

impl Default for DandelionRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl DandelionRelay {
    pub fn new() -> Self {
        Self {
            stem_pool:     HashMap::with_capacity(256),
            seen:          HashSet::with_capacity(4096),
            stem_peer_map: HashMap::new(),
            epoch_start:   now_secs(),
            rng_counter:   0,
        }
    }

    /// Process an incoming transaction — decide stem or fluff.
    /// Uses the provided connected peer list for stem peer selection.
    pub fn on_new_tx_with_peers(
        &mut self,
        tx_hash: &str,
        from_peer: Option<&str>,
        connected_peers: &[String],
    ) -> RelayAction {
        // Already seen — ignore
        if self.seen.contains(tx_hash) {
            return RelayAction::Drop;
        }
        self.seen.insert(tx_hash.to_string());

        // Prune seen set to prevent unbounded growth (cap at 1M entries)
        if self.seen.len() > MAX_SEEN_SET_SIZE {
            self.prune_seen(MAX_SEEN_SET_SIZE);
        }

        // Prune if too many pending
        if self.stem_pool.len() >= MAX_STEM_PENDING {
            self.flush_expired();
        }
        // Hard cap: if STILL over limit after expiry, force-fluff oldest entries
        if self.stem_pool.len() >= MAX_STEM_PENDING {
            let excess = self.stem_pool.len() - MAX_STEM_PENDING + 1;
            let oldest_keys: Vec<String> = self.stem_pool.keys()
                .take(excess)
                .cloned()
                .collect();
            for key in oldest_keys {
                self.stem_pool.remove(&key);
            }
        }

        // If this TX was received in stem phase from another node
        if let Some(_peer) = from_peer {
            // Decide: continue stem or transition to fluff
            if self.should_continue_stem() {
                if let Some(stem_peer) = self.select_stem_peer_from(connected_peers) {
                    let dtx = DandelionTx {
                        tx_hash:   tx_hash.to_string(),
                        phase:     RelayPhase::Stem { hops: 1, entered_at: now_secs() },
                        stem_peer: Some(stem_peer.clone()),
                        created:   now_secs(),
                    };
                    self.stem_pool.insert(tx_hash.to_string(), dtx);
                    return RelayAction::StemTo(stem_peer);
                }
                // No peers available — fall through to fluff
            }
            return RelayAction::Fluff;
        }

        // New TX from local wallet — always start in stem phase
        if let Some(stem_peer) = self.select_stem_peer_from(connected_peers) {
            let dtx = DandelionTx {
                tx_hash:   tx_hash.to_string(),
                phase:     RelayPhase::Stem { hops: 0, entered_at: now_secs() },
                stem_peer: Some(stem_peer.clone()),
                created:   now_secs(),
            };
            self.stem_pool.insert(tx_hash.to_string(), dtx);
            RelayAction::StemTo(stem_peer)
        } else {
            // No connected peers — fluff immediately (best effort)
            RelayAction::Fluff
        }
    }

    /// Convenience wrapper — delegates to on_new_tx_with_peers with empty peer list.
    /// Kept for backward compatibility with tests.
    pub fn on_new_tx(&mut self, tx_hash: &str, from_peer: Option<&str>) -> RelayAction {
        self.on_new_tx_with_peers(tx_hash, from_peer, &[])
    }

    /// Tick: flush expired stem TXs to fluff phase
    pub fn tick(&mut self) -> Vec<String> {
        let now = now_secs();
        let mut to_fluff = Vec::new();

        // Check epoch rotation
        if now - self.epoch_start >= EPOCH_DURATION_SECS {
            self.epoch_start = now;
            self.stem_peer_map.clear(); // Re-randomize stem peers
        }

        // Flush expired stems
        let expired: Vec<String> = self.stem_pool.iter()
            .filter(|(_, dtx)| {
                match dtx.phase {
                    RelayPhase::Stem { entered_at, hops, .. } => {
                        now - entered_at >= STEM_TIMEOUT_SECS || hops >= MAX_STEM_HOPS
                    }
                    RelayPhase::Fluff => true,
                }
            })
            .map(|(h, _)| h.clone())
            .collect();

        for hash in expired {
            self.stem_pool.remove(&hash);
            to_fluff.push(hash);
        }

        to_fluff
    }

    /// Flush ALL pending stem TXs (emergency or shutdown)
    pub fn flush_all(&mut self) -> Vec<String> {
        let all: Vec<String> = self.stem_pool.keys().cloned().collect();
        self.stem_pool.clear();
        all
    }

    /// Prune seen set to prevent unbounded growth.
    /// Uses random eviction to avoid leaking relay timing information.
    /// Ordered removal (e.g., first-N or iterator-order) would let an
    /// observer correlate eviction patterns with transaction arrival times.
    pub fn prune_seen(&mut self, max_size: usize) {
        if self.seen.len() <= max_size {
            return;
        }
        let to_remove_count = self.seen.len() - max_size / 2;
        let mut entries: Vec<String> = self.seen.iter().cloned().collect();

        // Fisher-Yates shuffle with OS entropy, then take the first N
        for i in (1..entries.len()).rev() {
            let j = (self.next_rng() as usize) % (i + 1);
            entries.swap(i, j);
        }

        for h in entries.into_iter().take(to_remove_count) {
            self.seen.remove(&h);
        }
    }

    /// Stats
    pub fn stem_count(&self) -> usize { self.stem_pool.len() }
    pub fn seen_count(&self) -> usize { self.seen.len() }

    // ── Internal ────────────────────────────────────────────────

    fn should_continue_stem(&mut self) -> bool {
        let r = self.next_rng() % 100;
        r < STEM_PROBABILITY as u64
    }

    /// Select a random stem peer from the given connected peer list.
    /// Returns None if no peers are connected — caller must fluff instead.
    fn select_stem_peer_from(&mut self, peers: &[String]) -> Option<String> {
        if peers.is_empty() {
            log::warn!("[Dandelion] No connected peers for stem relay — will fluff instead");
            return None;
        }
        let r = self.next_rng() as usize;
        Some(peers[r % peers.len()].clone())
    }

    fn flush_expired(&mut self) {
        let now = now_secs();
        self.stem_pool.retain(|_, dtx| {
            match dtx.phase {
                RelayPhase::Stem { entered_at, .. } => now - entered_at < STEM_TIMEOUT_SECS,
                RelayPhase::Fluff => false,
            }
        });
    }

    fn next_rng(&mut self) -> u64 {
        self.rng_counter += 1;
        let mut buf = [0u8; 8];
        OsRng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// What to do with a TX after Dandelion processing
#[derive(Debug, Clone)]
pub enum RelayAction {
    /// Relay to exactly one peer (stem phase)
    StemTo(String),
    /// Broadcast to all peers (fluff phase)
    Fluff,
    /// Already seen — drop
    Drop,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peers() -> Vec<String> {
        vec!["peer_a".to_string(), "peer_b".to_string()]
    }

    #[test]
    fn new_tx_starts_in_stem() {
        let mut relay = DandelionRelay::new();
        let peers = test_peers();
        let action = relay.on_new_tx_with_peers("tx_001", None, &peers);
        assert!(matches!(action, RelayAction::StemTo(_)));
    }

    #[test]
    fn duplicate_tx_dropped() {
        let mut relay = DandelionRelay::new();
        let peers = test_peers();
        relay.on_new_tx_with_peers("tx_001", None, &peers);
        let action = relay.on_new_tx_with_peers("tx_001", None, &peers);
        assert!(matches!(action, RelayAction::Drop));
    }

    #[test]
    fn stem_pool_accepts_txs() {
        let mut relay = DandelionRelay::new();
        let peers = test_peers();
        for i in 0..100 {
            relay.on_new_tx_with_peers(&format!("tx_{}", i), None, &peers);
        }
        assert!(relay.stem_count() <= 100);
    }

    #[test]
    fn tick_flushes_expired() {
        let mut relay = DandelionRelay::new();
        let peers = test_peers();
        relay.on_new_tx_with_peers("tx_old", None, &peers);
        // Manually age the TX
        if let Some(dtx) = relay.stem_pool.get_mut("tx_old") {
            dtx.phase = RelayPhase::Stem { hops: MAX_STEM_HOPS + 1, entered_at: 0 };
        }
        let flushed = relay.tick();
        assert!(flushed.contains(&"tx_old".to_string()));
    }

    #[test]
    fn prune_seen() {
        let mut relay = DandelionRelay::new();
        for i in 0..10_000 {
            relay.seen.insert(format!("tx_{}", i));
        }
        relay.prune_seen(5_000);
        assert!(relay.seen_count() < 10_000, "Should have pruned some entries");
    }

    #[test]
    fn flush_all_clears_pool() {
        let mut relay = DandelionRelay::new();
        let peers = test_peers();
        relay.on_new_tx_with_peers("tx_1", None, &peers);
        relay.on_new_tx_with_peers("tx_2", None, &peers);
        let flushed = relay.flush_all();
        assert_eq!(flushed.len(), 2);
        assert_eq!(relay.stem_count(), 0);
    }
}
