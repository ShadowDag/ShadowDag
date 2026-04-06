// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const INITIAL_SCORE:       i32  = 100;
pub const MIN_SCORE:           i32  = -100;
pub const BAN_THRESHOLD:       i32  = -50;
pub const AUTO_BAN_THRESHOLD:  i32  = -80;

pub const PENALTY_INVALID_BLOCK:  i32 = -20;
pub const PENALTY_INVALID_TX:     i32 = -10;
pub const PENALTY_MISBEHAVIOR:    i32 = -50;
pub const PENALTY_SPAM:           i32 = -5;
pub const PENALTY_TIMEOUT:        i32 = -2;
pub const PENALTY_BAD_PROTO:      i32 = -30;

pub const REWARD_VALID_BLOCK:     i32 = 2;
pub const REWARD_VALID_TX:        i32 = 1;
pub const REWARD_UPTIME:          i32 = 1;

pub const BAN_DURATION_SECS:      u64 = 86_400;
pub const SEVERE_BAN_DURATION:    u64 = 7 * 86_400;

#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub score:     i32,
    pub ban_expiry: u64,
    pub total_sent: u64,
    pub total_ok:   u64,
    pub last_seen:  u64,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            score:      INITIAL_SCORE,
            ban_expiry: 0,
            total_sent: 0,
            total_ok:   0,
            last_seen:  now_secs(),
        }
    }
}

impl PeerReputation {
    pub fn is_banned(&self) -> bool {
        self.ban_expiry > now_secs()
    }

    pub fn reliability(&self) -> f64 {
        if self.total_sent == 0 { return 1.0; }
        self.total_ok as f64 / self.total_sent as f64
    }
}

pub struct ReputationManager {
    records: HashMap<String, PeerReputation>,
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationManager {
    pub fn new() -> Self {
        Self { records: HashMap::new() }
    }

    fn entry(&mut self, peer: &str) -> &mut PeerReputation {
        self.records
            .entry(peer.to_string())
            .or_default()
    }

    pub fn penalize(&mut self, peer: &str, delta: i32, _reason: &str) {
        let rec = self.entry(peer);
        rec.score = (rec.score + delta).max(MIN_SCORE);
        rec.total_sent += 1;

        if rec.score <= AUTO_BAN_THRESHOLD {
            let exp = now_secs() + BAN_DURATION_SECS;
            rec.ban_expiry = exp;
        }
    }

    pub fn penalize_invalid_block(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_INVALID_BLOCK, "invalid_block");
    }
    pub fn penalize_invalid_tx(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_INVALID_TX, "invalid_tx");
    }
    pub fn penalize_spam(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_SPAM, "spam");
    }
    pub fn penalize_timeout(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_TIMEOUT, "timeout");
    }
    pub fn penalize_bad_protocol(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_BAD_PROTO, "bad_protocol");
    }
    pub fn penalize_misbehavior(&mut self, peer: &str) {
        self.penalize(peer, PENALTY_MISBEHAVIOR, "misbehavior");

        let exp = now_secs() + SEVERE_BAN_DURATION;
        if let Some(rec) = self.records.get_mut(peer) {
            rec.ban_expiry = rec.ban_expiry.max(exp);
        }
    }

    pub fn reward(&mut self, peer: &str, delta: i32) {
        let rec = self.entry(peer);
        rec.score    = (rec.score + delta).min(INITIAL_SCORE);
        rec.total_ok += 1;
        rec.last_seen = now_secs();
    }

    pub fn reward_valid_block(&mut self, peer: &str) {
        self.reward(peer, REWARD_VALID_BLOCK);
    }
    pub fn reward_valid_tx(&mut self, peer: &str) {
        self.reward(peer, REWARD_VALID_TX);
    }

    pub fn get(&self, peer: &str) -> Option<&PeerReputation> {
        self.records.get(peer)
    }

    pub fn score(&self, peer: &str) -> i32 {
        self.records.get(peer).map(|r| r.score).unwrap_or(INITIAL_SCORE)
    }

    pub fn is_banned(&self, peer: &str) -> bool {
        self.records.get(peer).map(|r| r.is_banned()).unwrap_or(false)
    }

    pub fn should_disconnect(&self, peer: &str) -> bool {
        self.score(peer) <= BAN_THRESHOLD
    }

    pub fn best_peers(&self, count: usize) -> Vec<String> {
        let mut peers: Vec<(&String, &PeerReputation)> = self.records.iter()
            .filter(|(_, r)| !r.is_banned())
            .collect();
        peers.sort_by(|a, b| b.1.score.cmp(&a.1.score));
        peers.iter().take(count).map(|(k, _)| k.to_string()).collect()
    }

    pub fn prune_expired_bans(&mut self) {
        let now = now_secs();
        for rec in self.records.values_mut() {
            if rec.ban_expiry > 0 && rec.ban_expiry <= now {
                rec.ban_expiry = 0;
                rec.score      = 0;
            }
        }
    }

    pub fn peer_count(&self) -> usize { self.records.len() }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_score_is_100() {
        let mgr = ReputationManager::new();
        assert_eq!(mgr.score("new_peer"), INITIAL_SCORE);
    }

    #[test]
    fn penalize_reduces_score() {
        let mut mgr = ReputationManager::new();
        mgr.penalize_invalid_block("bad_peer");
        assert!(mgr.score("bad_peer") < INITIAL_SCORE);
    }

    #[test]
    fn auto_ban_on_extreme_penalty() {
        let mut mgr = ReputationManager::new();
        mgr.penalize_misbehavior("evil_peer");
        assert!(mgr.is_banned("evil_peer"));
    }

    #[test]
    fn reward_increases_score() {
        let mut mgr = ReputationManager::new();
        mgr.penalize_spam("p");
        let before = mgr.score("p");
        mgr.reward_valid_block("p");
        assert!(mgr.score("p") > before);
    }

    #[test]
    fn best_peers_excludes_banned() {
        let mut mgr = ReputationManager::new();
        mgr.records.insert("good".into(), PeerReputation::default());
        mgr.penalize_misbehavior("evil");
        let best = mgr.best_peers(10);
        assert!(best.contains(&"good".to_string()));
        assert!(!best.contains(&"evil".to_string()));
    }

    #[test]
    fn should_disconnect_at_threshold() {
        let mut mgr = ReputationManager::new();

        for _ in 0..10 {
            mgr.penalize("slow", PENALTY_SPAM, "spam");
        }

        let score = mgr.score("slow");
        assert_eq!(mgr.should_disconnect("slow"), score <= BAN_THRESHOLD);
    }
}
