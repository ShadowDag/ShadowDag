// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_CONNECTIONS_PER_IP: usize = 4;
pub const MAX_MSG_SIZE_BYTES: usize = 4 * 1024 * 1024;
pub const MSG_FLOOD_THRESHOLD: u64 = 500;
pub const BLOCK_FLOOD_THRESHOLD: u64 = 20;
pub const BAN_SCORE_THRESHOLD: u64 = 100;
pub const BAN_DURATION_SECS: u64 = 86_400;
pub const IDLE_ENTRY_EXPIRY_SECS: u64 = 3_600;

#[derive(Debug, Clone)]
pub struct IpStats {
    pub connections: usize,
    pub msg_count: u64,
    pub block_count: u64,
    pub invalid_count: u64,
    pub ban_score: u64,
    pub ban_expiry: u64,
    pub window_start: Instant,
    pub last_seen: u64,
}

impl Default for IpStats {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            connections: 0,
            msg_count: 0,
            block_count: 0,
            invalid_count: 0,
            ban_score: 0,
            ban_expiry: 0,
            window_start: Instant::now(),
            last_seen: now,
        }
    }
}

impl IpStats {
    pub fn is_banned(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.ban_expiry > now
    }

    fn refresh_window(&mut self) {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.msg_count = 0;
            self.block_count = 0;
            self.window_start = Instant::now();
        }
    }
}

pub struct DosProtection {
    ip_stats: HashMap<String, IpStats>,
}

impl Default for DosProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl DosProtection {
    pub fn new() -> Self {
        Self {
            ip_stats: HashMap::new(),
        }
    }

    fn entry(&mut self, ip: &str) -> &mut IpStats {
        let stats = self.ip_stats.entry(ip.to_string()).or_default();
        stats.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        stats
    }

    pub fn allow_connection(&mut self, ip: &str) -> bool {
        let stats = self.entry(ip);
        if stats.is_banned() {
            return false;
        }
        if stats.connections >= MAX_CONNECTIONS_PER_IP {
            self.add_ban_score(ip, 10);
            return false;
        }
        stats.connections += 1;
        true
    }

    pub fn on_disconnect(&mut self, ip: &str) {
        if let Some(s) = self.ip_stats.get_mut(ip) {
            s.connections = s.connections.saturating_sub(1);
        }
    }

    pub fn allow_message(&mut self, ip: &str, size_bytes: usize) -> bool {
        if size_bytes > MAX_MSG_SIZE_BYTES {
            self.add_ban_score(ip, 20);
            return false;
        }
        let flood = {
            let stats = self.entry(ip);
            if stats.is_banned() {
                return false;
            }
            stats.refresh_window();
            stats.msg_count += 1;
            stats.msg_count > MSG_FLOOD_THRESHOLD
        };
        if flood {
            self.add_ban_score(ip, 5);
            return false;
        }
        true
    }

    pub fn allow_block(&mut self, ip: &str) -> bool {
        if self.entry(ip).is_banned() {
            return false;
        }
        let flood = {
            let stats = self.entry(ip);
            stats.refresh_window();
            stats.block_count += 1;
            stats.block_count > BLOCK_FLOOD_THRESHOLD
        };
        if flood {
            self.add_ban_score(ip, 10);
            return false;
        }
        true
    }

    pub fn report_invalid_block(&mut self, ip: &str) {
        self.entry(ip).invalid_count += 1;
        self.add_ban_score(ip, 20);
    }

    pub fn report_invalid_tx(&mut self, ip: &str) {
        self.entry(ip).invalid_count += 1;
        self.add_ban_score(ip, 5);
    }

    pub fn report_malformed(&mut self, ip: &str) {
        self.entry(ip).invalid_count += 1;
        self.add_ban_score(ip, 50);
    }

    fn add_ban_score(&mut self, ip: &str, delta: u64) {
        let stats = self.entry(ip);
        stats.ban_score += delta;
        if stats.ban_score >= BAN_SCORE_THRESHOLD {
            let expiry = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + BAN_DURATION_SECS;
            stats.ban_expiry = expiry;
        }
    }

    pub fn is_banned(&self, ip: &str) -> bool {
        self.ip_stats
            .get(ip)
            .map(|s| s.is_banned())
            .unwrap_or(false)
    }

    pub fn ban_score(&self, ip: &str) -> u64 {
        self.ip_stats.get(ip).map(|s| s.ban_score).unwrap_or(0)
    }

    pub fn prune_expired_bans(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for stats in self.ip_stats.values_mut() {
            if stats.ban_expiry > 0 && stats.ban_expiry <= now {
                stats.ban_expiry = 0;
                stats.ban_score = 0;
            }
        }
        // Remove entries that are no longer banned and have no active connections,
        // AND also remove idle entries (ban_score=0, no connections, last_seen older
        // than IDLE_ENTRY_EXPIRY_SECS) to prevent unbounded memory growth.
        self.ip_stats.retain(|_, s| {
            // Keep if actively banned or has a ban score
            if s.ban_score > 0 || s.ban_expiry > 0 {
                return true;
            }
            // Keep if there are active connections
            if s.connections > 0 {
                return true;
            }
            // Remove if idle for longer than the expiry threshold
            let idle_duration = now.saturating_sub(s.last_seen);
            idle_duration < IDLE_ENTRY_EXPIRY_SECS
        });
    }

    pub fn ip_count(&self) -> usize {
        self.ip_stats
            .values()
            .filter(|s| s.ban_score > 0 || s.ban_expiry > 0 || s.connections > 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_connection_normally() {
        let mut dos = DosProtection::new();
        assert!(dos.allow_connection("1.1.1.1"));
    }

    #[test]
    fn block_too_many_connections() {
        let mut dos = DosProtection::new();
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            dos.allow_connection("2.2.2.2");
        }
        assert!(!dos.allow_connection("2.2.2.2"));
    }

    #[test]
    fn report_invalid_block_increases_score() {
        let mut dos = DosProtection::new();
        dos.report_invalid_block("3.3.3.3");
        assert!(dos.ban_score("3.3.3.3") > 0);
    }

    #[test]
    fn ban_after_threshold() {
        let mut dos = DosProtection::new();

        for _ in 0..5 {
            dos.report_invalid_block("4.4.4.4");
        }
        assert!(dos.is_banned("4.4.4.4"));
    }

    #[test]
    fn oversized_message_rejected() {
        let mut dos = DosProtection::new();
        assert!(!dos.allow_message("5.5.5.5", MAX_MSG_SIZE_BYTES + 1));
    }

    #[test]
    fn normal_message_allowed() {
        let mut dos = DosProtection::new();
        assert!(dos.allow_message("5.5.5.5", 1_000));
    }
}
