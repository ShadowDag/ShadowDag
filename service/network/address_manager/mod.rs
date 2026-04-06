// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_ADDRESSES:        usize = 4_096;
pub const MAX_NEW_BUCKET_SIZE:  usize = 64;
pub const MAX_TRIED_BUCKET_SIZE: usize = 64;
pub const NEW_BUCKET_COUNT:     usize = 1_024;
pub const TRIED_BUCKET_COUNT:   usize = 256;
pub const ADDR_TIMEOUT_SECS:    u64   = 14 * 24 * 3_600;

#[derive(Debug, Clone)]
pub struct AddressEntry {
    pub address:    String,
    pub last_seen:  u64,
    pub attempts:   u32,
    pub successes:  u32,
    pub is_tried:   bool,
    pub source:     String,
}

impl AddressEntry {
    pub fn new(address: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            address:   address.into(),
            last_seen: now_secs(),
            attempts:  0,
            successes: 0,
            is_tried:  false,
            source:    source.into(),
        }
    }

    pub fn is_stale(&self) -> bool {
        now_secs().saturating_sub(self.last_seen) > ADDR_TIMEOUT_SECS
    }

    pub fn reliability_score(&self) -> f64 {
        if self.attempts == 0 { return 0.5; }
        self.successes as f64 / self.attempts as f64
    }
}

pub struct AddressManager {
    new_table:   HashMap<String, AddressEntry>,
    tried_table: HashMap<String, AddressEntry>,
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressManager {
    pub fn new() -> Self {
        Self {
            new_table:   HashMap::new(),
            tried_table: HashMap::new(),
        }
    }

    pub fn add_address(&mut self, address: &str, source: &str) {
        // Validate address format to prevent poisoning attacks.
        // Must be host:port format with valid port range.
        if !Self::is_valid_peer_addr(address) { return; }
        if self.tried_table.contains_key(address) { return; }
        if self.new_table.len() >= MAX_ADDRESSES   { self.evict_stale(); }
        self.new_table
            .entry(address.to_string())
            .and_modify(|e| e.last_seen = now_secs())
            .or_insert_with(|| AddressEntry::new(address, source));
    }

    /// Validate peer address format: must be host:port with port in [1, 65535]
    fn is_valid_peer_addr(addr: &str) -> bool {
        if addr.is_empty() || addr.len() > 256 { return false; }
        match addr.rsplit_once(':') {
            Some((host, port_str)) => {
                if host.is_empty() { return false; }
                match port_str.parse::<u16>() {
                    Ok(p) => p >= 1,
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    pub fn add_addresses(&mut self, addresses: &[String], source: &str) {
        for addr in addresses {
            self.add_address(addr, source);
        }
    }

    pub fn mark_tried(&mut self, address: &str) {
        if let Some(mut entry) = self.new_table.remove(address) {
            entry.is_tried   = true;
            entry.last_seen  = now_secs();
            entry.successes += 1;
            entry.attempts  += 1;
            if self.tried_table.len() >= MAX_ADDRESSES {
                self.evict_oldest_tried();
            }
            self.tried_table.insert(address.to_string(), entry);
        } else if let Some(entry) = self.tried_table.get_mut(address) {
            entry.last_seen  = now_secs();
            entry.successes += 1;
            entry.attempts  += 1;
        }
    }

    pub fn mark_attempt(&mut self, address: &str) {
        if let Some(e) = self.new_table.get_mut(address) {
            e.attempts += 1;
        } else if let Some(e) = self.tried_table.get_mut(address) {
            e.attempts += 1;
        }
    }

    pub fn select_peers(&self, count: usize) -> Vec<String> {
        let mut candidates: Vec<&AddressEntry> = self
            .tried_table.values()
            .chain(self.new_table.values())
            .filter(|e| !e.is_stale())
            .collect();

        candidates.sort_by(|a, b| {
            b.reliability_score()
                .partial_cmp(&a.reliability_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates.iter().take(count).map(|e| e.address.clone()).collect()
    }

    pub fn get_addr_list(&self, max: usize) -> Vec<String> {
        let mut entries: Vec<&AddressEntry> = self
            .new_table.values()
            .chain(self.tried_table.values())
            .filter(|e| !e.is_stale())
            .collect();

        entries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        entries.iter().take(max).map(|e| e.address.clone()).collect()
    }

    pub fn new_count(&self)   -> usize { self.new_table.len() }
    pub fn tried_count(&self) -> usize { self.tried_table.len() }
    pub fn total_count(&self) -> usize { self.new_table.len() + self.tried_table.len() }

    pub fn contains(&self, address: &str) -> bool {
        self.new_table.contains_key(address) || self.tried_table.contains_key(address)
    }

    pub fn evict_stale(&mut self) {
        self.new_table.retain(|_, e| !e.is_stale());
        self.tried_table.retain(|_, e| !e.is_stale());
    }

    fn evict_oldest_tried(&mut self) {
        if let Some(oldest) = self.tried_table
            .values()
            .min_by_key(|e| e.last_seen)
            .map(|e| e.address.clone())
        {
            self.tried_table.remove(&oldest);
        }
    }
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
    fn add_and_contains() {
        let mut mgr = AddressManager::new();
        mgr.add_address("1.2.3.4:9333", "self");
        assert!(mgr.contains("1.2.3.4:9333"));
    }

    #[test]
    fn mark_tried_moves_to_tried_table() {
        let mut mgr = AddressManager::new();
        mgr.add_address("1.2.3.4:9333", "self");
        mgr.mark_tried("1.2.3.4:9333");
        assert_eq!(mgr.new_count(), 0);
        assert_eq!(mgr.tried_count(), 1);
    }

    #[test]
    fn select_peers_returns_limited() {
        let mut mgr = AddressManager::new();
        for i in 0..20 {
            mgr.add_address(&format!("10.0.0.{}:9333", i), "self");
            mgr.mark_tried(&format!("10.0.0.{}:9333", i));
        }
        let selected = mgr.select_peers(5);
        assert!(selected.len() <= 5);
    }

    #[test]
    fn add_addresses_batch() {
        let mut mgr = AddressManager::new();
        let addrs: Vec<String> = (0..5).map(|i| format!("11.0.0.{}:9333", i)).collect();
        mgr.add_addresses(&addrs, "peer");
        assert_eq!(mgr.new_count(), 5);
    }

    #[test]
    fn no_duplicate_in_tried() {
        let mut mgr = AddressManager::new();
        mgr.add_address("5.5.5.5:9333", "self");
        mgr.mark_tried("5.5.5.5:9333");
        mgr.add_address("5.5.5.5:9333", "other");

        assert_eq!(mgr.new_count(), 0);
        assert_eq!(mgr.tried_count(), 1);
    }
}
