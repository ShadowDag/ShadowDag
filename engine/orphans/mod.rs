// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const MAX_ORPHANS:       usize    = 1_000;
pub const ORPHAN_TTL_SECS:   u64      = 3_600;
/// Maximum size of orphan block data (prevents memory exhaustion)
pub const MAX_ORPHAN_DATA_BYTES: usize = 4 * 1024 * 1024; // 4 MB

#[derive(Debug, Clone)]
pub struct OrphanBlock {
    pub hash:      String,
    pub parents:   Vec<String>,
    pub raw_data:  String,
    pub added_at:  Instant,
}

impl OrphanBlock {
    pub fn new(hash: &str, parents: Vec<String>, raw_data: &str) -> Self {
        Self {
            hash:     hash.to_string(),
            parents,
            raw_data: raw_data.to_string(),
            added_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.added_at.elapsed() > Duration::from_secs(ORPHAN_TTL_SECS)
    }
}

pub struct OrphanManager {
    orphans:     HashMap<String, OrphanBlock>,

    waiting_for: HashMap<String, HashSet<String>>,
    /// Tracks which parents each orphan is still waiting for.
    /// An orphan is only ready when its pending_parents set becomes empty.
    pending_parents: HashMap<String, HashSet<String>>,
    pub eviction_count: u64,
}

impl Default for OrphanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanManager {
    pub fn new() -> Self {
        Self {
            orphans:         HashMap::new(),
            waiting_for:     HashMap::new(),
            pending_parents: HashMap::new(),
            eviction_count:  0,
        }
    }

    pub fn add(&mut self, hash: &str, parents: Vec<String>, raw_data: &str) -> bool {
        if self.orphans.contains_key(hash) { return false; }
        // Reject oversized orphan data to prevent memory exhaustion
        if raw_data.len() > MAX_ORPHAN_DATA_BYTES { return false; }

        if self.orphans.len() >= MAX_ORPHANS {
            self.evict_oldest();
        }

        for parent in &parents {
            self.waiting_for
                .entry(parent.clone())
                .or_default()
                .insert(hash.to_string());
        }

        // Track which parents this orphan is still waiting for
        self.pending_parents.insert(
            hash.to_string(),
            parents.iter().cloned().collect(),
        );

        self.orphans.insert(hash.to_string(), OrphanBlock::new(hash, parents, raw_data));
        true
    }

    pub fn get_ready(&mut self, parent_hash: &str) -> Vec<OrphanBlock> {
        let candidate_hashes: HashSet<String> = self
            .waiting_for
            .remove(parent_hash)
            .unwrap_or_default();

        let mut ready = Vec::new();
        for hash in &candidate_hashes {
            // Remove arrived parent from this orphan's pending set
            if let Some(pending) = self.pending_parents.get_mut(hash) {
                pending.remove(parent_hash);
                if !pending.is_empty() {
                    // Still waiting for other parents — not ready yet
                    continue;
                }
            }
            // All parents resolved — remove from tracking and return as ready
            self.pending_parents.remove(hash);
            if let Some(orphan) = self.orphans.remove(hash) {
                for p in &orphan.parents {
                    if p != parent_hash {
                        if let Some(set) = self.waiting_for.get_mut(p) {
                            set.remove(hash);
                            if set.is_empty() {
                                self.waiting_for.remove(p);
                            }
                        }
                    }
                }
                ready.push(orphan);
            }
        }

        if !ready.is_empty() {
            log::debug!("[Orphans] {} orphan blocks ready for processing", ready.len());
        }
        ready
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.orphans.contains_key(hash)
    }

    pub fn get(&self, hash: &str) -> Option<&OrphanBlock> {
        self.orphans.get(hash)
    }

    pub fn evict_oldest(&mut self) {
        if self.orphans.is_empty() { return; }
        let oldest = self.orphans.values()
            .min_by_key(|o| o.added_at)
            .map(|o| o.hash.clone());
        if let Some(hash) = oldest {
            self.remove_orphan(&hash);
            self.eviction_count += 1;
        }
    }

    pub fn evict_expired(&mut self) -> usize {
        let expired: Vec<String> = self.orphans.values()
            .filter(|o| o.is_expired())
            .map(|o| o.hash.clone())
            .collect();
        let count = expired.len();
        for hash in expired { self.remove_orphan(&hash); }
        if count > 0 {
            self.eviction_count += count as u64;
        }
        count
    }

    fn remove_orphan(&mut self, hash: &str) {
        if let Some(orphan) = self.orphans.remove(hash) {
            self.pending_parents.remove(hash);
            for parent in &orphan.parents {
                if let Some(set) = self.waiting_for.get_mut(parent) {
                    set.remove(hash);
                    if set.is_empty() {
                        self.waiting_for.remove(parent);
                    }
                }
            }
        }
    }

    pub fn count(&self) -> usize { self.orphans.len() }
    pub fn waiting_for_count(&self) -> usize { self.waiting_for.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_orphan_stored() {
        let mut mgr = OrphanManager::new();
        mgr.add("orphan1", vec!["missing_parent".into()], "data");
        assert!(mgr.contains("orphan1"));
    }

    #[test]
    fn duplicate_not_added() {
        let mut mgr = OrphanManager::new();
        mgr.add("o1", vec!["p1".into()], "data");
        let added = mgr.add("o1", vec!["p1".into()], "data");
        assert!(!added);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn get_ready_returns_waiting_orphan() {
        let mut mgr = OrphanManager::new();
        mgr.add("orphan1", vec!["parent1".into()], "data");
        let ready = mgr.get_ready("parent1");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].hash, "orphan1");
        assert!(!mgr.contains("orphan1"));
    }

    #[test]
    fn get_ready_returns_empty_for_unknown_parent() {
        let mut mgr = OrphanManager::new();
        let ready = mgr.get_ready("unknown");
        assert!(ready.is_empty());
    }

    #[test]
    fn multi_parent_orphan_waits_for_all() {
        let mut mgr = OrphanManager::new();
        mgr.add("o1", vec!["p1".into(), "p2".into()], "data");

        // First parent arrives — orphan should NOT be ready yet
        let ready = mgr.get_ready("p1");
        assert_eq!(ready.len(), 0, "orphan should wait for all parents");
        assert!(mgr.contains("o1"), "orphan should still be tracked");

        // Second parent arrives — now orphan should be ready
        let ready = mgr.get_ready("p2");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].hash, "o1");
        assert!(!mgr.contains("o1"));
    }

    #[test]
    fn evict_oldest_reduces_count() {
        let mut mgr = OrphanManager::new();
        mgr.add("o1", vec!["p1".into()], "d1");
        mgr.add("o2", vec!["p2".into()], "d2");
        mgr.evict_oldest();
        assert_eq!(mgr.count(), 1);
    }
}
