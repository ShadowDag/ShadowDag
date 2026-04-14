// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub mod pruning_engine;

use std::collections::{HashMap, HashSet};

pub const DEFAULT_PRUNE_DEPTH: u64 = 1_000;
pub const MIN_PRUNE_DEPTH: u64 = 100;
pub const PRUNE_BATCH_SIZE: usize = 500;

#[derive(Debug, Clone)]
pub struct PruneRecord {
    pub hash: String,
    pub height: u64,
    pub pruned: bool,
}

pub struct PruningEngine {
    pub depth: u64,
    pub pruned_count: u64,
    prune_set: HashSet<String>,
}

impl PruningEngine {
    pub fn new(depth: u64) -> Self {
        Self {
            depth: depth.max(MIN_PRUNE_DEPTH),
            pruned_count: 0,
            prune_set: HashSet::new(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(DEFAULT_PRUNE_DEPTH)
    }

    pub fn select_prunable(
        &mut self,
        block_heights: &HashMap<String, u64>,
        current_height: u64,
    ) -> Vec<String> {
        let cutoff = current_height.saturating_sub(self.depth);
        let mut prunable: Vec<(String, u64)> = block_heights
            .iter()
            .filter(|(hash, &height)| height < cutoff && !self.prune_set.contains(*hash))
            .map(|(hash, &h)| (hash.clone(), h))
            .collect();

        // Sort by height first for deterministic selection, then truncate
        prunable.sort_by_key(|(_, h)| *h);
        prunable.truncate(PRUNE_BATCH_SIZE);

        prunable.into_iter().map(|(hash, _)| hash).collect()
    }

    pub fn mark_pruned(&mut self, hashes: &[String]) {
        for hash in hashes {
            if self.prune_set.insert(hash.clone()) {
                self.pruned_count += 1; // Only count if actually new
            }
        }
    }

    pub fn is_pruned(&self, hash: &str) -> bool {
        self.prune_set.contains(hash)
    }

    pub fn set_depth(&mut self, depth: u64) {
        self.depth = depth.max(MIN_PRUNE_DEPTH);
    }

    pub fn pruned_count(&self) -> u64 {
        self.pruned_count
    }
    pub fn prune_set_size(&self) -> usize {
        self.prune_set.len()
    }

    pub fn compact_prune_set(&mut self, known_hashes: &HashSet<String>) {
        self.prune_set.retain(|h| known_hashes.contains(h));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heights(data: &[(&str, u64)]) -> HashMap<String, u64> {
        data.iter()
            .map(|(h, height)| (h.to_string(), *height))
            .collect()
    }

    #[test]
    fn selects_old_blocks() {
        let mut engine = PruningEngine::new(100);
        let blocks = heights(&[("old_b", 5), ("recent_b", 150)]);
        let prunable = engine.select_prunable(&blocks, 200);
        assert!(prunable.contains(&"old_b".to_string()));
        assert!(!prunable.contains(&"recent_b".to_string()));
    }

    #[test]
    fn mark_pruned_excludes_from_next_select() {
        let mut engine = PruningEngine::new(100);
        let blocks = heights(&[("b1", 1)]);
        let prunable = engine.select_prunable(&blocks, 500);
        engine.mark_pruned(&prunable);
        let second = engine.select_prunable(&blocks, 500);
        assert!(second.is_empty(), "already pruned must not appear again");
    }

    #[test]
    fn min_depth_enforced() {
        let engine = PruningEngine::new(10);
        assert_eq!(engine.depth, MIN_PRUNE_DEPTH);
    }

    #[test]
    fn pruned_count_increments() {
        let mut engine = PruningEngine::new(100);
        engine.mark_pruned(&["h1".to_string(), "h2".to_string()]);
        assert_eq!(engine.pruned_count(), 2);
    }

    #[test]
    fn is_pruned_returns_true_after_mark() {
        let mut engine = PruningEngine::new(100);
        engine.mark_pruned(&["hash_x".to_string()]);
        assert!(engine.is_pruned("hash_x"));
        assert!(!engine.is_pruned("hash_y"));
    }

    #[test]
    fn empty_set_returns_nothing() {
        let mut engine = PruningEngine::new(100);
        let prunable = engine.select_prunable(&HashMap::new(), 1000);
        assert!(prunable.is_empty());
    }
}
