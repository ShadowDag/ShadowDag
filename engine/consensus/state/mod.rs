// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::errors::ConsensusError;
use crate::{slog_info, slog_warn, slog_error};

#[derive(Debug, Clone)]
pub struct BlockConsensusData {
    pub hash: String,
    pub blue_score: u64,
    pub selected_parent: Option<String>,
    pub blue_set: HashSet<String>,
    pub red_set: HashSet<String>,
    pub is_chain_block: bool,
    pub height: u64,
}

impl BlockConsensusData {
    pub fn genesis(hash: &str) -> Self {
        Self {
            hash: hash.to_string(),
            blue_score: 0,
            selected_parent: None,
            blue_set: HashSet::new(),
            red_set: HashSet::new(),
            is_chain_block: true,
            height: 0,
        }
    }
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct ChainState {
    pub selected_tip: String,
    pub best_blue_score: u64,
    pub best_height: u64,
    pub finality_point: Option<String>,
}


const CS_PREFIX: &str = "cs:block:";
const CS_CHAIN_KEY: &str = "cs:chain";

pub struct ConsensusState {
    block_data: HashMap<String, BlockConsensusData>,
    /// Flat index of all blocks that have been colored blue by any chain block.
    blue_blocks: HashSet<String>,
    pub chain: ChainState,
    chain_path_cache: Vec<String>,
    db: Option<Arc<rocksdb::DB>>,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusState {
    pub fn new() -> Self {
        Self {
            block_data: HashMap::new(),
            blue_blocks: HashSet::new(),
            chain: ChainState::default(),
            chain_path_cache: Vec::new(),
            db: None,
        }
    }

    /// Create a ConsensusState backed by RocksDB.
    /// Automatically recovers all state from DB — the caller does NOT need
    /// to call `recover_from_db()` separately. This prevents the bug where
    /// someone forgets to call recovery and the node runs with empty state.
    pub fn new_with_db(db: Arc<rocksdb::DB>) -> Self {
        let mut s = Self {
            block_data: HashMap::new(),
            blue_blocks: HashSet::new(),
            chain: ChainState::default(),
            chain_path_cache: Vec::new(),
            db: Some(db),
        };
        s.recover_from_db();
        slog_info!("consensus", "state_recovered", blocks => s.block_data.len(), tip => s.chain.selected_tip, blue_score => s.chain.best_blue_score);
        let issues = s.verify_consistency();
        if !issues.is_empty() {
            slog_warn!("consensus", "consistency_issues_after_recovery", count => issues.len());
        }
        s
    }

    pub fn init_with_genesis(&mut self, genesis_hash: &str) {
        let data = BlockConsensusData::genesis(genesis_hash);
        self.persist_block_data(&data);
        self.block_data.insert(genesis_hash.to_string(), data);
        self.chain.selected_tip = genesis_hash.to_string();
        self.chain.best_blue_score = 0;
        self.chain.best_height = 0;
        self.persist_chain_state();
        self.chain_path_cache.clear();
        self.chain_path_cache.push(genesis_hash.to_string());
    }

    pub fn insert_block_data(&mut self, data: BlockConsensusData) -> Result<(), ConsensusError> {
        if let Some(parent_hash) = &data.selected_parent {
            if !self.block_data.contains_key(parent_hash) {
                return Err(ConsensusError::BlockValidation(format!(
                    "Parent block '{}' not found for block '{}'", parent_hash, data.hash
                )));
            }
        }

        let hash = data.hash.clone();

        let should_update = data.blue_score > self.chain.best_blue_score
            || (data.blue_score == self.chain.best_blue_score
                && hash < self.chain.selected_tip);
        if data.is_chain_block && should_update {
            self.chain.selected_tip = hash.clone();
            self.chain.best_blue_score = data.blue_score;
            self.chain.best_height = data.height;
            self.chain_path_cache.clear(); // 🔹 إعادة بناء cache لاحقًا عند الطلب
        }

        // Index all blocks colored blue by this block
        for blue_hash in &data.blue_set {
            self.blue_blocks.insert(blue_hash.clone());
        }

        self.persist_block_data(&data);
        self.persist_chain_state();
        self.block_data.insert(hash, data);
        Ok(())
    }

    /// Persist a single block's consensus data to RocksDB.
    fn persist_block_data(&self, data: &BlockConsensusData) {
        if let Some(db) = &self.db {
            let key = format!("{}{}", CS_PREFIX, data.hash);
            // Serialize as: blue_score|height|is_chain|selected_parent|blue_set|red_set
            let blue_set_str: Vec<&str> = data.blue_set.iter().map(|s| s.as_str()).collect();
            let red_set_str: Vec<&str> = data.red_set.iter().map(|s| s.as_str()).collect();
            let val = format!(
                "{}|{}|{}|{}|{}|{}",
                data.blue_score,
                data.height,
                data.is_chain_block,
                data.selected_parent.as_deref().unwrap_or(""),
                blue_set_str.join(","),
                red_set_str.join(","),
            );
            if let Err(e) = db.put(key.as_bytes(), val.as_bytes()) {
                slog_error!("consensus", "persist_block_data_failed", error => e);
            }
        }
    }

    /// Persist the chain state to RocksDB.
    fn persist_chain_state(&self) {
        if let Some(db) = &self.db {
            let val = format!(
                "{}|{}|{}|{}",
                self.chain.selected_tip,
                self.chain.best_blue_score,
                self.chain.best_height,
                self.chain.finality_point.as_deref().unwrap_or(""),
            );
            if let Err(e) = db.put(CS_CHAIN_KEY.as_bytes(), val.as_bytes()) {
                slog_error!("consensus", "persist_chain_state_failed", error => e);
            }
        }
    }

    /// Recover the full consensus state from RocksDB on startup.
    /// Loads all block data and chain state from the database into the
    /// in-memory HashMap cache.
    pub fn recover_from_db(&mut self) {
        let db = match &self.db {
            Some(db) => db.clone(),
            None => return,
        };

        // Recover chain state
        if let Ok(Some(data)) = db.get(CS_CHAIN_KEY.as_bytes()) {
            if let Ok(val) = String::from_utf8(data.to_vec()) {
                let parts: Vec<&str> = val.splitn(4, '|').collect();
                if parts.len() == 4 {
                    self.chain.selected_tip = parts[0].to_string();
                    self.chain.best_blue_score = match parts[1].parse() {
                        Ok(v) => v,
                        Err(e) => {
                            slog_error!("consensus", "corrupted_best_blue_score", value => parts[1], error => e);
                            0
                        }
                    };
                    self.chain.best_height = match parts[2].parse() {
                        Ok(v) => v,
                        Err(e) => {
                            slog_error!("consensus", "corrupted_best_height", value => parts[2], error => e);
                            0
                        }
                    };
                    self.chain.finality_point = if parts[3].is_empty() {
                        None
                    } else {
                        Some(parts[3].to_string())
                    };
                }
            }
        }

        // Recover block data by iterating prefix
        let prefix = CS_PREFIX.as_bytes();
        let iter = db.prefix_iterator(prefix);
        for (key, value) in iter.flatten() {
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !key_str.starts_with(CS_PREFIX) {
                break;
            }
            let hash = key_str[CS_PREFIX.len()..].to_string();
            let val_str = match std::str::from_utf8(&value) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let parts: Vec<&str> = val_str.splitn(6, '|').collect();
            if parts.len() == 6 {
                let blue_score: u64 = parts[0].parse().unwrap_or_else(|e| {
                    slog_warn!("consensus", "corrupt_blue_score_in_db", error => e);
                    0
                });
                let height: u64 = parts[1].parse().unwrap_or_else(|e| {
                    slog_warn!("consensus", "corrupt_height_in_db", error => e);
                    0
                });
                let is_chain_block = parts[2] == "true";
                let selected_parent = if parts[3].is_empty() {
                    None
                } else {
                    Some(parts[3].to_string())
                };
                let blue_set: HashSet<String> = parts[4]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                let red_set: HashSet<String> = parts[5]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                self.block_data.insert(hash.clone(), BlockConsensusData {
                    hash,
                    blue_score,
                    selected_parent,
                    blue_set,
                    red_set,
                    is_chain_block,
                    height,
                });
            }
        }

        // Rebuild blue_blocks index from recovered data
        self.blue_blocks.clear();
        for data in self.block_data.values() {
            for blue_hash in &data.blue_set {
                self.blue_blocks.insert(blue_hash.clone());
            }
        }

        self.chain_path_cache.clear();
    }

    pub fn get(&self, hash: &str) -> Option<&BlockConsensusData> {
        self.block_data.get(hash)
    }

    pub fn blue_score(&self, hash: &str) -> Option<u64> {
        self.block_data.get(hash).map(|d| d.blue_score)
    }

    pub fn selected_parent(&self, hash: &str) -> Option<&str> {
        self.block_data.get(hash).and_then(|d| d.selected_parent.as_deref())
    }

    pub fn is_chain_block(&self, hash: &str) -> bool {
        self.block_data.get(hash).map(|d| d.is_chain_block).unwrap_or(false)
    }

    pub fn is_blue(&self, hash: &str) -> bool {
        self.blue_blocks.contains(hash)
    }

    pub fn selected_chain_path(&mut self) -> &Vec<String> {
        if self.chain_path_cache.is_empty() || self.chain_path_cache.last() != Some(&self.chain.selected_tip) {
            let mut path = Vec::new();
            let mut current = &self.chain.selected_tip;
            let mut visited = HashSet::new();

            while !current.is_empty() {
                if !visited.insert(current.clone()) {
                    slog_error!("consensus", "cycle_detected_in_chain_path", block => current);
                    break;
                }
                path.push(current.clone());
                if let Some(parent) = self.block_data.get(current).and_then(|d| d.selected_parent.as_ref()) {
                    current = parent;
                } else {
                    break;
                }
            }

            path.reverse();
            self.chain_path_cache = path;
        }
        &self.chain_path_cache
    }

    /// Update the finality point to the block at `depth` positions below the tip.
    /// Callers should use `FinalityManager::current_depth()` for the dynamic depth
    /// instead of the static `FINALITY_DEPTH` constant.
    /// Blocks at or below the finality point are considered irreversible.
    /// Returns the new finality point hash if updated.
    pub fn update_finality(&mut self, depth: u64) -> Option<String> {
        let path = self.selected_chain_path();
        if path.len() as u64 > depth + 1 {
            let idx = (path.len() as u64 - depth - 1) as usize;
            let new_fp = path[idx].clone();
            // Ensure finality only moves forward (never regresses)
            if let Some(ref old_fp) = self.chain.finality_point {
                let old_height = self.block_data.get(old_fp).map(|d| d.height).unwrap_or(0);
                let new_height = self.block_data.get(&new_fp).map(|d| d.height).unwrap_or(0);
                if new_height < old_height {
                    // Finality regression detected -- keep the old point
                    return None;
                }
            }
            let changed = self.chain.finality_point.as_ref() != Some(&new_fp);
            self.chain.finality_point = Some(new_fp.clone());
            if changed {
                self.persist_chain_state();
            }
            Some(new_fp)
        } else {
            None
        }
    }

    /// Check if a block is below the finality point (i.e., it's finalized
    /// and cannot be reorged). Returns true if the block is at or below
    /// the finality point in the selected chain.
    pub fn is_finalized(&self, block_hash: &str) -> bool {
        let fp = match &self.chain.finality_point {
            Some(fp) => fp,
            None => return false,
        };

        // If the block IS the finality point, it's finalized
        if block_hash == fp {
            return true;
        }

        // Check if the block's height is below the finality point's height
        let fp_height = self.block_data.get(fp).map(|d| d.height).unwrap_or(0);
        let block_height = self.block_data.get(block_hash).map(|d| d.height).unwrap_or(u64::MAX);

        block_height <= fp_height
    }

    /// Get the finality point height (0 if no finality point set).
    pub fn finality_height(&self) -> u64 {
        self.chain.finality_point.as_ref()
            .and_then(|fp| self.block_data.get(fp))
            .map(|d| d.height)
            .unwrap_or(0)
    }

    pub fn block_count(&self) -> usize {
        self.block_data.len()
    }

    /// Verify consistency of recovered state. Call after recovery to detect
    /// corruption or incomplete writes that could cause consensus divergence.
    /// Returns a list of issues found (empty = healthy).
    pub fn verify_consistency(&self) -> Vec<String> {
        let mut issues = Vec::new();

        // 1. Selected tip must exist in block_data
        if !self.chain.selected_tip.is_empty()
            && !self.block_data.contains_key(&self.chain.selected_tip)
        {
            issues.push(format!(
                "Selected tip '{}' not found in block_data ({} blocks loaded)",
                self.chain.selected_tip,
                self.block_data.len()
            ));
        }

        // 2. Finality point must exist in block_data (if set)
        if let Some(fp) = &self.chain.finality_point {
            if !self.block_data.contains_key(fp) {
                issues.push(format!(
                    "Finality point '{}' not found in block_data",
                    fp
                ));
            }
        }

        // 3. Every block's selected_parent must also exist in block_data
        for (hash, data) in &self.block_data {
            if let Some(parent) = &data.selected_parent {
                if !self.block_data.contains_key(parent) {
                    issues.push(format!(
                        "Block '{}' references parent '{}' which is missing",
                        hash, parent
                    ));
                }
            }
        }

        // 4. Best blue score must match the tip's actual score
        if let Some(tip_data) = self.block_data.get(&self.chain.selected_tip) {
            if tip_data.blue_score != self.chain.best_blue_score {
                issues.push(format!(
                    "Chain best_blue_score ({}) != tip actual blue_score ({})",
                    self.chain.best_blue_score, tip_data.blue_score
                ));
            }
            if tip_data.height != self.chain.best_height {
                issues.push(format!(
                    "Chain best_height ({}) != tip actual height ({})",
                    self.chain.best_height, tip_data.height
                ));
            }
        }

        if issues.is_empty() {
            slog_info!("consensus", "consistency_check_passed", blocks => self.block_data.len());
        } else {
            slog_error!("consensus", "consistency_check_failed", count => issues.len());
            for issue in &issues {
                slog_warn!("consensus", "consistency_issue", detail => issue);
            }
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_with_genesis_sets_tip() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("genesis_hash");
        assert_eq!(state.chain.selected_tip, "genesis_hash");
        assert_eq!(state.chain.best_blue_score, 0);
    }

    #[test]
    fn insert_block_updates_tip() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        let _ = state.insert_block_data(BlockConsensusData {
            hash: "b1".into(),
            blue_score: 5,
            selected_parent: Some("g".into()),
            blue_set: HashSet::new(),
            red_set: HashSet::new(),
            is_chain_block: true,
            height: 1,
        });
        assert_eq!(state.chain.selected_tip, "b1");
        assert_eq!(state.chain.best_blue_score, 5);
    }

    #[test]
    fn blue_score_returns_correct_value() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        assert_eq!(state.blue_score("g"), Some(0));
    }

    #[test]
    fn selected_chain_path_from_tip() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        let _ = state.insert_block_data(BlockConsensusData {
            hash: "b1".into(),
            blue_score: 1,
            selected_parent: Some("g".into()),
            blue_set: HashSet::new(),
            red_set: HashSet::new(),
            is_chain_block: true,
            height: 1,
        });
        let _ = state.insert_block_data(BlockConsensusData {
            hash: "b2".into(),
            blue_score: 2,
            selected_parent: Some("b1".into()),
            blue_set: HashSet::new(),
            red_set: HashSet::new(),
            is_chain_block: true,
            height: 2,
        });
        let path = state.selected_chain_path();
        assert_eq!(path, &vec!["g".to_string(), "b1".to_string(), "b2".to_string()]);
    }

    #[test]
    fn block_count_is_correct() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        assert_eq!(state.block_count(), 1);
    }

    #[test]
    fn update_finality_sets_point() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        for i in 1..=10 {
            let hash = format!("b{}", i);
            let parent = if i == 1 { "g".to_string() } else { format!("b{}", i - 1) };
            let _ = state.insert_block_data(BlockConsensusData {
                hash, blue_score: i, selected_parent: Some(parent),
                blue_set: HashSet::new(), red_set: HashSet::new(),
                is_chain_block: true, height: i,
            });
        }
        // Finality at depth 5: chain has 11 blocks (g + b1..b10)
        // idx = 11 - 5 = 6, path[6] = "b6"
        let fp = state.update_finality(5);
        assert!(fp.is_some());
        assert_eq!(state.chain.finality_point.as_deref(), Some("b6"));
    }

    #[test]
    fn is_finalized_below_finality_point() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        for i in 1..=10 {
            let hash = format!("b{}", i);
            let parent = if i == 1 { "g".to_string() } else { format!("b{}", i - 1) };
            let _ = state.insert_block_data(BlockConsensusData {
                hash, blue_score: i, selected_parent: Some(parent),
                blue_set: HashSet::new(), red_set: HashSet::new(),
                is_chain_block: true, height: i,
            });
        }
        state.update_finality(5);
        // Finality point = b6 (height 6). idx = 11 - 5 = 6.
        assert!(state.is_finalized("g"));   // height 0 <= 6 ✓
        assert!(state.is_finalized("b1"));  // height 1 <= 6 ✓
        assert!(state.is_finalized("b6"));  // IS the finality point ✓
        assert!(!state.is_finalized("b7")); // height 7 > 6 ✗
        assert!(!state.is_finalized("b10")); // height 10 > 6 ✗
    }

    #[test]
    fn finality_height_returns_correct_value() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        for i in 1..=5 {
            let hash = format!("b{}", i);
            let parent = if i == 1 { "g".to_string() } else { format!("b{}", i - 1) };
            let _ = state.insert_block_data(BlockConsensusData {
                hash, blue_score: i, selected_parent: Some(parent),
                blue_set: HashSet::new(), red_set: HashSet::new(),
                is_chain_block: true, height: i,
            });
        }
        assert_eq!(state.finality_height(), 0); // No finality point yet
        state.update_finality(3);
        // chain=[g,b1,b2,b3,b4,b5] len=6, depth 3 → idx = 6-3 = 3, path[3] = b3 (height 3)
        assert_eq!(state.finality_height(), 3);
    }

    #[test]
    fn insert_block_with_missing_parent_returns_error() {
        let mut state = ConsensusState::new();
        state.init_with_genesis("g");
        let result = state.insert_block_data(BlockConsensusData {
            hash: "b1".into(),
            blue_score: 1,
            selected_parent: Some("x".into()),
            blue_set: HashSet::new(),
            red_set: HashSet::new(),
            is_chain_block: true,
            height: 1,
        });
        assert!(result.is_err(), "Missing parent must return an error");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Parent block 'x' not found"),
            "Error message should mention missing parent, got: {}", err);
    }
}