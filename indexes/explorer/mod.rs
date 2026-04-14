// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const MAX_RECENT_BLOCKS: usize = 100;
pub const MAX_RECENT_TXS: usize = 500;
pub const MAX_SEARCH_RESULTS: usize = 50;

#[derive(Debug, Clone)]
pub struct ExplorerBlock {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: usize,
    pub size_bytes: usize,
    pub difficulty: u64,
    pub miner: String,
    pub blue_score: u64,
    pub total_fees: u64,
}

#[derive(Debug, Clone)]
pub struct ExplorerTx {
    pub hash: String,
    pub block_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub total_output: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub best_height: u64,
    pub best_blue_score: u64,
    pub peer_count: usize,
    pub mempool_size: usize,
    pub total_supply: u64,
    pub dag_tips: Vec<String>,
    pub block_rate_bps: f64,
}

/// Contract information for the explorer page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractExplorerInfo {
    pub address: String,
    pub verified: bool,
    pub name: Option<String>,
    pub code_size: usize,
    pub vm_version: u8,
    pub abi: Option<String>, // JSON
    pub methods: Vec<String>,
    pub events: Vec<String>,
    pub bytecode_hash: String,
    pub created_at_block: Option<u64>,
    pub creator: Option<String>,
}

/// Explorer index that maintains a sliding window of the most recent blocks
/// and transactions for display purposes.
///
/// **Limitation:** `find_block`, `find_tx`, and `block_at_height` only search
/// within the in-memory window (up to `MAX_RECENT_BLOCKS` / `MAX_RECENT_TXS`).
/// They will return `None` for blocks or transactions that have aged out of the
/// window. For full lookups, use `TxIndex` or `BlockStore` directly.
pub struct ExplorerIndex {
    recent_blocks: VecDeque<ExplorerBlock>,
    recent_txs: VecDeque<ExplorerTx>,
    pub stats: NetworkStats,
}

impl Default for ExplorerIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ExplorerIndex {
    pub fn new() -> Self {
        Self {
            recent_blocks: VecDeque::new(),
            recent_txs: VecDeque::new(),
            stats: NetworkStats {
                best_height: 0,
                best_blue_score: 0,
                peer_count: 0,
                mempool_size: 0,
                total_supply: 0,
                dag_tips: vec![],
                block_rate_bps: 0.0,
            },
        }
    }

    pub fn on_new_block(&mut self, block: ExplorerBlock) {
        if block.height > self.stats.best_height {
            self.stats.best_height = block.height;
        }
        if block.blue_score > self.stats.best_blue_score {
            self.stats.best_blue_score = block.blue_score;
        }

        self.recent_blocks.push_front(block);
        if self.recent_blocks.len() > MAX_RECENT_BLOCKS {
            self.recent_blocks.pop_back();
        }

        // Update block rate AFTER push_front so the new block is counted
        if let Some(newest) = self.recent_blocks.front() {
            let newest_ts = newest.timestamp;
            self.update_block_rate_with_ts(newest_ts);
        }
    }

    fn update_block_rate_with_ts(&mut self, newest_timestamp: u64) {
        if self.recent_blocks.len() >= 2 {
            let oldest = match self.recent_blocks.back() {
                Some(b) => b,
                None => return,
            };
            let time_span = newest_timestamp.saturating_sub(oldest.timestamp);
            if time_span > 0 {
                // Number of intervals = count - 1 (fence-post correction)
                let count = self.recent_blocks.len() as f64;
                self.stats.block_rate_bps = (count - 1.0) / time_span as f64;
            }
        }
    }

    pub fn on_new_tx(&mut self, tx: ExplorerTx) {
        self.recent_txs.push_front(tx);
        if self.recent_txs.len() > MAX_RECENT_TXS {
            self.recent_txs.pop_back();
        }
    }

    pub fn update_stats(
        &mut self,
        peer_count: usize,
        mempool_size: usize,
        total_supply: u64,
        dag_tips: Vec<String>,
    ) {
        self.stats.peer_count = peer_count;
        self.stats.mempool_size = mempool_size;
        self.stats.total_supply = total_supply;
        self.stats.dag_tips = dag_tips;
    }

    pub fn recent_blocks(&self, count: usize) -> Vec<&ExplorerBlock> {
        self.recent_blocks
            .iter()
            .take(count.min(MAX_RECENT_BLOCKS))
            .collect()
    }

    pub fn recent_txs(&self, count: usize) -> Vec<&ExplorerTx> {
        self.recent_txs
            .iter()
            .take(count.min(MAX_RECENT_TXS))
            .collect()
    }

    pub fn find_block(&self, hash: &str) -> Option<&ExplorerBlock> {
        self.recent_blocks.iter().find(|b| b.hash == hash)
    }

    pub fn find_tx(&self, hash: &str) -> Option<&ExplorerTx> {
        self.recent_txs.iter().find(|t| t.hash == hash)
    }

    pub fn block_at_height(&self, height: u64) -> Option<&ExplorerBlock> {
        self.recent_blocks.iter().find(|b| b.height == height)
    }

    pub fn cached_blocks(&self) -> usize {
        self.recent_blocks.len()
    }
    pub fn cached_txs(&self) -> usize {
        self.recent_txs.len()
    }

    /// Get contract information for the explorer.
    /// Returns verification status, ABI, methods, events, and metadata.
    pub fn get_contract_info(&self, address: &str) -> Option<ContractExplorerInfo> {
        // This would query ContractStorage and verification data
        // For now, return a struct that the explorer API can serve
        Some(ContractExplorerInfo {
            address: address.to_string(),
            verified: false, // Updated when verification data is loaded
            name: None,
            code_size: 0,
            vm_version: 1,
            abi: None,
            methods: vec![],
            events: vec![],
            bytecode_hash: String::new(),
            created_at_block: None,
            creator: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(hash: &str, height: u64, ts: u64) -> ExplorerBlock {
        ExplorerBlock {
            hash: hash.to_string(),
            height,
            timestamp: ts,
            tx_count: 5,
            size_bytes: 50_000,
            difficulty: 4,
            miner: "miner1".into(),
            blue_score: height * 2,
            total_fees: 5_000,
        }
    }

    #[test]
    fn on_new_block_updates_height() {
        let mut idx = ExplorerIndex::new();
        idx.on_new_block(sample_block("b1", 10, 1000));
        assert_eq!(idx.stats.best_height, 10);
    }

    #[test]
    fn recent_blocks_returns_latest() {
        let mut idx = ExplorerIndex::new();
        idx.on_new_block(sample_block("b1", 1, 1000));
        idx.on_new_block(sample_block("b2", 2, 2000));
        let recent = idx.recent_blocks(1);
        assert_eq!(recent[0].hash, "b2");
    }

    #[test]
    fn find_block_by_hash() {
        let mut idx = ExplorerIndex::new();
        idx.on_new_block(sample_block("findme", 5, 1000));
        assert!(idx.find_block("findme").is_some());
        assert!(idx.find_block("notexist").is_none());
    }

    #[test]
    fn recent_blocks_capped_at_max() {
        let mut idx = ExplorerIndex::new();
        for i in 0..(MAX_RECENT_BLOCKS + 10) {
            idx.on_new_block(sample_block(&format!("b{}", i), i as u64, i as u64 * 10));
        }
        assert_eq!(idx.cached_blocks(), MAX_RECENT_BLOCKS);
    }

    #[test]
    fn block_at_height_returns_correct() {
        let mut idx = ExplorerIndex::new();
        idx.on_new_block(sample_block("bh5", 5, 5000));
        assert!(idx.block_at_height(5).is_some());
        assert!(idx.block_at_height(99).is_none());
    }
}
