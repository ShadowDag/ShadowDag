// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub hash: String,
    pub parents: Vec<String>,
    pub merkle_root: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u64,
    pub height: u64,

    #[serde(default)]
    pub blue_score: u64,

    #[serde(default)]
    pub selected_parent: Option<String>,

    /// Commitment hash over the full UTXO set state after this block.
    /// Used by crash recovery to verify UTXO integrity beyond just count.
    /// SHA-256 of all sorted (key, amount, owner, spent) tuples.
    #[serde(default)]
    pub utxo_commitment: Option<String>,

    /// Extra nonce for miners when primary nonce space (u64) is exhausted.
    /// Provides additional 2^64 nonce space per primary nonce cycle.
    /// At extreme hashrates (>10 EH/s), this prevents template exhaustion.
    #[serde(default)]
    pub extra_nonce: u64,

    /// Merkle root of all transaction execution receipts in this block.
    /// SHA-256 of concatenated (tx_hash, execution_success, gas_used) for each tx.
    /// None for blocks with no contract transactions.
    #[serde(default)]
    pub receipt_root: Option<String>,

    /// Root hash of the contract state after executing this block.
    /// Commits the entire contract storage state to the block header.
    /// None for blocks with no contract state changes.
    #[serde(default)]
    pub state_root: Option<String>,
}

impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_defaults(
        version: u32,
        hash: String,
        parents: Vec<String>,
        merkle_root: String,
        timestamp: u64,
        nonce: u64,
        difficulty: u64,
        height: u64,
    ) -> Self {
        Self {
            version,
            hash,
            parents,
            merkle_root,
            timestamp,
            nonce,
            difficulty,
            height,
            blue_score: 0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce: 0,
            receipt_root: None,
            state_root: None,
        }
    }

    /// The canonical parent edge for selected-parent-chain walks.
    ///
    /// Returns `selected_parent` when it is set, non-empty, and a member of
    /// `parents`; otherwise falls back to the FIRST listed parent. The
    /// `parents` list (including its order) is covered by proof-of-work,
    /// so the fallback is deterministic and unforgeable on every node.
    ///
    /// CONSENSUS-CRITICAL: cumulative work, difficulty retarget, reorg
    /// fork-point discovery, and undo pruning all walk this edge. Blocks
    /// accepted via `submitblock` are stored with `selected_parent=None`
    /// (client input is untrusted), so walking the raw field made every
    /// walk stop after one hop — the node treated each chain extension as
    /// a disjoint chain, rolled back the tip on every insert, and retained
    /// only the newest block's UTXOs (observed live: utxo_count=2 at
    /// height 304 with one reorg rollback per block).
    ///
    /// Genesis (no parents) returns None, which terminates walks.
    pub fn resolved_selected_parent(&self) -> Option<String> {
        if let Some(sp) = &self.selected_parent {
            if !sp.is_empty() && self.parents.iter().any(|p| p == sp) {
                return Some(sp.clone());
            }
        }
        self.parents.first().filter(|p| !p.is_empty()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with(parents: Vec<&str>, selected: Option<&str>) -> BlockHeader {
        let mut h = BlockHeader::new_with_defaults(
            1,
            "h".into(),
            parents.into_iter().map(String::from).collect(),
            "m".into(),
            0,
            0,
            1,
            1,
        );
        h.selected_parent = selected.map(String::from);
        h
    }

    #[test]
    fn resolved_prefers_valid_selected_parent() {
        let h = header_with(vec!["a", "b"], Some("b"));
        assert_eq!(h.resolved_selected_parent().as_deref(), Some("b"));
    }

    #[test]
    fn resolved_falls_back_to_first_parent_when_none() {
        // The submitblock path stores None — the walkable edge must still exist.
        let h = header_with(vec!["a", "b"], None);
        assert_eq!(h.resolved_selected_parent().as_deref(), Some("a"));
    }

    #[test]
    fn resolved_rejects_selected_parent_not_in_parents() {
        // A selected_parent outside the PoW-covered parents list is untrusted.
        let h = header_with(vec!["a", "b"], Some("evil"));
        assert_eq!(h.resolved_selected_parent().as_deref(), Some("a"));
    }

    #[test]
    fn resolved_genesis_has_no_parent() {
        let h = header_with(vec![], None);
        assert_eq!(h.resolved_selected_parent(), None);
    }

    #[test]
    fn resolved_ignores_empty_strings() {
        let h = header_with(vec![""], Some(""));
        assert_eq!(h.resolved_selected_parent(), None);
    }
}
