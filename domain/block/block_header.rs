// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockHeader {
    pub version:         u32,
    pub hash:            String,
    pub parents:         Vec<String>,
    pub merkle_root:     String,
    pub timestamp:       u64,
    pub nonce:           u64,
    pub difficulty:      u64,
    pub height:          u64,

    #[serde(default)]
    pub blue_score:       u64,

    #[serde(default)]
    pub selected_parent:  Option<String>,

    /// Commitment hash over the full UTXO set state after this block.
    /// Used by crash recovery to verify UTXO integrity beyond just count.
    /// SHA-256 of all sorted (key, amount, owner, spent) tuples.
    #[serde(default)]
    pub utxo_commitment:  Option<String>,

    /// Extra nonce for miners when primary nonce space (u64) is exhausted.
    /// Provides additional 2^64 nonce space per primary nonce cycle.
    /// At extreme hashrates (>10 EH/s), this prevents template exhaustion.
    #[serde(default)]
    pub extra_nonce:      u64,

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
        version:     u32,
        hash:        String,
        parents:     Vec<String>,
        merkle_root: String,
        timestamp:   u64,
        nonce:       u64,
        difficulty:  u64,
        height:      u64,
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
            blue_score:      0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce:     0,
            receipt_root:    None,
            state_root:      None,
        }
    }
}
