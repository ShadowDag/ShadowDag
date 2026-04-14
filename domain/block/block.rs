// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block_body::BlockBody;
use crate::domain::block::block_header::BlockHeader;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl Block {
    /// Fast size estimate (no serialization) for DoS guard checks.
    /// Under-estimates are OK — this is a pre-filter, not consensus.
    pub fn canonical_size_estimate(&self) -> usize {
        // header ~256 bytes + per-tx ~200 bytes average
        256 + self.body.transactions.len() * 200
    }
}
