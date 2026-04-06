// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::errors::NodeError;

/// Abstract block processor for sync operations.
///
/// domain/ defines this trait; service/network/nodes implements it.
/// This breaks the engine → service dependency in dag_sync.
pub trait BlockProcessor: Send + Sync {
    /// Process a received block through the consensus pipeline.
    fn process_block(&self, block: &Block) -> Result<(), NodeError>;

    /// Get current DAG tip hashes (used for building sync locators).
    fn get_tips(&self) -> Vec<String>;
}
