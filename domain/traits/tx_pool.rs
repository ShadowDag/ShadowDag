// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo_set::UtxoSet;

/// Abstract transaction pool.
///
/// domain/ defines this trait; service/mempool implements it.
/// This breaks the domain → service dependency.
pub trait TxPool: Send + Sync {
    fn get_transaction(&self, hash: &str) -> Option<Transaction>;
    fn has_transaction(&self, hash: &str) -> bool;
    fn count(&self) -> usize;

    /// Get transactions ordered by fee priority, up to `limit`.
    /// Used by block builders to select transactions for inclusion.
    fn get_prioritized_txs(&self, limit: usize) -> Vec<Transaction>;

    /// Get transactions for block building, validated against the UTXO set.
    /// Returns up to `max_count` transactions ordered by fee priority.
    fn get_transactions_for_block(
        &self,
        utxo_set: &UtxoSet,
        max_count: usize,
    ) -> Vec<Transaction>;
}
