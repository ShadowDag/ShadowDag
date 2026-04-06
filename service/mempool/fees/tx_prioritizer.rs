// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::service::mempool::fees::fee_market::FeeMarket;

pub struct TxPrioritizer;

impl TxPrioritizer {
    pub fn prioritize(
        mut txs: Vec<Transaction>
    ) -> Vec<Transaction> {
        txs.sort_by(|a, b| {
            let fee_a = FeeMarket::calculate_fee(a);
            let fee_b = FeeMarket::calculate_fee(b);

            fee_b.cmp(&fee_a)

        });

        txs

    }

}
