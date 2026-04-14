// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;

/// Priority score for mempool transaction ordering.
///
/// Combines fee-rate (sat/byte), age bonus, and size preference into a single
/// comparable score. Higher score = mined first.
///
/// Formula: `score = fee_rate * 1_000_000 + age_bonus`
///
/// - fee_rate is the dominant factor (sat/byte × 1M for integer precision)
/// - age_bonus rewards transactions waiting longer (prevents starvation)
/// - Coinbase transactions always get maximum priority
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPriority {
    /// Fee per byte, scaled by 1_000_000 for integer precision.
    pub fee_rate_scaled: u64,
    /// Bonus points for time spent in mempool (seconds × 100).
    /// Prevents low-fee TXs from being starved forever.
    pub age_bonus: u64,
    /// Combined score = fee_rate_scaled + age_bonus.
    pub score: u64,
}

pub struct TxPrioritizer;

impl TxPrioritizer {
    /// Compute the priority score for a single transaction.
    ///
    /// `mempool_entry_time` is the Unix timestamp when the TX entered the pool.
    /// `now` is the current Unix timestamp.
    pub fn score(tx: &Transaction, mempool_entry_time: u64, now: u64) -> TxPriority {
        // Fee rate: sat/byte (scaled to integer)
        let size = tx.canonical_bytes().len().max(1) as u64;
        let fee_rate_scaled = (tx.fee as u128 * 1_000_000 / size as u128) as u64;

        // Age bonus: 100 points per second in mempool (caps at 1 hour = 360,000)
        let age_secs = now.saturating_sub(mempool_entry_time);
        let age_bonus = (age_secs * 100).min(360_000);

        let score = fee_rate_scaled.saturating_add(age_bonus);

        TxPriority {
            fee_rate_scaled,
            age_bonus,
            score,
        }
    }

    /// Sort transactions by priority score (highest first).
    ///
    /// Uses fee-rate as the primary sort key, NOT absolute fee.
    /// A 100-byte TX paying 500 sat (5 sat/byte) ranks higher than
    /// a 10,000-byte TX paying 1000 sat (0.1 sat/byte).
    pub fn prioritize(mut txs: Vec<Transaction>) -> Vec<Transaction> {
        txs.sort_by(|a, b| {
            let rate_a = Self::fee_rate_u64(a);
            let rate_b = Self::fee_rate_u64(b);
            rate_b.cmp(&rate_a)
        });
        txs
    }

    /// Sort with age weighting — older TXs with decent fees get priority boost.
    pub fn prioritize_with_age(
        mut txs: Vec<(Transaction, u64)>, // (tx, entry_timestamp)
        now: u64,
    ) -> Vec<Transaction> {
        txs.sort_by(|(a, a_time), (b, b_time)| {
            let sa = Self::score(a, *a_time, now);
            let sb = Self::score(b, *b_time, now);
            sb.score.cmp(&sa.score)
        });
        txs.into_iter().map(|(tx, _)| tx).collect()
    }

    /// Fee rate as u64 (sat/byte × 1,000,000) for sorting.
    fn fee_rate_u64(tx: &Transaction) -> u64 {
        let size = tx.canonical_bytes().len().max(1) as u64;
        (tx.fee as u128 * 1_000_000 / size as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn make_tx(fee: u64, output_count: usize) -> Transaction {
        Transaction {
            hash: format!("tx_{}", fee),
            inputs: vec![TxInput::new(
                "aa".repeat(32),
                0,
                "owner".into(),
                "sig".into(),
                "pk".into(),
            )],
            outputs: (0..output_count)
                .map(|i| TxOutput::new(format!("addr_{}", i), 1000))
                .collect(),
            fee,
            timestamp: 1700000000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn higher_fee_rate_wins_over_higher_absolute_fee() {
        // Small TX with moderate fee (high fee/byte)
        let small = make_tx(500, 1); // ~200 bytes → ~2.5 sat/byte
                                     // Large TX with higher absolute fee but lower fee/byte
        let large = make_tx(1000, 50); // ~5000 bytes → ~0.2 sat/byte

        let sorted = TxPrioritizer::prioritize(vec![large.clone(), small.clone()]);
        assert_eq!(
            sorted[0].hash, small.hash,
            "Small TX with higher fee-rate should come first"
        );
    }

    #[test]
    fn age_bonus_helps_old_transactions() {
        let tx = make_tx(100, 1);
        let now = 1700003600; // 1 hour later

        let fresh = TxPrioritizer::score(&tx, now, now); // just entered
        let old = TxPrioritizer::score(&tx, now - 3600, now); // 1 hour old

        assert!(old.score > fresh.score, "Old TX should have higher score");
        assert!(old.age_bonus > 0);
        assert_eq!(fresh.age_bonus, 0);
    }
}
