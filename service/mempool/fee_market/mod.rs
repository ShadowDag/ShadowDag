// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;

pub const BASE_FEE:           u64   = 1_000;
pub const MIN_RELAY_FEE:      u64   = 100;
pub const TARGET_BLOCK_SIZE:  usize = 1_000_000;
pub const FEE_HISTORY_BLOCKS: usize = 20;
pub const FEE_PERCENTILE_LOW: f64   = 25.0;
pub const FEE_PERCENTILE_MED: f64   = 50.0;
pub const FEE_PERCENTILE_HIGH: f64  = 90.0;

#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub low:    u64,
    pub medium: u64,
    pub high:   u64,
}

#[derive(Debug, Clone)]
pub struct BlockFeeStats {
    pub height:       u64,
    pub min_fee_rate: f64,
    pub max_fee_rate: f64,
    pub median:       f64,
    pub tx_count:     usize,
    pub total_size:   usize,
}

pub struct FeeMarket {
    history:         VecDeque<BlockFeeStats>,
    pub base_fee:    u64,
    congestion_level: f64,
}

impl FeeMarket {
    pub fn new() -> Self {
        Self {
            history:          VecDeque::new(),
            base_fee:         BASE_FEE,
            congestion_level: 0.0,
        }
    }

    pub fn record_block(&mut self, stats: BlockFeeStats) {
        self.congestion_level = (stats.total_size as f64 / TARGET_BLOCK_SIZE as f64).min(1.0);

        self.history.push_back(stats);
        if self.history.len() > FEE_HISTORY_BLOCKS {
            self.history.pop_front();
        }
        self.update_base_fee();
    }

    fn update_base_fee(&mut self) {
        if self.history.is_empty() { return; }

        let avg: f64 = self.history.iter().map(|s| s.median).sum::<f64>()
            / self.history.len() as f64;

        self.base_fee = (avg as u64).max(MIN_RELAY_FEE);
    }

    pub fn estimate(&self) -> FeeEstimate {
        if self.history.is_empty() {
            return FeeEstimate {
                low:    BASE_FEE,
                medium: BASE_FEE * 2,
                high:   BASE_FEE * 5,
            };
        }

        let mut rates: Vec<f64> = self.history.iter().map(|s| s.median).collect();
        rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        FeeEstimate {
            low:    percentile(&rates, FEE_PERCENTILE_LOW)  as u64,
            medium: percentile(&rates, FEE_PERCENTILE_MED)  as u64,
            high:   percentile(&rates, FEE_PERCENTILE_HIGH) as u64,
        }
    }

    pub fn is_acceptable_fee(&self, fee_rate: f64) -> bool {
        fee_rate >= (self.base_fee as f64 * 0.5)
    }

    pub fn is_high_priority(&self, fee_rate: f64) -> bool {
        let est = self.estimate();
        fee_rate >= est.high as f64
    }

    pub fn select_transactions<'a>(
        &self,
        txs: &'a [(String, u64, usize)],
        max_size: usize,
    ) -> Vec<&'a (String, u64, usize)> {
        let mut sorted: Vec<&'a (String, u64, usize)> = txs.iter().collect();
        sorted.sort_by(|a, b| {
            let rate_a = if a.2 > 0 { a.1 as f64 / a.2 as f64 } else { 0.0 };
            let rate_b = if b.2 > 0 { b.1 as f64 / b.2 as f64 } else { 0.0 };
            rate_b.partial_cmp(&rate_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut total = 0;
        sorted.into_iter().take_while(|tx| {
            if total + tx.2 <= max_size {
                total += tx.2;
                true
            } else {
                false
            }
        }).collect()
    }

    pub fn congestion(&self) -> f64 { self.congestion_level }
    pub fn history_len(&self) -> usize { self.history.len() }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stats(height: u64, median: f64, size: usize) -> BlockFeeStats {
        BlockFeeStats {
            height,
            min_fee_rate: median * 0.5,
            max_fee_rate: median * 2.0,
            median,
            tx_count:     100,
            total_size:   size,
        }
    }

    #[test]
    fn empty_returns_base_fee() {
        let market = FeeMarket::new();
        let est = market.estimate();
        assert!(est.low > 0);
        assert!(est.high >= est.medium);
        assert!(est.medium >= est.low);
    }

    #[test]
    fn record_block_updates_history() {
        let mut market = FeeMarket::new();
        market.record_block(sample_stats(1, 5000.0, 500_000));
        assert_eq!(market.history_len(), 1);
    }

    #[test]
    fn history_capped_at_max() {
        let mut market = FeeMarket::new();
        for i in 0..(FEE_HISTORY_BLOCKS + 5) {
            market.record_block(sample_stats(i as u64, 1000.0, 200_000));
        }
        assert_eq!(market.history_len(), FEE_HISTORY_BLOCKS);
    }

    #[test]
    fn high_congestion_increases_fee() {
        let mut market = FeeMarket::new();
        market.record_block(sample_stats(1, 10_000.0, TARGET_BLOCK_SIZE));
        assert!(market.congestion() >= 0.9);
    }

    #[test]
    fn select_transactions_picks_highest_fee() {
        let market = FeeMarket::new();
        let txs: Vec<(String, u64, usize)> = vec![
            ("low".into(),  100, 200),
            ("high".into(), 1000, 200),
            ("med".into(),  500, 200),
        ];
        let selected = market.select_transactions(&txs, 400);
        assert_eq!(selected[0].0, "high");
    }

    #[test]
    fn acceptable_fee_check() {
        let market = FeeMarket::new();
        assert!(market.is_acceptable_fee(BASE_FEE as f64));
        assert!(!market.is_acceptable_fee(1.0));
    }
}
