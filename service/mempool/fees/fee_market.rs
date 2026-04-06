// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::mempool::core::mempool::Mempool;
use crate::config::consensus::consensus_params::ConsensusParams;

/// EIP-1559 style base fee parameters
const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8; // Max 12.5% change per block
const ELASTICITY_MULTIPLIER: u64 = 2;           // Target = max_gas / 2
const MIN_BASE_FEE: u64 = 1;

pub struct FeeMarket;

impl FeeMarket {
    /// Suggest a fee based on current mempool congestion (simple mode)
    pub fn suggested_fee(mempool: &Mempool) -> u64 {
        let count   = mempool.count();
        let max     = ConsensusParams::MAX_MEMPOOL_SIZE;
        let min_fee = ConsensusParams::MIN_FEE;
        let congestion = (count * 100) / max.max(1);

        if congestion < 25 {
            min_fee
        } else if congestion < 50 {
            min_fee * 2
        } else if congestion < 75 {
            min_fee * 5
        } else {
            min_fee * 10
        }
    }

    /// EIP-1559 style base fee calculation.
    /// Adjusts base fee up/down based on how full the previous block was
    /// relative to the target gas usage (50% of max).
    pub fn calculate_base_fee(
        parent_base_fee: u64,
        parent_gas_used: u64,
        parent_gas_limit: u64,
    ) -> u64 {
        let target_gas = parent_gas_limit / ELASTICITY_MULTIPLIER;

        if parent_gas_used == target_gas {
            return parent_base_fee;
        }

        if parent_gas_used > target_gas {
            // Block was more than 50% full → increase base fee
            let gas_delta = parent_gas_used - target_gas;
            let fee_delta = parent_base_fee
                .saturating_mul(gas_delta)
                / target_gas.max(1)
                / BASE_FEE_MAX_CHANGE_DENOMINATOR;
            parent_base_fee.saturating_add(fee_delta.max(1))
        } else {
            // Block was less than 50% full → decrease base fee
            let gas_delta = target_gas - parent_gas_used;
            let fee_delta = parent_base_fee
                .saturating_mul(gas_delta)
                / target_gas.max(1)
                / BASE_FEE_MAX_CHANGE_DENOMINATOR;
            parent_base_fee.saturating_sub(fee_delta).max(MIN_BASE_FEE)
        }
    }

    /// Calculate the effective fee a user should pay.
    /// In EIP-1559: effective_fee = min(max_fee, base_fee + priority_fee)
    pub fn effective_fee(base_fee: u64, max_fee: u64, priority_fee: u64) -> u64 {
        let total = base_fee.saturating_add(priority_fee);
        total.min(max_fee)
    }

    /// Fee estimation with priority levels
    pub fn estimate_fee(mempool: &Mempool) -> FeeEstimate {
        let congestion = Self::congestion_ratio(mempool);
        let base = ConsensusParams::MIN_FEE;
        FeeEstimate {
            low:      base,
            medium:   base.saturating_mul(2 + congestion as u64),
            high:     base.saturating_mul(5 + congestion as u64 * 2),
            base_fee: base,
            congestion_pct: congestion,
        }
    }

    /// Get congestion ratio as percentage (0-100)
    pub fn congestion_ratio(mempool: &Mempool) -> u32 {
        let count = mempool.count();
        let max = ConsensusParams::MAX_MEMPOOL_SIZE.max(1);
        ((count * 100) / max) as u32
    }

    pub fn min_fee() -> u64 {
        ConsensusParams::MIN_FEE
    }

    pub fn calculate_fee(tx: &crate::domain::transaction::transaction::Transaction) -> u64 {
        if tx.fee > 0 {
            tx.fee
        } else {
            ConsensusParams::MIN_FEE
        }
    }
}

/// Fee estimation result with multiple priority levels
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub low:            u64,
    pub medium:         u64,
    pub high:           u64,
    pub base_fee:       u64,
    pub congestion_pct: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_stays_at_target() {
        let fee = FeeMarket::calculate_base_fee(100, 500, 1000);
        assert_eq!(fee, 100); // 50% full = no change
    }

    #[test]
    fn base_fee_increases_when_full() {
        let fee = FeeMarket::calculate_base_fee(100, 800, 1000);
        assert!(fee > 100); // 80% full = increase
    }

    #[test]
    fn base_fee_decreases_when_empty() {
        let fee = FeeMarket::calculate_base_fee(100, 200, 1000);
        assert!(fee < 100); // 20% full = decrease
    }

    #[test]
    fn base_fee_never_below_min() {
        let fee = FeeMarket::calculate_base_fee(1, 0, 1000);
        assert!(fee >= MIN_BASE_FEE);
    }

    #[test]
    fn effective_fee_capped_by_max() {
        assert_eq!(FeeMarket::effective_fee(100, 50, 10), 50);
        assert_eq!(FeeMarket::effective_fee(10, 100, 5), 15);
    }
}
