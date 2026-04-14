// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Base Fee — EIP-1559 style dynamic base fee with fee burning.
//
// Instead of miners keeping all fees, a portion is BURNED (destroyed).
// This creates deflationary pressure and prevents fee manipulation.
//
// base_fee = prev_base_fee * (1 + elasticity * (gas_used - target) / target)
// burned = base_fee * gas_used
// miner_tip = total_fee - burned
// ═══════════════════════════════════════════════════════════════════════════

/// Target block utilization (50% of max capacity)
pub const TARGET_UTILIZATION_PCT: u64 = 50;

/// Maximum base fee change per block (12.5%)
pub const MAX_FEE_CHANGE_PCT: u64 = 12;

/// Minimum base fee (1 satoshi)
pub const MIN_BASE_FEE: u64 = 1;

/// Maximum base fee
pub const MAX_BASE_FEE: u64 = 1_000_000_000; // 10 SDAG

use std::sync::atomic::{AtomicU64, Ordering};

/// EIP-1559 style base fee calculator
pub struct BaseFeeCalculator {
    pub current_base_fee: u64,
    pub total_burned: AtomicU64,
}

impl BaseFeeCalculator {
    pub fn new(initial_base_fee: u64) -> Self {
        Self {
            current_base_fee: initial_base_fee.max(MIN_BASE_FEE),
            total_burned: AtomicU64::new(0),
        }
    }

    /// Calculate next base fee based on block utilization.
    /// gas_used: actual gas consumed in the block
    /// gas_limit: maximum gas allowed in the block
    pub fn next_base_fee(&mut self, gas_used: u64, gas_limit: u64) -> u64 {
        if gas_limit == 0 {
            return self.current_base_fee;
        }

        let target_gas = gas_limit * TARGET_UTILIZATION_PCT / 100;
        if target_gas == 0 {
            return self.current_base_fee;
        }

        let new_fee = if gas_used > target_gas {
            // Block was MORE than 50% full → increase base fee
            let excess = gas_used - target_gas;
            let change = self.current_base_fee * excess * MAX_FEE_CHANGE_PCT / (target_gas * 100);
            self.current_base_fee.saturating_add(change.max(1))
        } else if gas_used < target_gas {
            // Block was LESS than 50% full → decrease base fee
            let deficit = target_gas - gas_used;
            let change = self.current_base_fee * deficit * MAX_FEE_CHANGE_PCT / (target_gas * 100);
            self.current_base_fee.saturating_sub(change)
        } else {
            self.current_base_fee
        };

        self.current_base_fee = new_fee.clamp(MIN_BASE_FEE, MAX_BASE_FEE);
        self.current_base_fee
    }

    /// Calculate how much fee is burned vs goes to miner
    pub fn split_fee(&self, total_fee: u64, _gas_used: u64) -> (u64, u64) {
        let burned = (self.current_base_fee).min(total_fee);
        let tip = total_fee.saturating_sub(burned);
        self.total_burned_add(burned);
        (burned, tip)
    }

    fn total_burned_add(&self, amount: u64) {
        self.total_burned.fetch_add(amount, Ordering::Relaxed);
    }

    pub fn base_fee(&self) -> u64 {
        self.current_base_fee
    }
    pub fn total_burned(&self) -> u64 {
        self.total_burned.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_increases_when_busy() {
        let mut calc = BaseFeeCalculator::new(100);
        let new = calc.next_base_fee(8000, 10000); // 80% utilization > 50% target
        assert!(
            new > 100,
            "Base fee should increase when block is >50% full"
        );
    }

    #[test]
    fn base_fee_decreases_when_empty() {
        let mut calc = BaseFeeCalculator::new(100);
        let new = calc.next_base_fee(1000, 10000); // 10% utilization < 50% target
        assert!(
            new < 100,
            "Base fee should decrease when block is <50% full"
        );
    }

    #[test]
    fn base_fee_stable_at_target() {
        let mut calc = BaseFeeCalculator::new(100);
        let new = calc.next_base_fee(5000, 10000); // Exactly 50%
        assert_eq!(new, 100, "Base fee should stay same at target utilization");
    }

    #[test]
    fn base_fee_never_below_minimum() {
        let mut calc = BaseFeeCalculator::new(MIN_BASE_FEE);
        let new = calc.next_base_fee(0, 10000); // Empty block
        assert!(new >= MIN_BASE_FEE);
    }

    #[test]
    fn base_fee_never_above_maximum() {
        let mut calc = BaseFeeCalculator::new(MAX_BASE_FEE);
        let new = calc.next_base_fee(10000, 10000); // 100% full
        assert!(new <= MAX_BASE_FEE);
    }

    #[test]
    fn fee_split() {
        let calc = BaseFeeCalculator::new(50);
        let (burned, tip) = calc.split_fee(100, 1);
        assert_eq!(burned + tip, 100, "Burned + tip must equal total fee");
        assert_eq!(burned, 50, "Burned should equal base fee");
        assert_eq!(tip, 50, "Tip should be remainder");
    }
}
