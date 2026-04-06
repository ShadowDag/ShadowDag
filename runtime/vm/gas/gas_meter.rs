// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// GasMeter — In-memory gas accounting for deterministic VM execution.
//
// Gas is tracked entirely in memory (no DB I/O) for speed and determinism.
// Every opcode must call `consume()` BEFORE executing. If gas is
// insufficient, execution halts immediately with OutOfGas.
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum gas refund as a fraction of gas_used.
/// EIP-3529 reduced this from 50% to 20% in Ethereum.
/// ShadowDAG uses 50% (pre-London behavior).
const MAX_REFUND_QUOTIENT: u64 = 2;

/// Tracks gas consumption during a single contract execution.
///
/// All tracking is in-memory for deterministic, fast accounting.
/// No floating point, no system time, no randomness.
pub struct GasMeter {
    /// Maximum gas allowed for this execution
    gas_limit: u64,
    /// Gas consumed so far
    gas_used: u64,
    /// Accumulated gas refund (e.g. from SDELETE)
    gas_refund: u64,
}

/// Result of attempting to consume gas
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasResult {
    /// Gas consumed successfully; returns remaining gas
    Ok(u64),
    /// Insufficient gas; returns how much was available
    OutOfGas { available: u64, required: u64 },
}

impl GasMeter {
    /// Create a new gas meter with the given limit
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_used: 0,
            gas_refund: 0,
        }
    }

    /// Attempt to consume `cost` gas BEFORE executing an opcode.
    ///
    /// Returns `GasResult::Ok(remaining)` on success, or
    /// `GasResult::OutOfGas` if insufficient gas remains.
    /// On failure, `gas_used` is set to `gas_limit` (all gas consumed).
    pub fn consume(&mut self, cost: u64) -> GasResult {
        // Overflow-safe addition
        let new_used = match self.gas_used.checked_add(cost) {
            Some(v) => v,
            None => {
                // Overflow means cost is absurdly high; consume all gas
                let available = self.gas_limit.saturating_sub(self.gas_used);
                self.gas_used = self.gas_limit;
                return GasResult::OutOfGas {
                    available,
                    required: cost,
                };
            }
        };

        if new_used > self.gas_limit {
            let available = self.gas_limit.saturating_sub(self.gas_used);
            self.gas_used = self.gas_limit;
            return GasResult::OutOfGas {
                available,
                required: cost,
            };
        }

        self.gas_used = new_used;
        GasResult::Ok(self.gas_limit - new_used)
    }

    /// Add to the gas refund counter (e.g. for SDELETE clearing storage)
    pub fn add_refund(&mut self, amount: u64) {
        self.gas_refund = self.gas_refund.saturating_add(amount);
    }

    /// Gas consumed so far
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Gas remaining
    pub fn gas_remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }

    /// The gas limit for this execution
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Accumulated refund counter
    pub fn gas_refund(&self) -> u64 {
        self.gas_refund
    }

    /// Compute effective gas used after applying refunds (capped at 50% of gas_used)
    pub fn effective_gas_used(&self) -> u64 {
        let max_refund = self.gas_used / MAX_REFUND_QUOTIENT;
        let actual_refund = self.gas_refund.min(max_refund);
        self.gas_used.saturating_sub(actual_refund)
    }

    /// Check if there is at least `cost` gas remaining, without consuming it.
    ///
    /// RESTRICTED to `pub(crate)` to prevent smart contracts from branching
    /// on remaining gas, which would create non-deterministic execution paths
    /// (different gas limits → different branches → state divergence).
    /// Only the VM execution loop should call this, not user-visible opcodes.
    #[allow(dead_code)] // Reserved for VM execution loop; intentionally restricted from public API
    pub(crate) fn has_gas(&self, cost: u64) -> bool {
        self.gas_remaining() >= cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_basic() {
        let mut meter = GasMeter::new(100);
        assert_eq!(meter.consume(30), GasResult::Ok(70));
        assert_eq!(meter.gas_used(), 30);
        assert_eq!(meter.gas_remaining(), 70);
    }

    #[test]
    fn consume_exact_limit() {
        let mut meter = GasMeter::new(100);
        assert_eq!(meter.consume(100), GasResult::Ok(0));
        assert_eq!(meter.gas_remaining(), 0);
    }

    #[test]
    fn consume_out_of_gas() {
        let mut meter = GasMeter::new(100);
        meter.consume(80);
        match meter.consume(30) {
            GasResult::OutOfGas { available, required } => {
                assert_eq!(available, 20);
                assert_eq!(required, 30);
            }
            _ => panic!("Expected OutOfGas"),
        }
        // All gas consumed on failure
        assert_eq!(meter.gas_used(), 100);
    }

    #[test]
    fn consume_overflow_protection() {
        let mut meter = GasMeter::new(1000);
        meter.consume(500);
        match meter.consume(u64::MAX) {
            GasResult::OutOfGas { available, required } => {
                assert_eq!(available, 500, "available must reflect gas remaining before overflow");
                assert_eq!(required, u64::MAX);
            }
            _ => panic!("Expected OutOfGas on overflow"),
        }
        assert_eq!(meter.gas_used(), 1000, "all gas consumed on overflow");
    }

    #[test]
    fn refund_capped_at_50_percent() {
        let mut meter = GasMeter::new(1000);
        meter.consume(1000);
        meter.add_refund(800);
        // Refund capped at 50% of 1000 = 500
        assert_eq!(meter.effective_gas_used(), 500);
    }

    #[test]
    fn refund_below_cap() {
        let mut meter = GasMeter::new(1000);
        meter.consume(1000);
        meter.add_refund(100);
        assert_eq!(meter.effective_gas_used(), 900);
    }

    #[test]
    fn has_gas_check() {
        let mut meter = GasMeter::new(100);
        assert!(meter.has_gas(100));
        assert!(!meter.has_gas(101));
        meter.consume(90);
        assert!(meter.has_gas(10));
        assert!(!meter.has_gas(11));
    }

    #[test]
    fn zero_cost_always_succeeds() {
        let mut meter = GasMeter::new(0);
        assert_eq!(meter.consume(0), GasResult::Ok(0));
    }
}
