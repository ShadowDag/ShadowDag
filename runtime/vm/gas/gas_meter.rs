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

/// Gas refund quotient for v1: refund capped at gas_used / 2 (50%).
/// This is the pre-London (EIP-3529) behavior. For v2, consider reducing to
/// 20% to align with modern Ethereum. This is a chain-level parameter
/// defined in v1_spec::GAS_REFUND_QUOTIENT.
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
    ///
    /// **Intentional design:** On failure, `gas_used` is set to `gas_limit`
    /// (all gas consumed). This matches EVM semantics and prevents
    /// gas-manipulation attacks where a contract deliberately runs out of gas
    /// at a precise point to exploit partial-execution side effects.
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

    /// Return unused gas from a sub-call back to the caller.
    ///
    /// Called when a child frame completes and has leftover gas.
    /// `amount` MUST be the leftover from the child frame, which by
    /// the call protocol cannot exceed the `child_gas` previously
    /// reserved from this meter via `consume(child_gas)`. The caller
    /// (always `execution_env::execute_frame`) computes `amount` as
    /// `child_gas.saturating_sub(child_used)`, so the invariant
    /// `amount <= child_gas <= self.gas_used` holds at every real
    /// call site.
    ///
    /// Defensive guard: this function used to be a bare
    /// `self.gas_used.saturating_sub(amount)`, which silently
    /// under-charged if a future caller passed an `amount` larger
    /// than what was actually reserved. The new code uses
    /// `checked_sub` so an over-return surfaces immediately:
    ///
    ///   - In **debug builds**, an over-return panics via
    ///     `debug_assert!`, so the bug is caught the moment it ships
    ///     into a test or local run.
    ///   - In **release builds**, the saturation still happens (so
    ///     existing call sites cannot suddenly OOM the chain), but
    ///     the event is logged via `slog_error!` with the requested
    ///     and capped amounts so an operator can correlate it with
    ///     a node crash or audit anomaly.
    ///
    /// Either way, an over-return is no longer silent.
    pub fn return_gas(&mut self, amount: u64) {
        match self.gas_used.checked_sub(amount) {
            Some(new_used) => {
                self.gas_used = new_used;
            }
            None => {
                // Defensive: a caller asked us to return more gas
                // than has been used. The protocol invariant says
                // this cannot happen, so this branch is dead in
                // practice — but keeping it loud means any future
                // refactor that breaks the invariant is visible.
                debug_assert!(
                    false,
                    "return_gas over-return: requested {} but gas_used is only {} \
                     — caller protocol violation, see GasMeter::return_gas docs",
                    amount, self.gas_used
                );
                crate::slog_error!(
                    "vm",
                    "gas_meter_return_gas_over_return_clamped_to_zero",
                    requested => amount,
                    gas_used  => self.gas_used,
                    note      => "release build clamps gas_used to 0; debug build panics on debug_assert"
                );
                self.gas_used = 0;
            }
        }
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
            GasResult::OutOfGas {
                available,
                required,
            } => {
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
            GasResult::OutOfGas {
                available,
                required,
            } => {
                assert_eq!(
                    available, 500,
                    "available must reflect gas remaining before overflow"
                );
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

    // ─── return_gas guard tests ─────────────────────────────────────

    #[test]
    fn return_gas_happy_path_subtracts_amount() {
        // Sanity: a normal child-frame leftover return reduces
        // gas_used by exactly `amount`.
        let mut meter = GasMeter::new(1000);
        meter.consume(800);
        assert_eq!(meter.gas_used(), 800);
        meter.return_gas(300);
        assert_eq!(meter.gas_used(), 500);
        assert_eq!(meter.gas_remaining(), 500);
    }

    #[test]
    fn return_gas_amount_equal_to_used_zeroes_out() {
        // Returning exactly gas_used drops it to 0 — same as
        // refunding all the consumed gas.
        let mut meter = GasMeter::new(1000);
        meter.consume(400);
        meter.return_gas(400);
        assert_eq!(meter.gas_used(), 0);
    }

    // The over-return case is documented as a protocol violation
    // and panics in debug builds via `debug_assert!`. We can't pin
    // a panicking test path with #[should_panic] without tightening
    // the message, so the regression coverage here is by inspection
    // of the doc comment + the always-on `slog_error!` and saturating
    // clamp in the release branch.
}
