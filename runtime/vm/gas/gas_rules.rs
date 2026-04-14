// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Gas Rules — Gas accounting with limits and refunds for ShadowVM.
//
// Public surface intentionally LIMITED to:
//   - `GasRules::new`            — construction
//   - `GasRules::charge`         — the only legitimate way to spend gas
//   - `GasRules::calculate_refund` — pure helper
//
// The gas-introspection helpers (`has_gas`, `remaining`, `meter`,
// `meter_mut`) are restricted to `pub(crate)` so neither user
// contracts nor downstream tooling can branch on the meter's current
// state, mirroring the same restriction `GasMeter::has_gas` already
// carries. The previous `pub fn has_gas` / `pub fn remaining` /
// `pub fn meter` / `pub fn meter_mut` exposed exactly the
// branch-on-remaining-gas surface `GasMeter` was trying to hide,
// re-opening the determinism hole from a different door:
//
//     // Old surface: a downstream caller could write
//     if rules.has_gas(SOME_THRESHOLD) {
//         // expensive happy path
//     } else {
//         // cheaper fallback
//     }
//
// which would make the contract's behaviour depend on the gas
// the caller happened to allocate — different gas limits → different
// branches → state divergence between honest validators.
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::VmError;
use crate::runtime::vm::gas::gas_meter::{GasMeter, GasResult};

/// Maximum gas per transaction (10 million)
pub const MAX_GAS_PER_TX: u64 = 10_000_000;

/// Maximum gas per block (100 million)
pub const MAX_GAS_PER_BLOCK: u64 = 100_000_000;

/// Gas refund rate for SDELETE (clearing storage)
pub const SDELETE_REFUND: u64 = 2_400;

/// Maximum refund = 50% of gas used
pub const MAX_REFUND_RATIO: u64 = 2; // gas_used / 2

pub struct GasRules {
    meter: GasMeter,
}

impl GasRules {
    pub fn new(meter: GasMeter) -> Self {
        Self { meter }
    }

    /// Charge gas with overflow protection and limit enforcement.
    /// Uses GasMeter::consume() which properly tracks gas_used.
    pub fn charge(&mut self, _key: &str, cost: u64) -> Result<u64, VmError> {
        match self.meter.consume(cost) {
            GasResult::Ok(remaining) => Ok(remaining),
            GasResult::OutOfGas { .. } => Err(VmError::OutOfGas {
                used: self.meter.gas_used(),
                limit: self.meter.gas_limit(),
            }),
        }
    }

    /// Calculate gas refund (capped at 50% of used gas)
    pub fn calculate_refund(gas_used: u64, refund_counter: u64) -> u64 {
        let max_refund = gas_used / MAX_REFUND_RATIO;
        refund_counter.min(max_refund)
    }

    /// Get remaining gas.
    ///
    /// **Restricted to `pub(crate)`** for the same reason
    /// `GasMeter::has_gas` is restricted: exposing a branch-on-
    /// remaining-gas surface to user contracts or downstream tooling
    /// creates non-deterministic execution paths (different gas
    /// limits → different branches → state divergence). Only the
    /// VM execution loop should call this. The `_key` and
    /// `_gas_limit` arguments are vestigial from an older signature
    /// and kept to avoid touching the call sites that already
    /// import the function — they are not used.
    #[allow(dead_code)] // Reserved for VM execution loop; intentionally restricted from public API
    pub(crate) fn remaining(&self, _key: &str, _gas_limit: u64) -> u64 {
        self.meter.gas_remaining()
    }

    /// Check if there is enough gas remaining for the given cost.
    ///
    /// **Restricted to `pub(crate)`** to match the same restriction
    /// on `GasMeter::has_gas`. See the doc comment on
    /// [`Self::remaining`] for the rationale. The previous `pub fn`
    /// signature re-opened the introspection surface that
    /// `GasMeter::has_gas` was specifically restricted to close.
    #[allow(dead_code)] // Reserved for VM execution loop; intentionally restricted from public API
    pub(crate) fn has_gas(&self, cost: u64) -> bool {
        self.meter.gas_remaining() >= cost
    }

    /// Access the underlying meter.
    ///
    /// **Restricted to `pub(crate)`** because handing out a
    /// `&GasMeter` lets the recipient call any of the meter's own
    /// pub-readable accessors (`gas_used`, `gas_remaining`,
    /// `gas_limit`) and re-derive the introspection surface
    /// `GasMeter::has_gas` was restricted to hide.
    #[allow(dead_code)] // Reserved for VM execution loop; intentionally restricted from public API
    pub(crate) fn meter(&self) -> &GasMeter {
        &self.meter
    }

    /// Access the underlying meter mutably.
    ///
    /// **Restricted to `pub(crate)`** for the same reason as
    /// [`Self::meter`].
    #[allow(dead_code)] // Reserved for VM execution loop; intentionally restricted from public API
    pub(crate) fn meter_mut(&mut self) -> &mut GasMeter {
        &mut self.meter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refund_capped_at_50_percent() {
        // Used 1000 gas, accumulated 800 refund → max refund = 500
        assert_eq!(GasRules::calculate_refund(1000, 800), 500);
    }

    #[test]
    fn refund_below_cap() {
        // Used 1000 gas, accumulated 100 refund → refund = 100
        assert_eq!(GasRules::calculate_refund(1000, 100), 100);
    }

    #[test]
    fn charge_deducts_gas() {
        let meter = GasMeter::new(1_000_000);
        let mut rules = GasRules::new(meter);

        let remaining = rules.charge("test", 100).unwrap();
        assert_eq!(remaining, 999_900);
    }

    #[test]
    fn charge_fails_when_over_limit() {
        let meter = GasMeter::new(100);
        let mut rules = GasRules::new(meter);

        let result = rules.charge("test", 200);
        assert!(result.is_err());
    }
}
