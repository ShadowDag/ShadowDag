//! Observability — metrics and event hooks for monitoring VM execution.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global VM execution metrics.
pub struct VmMetrics {
    pub blocks_processed: AtomicU64,
    pub contracts_deployed: AtomicU64,
    pub contract_calls: AtomicU64,
    pub total_gas_used: AtomicU64,
    pub reverts: AtomicU64,
    pub oog_failures: AtomicU64,
    pub reorgs: AtomicU64,
    pub invariant_violations: AtomicU64,
    pub receipts_stored: AtomicU64,
    pub logs_emitted: AtomicU64,
}

impl Default for VmMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl VmMetrics {
    pub const fn new() -> Self {
        Self {
            blocks_processed: AtomicU64::new(0),
            contracts_deployed: AtomicU64::new(0),
            contract_calls: AtomicU64::new(0),
            total_gas_used: AtomicU64::new(0),
            reverts: AtomicU64::new(0),
            oog_failures: AtomicU64::new(0),
            reorgs: AtomicU64::new(0),
            invariant_violations: AtomicU64::new(0),
            receipts_stored: AtomicU64::new(0),
            logs_emitted: AtomicU64::new(0),
        }
    }

    pub fn record_block(&self) { self.blocks_processed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_deploy(&self) { self.contracts_deployed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_call(&self) { self.contract_calls.fetch_add(1, Ordering::Relaxed); }
    pub fn record_gas(&self, gas: u64) { self.total_gas_used.fetch_add(gas, Ordering::Relaxed); }
    pub fn record_revert(&self) { self.reverts.fetch_add(1, Ordering::Relaxed); }
    pub fn record_oog(&self) { self.oog_failures.fetch_add(1, Ordering::Relaxed); }
    pub fn record_reorg(&self) { self.reorgs.fetch_add(1, Ordering::Relaxed); }
    pub fn record_violation(&self) { self.invariant_violations.fetch_add(1, Ordering::Relaxed); }
    pub fn record_receipt(&self) { self.receipts_stored.fetch_add(1, Ordering::Relaxed); }
    pub fn record_logs(&self, count: u64) { self.logs_emitted.fetch_add(count, Ordering::Relaxed); }

    /// Format metrics as a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "VM Metrics:\n  Blocks:       {}\n  Deploys:      {}\n  Calls:        {}\n  Gas used:     {}\n  Reverts:      {}\n  OOG:          {}\n  Reorgs:       {}\n  Violations:   {}\n  Receipts:     {}\n  Logs:         {}",
            self.blocks_processed.load(Ordering::Relaxed),
            self.contracts_deployed.load(Ordering::Relaxed),
            self.contract_calls.load(Ordering::Relaxed),
            self.total_gas_used.load(Ordering::Relaxed),
            self.reverts.load(Ordering::Relaxed),
            self.oog_failures.load(Ordering::Relaxed),
            self.reorgs.load(Ordering::Relaxed),
            self.invariant_violations.load(Ordering::Relaxed),
            self.receipts_stored.load(Ordering::Relaxed),
            self.logs_emitted.load(Ordering::Relaxed),
        )
    }

    /// Check exit criteria: zero violations, non-zero blocks.
    pub fn meets_exit_criteria(&self) -> bool {
        self.blocks_processed.load(Ordering::Relaxed) > 0
            && self.invariant_violations.load(Ordering::Relaxed) == 0
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.blocks_processed.store(0, Ordering::Relaxed);
        self.contracts_deployed.store(0, Ordering::Relaxed);
        self.contract_calls.store(0, Ordering::Relaxed);
        self.total_gas_used.store(0, Ordering::Relaxed);
        self.reverts.store(0, Ordering::Relaxed);
        self.oog_failures.store(0, Ordering::Relaxed);
        self.reorgs.store(0, Ordering::Relaxed);
        self.invariant_violations.store(0, Ordering::Relaxed);
        self.receipts_stored.store(0, Ordering::Relaxed);
        self.logs_emitted.store(0, Ordering::Relaxed);
    }
}

/// Global metrics instance.
pub static VM_METRICS: VmMetrics = VmMetrics::new();

/// Exit criteria for public testnet launch.
pub struct ExitCriteria {
    pub min_blocks: u64,
    pub max_violations: u64,
    pub max_revert_rate_pct: u64,
    pub max_oog_rate_pct: u64,
}

impl Default for ExitCriteria {
    fn default() -> Self {
        Self {
            min_blocks: 1000,        // At least 1000 blocks
            max_violations: 0,       // Zero invariant violations
            max_revert_rate_pct: 50, // Under 50% reverts
            max_oog_rate_pct: 10,    // Under 10% OOG
        }
    }
}

impl ExitCriteria {
    pub fn check(&self, metrics: &VmMetrics) -> (bool, Vec<String>) {
        let blocks = metrics.blocks_processed.load(Ordering::Relaxed);
        let violations = metrics.invariant_violations.load(Ordering::Relaxed);
        let calls = metrics.contract_calls.load(Ordering::Relaxed).max(1);
        let reverts = metrics.reverts.load(Ordering::Relaxed);
        let oogs = metrics.oog_failures.load(Ordering::Relaxed);

        let mut failures = Vec::new();

        if blocks < self.min_blocks {
            failures.push(format!("blocks {} < min {}", blocks, self.min_blocks));
        }
        if violations > self.max_violations {
            failures.push(format!("violations {} > max {}", violations, self.max_violations));
        }
        let revert_pct = reverts * 100 / calls;
        if revert_pct > self.max_revert_rate_pct {
            failures.push(format!("revert rate {}% > max {}%", revert_pct, self.max_revert_rate_pct));
        }
        let oog_pct = oogs * 100 / calls;
        if oog_pct > self.max_oog_rate_pct {
            failures.push(format!("OOG rate {}% > max {}%", oog_pct, self.max_oog_rate_pct));
        }

        (failures.is_empty(), failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_record_and_summary() {
        let m = VmMetrics::new();
        m.record_block();
        m.record_deploy();
        m.record_call();
        m.record_gas(5000);
        assert!(m.summary().contains("Blocks:       1"));
        assert!(m.summary().contains("Gas used:     5000"));
    }

    #[test]
    fn exit_criteria_pass() {
        let m = VmMetrics::new();
        for _ in 0..1000 { m.record_block(); m.record_call(); }
        let (pass, _) = ExitCriteria::default().check(&m);
        assert!(pass, "1000 clean blocks should pass");
    }

    #[test]
    fn exit_criteria_fail_violations() {
        let m = VmMetrics::new();
        for _ in 0..1000 { m.record_block(); m.record_call(); }
        m.record_violation();
        let (pass, failures) = ExitCriteria::default().check(&m);
        assert!(!pass);
        assert!(failures.iter().any(|f| f.contains("violations")));
    }

    #[test]
    fn exit_criteria_fail_too_few_blocks() {
        let m = VmMetrics::new();
        for _ in 0..10 { m.record_block(); m.record_call(); }
        let (pass, failures) = ExitCriteria::default().check(&m);
        assert!(!pass);
        assert!(failures.iter().any(|f| f.contains("blocks")));
    }
}
