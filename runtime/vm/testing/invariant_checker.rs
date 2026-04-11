//! Invariant Checker — verifies system consistency after each block.
//!
//! Checks that receipt_root, state_root, storage state, and indexes
//! are all consistent. Designed to run continuously during soak tests.

use crate::runtime::vm::core::execution_env::ExecutionEnvironment;
use crate::domain::transaction::tx_receipt::{TxReceipt, compute_receipt_root};

/// Result of an invariant check
#[derive(Debug, Clone)]
pub struct InvariantResult {
    pub block_height: u64,
    pub block_hash: String,
    pub checks_run: usize,
    pub checks_passed: usize,
    pub violations: Vec<String>,
}

impl InvariantResult {
    pub fn is_clean(&self) -> bool { self.violations.is_empty() }
}

/// Invariant checker that validates system state consistency.
pub struct InvariantChecker;

impl InvariantChecker {
    /// Run all invariant checks for a block.
    pub fn check_block(
        block_height: u64,
        block_hash: &str,
        claimed_receipt_root: Option<&str>,
        claimed_state_root: Option<&str>,
        receipts: &[TxReceipt],
        env: &ExecutionEnvironment,
    ) -> InvariantResult {
        let mut result = InvariantResult {
            block_height,
            block_hash: block_hash.to_string(),
            checks_run: 0,
            checks_passed: 0,
            violations: Vec::new(),
        };

        // 1. Receipt root matches actual receipts
        if let Some(claimed) = claimed_receipt_root {
            result.checks_run += 1;
            let computed = compute_receipt_root(receipts);
            if computed == claimed {
                result.checks_passed += 1;
            } else {
                result.violations.push(format!(
                    "receipt_root mismatch: claimed={} computed={}",
                    &claimed[..16.min(claimed.len())],
                    &computed[..16.min(computed.len())]
                ));
            }
        }

        // 2. State root matches actual state
        if let Some(claimed) = claimed_state_root {
            result.checks_run += 1;
            let computed = env.state.state_root();
            if computed == claimed {
                result.checks_passed += 1;
            } else {
                result.violations.push(format!(
                    "state_root mismatch: claimed={} computed={}",
                    &claimed[..16.min(claimed.len())],
                    &computed[..16.min(computed.len())]
                ));
            }
        }

        // 3. Receipt tx_hashes are unique within the block
        result.checks_run += 1;
        let mut seen = std::collections::HashSet::new();
        let unique = receipts.iter().all(|r| seen.insert(r.tx_hash.clone()));
        if unique {
            result.checks_passed += 1;
        } else {
            result.violations.push("duplicate tx_hash in block receipts".into());
        }

        // 4. No destroyed contracts still have code
        result.checks_run += 1;
        let destroyed_clean = env.destroyed_contracts.iter().all(|addr| {
            env.state.get_code(addr).is_empty()
        });
        if destroyed_clean {
            result.checks_passed += 1;
        } else {
            result.violations.push("destroyed contract still has code".into());
        }

        // 5. State root is deterministic (compute twice = same result)
        result.checks_run += 1;
        let root1 = env.state.state_root();
        let root2 = env.state.state_root();
        if root1 == root2 {
            result.checks_passed += 1;
        } else {
            result.violations.push(format!("state_root not deterministic: {} vs {}", root1, root2));
        }

        result
    }

    /// Quick check: just verify receipt and state roots match.
    pub fn quick_check(
        claimed_receipt_root: Option<&str>,
        claimed_state_root: Option<&str>,
        receipts: &[TxReceipt],
        env: &ExecutionEnvironment,
    ) -> bool {
        if let Some(claimed) = claimed_receipt_root {
            if compute_receipt_root(receipts) != claimed { return false; }
        }
        if let Some(claimed) = claimed_state_root {
            if env.state.state_root() != claimed { return false; }
        }
        true
    }

    /// Format invariant result for logging/display.
    pub fn format_result(result: &InvariantResult) -> String {
        if result.is_clean() {
            format!("Block {} ({}): OK {}/{} checks passed",
                result.block_height, &result.block_hash[..8.min(result.block_hash.len())],
                result.checks_passed, result.checks_run)
        } else {
            let mut out = format!("Block {} ({}): FAIL {}/{} checks -- {} violations:\n",
                result.block_height, &result.block_hash[..8.min(result.block_hash.len())],
                result.checks_passed, result.checks_run, result.violations.len());
            for v in &result.violations {
                out.push_str(&format!("  - {}\n", v));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::vm::core::execution_env::BlockContext;

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(BlockContext {
            timestamp: 1000,
            block_hash: "00".repeat(32),
            network: "mainnet".to_string(),
        })
    }

    #[test]
    fn clean_check_passes() {
        let env = make_env();
        let receipts = vec![];
        let receipt_root = compute_receipt_root(&receipts);

        let result = InvariantChecker::check_block(
            1, "block1", Some(&receipt_root), Some(&env.state.state_root()),
            &receipts, &env,
        );
        assert!(result.is_clean(), "Empty block should pass all checks: {:?}", result.violations);
    }

    #[test]
    fn mismatched_receipt_root_detected() {
        let env = make_env();
        let result = InvariantChecker::check_block(
            1, "block1", Some("wrong_root"), None, &[], &env,
        );
        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|v| v.contains("receipt_root")));
    }

    #[test]
    fn quick_check_valid() {
        let env = make_env();
        let receipts: Vec<TxReceipt> = vec![];
        let root = compute_receipt_root(&receipts);
        assert!(InvariantChecker::quick_check(Some(&root), Some(&env.state.state_root()), &receipts, &env));
    }

    #[test]
    fn quick_check_invalid() {
        let env = make_env();
        assert!(!InvariantChecker::quick_check(Some("bad"), None, &[], &env));
    }

    #[test]
    fn state_root_determinism_check() {
        let env = make_env();
        let result = InvariantChecker::check_block(1, "b", None, None, &[], &env);
        // State root determinism check should always pass
        assert!(result.is_clean());
    }

    #[test]
    fn format_result_clean() {
        let env = make_env();
        let result = InvariantChecker::check_block(100, "abcdef12", None, None, &[], &env);
        let formatted = InvariantChecker::format_result(&result);
        assert!(formatted.contains("OK"));
        assert!(formatted.contains("100"));
    }

    #[test]
    fn format_result_violation() {
        let env = make_env();
        let result = InvariantChecker::check_block(1, "b", Some("wrong"), None, &[], &env);
        let formatted = InvariantChecker::format_result(&result);
        assert!(formatted.contains("FAIL"));
        assert!(formatted.contains("receipt_root"));
    }
}
