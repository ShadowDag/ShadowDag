//! ShadowVM Test Framework -- run contract tests with assertions.
//!
//! Provides a TestRunner that sets up an isolated execution environment
//! with pre-funded accounts, deploys contracts, calls functions, and
//! asserts on return data, storage, logs, gas, and revert reasons.

use crate::runtime::vm::core::execution_env::*;
use crate::runtime::vm::core::assembler::Assembler;
use crate::runtime::vm::core::v1_spec;
use crate::runtime::vm::core::source_map::SourceMap;

/// Test assertion result
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub gas_used: u64,
    pub message: Option<String>,
}

/// A single test case for a contract
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub calldata: Vec<u8>,
    pub value: u64,
    pub gas_limit: u64,
    pub expect_success: bool,
    pub expect_return: Option<Vec<u8>>,
    pub expect_revert: bool,
    pub expect_storage: Vec<(String, String)>, // (slot_key, expected_value)
    pub expect_log_count: Option<usize>,
    pub max_gas: Option<u64>,
}

impl Default for TestCase {
    fn default() -> Self {
        Self {
            name: "unnamed".into(),
            calldata: vec![],
            value: 0,
            gas_limit: 10_000_000,
            expect_success: true,
            expect_return: None,
            expect_revert: false,
            expect_storage: vec![],
            expect_log_count: None,
            max_gas: None,
        }
    }
}

/// Test runner with isolated execution environment
pub struct TestRunner {
    env: ExecutionEnvironment,
    contract_addr: String,
    results: Vec<TestResult>,
}

impl TestRunner {
    /// Create a new test runner with a fresh environment.
    pub fn new() -> Self {
        let env = ExecutionEnvironment::new(BlockContext {
            timestamp: 1_000_000,
            block_hash: "00".repeat(32),
        });
        Self {
            env,
            contract_addr: String::new(),
            results: Vec::new(),
        }
    }

    /// Fund a test account with a balance.
    pub fn fund_account(&mut self, address: &str, balance: u64) {
        self.env.state.set_balance(address, balance).ok();
    }

    /// Deploy bytecode and set the active contract address.
    pub fn deploy_bytecode(&mut self, bytecode: Vec<u8>, _deployer: &str) -> Result<String, String> {
        // V1 validation
        if let Err((pos, byte)) = v1_spec::validate_v1_bytecode(&bytecode) {
            return Err(format!("invalid opcode 0x{:02X} at position {}", byte, pos));
        }

        let addr = format!("SD1c_test_{}", self.results.len());
        self.env.state.set_code(&addr, bytecode).ok();
        self.contract_addr = addr.clone();
        Ok(addr)
    }

    /// Deploy from assembly source.
    pub fn deploy_source(&mut self, source: &str, deployer: &str) -> Result<String, String> {
        let bytecode = Assembler::assemble(source).map_err(|e| e.to_string())?;
        self.deploy_bytecode(bytecode, deployer)
    }

    /// Run a test case against the deployed contract.
    pub fn run_test(&mut self, test: &TestCase) -> TestResult {
        let ctx = CallContext {
            address: self.contract_addr.clone(),
            code_address: self.contract_addr.clone(),
            caller: "test_caller".into(),
            value: test.value,
            gas_limit: test.gas_limit,
            calldata: test.calldata.clone(),
            is_static: false,
            depth: 0,
        };

        let outcome = self.env.execute_frame(&ctx);

        let (success, gas_used, return_data, logs) = match &outcome {
            CallOutcome::Success { gas_used, return_data, logs } => {
                (true, *gas_used, return_data.clone(), logs.clone())
            }
            CallOutcome::Revert { gas_used, return_data } => {
                (false, *gas_used, return_data.clone(), vec![])
            }
            CallOutcome::Failure { gas_used } => {
                (false, *gas_used, vec![], vec![])
            }
        };

        let mut errors = Vec::new();

        // Assert success/failure
        if test.expect_success && !success {
            let reason = SourceMap::decode_revert_reason(&return_data);
            errors.push(format!("expected success but got failure: {}", reason));
        }
        if test.expect_revert && success {
            errors.push("expected revert but execution succeeded".into());
        }

        // Assert return data
        if let Some(ref expected) = test.expect_return {
            if return_data != *expected {
                errors.push(format!("return data mismatch: expected {} got {}",
                    hex::encode(expected), hex::encode(&return_data)));
            }
        }

        // Assert storage (normalize hex: strip leading 0x and zeros for comparison)
        for (slot_key, expected_val) in &test.expect_storage {
            let actual = self.env.state.storage_load(&self.contract_addr, slot_key);
            match actual {
                Some(ref v) => {
                    let norm_actual = v.trim_start_matches("0x").trim_start_matches('0');
                    let norm_expected = expected_val.trim_start_matches("0x").trim_start_matches('0');
                    if norm_actual != norm_expected {
                        errors.push(format!("storage {}: expected '{}' got '{}'", slot_key, expected_val, v));
                    }
                }
                None => errors.push(format!("storage {}: expected '{}' but slot is empty", slot_key, expected_val)),
            }
        }

        // Assert log count
        if let Some(expected_count) = test.expect_log_count {
            if logs.len() != expected_count {
                errors.push(format!("log count: expected {} got {}", expected_count, logs.len()));
            }
        }

        // Assert gas upper bound
        if let Some(max) = test.max_gas {
            if gas_used > max {
                errors.push(format!("gas {} exceeds max {}", gas_used, max));
            }
        }

        let passed = errors.is_empty();
        let message = if errors.is_empty() { None } else { Some(errors.join("; ")) };

        let result = TestResult {
            name: test.name.clone(),
            passed,
            gas_used,
            message,
        };
        self.results.push(result.clone());
        result
    }

    /// Get all test results.
    pub fn results(&self) -> &[TestResult] {
        &self.results
    }

    /// Print a summary of all test results.
    pub fn print_summary(&self) {
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        println!("\n=== Test Results ===");
        for r in &self.results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            print!("  {} {} (gas: {})", status, r.name, r.gas_used);
            if let Some(ref msg) = r.message {
                print!(" -- {}", msg);
            }
            println!();
        }
        println!("\n  {} passed, {} failed, {} total", passed, failed, total);
    }

    /// Reset the environment (for snapshot/revert testing).
    pub fn snapshot(&mut self) -> usize {
        self.env.state.snapshot()
    }

    pub fn revert_to(&mut self, id: usize) {
        self.env.state.rollback(id).ok();
    }

    /// Get the active contract address.
    pub fn contract_addr(&self) -> &str {
        &self.contract_addr
    }

    /// Access the environment directly for advanced assertions.
    pub fn env(&self) -> &ExecutionEnvironment {
        &self.env
    }

    pub fn env_mut(&mut self) -> &mut ExecutionEnvironment {
        &mut self.env
    }
}

impl Default for TestRunner {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_deploy_and_call() {
        let mut runner = TestRunner::new();
        // PUSH1 42, PUSH1 0, SSTORE, STOP
        let addr = runner.deploy_bytecode(vec![0x10, 42, 0x10, 0, 0x51, 0x00], "deployer").unwrap();
        assert!(addr.starts_with("SD1c_test_"));

        let result = runner.run_test(&TestCase {
            name: "store_42".into(),
            expect_success: true,
            expect_storage: vec![("slot:0".into(), "0x2a".into())],
            ..Default::default()
        });
        assert!(result.passed, "Test should pass: {:?}", result.message);
    }

    #[test]
    fn test_runner_revert_assertion() {
        let mut runner = TestRunner::new();
        // PUSH1 0, PUSH1 0, REVERT
        runner.deploy_bytecode(vec![0x10, 0, 0x10, 0, 0xB7], "d").unwrap();

        let result = runner.run_test(&TestCase {
            name: "expect_revert".into(),
            expect_revert: true,
            expect_success: false,
            ..Default::default()
        });
        assert!(result.passed);
    }

    #[test]
    fn test_runner_gas_assertion() {
        let mut runner = TestRunner::new();
        // PUSH1 1, PUSH1 2, ADD, STOP
        runner.deploy_bytecode(vec![0x10, 1, 0x10, 2, 0x20, 0x00], "d").unwrap();

        let result = runner.run_test(&TestCase {
            name: "gas_check".into(),
            max_gas: Some(500),
            ..Default::default()
        });
        assert!(result.passed, "Simple contract should use < 500 gas");
    }

    #[test]
    fn test_runner_snapshot_revert() {
        let mut runner = TestRunner::new();
        runner.deploy_bytecode(vec![0x10, 99, 0x10, 0, 0x51, 0x00], "d").unwrap();

        // Take snapshot
        let snap = runner.snapshot();

        // Call contract -- changes state
        runner.run_test(&TestCase {
            name: "modify_state".into(),
            ..Default::default()
        });

        // Revert to snapshot
        runner.revert_to(snap);

        // State should be clean
        let val = runner.env().state.storage_load(runner.contract_addr(), "slot:0");
        assert!(val.is_none(), "State should be reverted");
    }

    #[test]
    fn test_runner_return_data_assertion() {
        let mut runner = TestRunner::new();
        // PUSH2 0xBEEF, PUSH1 0, MSTORE, PUSH1 2, PUSH1 30, RETURN
        runner.deploy_bytecode(vec![0x11, 0xBE, 0xEF, 0x10, 0, 0x91, 0x10, 2, 0x10, 30, 0xB6], "d").unwrap();

        let result = runner.run_test(&TestCase {
            name: "check_return".into(),
            expect_return: Some(vec![0xBE, 0xEF]),
            ..Default::default()
        });
        assert!(result.passed, "Return data should match: {:?}", result.message);
    }

    #[test]
    fn test_runner_print_summary() {
        let mut runner = TestRunner::new();
        runner.deploy_bytecode(vec![0x00], "d").unwrap(); // STOP
        runner.run_test(&TestCase { name: "test1".into(), ..Default::default() });
        runner.run_test(&TestCase { name: "test2".into(), ..Default::default() });
        runner.print_summary();
        assert_eq!(runner.results().len(), 2);
    }
}
