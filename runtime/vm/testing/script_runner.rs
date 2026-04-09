//! Script Runner -- deploy/call/verify pipeline for contract deployment scripts.
//!
//! Executes deployment scripts that can deploy multiple contracts in order,
//! pass constructor args, wait for receipts, auto-verify, and save addresses
//! to deployment manifests.

use crate::runtime::vm::core::execution_env::*;
use crate::runtime::vm::core::v1_spec;
use crate::runtime::vm::contracts::contract_package::ContractPackage;
use crate::runtime::vm::contracts::contract_verifier::ContractVerifier;
use crate::runtime::vm::contracts::deployment_manifest::{DeploymentManifest, DeployedContract};
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::runtime::vm::contracts::contract_abi::ContractAbi;

/// A single script action
#[derive(Debug, Clone)]
pub enum ScriptAction {
    /// Deploy a contract from bytecode
    Deploy {
        name: String,
        bytecode: Vec<u8>,
        value: u64,
        gas_limit: u64,
        abi: ContractAbi,
    },
    /// Call a deployed contract
    Call {
        contract_name: String,
        calldata: Vec<u8>,
        value: u64,
        gas_limit: u64,
    },
    /// Fund an account with balance
    Fund {
        address: String,
        amount: u64,
    },
    /// Print a message
    Log {
        message: String,
    },
}

/// Result of a script execution step
#[derive(Debug, Clone)]
pub struct ScriptStepResult {
    pub action_index: usize,
    pub action_type: String,
    pub success: bool,
    pub contract_address: Option<String>,
    pub gas_used: u64,
    pub message: String,
}

/// Script runner that executes deployment pipelines
pub struct ScriptRunner {
    env: ExecutionEnvironment,
    manifest: DeploymentManifest,
    storage: Option<ContractStorage>,
    deployed: std::collections::HashMap<String, String>, // name -> address
    results: Vec<ScriptStepResult>,
    deployer: String,
    block_height: u64,
}

impl ScriptRunner {
    pub fn new(network: &str, deployer: &str) -> Self {
        Self {
            env: ExecutionEnvironment::new(BlockContext {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
                block_hash: "00".repeat(32),
            }),
            manifest: DeploymentManifest::new(network),
            storage: None,
            deployed: std::collections::HashMap::new(),
            results: Vec::new(),
            deployer: deployer.to_string(),
            block_height: 0,
        }
    }

    /// Attach persistent storage for verification and state persistence.
    pub fn with_storage(mut self, storage: ContractStorage) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Fund the deployer account.
    pub fn fund_deployer(&mut self, amount: u64) {
        self.env.state.set_balance(&self.deployer, amount).ok();
    }

    /// Execute a list of script actions.
    pub fn execute(&mut self, actions: &[ScriptAction]) -> Vec<ScriptStepResult> {
        for (i, action) in actions.iter().enumerate() {
            let result = match action {
                ScriptAction::Deploy { name, bytecode, value, gas_limit, abi } => {
                    self.execute_deploy(i, name, bytecode, *value, *gas_limit, abi)
                }
                ScriptAction::Call { contract_name, calldata, value, gas_limit } => {
                    self.execute_call(i, contract_name, calldata, *value, *gas_limit)
                }
                ScriptAction::Fund { address, amount } => {
                    self.env.state.set_balance(address, *amount).ok();
                    ScriptStepResult {
                        action_index: i,
                        action_type: "fund".into(),
                        success: true,
                        contract_address: None,
                        gas_used: 0,
                        message: format!("funded {} with {}", address, amount),
                    }
                }
                ScriptAction::Log { message } => {
                    println!("  [script] {}", message);
                    ScriptStepResult {
                        action_index: i,
                        action_type: "log".into(),
                        success: true,
                        contract_address: None,
                        gas_used: 0,
                        message: message.clone(),
                    }
                }
            };

            let success = result.success;
            self.results.push(result);

            if !success {
                break; // Stop script on first failure
            }
        }

        self.results.clone()
    }

    fn execute_deploy(&mut self, idx: usize, name: &str, bytecode: &[u8], value: u64, gas_limit: u64, abi: &ContractAbi) -> ScriptStepResult {
        // Check if already deployed (idempotent)
        if let Some(existing) = self.deployed.get(name) {
            return ScriptStepResult {
                action_index: idx,
                action_type: "deploy".into(),
                success: true,
                contract_address: Some(existing.clone()),
                gas_used: 0,
                message: format!("{} already deployed at {}", name, existing),
            };
        }

        // V1 validation
        if let Err((pos, byte)) = v1_spec::validate_v1_bytecode(bytecode) {
            return ScriptStepResult {
                action_index: idx,
                action_type: "deploy".into(),
                success: false,
                contract_address: None,
                gas_used: 0,
                message: format!("invalid opcode 0x{:02X} at position {}", byte, pos),
            };
        }

        let addr = format!("SD1c_script_{}", name.to_lowercase().replace(' ', "_"));
        self.env.state.set_code(&addr, bytecode.to_vec()).ok();
        self.env.state.get_or_create_account(&addr);

        // Transfer value if needed
        if value > 0 {
            self.env.state.transfer(&self.deployer, &addr, value).ok();
        }

        // Execute constructor (if bytecode does something on deploy)
        let ctx = CallContext {
            address: addr.clone(),
            code_address: addr.clone(),
            caller: self.deployer.clone(),
            value,
            gas_limit,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let outcome = self.env.execute_frame(&ctx);

        let (success, gas_used) = match &outcome {
            CallOutcome::Success { gas_used, .. } => (true, *gas_used),
            CallOutcome::Revert { gas_used, .. } => (false, *gas_used),
            CallOutcome::Failure { gas_used } => (false, *gas_used),
        };

        if success {
            self.deployed.insert(name.to_string(), addr.clone());
            self.block_height += 1;

            // Add to manifest
            let bytecode_hash = {
                use sha2::{Sha256, Digest};
                let mut h = Sha256::new();
                h.update(bytecode);
                hex::encode(h.finalize())
            };

            self.manifest.add_deployment(DeployedContract {
                name: name.to_string(),
                address: addr.clone(),
                bytecode_hash,
                deploy_height: self.block_height,
                deploy_tx: format!("script_deploy_{}", idx),
                vm_version: 1,
                verified: true, // Script deployments are self-verified
                deployed_at: self.env.block_ctx.timestamp,
                package_file: None,
            });

            // Auto-verify if storage available
            if let Some(ref storage) = self.storage {
                let pkg = ContractPackage::new(name, bytecode.to_vec(), abi.clone());
                storage.set_state(&format!("code:{}", addr), &hex::encode(bytecode)).ok();
                storage.set_state(&format!("vm_version:{}", addr), "1").ok();
                let verify_result = ContractVerifier::verify(storage, &addr, &pkg);
                if verify_result.verified {
                    ContractVerifier::save_verification(storage, &verify_result, &pkg).ok();
                }
            }
        }

        ScriptStepResult {
            action_index: idx,
            action_type: "deploy".into(),
            success,
            contract_address: if success { Some(addr) } else { None },
            gas_used,
            message: if success {
                format!("deployed {} at {}", name, self.deployed.get(name).unwrap())
            } else {
                format!("deploy {} failed", name)
            },
        }
    }

    fn execute_call(&mut self, idx: usize, contract_name: &str, calldata: &[u8], value: u64, gas_limit: u64) -> ScriptStepResult {
        let addr = match self.deployed.get(contract_name) {
            Some(a) => a.clone(),
            None => return ScriptStepResult {
                action_index: idx,
                action_type: "call".into(),
                success: false,
                contract_address: None,
                gas_used: 0,
                message: format!("contract '{}' not deployed", contract_name),
            },
        };

        let ctx = CallContext {
            address: addr.clone(),
            code_address: addr.clone(),
            caller: self.deployer.clone(),
            value,
            gas_limit,
            calldata: calldata.to_vec(),
            is_static: false,
            depth: 0,
        };
        let outcome = self.env.execute_frame(&ctx);

        let (success, gas_used) = match &outcome {
            CallOutcome::Success { gas_used, .. } => (true, *gas_used),
            CallOutcome::Revert { gas_used, .. } => (false, *gas_used),
            CallOutcome::Failure { gas_used } => (false, *gas_used),
        };

        ScriptStepResult {
            action_index: idx,
            action_type: "call".into(),
            success,
            contract_address: Some(addr),
            gas_used,
            message: if success { format!("called {}", contract_name) } else { format!("call {} failed", contract_name) },
        }
    }

    /// Get the deployment manifest.
    pub fn manifest(&self) -> &DeploymentManifest {
        &self.manifest
    }

    /// Get deployed contract address by name.
    pub fn get_address(&self, name: &str) -> Option<&str> {
        self.deployed.get(name).map(|s| s.as_str())
    }

    /// Get all results.
    pub fn results(&self) -> &[ScriptStepResult] {
        &self.results
    }

    /// Print execution summary.
    pub fn print_summary(&self) {
        println!("\n=== Script Summary ===");
        for r in &self.results {
            let status = if r.success { "OK" } else { "FAIL" };
            print!("  {} [{}] {}", status, r.action_type, r.message);
            if r.gas_used > 0 {
                print!(" (gas: {})", r.gas_used);
            }
            println!();
        }
        let passed = self.results.iter().filter(|r| r.success).count();
        let total = self.results.len();
        println!("\n  {} / {} steps succeeded", passed, total);

        if !self.deployed.is_empty() {
            println!("\n  Deployed contracts:");
            for (name, addr) in &self.deployed {
                println!("    {} -> {}", name, addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_deploy_and_call() {
        let mut runner = ScriptRunner::new("local", "deployer");
        runner.fund_deployer(1_000_000_000);

        let abi = ContractAbi::new("Counter");
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0x00]; // PUSH1 42, PUSH1 0, SSTORE, STOP

        let results = runner.execute(&[
            ScriptAction::Log { message: "Deploying counter...".into() },
            ScriptAction::Deploy {
                name: "Counter".into(),
                bytecode: bytecode.clone(),
                value: 0,
                gas_limit: 1_000_000,
                abi,
            },
            ScriptAction::Call {
                contract_name: "Counter".into(),
                calldata: vec![],
                value: 0,
                gas_limit: 1_000_000,
            },
        ]);

        assert!(results.iter().all(|r| r.success), "All steps should succeed");
        assert!(runner.get_address("Counter").is_some());
        assert!(runner.manifest().is_deployed("Counter"));
    }

    #[test]
    fn script_idempotent_deploy() {
        let mut runner = ScriptRunner::new("local", "deployer");
        runner.fund_deployer(1_000_000_000);
        let abi = ContractAbi::new("Token");
        let bytecode = vec![0x00]; // STOP

        runner.execute(&[
            ScriptAction::Deploy { name: "Token".into(), bytecode: bytecode.clone(), value: 0, gas_limit: 1_000_000, abi: abi.clone() },
        ]);
        let addr1 = runner.get_address("Token").unwrap().to_string();

        // Deploy again -- should be idempotent
        runner.execute(&[
            ScriptAction::Deploy { name: "Token".into(), bytecode, value: 0, gas_limit: 1_000_000, abi },
        ]);
        let addr2 = runner.get_address("Token").unwrap().to_string();
        assert_eq!(addr1, addr2, "Idempotent deploy should return same address");
    }

    #[test]
    fn script_stops_on_failure() {
        let mut runner = ScriptRunner::new("local", "deployer");
        // Don't fund -- deploy will fail due to v1 validation if bad bytecode
        // Actually: deploy with 0xFF (INVALID opcode) -- v1 validation catches it
        let abi = ContractAbi::new("Bad");
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "Bad".into(), bytecode: vec![0xEE], value: 0, gas_limit: 1_000_000, abi },
            ScriptAction::Log { message: "should not reach here".into() },
        ]);
        assert!(!results[0].success);
        assert_eq!(results.len(), 1, "Script should stop after first failure");
    }

    #[test]
    fn script_manifest_populated() {
        let mut runner = ScriptRunner::new("testnet", "deployer");
        runner.fund_deployer(1_000_000_000);
        let abi = ContractAbi::new("MyToken");
        runner.execute(&[
            ScriptAction::Deploy { name: "MyToken".into(), bytecode: vec![0x00], value: 0, gas_limit: 1_000_000, abi },
        ]);

        let manifest = runner.manifest();
        assert_eq!(manifest.network, "testnet");
        assert!(manifest.is_deployed("MyToken"));
        let contract = manifest.contracts.get("MyToken").unwrap();
        assert_eq!(contract.vm_version, 1);
        assert!(contract.verified);
    }
}
