//! Script Runner -- deploy/call/verify pipeline for contract deployment scripts.
//!
//! Executes deployment scripts that can deploy multiple contracts in order,
//! pass constructor args, wait for receipts, auto-verify, and save addresses
//! to deployment manifests.

use crate::domain::address::address::network_prefix;
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
    /// Create a new ScriptRunner for the given network.
    ///
    /// Returns `Err(VmError::ContractError)` if `network` is not one
    /// of the known ShadowDAG networks — the cascade comes from
    /// `DeploymentManifest::new`, which now refuses to build a
    /// manifest for an unknown network string instead of silently
    /// defaulting to `chain_id = 0` with a bogus RPC URL.
    pub fn new(network: &str, deployer: &str) -> Result<Self, crate::errors::VmError> {
        Ok(Self {
            env: ExecutionEnvironment::new(BlockContext {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
                block_hash: "00".repeat(32),
                network: network.to_string(),
            }),
            manifest: DeploymentManifest::new(network)?,
            storage: None,
            deployed: std::collections::HashMap::new(),
            results: Vec::new(),
            deployer: deployer.to_string(),
            block_height: 0,
        })
    }

    /// Attach persistent storage for verification and state persistence.
    pub fn with_storage(mut self, storage: ContractStorage) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Fund the deployer account.
    ///
    /// Returns `Err(String)` if the underlying `set_balance` fails —
    /// the previous implementation used `.ok()` to silently swallow
    /// the error, so a failed fund looked like a successful setup
    /// and later steps would run against an unfunded account.
    pub fn fund_deployer(&mut self, amount: u64) -> Result<(), String> {
        self.env.state.set_balance(&self.deployer, amount)
            .map_err(|e| format!("fund_deployer '{}' failed: {}", self.deployer, e))
    }

    /// Return `{prefix}c` for the manifest's network, e.g. `SD1c`,
    /// `ST1c`, or `SR1c`. Used to tag script-deploy addresses so a
    /// testnet manifest never produces mainnet-looking contract
    /// addresses. The manifest itself was constructed via
    /// `DeploymentManifest::new`, which rejects unknown networks, so
    /// this helper cannot see an invalid `self.manifest.network`.
    fn contract_addr_prefix(&self) -> &'static str {
        match network_prefix(&self.manifest.network) {
            Some(p) => match p {
                "SD1" => "SD1c",
                "ST1" => "ST1c",
                "SR1" => "SR1c",
                _     => "SD1c", // unreachable: network_prefix limited to 3 values
            },
            // Unreachable: DeploymentManifest::new already refuses
            // unknown networks. Use a sentinel that no other path
            // produces so any future regression is visible.
            None => "??1c",
        }
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
                    // Propagate set_balance failure instead of .ok() so
                    // a failed fund doesn't masquerade as a successful
                    // step. Downstream actions will see the Fund as
                    // failed and the script will stop.
                    match self.env.state.set_balance(address, *amount) {
                        Ok(()) => ScriptStepResult {
                            action_index: i,
                            action_type: "fund".into(),
                            success: true,
                            contract_address: None,
                            gas_used: 0,
                            message: format!("funded {} with {}", address, amount),
                        },
                        Err(e) => ScriptStepResult {
                            action_index: i,
                            action_type: "fund".into(),
                            success: false,
                            contract_address: None,
                            gas_used: 0,
                            message: format!("fund {} with {} failed: {}", address, amount, e),
                        },
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
        // Compute the bytecode hash up front so it can participate in
        // the idempotency check below.
        let bytecode_hash = {
            use sha2::{Sha256, Digest};
            let mut h = Sha256::new();
            h.update(bytecode);
            hex::encode(h.finalize())
        };

        // Content-based idempotency: a re-deploy of the same `name`
        // with the SAME bytecode returns the existing address as a
        // successful no-op, but a re-deploy of the same name with
        // DIFFERENT bytecode fails loudly. The previous behaviour
        // compared only on name, so a caller that re-ran a script
        // after editing the contract source would silently keep the
        // old contract and report the step as successful.
        if let Some(existing) = self.deployed.get(name).cloned() {
            // Look up the prior bytecode_hash from the manifest to
            // compare by content.
            let prior_hash = self.manifest.contracts.get(name)
                .map(|c| c.bytecode_hash.clone());
            return match prior_hash {
                Some(ph) if ph == bytecode_hash => ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: true,
                    contract_address: Some(existing.clone()),
                    gas_used: 0,
                    message: format!("{} already deployed at {} (same bytecode)", name, existing),
                },
                Some(ph) => ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: false,
                    contract_address: Some(existing.clone()),
                    gas_used: 0,
                    message: format!(
                        "deploy {} refused: already deployed at {} with a DIFFERENT bytecode \
                         (prior hash: {}, new hash: {}) — re-deploying would silently shadow \
                         the previous contract",
                        name, existing, ph, bytecode_hash
                    ),
                },
                // No manifest entry but the `deployed` map has one —
                // shouldn't happen in practice but surface it.
                None => ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: false,
                    contract_address: Some(existing.clone()),
                    gas_used: 0,
                    message: format!(
                        "deploy {} refused: in-memory deployed map has an entry but the \
                         manifest does not — cannot verify content equivalence",
                        name
                    ),
                },
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

        // Tag the deployed address with the MANIFEST's network prefix
        // — not a hardcoded "SD1c". A testnet manifest now produces
        // "ST1c_script_…" and a regtest manifest produces
        // "SR1c_script_…", matching the rest of the network-aware
        // contract-address pipeline (contract_deployer, executor, wasm).
        let addr = format!(
            "{}_script_{}",
            self.contract_addr_prefix(),
            name.to_lowercase().replace(' ', "_")
        );

        // Load the code into state and surface a failure as a
        // ScriptStepResult with success=false. The previous `.ok()`
        // swallow would have marked the step successful even when
        // set_code failed at the state-manager layer.
        if let Err(e) = self.env.state.set_code(&addr, bytecode.to_vec()) {
            return ScriptStepResult {
                action_index: idx,
                action_type: "deploy".into(),
                success: false,
                contract_address: None,
                gas_used: 0,
                message: format!("set_code({}) failed: {}", addr, e),
            };
        }
        self.env.state.get_or_create_account(&addr);

        // Transfer value if needed — fail loudly instead of .ok().
        if value > 0 {
            if let Err(e) = self.env.state.transfer(&self.deployer, &addr, value) {
                return ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: false,
                    contract_address: None,
                    gas_used: 0,
                    message: format!("transfer {} -> {} ({}) failed: {}",
                        self.deployer, addr, value, e),
                };
            }
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

        if !success {
            return ScriptStepResult {
                action_index: idx,
                action_type: "deploy".into(),
                success: false,
                contract_address: None,
                gas_used,
                message: format!("deploy {} failed", name),
            };
        }

        // Persist + verify BEFORE mutating the manifest, so a
        // persistence failure doesn't leave behind a manifest entry
        // that claims `verified: true` on a record that never made
        // it to disk.
        let mut persisted_verified = false;
        if let Some(ref storage) = self.storage {
            let pkg = ContractPackage::new(name, bytecode.to_vec(), abi.clone());

            if let Err(e) = storage.set_state(&format!("code:{}", addr), &hex::encode(bytecode)) {
                return ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: false,
                    contract_address: None,
                    gas_used,
                    message: format!("storage.set_state(code:{}) failed: {}", addr, e),
                };
            }
            if let Err(e) = storage.set_state(&format!("vm_version:{}", addr), "1") {
                return ScriptStepResult {
                    action_index: idx,
                    action_type: "deploy".into(),
                    success: false,
                    contract_address: None,
                    gas_used,
                    message: format!("storage.set_state(vm_version:{}) failed: {}", addr, e),
                };
            }

            let verify_result = ContractVerifier::verify(storage, &addr, &pkg);
            if verify_result.verified {
                if let Err(e) = ContractVerifier::save_verification(storage, &verify_result, &pkg) {
                    return ScriptStepResult {
                        action_index: idx,
                        action_type: "deploy".into(),
                        success: false,
                        contract_address: None,
                        gas_used,
                        message: format!("save_verification({}) failed: {}", addr, e),
                    };
                }
                persisted_verified = true;
            }
        }

        // All persistence paths succeeded (or no storage attached);
        // THEN record the deployment in the in-memory map and the
        // manifest. The manifest's `verified` flag now reflects the
        // ACTUAL persistence outcome rather than a pre-commit
        // optimistic `true`.
        self.deployed.insert(name.to_string(), addr.clone());
        self.block_height += 1;

        // `verified` is only true if we actually attached storage AND
        // `save_verification` succeeded. A runner without storage
        // still reports the deployment but with `verified: false`,
        // which is accurate: no one ever called ContractVerifier.
        //
        // `add_deployment` now validates that the address prefix
        // matches the manifest's network. This should always succeed
        // because `contract_addr_prefix()` derives `addr` from the
        // SAME network string, but we propagate the error just in
        // case a future refactor breaks that invariant.
        if let Err(e) = self.manifest.add_deployment(DeployedContract {
            name: name.to_string(),
            address: addr.clone(),
            bytecode_hash,
            deploy_height: self.block_height,
            deploy_tx: format!("script_deploy_{}", idx),
            vm_version: 1,
            verified: persisted_verified,
            deployed_at: self.env.block_ctx.timestamp,
            package_file: None,
        }) {
            // Roll back the in-memory `deployed` entry so the runner
            // state stays consistent with the manifest.
            self.deployed.remove(name);
            return ScriptStepResult {
                action_index: idx,
                action_type: "deploy".into(),
                success: false,
                contract_address: None,
                gas_used,
                message: format!("manifest.add_deployment({}) failed: {}", name, e),
            };
        }

        ScriptStepResult {
            action_index: idx,
            action_type: "deploy".into(),
            success: true,
            contract_address: Some(addr.clone()),
            gas_used,
            message: format!("deployed {} at {}", name, addr),
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
        let mut runner = ScriptRunner::new("local", "SR1deployer").expect("local is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");

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

        assert!(results.iter().all(|r| r.success),
            "All steps should succeed, got {:#?}", results);
        assert!(runner.get_address("Counter").is_some());
        assert!(runner.manifest().is_deployed("Counter"));
    }

    #[test]
    fn script_idempotent_deploy_with_same_bytecode() {
        // Same name + same bytecode → success + same address.
        let mut runner = ScriptRunner::new("local", "SR1deployer").expect("local is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");
        let abi = ContractAbi::new("Token");
        let bytecode = vec![0x00]; // STOP

        runner.execute(&[
            ScriptAction::Deploy { name: "Token".into(), bytecode: bytecode.clone(), value: 0, gas_limit: 1_000_000, abi: abi.clone() },
        ]);
        let addr1 = runner.get_address("Token").unwrap().to_string();

        // Deploy again with the SAME bytecode -- should be idempotent
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "Token".into(), bytecode, value: 0, gas_limit: 1_000_000, abi },
        ]);
        let addr2 = runner.get_address("Token").unwrap().to_string();
        assert_eq!(addr1, addr2, "Idempotent deploy should return same address");
        assert!(results.last().unwrap().success);
        assert!(results.last().unwrap().message.contains("same bytecode"));
    }

    #[test]
    fn script_redeploy_with_different_bytecode_refused() {
        // Regression for the name-only idempotency bug. The old
        // implementation returned "already deployed" as a SUCCESS
        // when the same name was re-deployed with a DIFFERENT
        // bytecode — silently shadowing the new contract with the
        // old one. The new code refuses the re-deploy and surfaces
        // both hashes in the error message.
        let mut runner = ScriptRunner::new("local", "SR1deployer").expect("local is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");
        let abi = ContractAbi::new("Token");

        // First deploy with bytecode A.
        runner.execute(&[
            ScriptAction::Deploy {
                name: "Token".into(),
                bytecode: vec![0x00], // STOP
                value: 0,
                gas_limit: 1_000_000,
                abi: abi.clone(),
            },
        ]);
        assert!(runner.results().last().unwrap().success);

        // Second deploy with bytecode B, SAME name.
        let results = runner.execute(&[
            ScriptAction::Deploy {
                name: "Token".into(),
                bytecode: vec![0x10, 1, 0x00], // PUSH1 1, STOP — different
                value: 0,
                gas_limit: 1_000_000,
                abi,
            },
        ]);
        let last = results.last().unwrap();
        assert!(!last.success, "re-deploy with different bytecode must fail");
        assert!(last.message.contains("DIFFERENT bytecode"),
            "error must explain the content mismatch, got: {}", last.message);
        assert!(last.message.contains("prior hash"));
        assert!(last.message.contains("new hash"));
    }

    #[test]
    fn script_stops_on_failure() {
        let mut runner = ScriptRunner::new("local", "SR1deployer").expect("local is valid");
        // Don't fund -- deploy will fail due to v1 validation if bad bytecode
        // Actually: deploy with 0xEE (non-v1 opcode) -- v1 validation catches it
        let abi = ContractAbi::new("Bad");
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "Bad".into(), bytecode: vec![0xEE], value: 0, gas_limit: 1_000_000, abi },
            ScriptAction::Log { message: "should not reach here".into() },
        ]);
        assert!(!results[0].success);
        assert_eq!(results.len(), 1, "Script should stop after first failure");
    }

    #[test]
    fn script_manifest_populated_on_testnet() {
        // Regression for the hardcoded "SD1c" bug. A testnet manifest
        // used to produce SD1c_script_… addresses because
        // execute_deploy hardcoded the prefix. It must now produce
        // ST1c_script_… so the manifest network and the contract
        // address prefix agree.
        let mut runner = ScriptRunner::new("testnet", "ST1deployer").expect("testnet is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");
        let abi = ContractAbi::new("MyToken");
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "MyToken".into(), bytecode: vec![0x00], value: 0, gas_limit: 1_000_000, abi },
        ]);
        assert!(results.iter().all(|r| r.success),
            "deploy must succeed on testnet, got {:#?}", results);

        let manifest = runner.manifest();
        assert_eq!(manifest.network, "testnet");
        assert!(manifest.is_deployed("MyToken"));
        let contract = manifest.contracts.get("MyToken").unwrap();
        assert_eq!(contract.vm_version, 1);
        // Without storage attached, `verified` is now false — the
        // runner did not persist anything through ContractVerifier,
        // so claiming "verified" would be a lie. The old code
        // optimistically set this to true.
        assert!(!contract.verified,
            "runner without storage must not report verified=true");
        // Address prefix MUST match the manifest network.
        assert!(contract.address.starts_with("ST1c_script_"),
            "testnet manifest must produce ST1c-prefixed addresses, got: {}",
            contract.address);
        assert!(!contract.address.starts_with("SD1"),
            "testnet manifest must NOT leak SD1 (mainnet) tag, got: {}",
            contract.address);
    }

    #[test]
    fn script_mainnet_manifest_produces_sd1c_addresses() {
        let mut runner = ScriptRunner::new("mainnet", "SD1deployer").expect("mainnet is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");
        let abi = ContractAbi::new("Any");
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "Any".into(), bytecode: vec![0x00], value: 0, gas_limit: 1_000_000, abi },
        ]);
        assert!(results.iter().all(|r| r.success));
        let addr = runner.get_address("Any").unwrap();
        assert!(addr.starts_with("SD1c_script_"), "mainnet prefix, got: {}", addr);
    }

    #[test]
    fn script_regtest_manifest_produces_sr1c_addresses() {
        let mut runner = ScriptRunner::new("regtest", "SR1deployer").expect("regtest is valid");
        runner.fund_deployer(1_000_000_000).expect("fund_deployer must succeed");
        let abi = ContractAbi::new("Any");
        let results = runner.execute(&[
            ScriptAction::Deploy { name: "Any".into(), bytecode: vec![0x00], value: 0, gas_limit: 1_000_000, abi },
        ]);
        assert!(results.iter().all(|r| r.success));
        let addr = runner.get_address("Any").unwrap();
        assert!(addr.starts_with("SR1c_script_"), "regtest prefix, got: {}", addr);
    }
}
