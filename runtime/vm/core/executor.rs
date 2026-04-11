// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Executor — Manages contract deployment, execution, and state transitions.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::domain::address::address::prefix_from_address;
use crate::errors::VmError;
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::core::execution_env::{
    ExecutionEnvironment, BlockContext, CallContext, CallOutcome,
};
use crate::slog_error;
/// Default gas limit per contract execution
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

/// Maximum contract bytecode size
pub const MAX_CONTRACT_SIZE: usize = 24 * 1024; // 24 KB

pub struct Executor {
    context: VMContext,
}

impl Executor {
    pub fn new(context: VMContext) -> Self {
        Self { context }
    }

    /// Deploy a new contract. Returns the contract address.
    ///
    /// Two-phase EVM-style deployment, matching the inline `CREATE` /
    /// `CREATE2` opcode path in
    /// `execution_env::execute_frame`. The previous implementation of
    /// this function stored the passed `bytecode` as the contract's
    /// permanent code and ran it once, then kept whatever was there
    /// as the runtime code — so the contract's runtime code was
    /// always the INIT code, never the runtime code produced by the
    /// constructor. This inconsistency between the inline CREATE
    /// (which correctly replaces with RETURN data) and the top-level
    /// deploy (which didn't) is the critical bug this commit closes.
    ///
    /// Flow:
    ///   1. Install `bytecode` as the address's temporary code so
    ///      `execute_frame` has something to run.
    ///   2. Run the constructor via `execute_frame(ctx)` and capture
    ///      its `return_data` on success.
    ///   3. If `return_data` is non-empty, use it as the **runtime
    ///      code** and `set_code(contract_addr, return_data)`. Validate
    ///      via `ContractDeployer::validate_runtime_code` to catch
    ///      EIP-3541 (reject `0xEF` prefix) and size overflows.
    ///   4. If `return_data` is empty, the constructor had no
    ///      distinct runtime payload — keep `bytecode` as the runtime
    ///      code (this is the "upload raw runtime code" convenience
    ///      pattern used by simple tests and contracts that don't
    ///      want the init/runtime split).
    ///
    /// Both branches match `execution_env.rs`'s CREATE/CREATE2
    /// opcode handlers, which do the same `if !runtime_code.is_empty()
    /// { set_code(...) }` replacement after `execute_frame`. With this
    /// commit, the top-level deploy path and the inline CREATE path
    /// are semantically identical.
    #[allow(clippy::too_many_arguments)]
    pub fn deploy(
        &self,
        bytecode:  &[u8],
        deployer:  &str,
        value:     u64,
        gas_limit: u64,
        timestamp: u64,
        block_hash: &str,
        nonce:     u64,
    ) -> Result<(String, ExecutionResult), VmError> {
        if bytecode.is_empty() {
            return Err(VmError::ContractError("Empty bytecode".to_string()));
        }
        if bytecode.len() > MAX_CONTRACT_SIZE {
            return Err(VmError::CodeTooLarge { size: bytecode.len(), limit: MAX_CONTRACT_SIZE });
        }

        // Reject bytecode containing unimplemented opcodes
        Self::validate_supported_opcodes(bytecode)?;

        // VM version check: only v1 is currently supported
        let vm_version = crate::runtime::vm::core::v1_spec::VERSION;

        // Generate deterministic contract address using deployer + bytecode
        // + nonce. Propagates unknown-deployer-prefix errors to the caller
        // rather than silently minting a mainnet-tagged address.
        let contract_addr = Self::compute_contract_address(deployer, bytecode, nonce)?;

        // Create ExecutionEnvironment for reentrant execution
        let mut env = ExecutionEnvironment::new(BlockContext {
            timestamp,
            block_hash: block_hash.to_string(),
        });

        // Load deployer account from persistent storage. Propagate any
        // corruption as a structured error instead of silently loading
        // a zero-balance account.
        env.load_contract_from_storage(self.context.storage(), deployer)?;

        // Phase 1: Install the INIT code as the new contract's code so
        // execute_frame has something to run. This is the "init" code
        // that will either (a) simply execute side effects and RETURN
        // nothing, in which case the init code IS the runtime code, or
        // (b) compute and RETURN the runtime code, in which case we
        // replace the code in Phase 3 below.
        env.state.set_code(&contract_addr, bytecode.to_vec())?;

        // Build call context for constructor execution
        let ctx = CallContext {
            address: contract_addr.clone(),
            code_address: contract_addr.clone(),
            caller: deployer.to_string(),
            value,
            gas_limit,
            calldata: vec![], // deploy has no input data
            is_static: false,
            depth: 0,
        };

        // Phase 2: Run the constructor.
        let outcome = env.execute_frame(&ctx);

        // Phase 3: On success, replace the init code with the returned
        // runtime code (if any) and persist.
        let result = match outcome {
            CallOutcome::Success { gas_used, return_data, logs } => {
                // If the constructor RETURNed a non-empty payload, that
                // payload IS the runtime code. Validate and install it.
                // Otherwise keep the init code as the runtime code —
                // this preserves the simple "upload raw runtime code"
                // pattern for tests and contracts that don't want the
                // init/runtime split.
                if !return_data.is_empty() {
                    // EIP-3541 + size sanity check on the returned runtime code.
                    crate::runtime::vm::contracts::contract_deployer::ContractDeployer::validate_runtime_code(&return_data)?;
                    env.state.set_code(&contract_addr, return_data.clone())?;
                }

                // Persist all state changes (accounts, storage, code) to RocksDB.
                // `persist_to_storage` commits a WriteBatch atomically; see
                // execution_env.rs::persist_to_storage for the full contract.
                //
                // NOTE: This helper is NOT the consensus block-application
                // path (that path lives in `full_node::execute_contract_transactions`
                // + `persist_with_undo`). `Executor::deploy` is a one-shot
                // API used by tests and the RPC `cmd_deploy_contract` endpoint.
                // See the doc comment on the struct / module for the full
                // distinction and the rollback implications.
                env.persist_to_storage(self.context.storage())?;

                // Store VM version in contract metadata
                let vm_key = format!("vm_version:{}", contract_addr);
                self.context.set(&vm_key, &vm_version.to_string())?;

                ExecutionResult::Success { gas_used, return_data, logs }
            }
            CallOutcome::Revert { gas_used, return_data } => {
                ExecutionResult::Revert {
                    gas_used,
                    reason: String::from_utf8_lossy(&return_data).to_string(),
                }
            }
            CallOutcome::Failure { gas_used } => {
                ExecutionResult::OutOfGas { gas_used }
            }
        };

        Ok((contract_addr, result))
    }

    /// Execute a contract call.
    ///
    /// Creates an ExecutionEnvironment, loads contract + caller state,
    /// runs via execute_frame, and persists state on success.
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        contract_addr: &str,
        input_data: &[u8],
        caller:     &str,
        value:      u64,
        gas_limit:  u64,
        timestamp:  u64,
        block_hash: &str,
    ) -> ExecutionResult {
        // Load contract bytecode from storage
        let code_key = format!("code:{}", contract_addr);
        let bytecode_hex = match self.context.get(&code_key) {
            Some(hex) => hex,
            None => return ExecutionResult::Error {
                gas_used: 0,
                message: format!("Contract {} not found", contract_addr),
            },
        };

        let bytecode = match hex::decode(&bytecode_hex) {
            Ok(b) => b,
            Err(e) => {
                // Log the corruption explicitly so operators can tell
                // "contract not found" apart from "stored bytecode is
                // not valid hex". The latter is data corruption and
                // should never happen in normal operation.
                slog_error!("vm", "contract_bytecode_corrupt_hex",
                    contract => contract_addr, error => &e.to_string());
                return ExecutionResult::Error {
                    gas_used: 0,
                    message: format!(
                        "contract '{}' has corrupt bytecode in storage: {}",
                        contract_addr, e
                    ),
                };
            }
        };

        // Create ExecutionEnvironment for reentrant execution
        let mut env = ExecutionEnvironment::new(BlockContext {
            timestamp,
            block_hash: block_hash.to_string(),
        });

        // Load contract and caller accounts from persistent storage. A
        // corruption in either path is surfaced as a structured error —
        // the VM must refuse to execute against zero-reset state.
        if let Err(e) = env.load_contract_from_storage(self.context.storage(), contract_addr) {
            return ExecutionResult::Error {
                gas_used: 0,
                message: format!(
                    "failed to load contract '{}' state: {}",
                    contract_addr, e
                ),
            };
        }
        if let Err(e) = env.load_contract_from_storage(self.context.storage(), caller) {
            return ExecutionResult::Error {
                gas_used: 0,
                message: format!(
                    "failed to load caller '{}' state: {}",
                    caller, e
                ),
            };
        }

        // Ensure contract code is loaded into the in-memory state.
        //
        // Previously this was `env.state.set_code(...).ok();` which
        // silently discarded any error from set_code and then continued
        // into execute_frame, producing bogus "contract exists but has
        // no code" behaviour. set_code failing during a contract CALL
        // is unambiguous: abort this frame with a structured error so
        // the caller sees the problem instead of a confusing revert.
        if env.state.get_code(contract_addr).is_empty() {
            if let Err(e) = env.state.set_code(contract_addr, bytecode) {
                return ExecutionResult::Error {
                    gas_used: 0,
                    message: format!(
                        "failed to load contract code for '{}': {}",
                        contract_addr, e
                    ),
                };
            }
        }

        // Build call context
        let ctx = CallContext {
            address: contract_addr.to_string(),
            code_address: contract_addr.to_string(),
            caller: caller.to_string(),
            value,
            gas_limit,
            calldata: input_data.to_vec(),
            is_static: false,
            depth: 0,
        };

        let outcome = env.execute_frame(&ctx);

        // Convert CallOutcome to ExecutionResult and persist on success
        match outcome {
            CallOutcome::Success { gas_used, return_data, logs } => {
                // Persist all state changes to RocksDB
                if let Err(e) = env.persist_to_storage(self.context.storage()) {
                    return ExecutionResult::Error {
                        gas_used,
                        message: format!("State persistence failed: {}", e),
                    };
                }
                ExecutionResult::Success { gas_used, return_data, logs }
            }
            CallOutcome::Revert { gas_used, return_data } => {
                ExecutionResult::Revert {
                    gas_used,
                    reason: String::from_utf8_lossy(&return_data).to_string(),
                }
            }
            CallOutcome::Failure { gas_used } => {
                ExecutionResult::OutOfGas { gas_used }
            }
        }
    }

    /// Simple KV execute (legacy)
    pub fn execute(&self, key: &str, value: &str) -> Result<(), crate::errors::StorageError> {
        self.context.set(key, value)
    }

    /// Check if a contract exists
    pub fn contract_exists(&self, addr: &str) -> bool {
        let code_key = format!("code:{}", addr);
        self.context.get(&code_key).is_some()
    }

    /// Get contract bytecode.
    ///
    /// Returns `None` when the contract is genuinely absent AND when the
    /// stored bytecode hex is corrupt. The corruption case is logged via
    /// `slog_error!` with a `may_be_false_negative` marker so operators
    /// can tell a real miss apart from a masked data-integrity failure.
    /// Callers that must distinguish these three states explicitly
    /// should use [`Self::get_code_strict`].
    pub fn get_code(&self, addr: &str) -> Option<Vec<u8>> {
        let code_key = format!("code:{}", addr);
        let hex_str = self.context.get(&code_key)?;
        match hex::decode(&hex_str) {
            Ok(b) => Some(b),
            Err(e) => {
                slog_error!("vm", "get_code_corrupt_hex_may_be_false_negative",
                    contract => addr, error => &e.to_string(),
                    note => "returning None but code entry exists with invalid hex payload");
                None
            }
        }
    }

    /// Strict variant of [`Self::get_code`].
    ///
    /// Distinguishes the three possible states:
    ///   - `Ok(None)` → contract does not exist
    ///   - `Ok(Some(bytecode))` → contract exists with valid hex bytecode
    ///   - `Err(VmError::ContractError)` → stored bytecode is not valid hex
    ///
    /// Use this from audit, crash-recovery, or chain-reorg code where
    /// corruption must not be silently treated as absence.
    pub fn get_code_strict(&self, addr: &str) -> Result<Option<Vec<u8>>, VmError> {
        let code_key = format!("code:{}", addr);
        let hex_str = match self.context.get(&code_key) {
            Some(s) => s,
            None => return Ok(None),
        };
        hex::decode(&hex_str).map(Some).map_err(|e| {
            slog_error!("vm", "get_code_corrupt_hex_strict",
                contract => addr, error => &e.to_string());
            VmError::ContractError(format!(
                "contract '{}' has corrupt bytecode in storage: {}",
                addr, e
            ))
        })
    }

    /// Validate that bytecode contains only v1-spec opcodes.
    ///
    /// Delegates to `v1_spec::validate_v1_bytecode()` which is the single
    /// source of truth for the v1 opcode set. The scan is PUSH-aware:
    /// inline data bytes following PUSHn instructions are skipped so that
    /// embedded constants are not mistaken for opcodes.
    fn validate_supported_opcodes(bytecode: &[u8]) -> Result<(), VmError> {
        if let Err((_pos, byte)) = crate::runtime::vm::core::v1_spec::validate_v1_bytecode(bytecode) {
            return Err(VmError::InvalidOpcode(byte));
        }
        Ok(())
    }

    /// Compute a deterministic contract address from
    /// `(deployer, bytecode, nonce)`.
    ///
    /// The resulting contract address **inherits the network prefix of
    /// its deployer**, so a testnet deployer produces a testnet contract
    /// and a regtest deployer produces a regtest contract. The previous
    /// implementation hard-coded `"SD1c"` regardless of deployer, which
    /// silently tagged all non-mainnet deployments as mainnet — a data
    /// integrity bug in any cross-network test harness or wallet client.
    ///
    /// Returns `Err(VmError::ContractError)` if `deployer` does not start
    /// with a known ShadowDAG prefix (`SD1` / `ST1` / `SR1`), so that
    /// `deploy()` surfaces a structured error instead of minting an
    /// addressless contract or silently falling back to mainnet.
    fn compute_contract_address(
        deployer: &str,
        bytecode: &[u8],
        nonce: u64,
    ) -> Result<String, VmError> {
        let net_prefix = prefix_from_address(deployer).ok_or_else(|| {
            VmError::ContractError(format!(
                "contract deployer '{}' has unknown network prefix \
                 (expected SD1/ST1/SR1)",
                deployer
            ))
        })?;

        let mut h = Sha256::new();
        h.update(b"ShadowDAG_Contract_v2");
        h.update(deployer.as_bytes());
        h.update(bytecode);
        h.update(nonce.to_le_bytes());
        let hash = h.finalize();
        Ok(format!("{}c{}", net_prefix, hex::encode(&hash[..20])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::vm::contracts::contract_storage::ContractStorage;

    fn make_executor() -> Executor {
        // Use unique path per test to avoid RocksDB lock conflicts.
        // open_shared_db caches by path, so each test needs a truly unique one.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("shadowdag_exec_{}_{}",ts, id));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = ContractStorage::new(dir.to_str().unwrap())
            .expect("ContractStorage::new failed");
        let ctx = VMContext::new(storage);
        Executor::new(ctx)
    }

    #[test]
    fn deploy_and_check_exists() {
        let exec = make_executor();
        // Simple contract: PUSH1 42, STOP
        let bytecode = vec![0x10, 42, 0x00];
        let (addr, result) = exec.deploy(&bytecode, "SD1deployer", 0, 100000, 1000, "bh", 0).unwrap();

        assert!(addr.starts_with("SD1c"));
        assert!(exec.contract_exists(&addr));
        match result {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn deploy_empty_fails() {
        let exec = make_executor();
        assert!(exec.deploy(&[], "SD1x", 0, 100000, 1000, "bh", 0).is_err());
    }

    #[test]
    fn call_nonexistent_fails() {
        let exec = make_executor();
        match exec.call("SD1cNONEXISTENT", &[], "SD1caller", 0, 100000, 1000, "bh") {
            ExecutionResult::Error { message, .. } => {
                assert!(message.contains("not found"));
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn get_code_returns_bytecode() {
        let exec = make_executor();
        let bytecode = vec![0x10, 1, 0x10, 2, 0x20, 0x00];
        let (addr, _) = exec.deploy(&bytecode, "SD1dep", 0, 100000, 2000, "bh", 0).unwrap();
        let code = exec.get_code(&addr).unwrap();
        assert_eq!(code, bytecode);
    }

    #[test]
    fn deploy_mainnet_deployer_yields_mainnet_contract_address() {
        let exec = make_executor();
        let bytecode = vec![0x10, 42, 0x00];
        let (addr, _) = exec.deploy(&bytecode, "SD1mainnetdeployer", 0, 100000, 3000, "bh", 0).unwrap();
        assert!(addr.starts_with("SD1c"), "mainnet deployer must produce SD1c address, got: {}", addr);
    }

    #[test]
    fn deploy_testnet_deployer_yields_testnet_contract_address() {
        // Previously compute_contract_address hard-coded "SD1c", so a
        // testnet deployer would be given a mainnet-looking contract
        // address. The fix makes the contract address inherit the
        // deployer's network.
        let exec = make_executor();
        let bytecode = vec![0x10, 42, 0x00];
        let (addr, _) = exec.deploy(&bytecode, "ST1testnetdeployer", 0, 100000, 3000, "bh", 0).unwrap();
        assert!(addr.starts_with("ST1c"), "testnet deployer must produce ST1c address, got: {}", addr);
        assert!(!addr.starts_with("SD1"), "testnet contract must not be tagged mainnet: {}", addr);
    }

    #[test]
    fn deploy_with_constructor_return_replaces_init_code_with_runtime_code() {
        // Regression for the "deploy stores init code" bug. The
        // previous Executor::deploy stored the passed bytecode as
        // the permanent contract code and ran it once, then kept
        // the init code as the runtime code — so a constructor
        // that RETURNed a distinct runtime payload was silently
        // ignored, and every subsequent CALL ran the init code
        // again instead of the runtime code.
        //
        // This test uses an init code that:
        //   PUSH2 0xCAFE  (0x11 CA FE)
        //   PUSH1 0       (0x10 00)
        //   MSTORE        (0x91)      → memory[0..32] = 0x00..00CAFE
        //   PUSH1 2       (0x10 02)   → length = 2
        //   PUSH1 30      (0x10 1E)   → offset = 30 (low 2 bytes of the word)
        //   RETURN        (0xB6)      → return_data = [0xCA, 0xFE]
        //
        // After the fix, the contract's stored runtime code must be
        // exactly [0xCA, 0xFE], NOT the original init code.
        let exec = make_executor();
        let init_code: Vec<u8> = vec![
            0x11, 0xCA, 0xFE, // PUSH2 0xCAFE
            0x10, 0x00,       // PUSH1 0
            0x91,             // MSTORE
            0x10, 0x02,       // PUSH1 2 (length)
            0x10, 0x1E,       // PUSH1 30 (offset)
            0xB6,             // RETURN
        ];
        let (addr, result) = exec
            .deploy(&init_code, "SD1ctordeployer", 0, 100000, 5000, "bh", 0)
            .expect("deploy with constructor return must succeed");

        match &result {
            ExecutionResult::Success { return_data, .. } => {
                assert_eq!(
                    return_data, &vec![0xCA, 0xFE],
                    "constructor return_data must be [0xCA, 0xFE]"
                );
            }
            other => panic!("expected Success, got: {:?}", other),
        }

        // The critical assertion: the stored runtime code is the
        // RETURNed bytes, not the init code. Previously this would
        // have returned the full init_code vec.
        let stored_code = exec
            .get_code(&addr)
            .expect("contract code must be retrievable after deploy");
        assert_eq!(
            stored_code, vec![0xCA, 0xFE],
            "runtime code must be the constructor's RETURN data, not the init code; \
             got {} bytes (init_code was {} bytes)",
            stored_code.len(), init_code.len()
        );
    }

    #[test]
    fn deploy_without_constructor_return_keeps_init_code_as_runtime() {
        // Backward-compat: a simple contract that has no distinct
        // runtime payload (RETURN is empty, or the bytecode is just
        // raw runtime code like PUSH1 42 STOP) must keep its uploaded
        // bytecode as the runtime code. This preserves every existing
        // test and contract that uses the "upload raw runtime" pattern.
        let exec = make_executor();
        let bytecode = vec![0x10, 42, 0x00]; // PUSH1 42, STOP — no RETURN
        let (addr, result) = exec
            .deploy(&bytecode, "SD1simpledeployer", 0, 100000, 5000, "bh", 0)
            .expect("deploy of raw runtime code must succeed");
        match &result {
            ExecutionResult::Success { return_data, .. } => {
                assert!(return_data.is_empty(),
                    "STOP path produces no return_data, got: {:?}", return_data);
            }
            other => panic!("expected Success, got: {:?}", other),
        }
        let stored_code = exec.get_code(&addr).unwrap();
        assert_eq!(stored_code, bytecode,
            "empty-return deploy must keep init code as runtime code");
    }

    #[test]
    fn deploy_regtest_deployer_yields_regtest_contract_address() {
        let exec = make_executor();
        let bytecode = vec![0x10, 42, 0x00];
        let (addr, _) = exec.deploy(&bytecode, "SR1regtestdeployer", 0, 100000, 3000, "bh", 0).unwrap();
        assert!(addr.starts_with("SR1c"), "regtest deployer must produce SR1c address, got: {}", addr);
        assert!(!addr.starts_with("SD1"), "regtest contract must not be tagged mainnet: {}", addr);
    }

    #[test]
    fn deploy_rejects_unknown_deployer_prefix() {
        // An unknown address prefix must not silently default to mainnet
        // — it must surface a structured error from deploy().
        let exec = make_executor();
        let bytecode = vec![0x10, 42, 0x00];
        let err = exec.deploy(&bytecode, "BTC1notours", 0, 100000, 3000, "bh", 0);
        assert!(err.is_err(), "deploy must reject unknown deployer prefix");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("unknown network prefix") || msg.contains("SD1"),
            "error should mention the prefix constraint, got: {}",
            msg
        );
    }

    #[test]
    fn get_code_strict_returns_ok_none_for_missing_contract() {
        let exec = make_executor();
        assert!(matches!(exec.get_code_strict("SD1cNOT_DEPLOYED"), Ok(None)));
    }

    #[test]
    fn get_code_strict_surfaces_corrupt_hex_as_err() {
        let exec = make_executor();
        // Plant a "code:{addr}" entry with non-hex data directly via the
        // context. execute() is the simple-KV backdoor for this store.
        let addr = "SD1cCORRUPT_TEST";
        exec.execute(&format!("code:{}", addr), "not-valid-hex").unwrap();

        // Non-strict masks the corruption as None (but logs it)
        assert!(exec.get_code(addr).is_none());
        // Strict surfaces it as an explicit error
        let strict = exec.get_code_strict(addr);
        assert!(strict.is_err(), "strict get_code must expose corruption, got: {:?}", strict);
    }
}
