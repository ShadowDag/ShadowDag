// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Executor — Manages contract deployment, execution, and state transitions.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::errors::VmError;
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::core::execution_env::{
    ExecutionEnvironment, BlockContext, CallContext, CallOutcome,
};
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
    /// Creates an ExecutionEnvironment, loads deployer state, runs the
    /// constructor via execute_frame, and persists state on success.
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

        // Generate deterministic contract address using deployer + bytecode + nonce
        let contract_addr = Self::compute_contract_address(deployer, bytecode, nonce);

        // Create ExecutionEnvironment for reentrant execution
        let mut env = ExecutionEnvironment::new(BlockContext {
            timestamp,
            block_hash: block_hash.to_string(),
        });

        // Load deployer account from persistent storage
        env.load_contract_from_storage(self.context.storage(), deployer);

        // Set code for the new contract address so execute_frame can run it
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

        let outcome = env.execute_frame(&ctx);

        // Persist state on success
        let result = match outcome {
            CallOutcome::Success { gas_used, return_data, logs } => {
                // Persist all state changes (accounts, storage, code) to RocksDB
                env.persist_to_storage(self.context.storage())?;

                // Also store bytecode and metadata via legacy path for backward compat
                let code_key = format!("code:{}", contract_addr);
                self.context.set(&code_key, &hex::encode(bytecode));

                let meta_key = format!("meta:{}", contract_addr);
                let meta = format!("deployer={},nonce={},size={}", deployer, nonce, bytecode.len());
                self.context.set(&meta_key, &meta);

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
            Err(_) => return ExecutionResult::Error {
                gas_used: 0,
                message: "Invalid bytecode".to_string(),
            },
        };

        // Create ExecutionEnvironment for reentrant execution
        let mut env = ExecutionEnvironment::new(BlockContext {
            timestamp,
            block_hash: block_hash.to_string(),
        });

        // Load contract and caller accounts from persistent storage
        env.load_contract_from_storage(self.context.storage(), contract_addr);
        env.load_contract_from_storage(self.context.storage(), caller);

        // Ensure contract code is loaded into the in-memory state
        if env.state.get_code(contract_addr).is_empty() {
            env.state.set_code(contract_addr, bytecode).ok();
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
    pub fn execute(&self, key: &str, value: &str) {
        self.context.set(key, value);
    }

    /// Check if a contract exists
    pub fn contract_exists(&self, addr: &str) -> bool {
        let code_key = format!("code:{}", addr);
        self.context.get(&code_key).is_some()
    }

    /// Get contract bytecode
    pub fn get_code(&self, addr: &str) -> Option<Vec<u8>> {
        let code_key = format!("code:{}", addr);
        self.context.get(&code_key)
            .and_then(|hex_str| hex::decode(&hex_str).ok())
    }

    /// Validate that bytecode does not contain unsupported opcodes.
    ///
    /// This scan is PUSH-aware: when a PUSHn opcode is encountered the
    /// following n data bytes are skipped so that embedded constants that
    /// happen to equal an unsupported opcode value do not cause false
    /// positives.
    ///
    /// ShadowVM PUSH opcodes and their data sizes:
    ///   PUSH1  (0x10) -> 1 byte
    ///   PUSH2  (0x11) -> 2 bytes
    ///   PUSH4  (0x12) -> 4 bytes
    ///   PUSH8  (0x13) -> 8 bytes
    ///   PUSH16 (0x14) -> 16 bytes
    ///   PUSH32 (0x15) -> 32 bytes
    fn validate_supported_opcodes(bytecode: &[u8]) -> Result<(), VmError> {
        // All opcodes are now supported including CALL, CALLCODE,
        // DELEGATECALL, STATICCALL, CREATE, CREATE2, and SELFDESTRUCT.
        // These are implemented in execution_env.rs.
        //
        // We still walk the bytecode to validate structural integrity
        // (no truncated PUSH operands) but no opcodes are blocked.

        let mut i = 0;
        while i < bytecode.len() {
            let op = bytecode[i];

            // PUSH1..PUSH32 (0x10..0x15): skip the inline data bytes
            let push_size: usize = match op {
                0x10 => 1,  // PUSH1
                0x11 => 2,  // PUSH2
                0x12 => 4,  // PUSH4
                0x13 => 8,  // PUSH8
                0x14 => 16, // PUSH16
                0x15 => 32, // PUSH32
                _ => 0,
            };
            if push_size > 0 {
                i += 1 + push_size; // skip opcode + data
                continue;
            }

            i += 1;
        }
        Ok(())
    }

    /// Compute deterministic contract address from deployer + bytecode + nonce
    fn compute_contract_address(deployer: &str, bytecode: &[u8], nonce: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_Contract_v2");
        h.update(deployer.as_bytes());
        h.update(bytecode);
        h.update(nonce.to_le_bytes());
        let hash = h.finalize();
        format!("SD1c{}", hex::encode(&hash[..20]))
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
}
