// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Executor — Manages contract deployment, execution, and state transitions.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::errors::VmError;
use crate::runtime::vm::core::vm::{VM, ExecutionResult};
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;

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

        // Execute constructor FIRST (before storing anything)
        // Reuse the existing DB handle to avoid RocksDB lock conflicts
        let shared_db = self.context.storage().shared_db();
        let storage = ContractStorage::new(shared_db)?;
        let vm = VM::from_context(VMContext::new(storage));

        let result = vm.execute_bytecode(
            bytecode,
            gas_limit,
            deployer,
            value,
            timestamp,
            block_hash,
            &contract_addr,
            &[], // deploy has no input data
        );

        // Only store bytecode and metadata if constructor succeeded
        if matches!(&result, ExecutionResult::Success { .. }) {
            let code_key = format!("code:{}", contract_addr);
            self.context.set(&code_key, &hex::encode(bytecode));

            let meta_key = format!("meta:{}", contract_addr);
            let meta = format!("deployer={},nonce={},size={}", deployer, nonce, bytecode.len());
            self.context.set(&meta_key, &meta);
        }

        Ok((contract_addr, result))
    }

    /// Execute a contract call
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
        // Load contract bytecode
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

        // Reuse the existing DB handle to avoid RocksDB lock conflicts
        let shared_db = self.context.storage().shared_db();
        let storage = match ContractStorage::new(shared_db) {
            Ok(s) => s,
            Err(e) => return ExecutionResult::Error {
                gas_used: 0,
                message: format!("Failed to init contract storage: {}", e),
            },
        };
        let vm = VM::from_context(VMContext::new(storage));

        vm.execute_bytecode(
            &bytecode,
            gas_limit,
            caller,
            value,
            timestamp,
            block_hash,
            contract_addr,
            input_data,
        )
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
    /// This is a simple byte-level scan -- it may match data bytes that happen
    /// to equal an opcode value. For production, a proper disassembler would be
    /// needed. But this prevents obvious cases of deploying contracts that use
    /// unimplemented inter-contract calls or self-destruct.
    fn validate_supported_opcodes(bytecode: &[u8]) -> Result<(), VmError> {
        use crate::runtime::vm::core::opcodes::OpCode;
        let unsupported: &[(u8, &str)] = &[
            (OpCode::CALL as u8, "CALL"),
            (OpCode::CALLCODE as u8, "CALLCODE"),
            (OpCode::DELEGATECALL as u8, "DELEGATECALL"),
            (OpCode::STATICCALL as u8, "STATICCALL"),
            (OpCode::CREATE as u8, "CREATE"),
            (OpCode::CREATE2 as u8, "CREATE2"),
            (OpCode::SELFDESTRUCT as u8, "SELFDESTRUCT"),
        ];
        for &byte in bytecode {
            for &(op, name) in unsupported {
                if byte == op {
                    return Err(VmError::ContractError(format!(
                        "Bytecode contains unsupported opcode {} (0x{:02x})", name, op
                    )));
                }
            }
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
