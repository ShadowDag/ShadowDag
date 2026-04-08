// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::VmError;
use crate::runtime::vm::core::executor::{Executor, DEFAULT_GAS_LIMIT};
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;

pub struct Contract;

impl Contract {
    /// Execute a contract call against a deployed contract.
    ///
    /// This performs actual bytecode execution via the VM, not just a storage
    /// write. The contract must have been previously deployed via `Executor::deploy`.
    ///
    /// # Arguments
    /// * `contract_addr` - Address of the deployed contract (e.g. "SD1c...")
    /// * `input_data`    - ABI-encoded call data
    /// * `caller`        - Address of the caller
    pub fn call(
        contract_addr: &str,
        input_data: &[u8],
        caller: &str,
    ) -> Result<ExecutionResult, VmError> {
        let contracts_path = crate::config::node::node_config::NetworkMode::base_data_dir().join("contracts");
        let path_str = contracts_path.to_string_lossy().to_string();
        let storage = ContractStorage::new(&path_str)?;
        let ctx     = VMContext::new(storage);

        let executor = Executor::new(ctx);
        let result = executor.call(
            contract_addr,
            input_data,
            caller,
            0,                 // value
            DEFAULT_GAS_LIMIT, // gas_limit
            0,                 // timestamp (filled by block context in production)
            "",                // block_hash
        );
        Ok(result)
    }

    /// Store a raw key-value pair in contract storage (non-execution helper).
    ///
    /// This is a storage-level operation only -- it does NOT execute any
    /// bytecode. Use `call()` to execute contract logic.
    pub fn store_value(key: &str, value: &str) -> Result<(), VmError> {
        let contracts_path = crate::config::node::node_config::NetworkMode::base_data_dir().join("contracts");
        let path_str = contracts_path.to_string_lossy().to_string();
        let storage = ContractStorage::new(&path_str)?;
        let ctx     = VMContext::new(storage);

        let executor = Executor::new(ctx);
        executor.execute(key, value)?;
        Ok(())
    }
}
