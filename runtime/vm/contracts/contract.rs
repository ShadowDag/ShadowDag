// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::VmError;
use crate::runtime::vm::core::executor::Executor;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;

pub struct Contract;

impl Contract {
    pub fn call(code: &str) -> Result<(), VmError> {
        let contracts_path = crate::config::node::node_config::NetworkMode::base_data_dir().join("contracts");
        let path_str = contracts_path.to_string_lossy().to_string();
        let storage = ContractStorage::new(&path_str)?;
        let ctx     = VMContext::new(storage);

        let executor = Executor::new(ctx);
        executor.execute("code", code);
        Ok(())
    }
}
