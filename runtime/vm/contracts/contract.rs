// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract helpers — thin wrappers around `Executor` for external callers
// that need to invoke or inspect a deployed contract WITHOUT spinning up
// a full block-processing pipeline (RPC handlers, CLI tools, tests, …).
//
// These helpers are deliberately minimal and pay extra attention to two
// things that have historically been footguns here:
//
//   1. **Block context propagation.** The live execution path
//      (`full_node::execute_contract_transactions`) always constructs
//      an `ExecutionEnvironment` from the current `BlockContext`, so
//      the contract sees the real `timestamp` / `block_hash` for the
//      block it's executing in. The old `Contract::call()` helper
//      passed `timestamp = 0` and `block_hash = ""`, meaning a
//      contract that reads `TIMESTAMP` or `BLOCKHASH` through this
//      helper would observe a value that NEVER matches what it sees
//      during real block execution. That's a consensus-adjacent
//      footgun — anything tested via the helper might behave
//      differently when the same inputs are committed on-chain.
//
//      The new `call()` requires the caller to supply `timestamp`
//      and `block_hash` explicitly; there is no default. Tooling
//      that legitimately wants the current wall clock can call
//      `call_at_now()`, which documents that it is NOT a valid
//      stand-in for on-chain execution.
//
//   2. **Storage isolation.** `store_value()` previously exposed
//      `executor.execute(key, value)` as a raw key-value writer on
//      the contracts DB. That bypassed ABI, contract addresses,
//      and gas accounting entirely. The function is kept (for
//      parity with tests that previously used it) but renamed to
//      reflect what it actually does, and its doc comment now
//      flags it as a debugging / test fixture, not a contract-
//      interaction API.
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::VmError;
use crate::runtime::vm::core::executor::{Executor, DEFAULT_GAS_LIMIT};
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;

pub struct Contract;

impl Contract {
    /// Execute a contract call against a deployed contract, with the
    /// caller explicitly providing the block context.
    ///
    /// `timestamp` and `block_hash` MUST be the real values for the
    /// block the caller is simulating. If you just want the
    /// "current moment" for an ad-hoc tool or a unit test, use
    /// [`Self::call_at_now`] instead — that variant at least
    /// documents the non-consensus nature of the context it
    /// constructs.
    ///
    /// # Arguments
    /// * `contract_addr` — Address of the deployed contract (`SD1c…` / `ST1c…` / `SR1c…`)
    /// * `input_data`    — ABI-encoded call data
    /// * `caller`        — Address of the caller
    /// * `value`         — Value to transfer with the call (in base units)
    /// * `gas_limit`     — Gas budget for the call
    /// * `timestamp`     — Block timestamp the call should observe via TIMESTAMP
    /// * `block_hash`    — Block hash the call should observe via BLOCKHASH
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        contract_addr: &str,
        input_data: &[u8],
        caller: &str,
        value: u64,
        gas_limit: u64,
        timestamp: u64,
        block_hash: &str,
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
            value,
            gas_limit,
            timestamp,
            block_hash,
        );
        Ok(result)
    }

    /// Convenience wrapper around [`Self::call`] that uses
    /// `DEFAULT_GAS_LIMIT`, zero value, the current wall-clock
    /// timestamp, and an empty block hash.
    ///
    /// **This is not equivalent to on-chain execution.** Contracts
    /// that read `TIMESTAMP` or `BLOCKHASH` will see values that
    /// differ from any real block. Use it only from ad-hoc tooling
    /// (CLI shells, read-only explorer queries, fuzzer harnesses)
    /// where that drift is acceptable; never from code that is
    /// supposed to match the validator's result.
    pub fn call_at_now(
        contract_addr: &str,
        input_data: &[u8],
        caller: &str,
    ) -> Result<ExecutionResult, VmError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::call(
            contract_addr,
            input_data,
            caller,
            0,
            DEFAULT_GAS_LIMIT,
            timestamp,
            "",
        )
    }

    /// Raw key-value write directly into the contracts DB.
    ///
    /// **TEST / DEBUG ONLY.** This bypasses:
    ///   - contract address prefixing (no `{addr}:slot:…` scoping)
    ///   - ABI encoding / decoding
    ///   - gas accounting
    ///   - the PendingBatch / commit-on-STOP pipeline that real
    ///     contract execution uses
    ///
    /// It exists for legacy tests and low-level fixtures that need
    /// to plant data on the contracts DB without going through a
    /// full deploy. Production code should NEVER call this — use
    /// [`Self::call`] to execute bytecode, or
    /// `ContractStorage::set_state` directly if the caller owns
    /// a `ContractStorage` handle and knows the exact on-disk key
    /// layout it wants to touch.
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
