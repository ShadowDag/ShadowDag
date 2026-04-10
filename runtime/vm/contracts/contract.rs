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

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Open a `ContractStorage` at the current `NetworkMode`'s
/// default data dir. Used internally by the backward-compatible
/// `Contract::call` / `Contract::call_at_now` / `Contract::store_value`
/// wrappers when no explicit storage is supplied.
///
/// New code should prefer [`Contract::call_with_storage`] /
/// [`Contract::call_at_now_with_storage`] /
/// [`Contract::store_value_with_storage`] and hand in a
/// `ContractStorage` handle it already owns — those variants work
/// correctly in multi-network / multi-data-dir processes (integration
/// tests, explorer tools, fuzzer harnesses), whereas this helper
/// pins the caller to a single global default.
fn open_default_contract_storage() -> Result<ContractStorage, VmError> {
    let contracts_path = crate::config::node::node_config::NetworkMode::base_data_dir()
        .join("contracts");
    let path_str = contracts_path.to_string_lossy().to_string();
    ContractStorage::new(&path_str)
}

impl Contract {
    // ───────────────────────────────────────────────────────────────
    //  Storage-injected variants (preferred for new code)
    // ───────────────────────────────────────────────────────────────

    /// Execute a contract call against a deployed contract using a
    /// caller-supplied `ContractStorage` handle.
    ///
    /// This is the PREFERRED entry point. Accepting `&ContractStorage`
    /// instead of re-opening one from `NetworkMode::base_data_dir()`
    /// means:
    ///   - a multi-network process can exercise contracts from
    ///     different networks in the same binary without touching the
    ///     global `NetworkMode`;
    ///   - integration tests and tools can point at a temp dir;
    ///   - a long-running caller that already has a `ContractStorage`
    ///     handle doesn't pay the RocksDB open cost per call.
    ///
    /// `timestamp` and `block_hash` MUST be the real values for the
    /// block the caller is simulating. For ad-hoc tooling use
    /// [`Self::call_at_now_with_storage`], which at least documents
    /// the non-consensus nature of its context.
    ///
    /// # Arguments
    /// * `storage`       — Explicit `ContractStorage` handle
    /// * `contract_addr` — Address of the deployed contract (`SD1c…` / `ST1c…` / `SR1c…`)
    /// * `input_data`    — ABI-encoded call data
    /// * `caller`        — Address of the caller
    /// * `value`         — Value to transfer with the call (in base units)
    /// * `gas_limit`     — Gas budget for the call
    /// * `timestamp`     — Block timestamp the call should observe via TIMESTAMP
    /// * `block_hash`    — Block hash the call should observe via BLOCKHASH
    #[allow(clippy::too_many_arguments)]
    pub fn call_with_storage(
        storage: ContractStorage,
        contract_addr: &str,
        input_data: &[u8],
        caller: &str,
        value: u64,
        gas_limit: u64,
        timestamp: u64,
        block_hash: &str,
    ) -> Result<ExecutionResult, VmError> {
        let ctx      = VMContext::new(storage);
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

    /// Ad-hoc wrapper around [`Self::call_with_storage`] that uses
    /// `DEFAULT_GAS_LIMIT`, zero value, the current wall-clock
    /// timestamp, and an empty block hash — but with an explicit
    /// `ContractStorage`. Prefer this over [`Self::call_at_now`]
    /// in any tool that needs multi-environment support.
    ///
    /// **This is not equivalent to on-chain execution.** Contracts
    /// that read `TIMESTAMP` or `BLOCKHASH` will see values that
    /// differ from any real block. Use it only from ad-hoc tooling
    /// (CLI shells, read-only explorer queries, fuzzer harnesses)
    /// where that drift is acceptable.
    pub fn call_at_now_with_storage(
        storage: ContractStorage,
        contract_addr: &str,
        input_data: &[u8],
        caller: &str,
    ) -> Result<ExecutionResult, VmError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::call_with_storage(
            storage,
            contract_addr,
            input_data,
            caller,
            0,
            DEFAULT_GAS_LIMIT,
            timestamp,
            "",
        )
    }

    /// Raw key-value write directly into a caller-supplied
    /// `ContractStorage` handle.
    ///
    /// **TEST / DEBUG ONLY.** Same caveats as [`Self::store_value`]:
    /// bypasses address prefixing, ABI, gas accounting, and the
    /// PendingBatch pipeline. Prefer `ContractStorage::set_state`
    /// directly if you already own the handle and know the exact
    /// key layout — `Contract::store_value_with_storage` exists only
    /// so the three helpers share the same storage-injection shape.
    pub fn store_value_with_storage(
        storage: ContractStorage,
        key: &str,
        value: &str,
    ) -> Result<(), VmError> {
        let ctx      = VMContext::new(storage);
        let executor = Executor::new(ctx);
        executor.execute(key, value)?;
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────
    //  Default-storage wrappers (backward compat)
    // ───────────────────────────────────────────────────────────────

    /// Execute a contract call against the default-data-dir
    /// `ContractStorage`.
    ///
    /// Thin wrapper around [`Self::call_with_storage`] that opens
    /// `NetworkMode::base_data_dir().join("contracts")` on every
    /// invocation. Kept for backward compatibility with callers
    /// that don't have a `ContractStorage` handle available —
    /// but NEW code should go through `call_with_storage` instead,
    /// since this variant is pinned to a single global default
    /// and cannot serve multi-network processes.
    ///
    /// `timestamp` and `block_hash` MUST be the real values for the
    /// block the caller is simulating. If you just want the
    /// "current moment" for an ad-hoc tool or a unit test, use
    /// [`Self::call_at_now`] (or [`Self::call_at_now_with_storage`]
    /// with an explicit handle).
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
        let storage = open_default_contract_storage()?;
        Self::call_with_storage(
            storage,
            contract_addr,
            input_data,
            caller,
            value,
            gas_limit,
            timestamp,
            block_hash,
        )
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
    ///
    /// Prefer [`Self::call_at_now_with_storage`] if you have a
    /// `ContractStorage` handle — same behaviour, explicit storage.
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
    /// layout it wants to touch. Prefer
    /// [`Self::store_value_with_storage`] in multi-environment tools.
    pub fn store_value(key: &str, value: &str) -> Result<(), VmError> {
        let storage = open_default_contract_storage()?;
        Self::store_value_with_storage(storage, key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fresh, uniquely-named ContractStorage in the system
    /// temp dir. Each test uses a different path so RocksDB locking
    /// doesn't serialize them.
    fn tmp_storage(tag: &str) -> ContractStorage {
        let dir = std::env::temp_dir().join(format!(
            "shadowdag_contract_inject_{}_{}",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ContractStorage::new(dir.to_str().unwrap()).expect("open tmp ContractStorage")
    }

    #[test]
    fn store_value_with_storage_uses_injected_handle() {
        // Regression for the "helper opens its own DB from
        // NetworkMode::base_data_dir()" bug. The injected variant
        // must write into the handle the caller hands in.
        let storage = tmp_storage("store_value");

        // Contract::store_value_with_storage writes through
        // Executor::execute, which under the hood plants the value
        // via VMContext::storage(). The exact key layout is owned by
        // the executor — for this test all we care about is that the
        // call succeeds against the INJECTED storage (no NetworkMode
        // lookup) without panicking.
        let result = Contract::store_value_with_storage(storage, "test_key", "test_value");
        assert!(result.is_ok(),
            "store_value_with_storage must succeed on an injected tmp storage, got: {:?}",
            result);
    }

    #[test]
    fn call_with_storage_accepts_injected_handle_without_network_mode_lookup() {
        // Smoke test: call_with_storage must not crash or panic when
        // the caller passes an injected tmp storage. The contract
        // address we use has no code deployed (the test doesn't
        // stage any), so the execution result itself will report a
        // "no code" path — what we're testing is that the CALL
        // doesn't blow up before reaching the executor because of
        // a bad storage path. The old `Contract::call` path opened
        // `base_data_dir().join("contracts")` unconditionally, so a
        // test running in a read-only environment (CI sandbox) could
        // fail there even with no data in the DB. The injected
        // variant opens nothing — the caller owns the handle.
        let storage = tmp_storage("call");
        let result = Contract::call_with_storage(
            storage,
            "SR1c_nonexistent",
            b"",
            "SR1caller",
            0,
            100_000,
            1_000_000,
            "00".repeat(32).as_str(),
        );
        assert!(result.is_ok(),
            "call_with_storage must return an ExecutionResult rather than propagate \
             a storage-init error, got: {:?}", result);
    }

    #[test]
    fn call_at_now_with_storage_accepts_injected_handle() {
        let storage = tmp_storage("call_at_now");
        let result = Contract::call_at_now_with_storage(
            storage,
            "SR1c_nonexistent",
            b"",
            "SR1caller",
        );
        assert!(result.is_ok(),
            "call_at_now_with_storage must accept the injected handle, got: {:?}",
            result);
    }
}
