// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ExecutionEnvironment — Reentrant execution engine for nested calls.
//
// Implements CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, CREATE2,
// and SELFDESTRUCT opcodes with proper gas accounting, snapshot/rollback,
// EIP-150 gas forwarding, and EIP-6780 SELFDESTRUCT semantics.
// ═══════════════════════════════════════════════════════════════════════════

// ── Stack helper macros (must be defined before use) ─────────────────────

macro_rules! pop1 {
    ($stack:expr, $gas:expr, $snapshot:expr, $self:expr) => {
        if $stack.is_empty() {
            $self.state.rollback($snapshot).ok();
            return CallOutcome::Failure { gas_used: $gas.gas_used() };
        } else {
            $stack.pop().unwrap()
        }
    };
}

macro_rules! pop2 {
    ($stack:expr, $gas:expr, $snapshot:expr, $self:expr) => {
        if $stack.len() < 2 {
            $self.state.rollback($snapshot).ok();
            return CallOutcome::Failure { gas_used: $gas.gas_used() };
        } else {
            ($stack.pop().unwrap(), $stack.pop().unwrap())
        }
    };
}

// ── Imports ──────────────────────────────────────────────────────────────

use std::collections::{HashMap, HashSet};
use sha2::{Sha256, Digest};

use crate::errors::VmError;
use crate::runtime::vm::core::u256::U256;
use crate::runtime::vm::core::state_manager::StateManager;
use crate::runtime::vm::core::vm::{
    OpCode, LogEntry, MAX_STACK_SIZE, MAX_MEMORY_SIZE,
    MAX_CODE_SIZE, MEMORY_GAS_PER_WORD,
};
use crate::runtime::vm::core::vm_address::VmAddressBody;
use crate::runtime::vm::gas::gas_meter::{GasMeter, GasResult};
use crate::runtime::vm::contracts::contract_deployer::ContractDeployer;
use crate::runtime::vm::precompiles::precompile_registry::PrecompileRegistry;
use crate::runtime::vm::contracts::contract_storage::{ContractStorage, PendingBatch};
use crate::slog_error;

/// Maximum call depth for nested calls
pub const MAX_CALL_DEPTH: usize = 1024;

/// Gas costs for call-related operations
pub const CALL_VALUE_TRANSFER_GAS: u64 = 9_000;
pub const NEW_ACCOUNT_GAS: u64 = 25_000;
pub const CALL_STIPEND: u64 = 2_300;
pub const CODE_DEPOSIT_GAS_PER_BYTE: u64 = 200;
pub const CREATE2_WORD_GAS: u64 = 6;

/// Block-level context (immutable for a transaction)
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub timestamp: u64,
    pub block_hash: String,
    /// Network identifier (`"mainnet"` / `"testnet"` / `"regtest"`).
    ///
    /// Used by `ExecutionEnvironment::resolve_address` as the prefix
    /// for reconstructing a ShadowDAG address string from a 20-byte
    /// body popped off the stack when the body is not in the runtime
    /// address registry. Defaults to `"mainnet"` when constructed via
    /// [`BlockContext::new`].
    pub network: String,
}

impl BlockContext {
    /// Construct a BlockContext with a default network of `"mainnet"`.
    pub fn new(timestamp: u64, block_hash: String) -> Self {
        Self { timestamp, block_hash, network: "mainnet".to_string() }
    }
}

/// Per-call execution context
#[derive(Debug, Clone)]
pub struct CallContext {
    pub address: String,        // Contract whose storage is accessed
    pub code_address: String,   // Contract whose code is executed
    pub caller: String,         // msg.sender
    pub value: u64,             // msg.value
    pub gas_limit: u64,         // Gas for this call
    pub calldata: Vec<u8>,      // Input data
    pub is_static: bool,        // STATICCALL flag (propagated to nested calls)
    pub depth: usize,           // Current call depth
}

/// Outcome of a sub-call execution
#[derive(Debug, Clone)]
pub enum CallOutcome {
    Success {
        gas_used: u64,
        return_data: Vec<u8>,
        logs: Vec<LogEntry>,
    },
    Revert {
        gas_used: u64,
        return_data: Vec<u8>,
    },
    Failure {
        gas_used: u64,
    },
}

/// Execution environment shared across nested calls.
pub struct ExecutionEnvironment {
    pub state: StateManager,
    pub block_ctx: BlockContext,
    pub destroyed_contracts: HashSet<String>,
    pub created_in_tx: HashSet<String>,
    pub last_return_data: Vec<u8>,
    /// Runtime address registry — maps 20-byte canonical address bodies
    /// to the full ShadowDAG address string they were derived from.
    ///
    /// Populated every time an address is PUSHED onto the stack via
    /// CALLER / ADDRESS / CREATE / CREATE2 (and during contract
    /// pre-loading in `load_contract_from_storage`). Consulted on the
    /// POP side by every opcode that treats a stack word as an
    /// address — BALANCE, CALL, CALLCODE, DELEGATECALL, STATICCALL,
    /// SELFDESTRUCT, EXTCODESIZE. Without this registry, the round
    /// trip from `ctx.caller` (a prefixed ShadowDAG string like
    /// `"SD1c…"`) through a 32-byte U256 stack word and back is
    /// lossy: the low 20 bytes carry the canonical hash body but
    /// lose the network prefix and type marker, so a direct
    /// reconstruction of the original string is not guaranteed.
    ///
    /// The fallback for "body not in registry" is
    /// `VmAddressBody::to_fallback_string(network)`, which produces
    /// `"{prefix}c{hex}"` using `block_ctx.network`. That default
    /// handles contracts called via raw inline PUSH — they resolve
    /// to a mainnet/testnet/regtest contract address string, which
    /// is almost certainly what the caller meant.
    pub address_registry: HashMap<[u8; 20], String>,
}

impl ExecutionEnvironment {
    pub fn new(block_ctx: BlockContext) -> Self {
        Self {
            state: StateManager::new(),
            block_ctx,
            destroyed_contracts: HashSet::new(),
            created_in_tx: HashSet::new(),
            last_return_data: Vec::new(),
            address_registry: HashMap::new(),
        }
    }

    /// Register an address string in the runtime registry so that later
    /// POPs of the same canonical 20-byte body resolve back to this
    /// exact string (including any non-canonical "ad-hoc test string"
    /// form that was synthesized via [`VmAddressBody::from_any`]).
    ///
    /// Safe to call with any string: canonical ShadowDAG addresses
    /// parse via [`VmAddressBody::from_address_string`], everything
    /// else falls through to the SHA-256 derivation in
    /// [`VmAddressBody::derive_from_nonstandard`]. Both cases
    /// register in the same map keyed by the resulting body bytes.
    pub fn register_address(&mut self, addr: &str) -> VmAddressBody {
        let body = VmAddressBody::from_any(addr);
        self.address_registry.insert(body.0, addr.to_string());
        body
    }

    /// Resolve a stack U256 back to its ShadowDAG address string.
    ///
    /// 1. Extract the low 20 bytes of the U256 as a canonical body.
    /// 2. If that body is in [`Self::address_registry`] (because an
    ///    earlier CALLER / ADDRESS / CREATE / contract pre-load
    ///    registered it), return the registered string unchanged.
    /// 3. Otherwise, reconstruct as `"{prefix}c{hex(body)}"` using
    ///    the network prefix from [`BlockContext::network`]. This
    ///    fallback assumes the caller intended a contract address on
    ///    the current network — the common case for inline-pushed
    ///    addresses — and may produce a key that does not exist in
    ///    state when that assumption is wrong.
    pub fn resolve_address(&self, u: U256) -> String {
        let body = VmAddressBody::from_u256(u);
        if let Some(s) = self.address_registry.get(&body.0) {
            return s.clone();
        }
        body.to_fallback_string(&self.block_ctx.network)
    }

    /// Persist all state changes to ContractStorage atomically.
    ///
    /// The previous implementation issued individual `set_state(...)` calls
    /// in a loop — one RocksDB put per account, per code blob, per storage
    /// slot. If any single put failed, the earlier writes had already
    /// landed on disk, leaving the contract store in a partial state
    /// (e.g. account metadata updated but storage slots half-written).
    /// `Executor::deploy()` and `Executor::call()` both rely on this
    /// method for their post-success persistence, so the bug opened a
    /// real window for corrupted on-disk contract state.
    ///
    /// The new implementation buffers every write into a `PendingBatch`
    /// and commits it in a single RocksDB `WriteBatch` via
    /// `ContractStorage::commit_batch`. RocksDB guarantees WriteBatch is
    /// atomic — either every put lands or none of them do — so partial
    /// persistence is no longer possible.
    pub fn persist_to_storage(&self, storage: &ContractStorage) -> Result<(), VmError> {
        let mut batch = PendingBatch::new();

        for (addr, account) in self.state.iter_accounts() {
            // Persist account metadata (balance|nonce|code_hash)
            let meta = format!("{}|{}|{}", account.balance, account.nonce, account.code_hash);
            batch.put(format!("account:{}", addr), meta);

            // Persist code if contract
            if !account.code.is_empty() {
                batch.put(format!("code:{}", addr), hex::encode(&account.code));
            }
        }

        // Persist storage slots
        for (addr, slots) in self.state.iter_storage() {
            for (key, value) in slots {
                batch.put(format!("{}:{}", addr, key), value.clone());
            }
        }

        storage.commit_batch(&mut batch)
    }

    /// Persist state changes AND build undo data for rollback, atomically.
    ///
    /// Captures the previous value of every key touched during this block
    /// before overwriting it, so that `ContractStorage::rollback_block()`
    /// can reverse the mutations during a reorg.
    ///
    /// Atomicity guarantees (all-or-nothing, enforced by a single RocksDB
    /// `WriteBatch`):
    ///
    /// - every account metadata update,
    /// - every contract code update,
    /// - every storage slot update,
    /// - and the `contract:undo:{block_hash}` record itself,
    ///
    /// commit together. The previous implementation called `set_state`
    /// once per key and then `save_undo` as a separate put, so a crash
    /// or write failure mid-loop could land account metadata without
    /// matching storage slots, or land all state without the
    /// corresponding undo record (making a later reorg silently fail).
    pub fn persist_with_undo(
        &self,
        storage: &ContractStorage,
        block_hash: &str,
    ) -> Result<crate::runtime::vm::contracts::contract_storage::ContractUndoData, VmError> {
        use crate::runtime::vm::contracts::contract_storage::ContractUndoData;
        use rocksdb::WriteBatch;

        let mut modified_keys = Vec::new();
        let mut created_accounts = Vec::new();
        let mut destroyed_accounts = Vec::new();
        let mut wb = WriteBatch::default();

        // Capture undo data BEFORE writing — accounts
        for (addr, account) in self.state.iter_accounts() {
            let account_key = format!("account:{}", addr);
            let old_val = storage.get_state(&account_key);

            if old_val.is_none() {
                created_accounts.push(addr.clone());
            }

            // Buffer new account state
            let meta = format!("{}|{}|{}", account.balance, account.nonce, account.code_hash);
            modified_keys.push((account_key.clone(), old_val));
            let db_key = format!("contract:{}", account_key);
            wb.put(db_key.as_bytes(), meta.as_bytes());

            // Buffer code
            if !account.code.is_empty() {
                let code_key = format!("code:{}", addr);
                let old_code = storage.get_state(&code_key);
                modified_keys.push((code_key.clone(), old_code));
                let db_key = format!("contract:{}", code_key);
                let code_hex = hex::encode(&account.code);
                wb.put(db_key.as_bytes(), code_hex.as_bytes());
            }
        }

        // Capture undo data BEFORE writing — storage slots
        for (addr, slots) in self.state.iter_storage() {
            for (key, value) in slots {
                let full_key = format!("{}:{}", addr, key);
                let old_val = storage.get_state(&full_key);
                modified_keys.push((full_key.clone(), old_val));
                let db_key = format!("contract:{}", full_key);
                wb.put(db_key.as_bytes(), value.as_bytes());
            }
        }

        // Handle destroyed accounts — capture their data before removal
        for addr in &self.destroyed_contracts {
            let account_key = format!("account:{}", addr);
            if let Some(old_data) = storage.get_state(&account_key) {
                destroyed_accounts.push((addr.clone(), old_data));
            }
        }

        let undo = ContractUndoData {
            modified_keys,
            created_accounts,
            destroyed_accounts,
            receipt_root: None, // Set by caller after receipt computation
            state_root: None,   // Set by caller after state root computation
        };

        // Serialize the undo record and include it in the SAME WriteBatch
        // so state + undo either both land or both don't. Mirrors the
        // layout used by `ContractStorage::save_undo` (prefix
        // `contract:undo:`, bincode payload).
        let undo_key = format!("contract:undo:{}", block_hash);
        let undo_bytes = bincode::serialize(&undo).map_err(|e| {
            VmError::Other(format!("failed to serialize contract undo data: {}", e))
        })?;
        wb.put(undo_key.as_bytes(), &undo_bytes);

        // Commit state + undo atomically via the shared DB handle.
        storage.shared_db().write(wb).map_err(|e| {
            VmError::Other(format!(
                "persist_with_undo atomic commit failed for block {}: {}",
                block_hash, e
            ))
        })?;

        Ok(undo)
    }

    /// Load a contract's state from ContractStorage into the in-memory
    /// StateManager, fail-closed on corruption.
    ///
    /// Returns `Ok(())` on success AND on genuine absence (no state on
    /// disk for `addr`). Returns `Err(VmError::ContractError)` only when
    /// the on-disk state is present but corrupt:
    ///
    ///   - account metadata is not in the expected `balance|nonce|code_hash`
    ///     layout (wrong field count),
    ///   - balance or nonce cannot be parsed as `u64`,
    ///   - the stored code blob is not valid hex,
    ///   - `StateManager::set_balance` / `set_code` / `increment_nonce`
    ///     returns an internal error.
    ///
    /// The previous implementation collapsed every one of those cases
    /// into a silent no-op via `unwrap_or(0)` and `.ok()`, which meant a
    /// single corrupt account could load into the VM as a zero-balance
    /// account and quietly reset state. Callers that must continue past
    /// a corruption error (for example best-effort block pre-loaders)
    /// can still do so by matching on the returned `Result` and logging;
    /// the error is no longer invisible.
    pub fn load_contract_from_storage(
        &mut self,
        storage: &ContractStorage,
        addr: &str,
    ) -> Result<(), VmError> {
        // Register the loaded address in the runtime address registry so
        // that later CALLER / ADDRESS / BALANCE / CALL opcodes can
        // resolve the 20-byte body popped off the stack back to this
        // exact `addr` string — including ad-hoc non-canonical test
        // fixtures that would otherwise fall through to the
        // `"{prefix}c{hex}"` fallback reconstruction.
        self.register_address(addr);

        // Load account metadata (if present).
        if let Some(meta) = storage.get_state(&format!("account:{}", addr)) {
            let parts: Vec<&str> = meta.splitn(3, '|').collect();
            if parts.len() != 3 {
                slog_error!("vm", "load_contract_account_meta_malformed",
                    contract => addr, field_count => parts.len(), raw => &meta);
                return Err(VmError::ContractError(format!(
                    "corrupt account metadata for '{}': expected 3 pipe-separated fields, got {}",
                    addr, parts.len()
                )));
            }

            let balance: u64 = parts[0].parse().map_err(|e| {
                slog_error!("vm", "load_contract_balance_parse_failed",
                    contract => addr, raw => parts[0], error => &format!("{}", e));
                VmError::ContractError(format!(
                    "corrupt account balance for '{}': cannot parse '{}' as u64: {}",
                    addr, parts[0], e
                ))
            })?;

            let nonce: u64 = parts[1].parse().map_err(|e| {
                slog_error!("vm", "load_contract_nonce_parse_failed",
                    contract => addr, raw => parts[1], error => &format!("{}", e));
                VmError::ContractError(format!(
                    "corrupt account nonce for '{}': cannot parse '{}' as u64: {}",
                    addr, parts[1], e
                ))
            })?;

            // Create account in StateManager and apply the parsed values.
            self.state.get_or_create_account(addr);
            self.state.set_balance(addr, balance).map_err(|e| {
                VmError::Other(format!(
                    "set_balance during load_contract_from_storage failed for '{}': {}",
                    addr, e
                ))
            })?;
            // Set nonce by incrementing — StateManager only exposes increment.
            for _ in 0..nonce {
                self.state.increment_nonce(addr).map_err(|e| {
                    VmError::Other(format!(
                        "increment_nonce during load_contract_from_storage failed for '{}': {}",
                        addr, e
                    ))
                })?;
            }
        }

        // Load code (if present).
        if let Some(code_hex) = storage.get_state(&format!("code:{}", addr)) {
            let code = hex::decode(&code_hex).map_err(|e| {
                slog_error!("vm", "load_contract_code_hex_corrupt",
                    contract => addr, error => &format!("{}", e));
                VmError::ContractError(format!(
                    "corrupt contract code hex for '{}': {}",
                    addr, e
                ))
            })?;
            self.state.set_code(addr, code).map_err(|e| {
                VmError::Other(format!(
                    "set_code during load_contract_from_storage failed for '{}': {}",
                    addr, e
                ))
            })?;
        }

        Ok(())
    }

    /// Execute a call frame. This is the reentrant core of the VM.
    pub fn execute_frame(&mut self, ctx: &CallContext) -> CallOutcome {
        // Depth check. Matches EVM semantics (EIP-150): a top-level call
        // starts at depth 0, and the maximum nested call depth is
        // MAX_CALL_DEPTH frames total. Because child frames are built
        // with `depth: ctx.depth + 1`, the valid range of `ctx.depth`
        // values is `0..MAX_CALL_DEPTH` — i.e. the highest depth that
        // may execute is `MAX_CALL_DEPTH - 1` (the 1024th frame).
        //
        // The previous check was `ctx.depth > MAX_CALL_DEPTH`, which
        // allowed `ctx.depth == MAX_CALL_DEPTH` to execute — one extra
        // frame beyond the EVM limit (1025 frames total instead of
        // 1024). Using `>=` closes the off-by-one and aligns with the
        // identical check in `call_stack.rs::CallStack::push`, which
        // already uses `self.frames.len() >= self.max_depth`.
        if ctx.depth >= MAX_CALL_DEPTH {
            return CallOutcome::Failure { gas_used: ctx.gas_limit };
        }

        // Register the frame's caller, storage address, and code address
        // in the runtime address registry so that every later CALLER /
        // ADDRESS push and every later BALANCE / CALL / SELFDESTRUCT /
        // EXTCODESIZE pop inside this frame can recover the original
        // ShadowDAG address string from a 20-byte U256 body. Without
        // this pre-registration, the pop side can only fall back to
        // `VmAddressBody::to_fallback_string(network)`, which
        // reconstructs the body as a `"{prefix}c{hex}"` contract-type
        // string — wrong for EOAs, tokens, stealth/schnorr/P2SH, and
        // ad-hoc test fixtures.
        self.register_address(&ctx.caller);
        self.register_address(&ctx.address);
        if ctx.code_address != ctx.address {
            self.register_address(&ctx.code_address);
        }

        // Load code for the target
        let code = self.state.get_code(&ctx.code_address);
        if code.is_empty() {
            // Calling a non-contract address with value -- just a transfer
            if ctx.value > 0 && !ctx.is_static
                && self.state.transfer(&ctx.caller, &ctx.address, ctx.value).is_err()
            {
                return CallOutcome::Failure { gas_used: 0 };
            }
            return CallOutcome::Success {
                gas_used: 0,
                return_data: Vec::new(),
                logs: Vec::new(),
            };
        }

        if code.len() > MAX_CODE_SIZE {
            return CallOutcome::Failure { gas_used: ctx.gas_limit };
        }

        // Take state snapshot for rollback on failure
        let snapshot = self.state.snapshot();

        // Value transfer (if not delegate/static)
        if ctx.value > 0 && !ctx.is_static
            && self.state.transfer(&ctx.caller, &ctx.address, ctx.value).is_err()
        {
            self.state.rollback(snapshot).ok();
            return CallOutcome::Failure { gas_used: 0 };
        }

        // Initialize execution state
        let mut gas = GasMeter::new(ctx.gas_limit);
        let mut stack: Vec<U256> = Vec::with_capacity(64);
        let init_mem_size = 256usize.max(ctx.calldata.len());
        let mut memory: Vec<u8> = vec![0u8; init_mem_size];
        let mut pc: usize = 0;
        let mut logs: Vec<LogEntry> = Vec::new();
        let mut return_data: Vec<u8> = Vec::new();

        // Charge initial memory
        let init_mem_cost = (init_mem_size as u64 / 32) * MEMORY_GAS_PER_WORD;
        if let GasResult::OutOfGas { .. } = gas.consume(init_mem_cost) {
            self.state.rollback(snapshot).ok();
            return CallOutcome::Failure { gas_used: gas.gas_used() };
        }

        // Copy calldata into memory
        if !ctx.calldata.is_empty() && ctx.calldata.len() <= memory.len() {
            memory[..ctx.calldata.len()].copy_from_slice(&ctx.calldata);
        }

        // Pre-compute jump destinations
        let jump_dests = find_jump_dests(&code);

        // Main execution loop
        while pc < code.len() {
            let op = OpCode::from_byte(code[pc]);
            let cost = op.gas_cost();

            if let GasResult::OutOfGas { .. } = gas.consume(cost) {
                self.state.rollback(snapshot).ok();
                return CallOutcome::Failure { gas_used: gas.gas_used() };
            }

            match op {
                OpCode::STOP => {
                    // Commit this frame's changes
                    self.state.commit(snapshot).ok();
                    return CallOutcome::Success {
                        gas_used: gas.effective_gas_used(),
                        return_data,
                        logs,
                    };
                }

                OpCode::NOP => { pc += 1; continue; }

                // ── PUSH ─────────────────────────────────────
                OpCode::PUSH1 => {
                    if pc + 1 >= code.len() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(code[pc + 1] as u64));
                    pc += 2; continue;
                }
                OpCode::PUSH2 => {
                    if pc + 2 >= code.len() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let v = u16::from_be_bytes([code[pc+1], code[pc+2]]);
                    stack.push(U256::from_u64(v as u64));
                    pc += 3; continue;
                }
                OpCode::PUSH4 => {
                    if pc + 4 >= code.len() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let v = u32::from_be_bytes([code[pc+1], code[pc+2], code[pc+3], code[pc+4]]);
                    stack.push(U256::from_u64(v as u64));
                    pc += 5; continue;
                }
                OpCode::PUSH8 => {
                    if pc + 8 >= code.len() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&code[pc+1..pc+9]);
                    stack.push(U256::from_u64(u64::from_be_bytes(buf)));
                    pc += 9; continue;
                }
                OpCode::PUSH16 | OpCode::PUSH32 => {
                    let size = if op == OpCode::PUSH16 { 16 } else { 32 };
                    if pc + size >= code.len() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let hex_str = hex::encode(&code[pc+1..pc+1+size]);
                    stack.push(U256::from_hex(&hex_str).unwrap_or(U256::ZERO));
                    pc += 1 + size; continue;
                }

                // ── Stack ops ────────────────────────────────
                OpCode::POP => {
                    if stack.is_empty() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.pop();
                }
                OpCode::DUP => {
                    if stack.is_empty() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let top = *stack.last().unwrap();
                    stack.push(top);
                }
                OpCode::SWAP => {
                    if stack.len() < 2 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let len = stack.len();
                    stack.swap(len - 1, len - 2);
                }

                // ── Arithmetic ───────────────────────────────
                OpCode::ADD => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.wrapping_add(b)); }
                OpCode::SUB => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.wrapping_sub(b)); }
                OpCode::MUL => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.wrapping_mul(b)); }
                OpCode::DIV => {
                    let (a, b) = pop2!(stack, gas, snapshot, self);
                    stack.push(if b.is_zero() { U256::ZERO } else { a.checked_div(b) });
                }
                OpCode::MOD => {
                    let (a, b) = pop2!(stack, gas, snapshot, self);
                    stack.push(if b.is_zero() { U256::ZERO } else { a.checked_mod(b) });
                }
                OpCode::EXP => {
                    let (base, exp) = pop2!(stack, gas, snapshot, self);
                    let exp_val = exp.as_u64().min(255);
                    let mut result = U256::ONE;
                    for _ in 0..exp_val { result = result.wrapping_mul(base); }
                    stack.push(result);
                }
                OpCode::ADDMOD => {
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let a = stack.pop().unwrap();
                    let b = stack.pop().unwrap();
                    let n = stack.pop().unwrap();
                    stack.push(if n.is_zero() { U256::ZERO } else { a.wrapping_add(b).checked_mod(n) });
                }
                OpCode::MULMOD => {
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let a = stack.pop().unwrap();
                    let b = stack.pop().unwrap();
                    let n = stack.pop().unwrap();
                    stack.push(if n.is_zero() { U256::ZERO } else { a.wrapping_mul(b).checked_mod(n) });
                }

                // ── Comparison ───────────────────────────────
                OpCode::EQ => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(if a == b { U256::ONE } else { U256::ZERO }); }
                OpCode::LT => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(if a < b { U256::ONE } else { U256::ZERO }); }
                OpCode::GT => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(if a > b { U256::ONE } else { U256::ZERO }); }
                OpCode::ISZERO => { let a = pop1!(stack, gas, snapshot, self); stack.push(if a.is_zero() { U256::ONE } else { U256::ZERO }); }

                // ── Bitwise ──────────────────────────────────
                OpCode::AND => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.bitand(b)); }
                OpCode::OR  => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.bitor(b)); }
                OpCode::XOR => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(a.bitxor(b)); }
                OpCode::NOT => { let a = pop1!(stack, gas, snapshot, self); stack.push(a.bitnot()); }
                OpCode::SHL => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(b.shl(a.as_u64() as u32)); }
                OpCode::SHR => { let (a, b) = pop2!(stack, gas, snapshot, self); stack.push(b.shr(a.as_u64() as u32)); }

                // ── Storage ──────────────────────────────────
                OpCode::SLOAD => {
                    let slot = pop1!(stack, gas, snapshot, self);
                    let key = format!("slot:{}", slot);
                    let val = self.state.storage_load(&ctx.address, &key)
                        .map(|s| parse_storage_value(&s))
                        .unwrap_or(U256::ZERO);
                    stack.push(val);
                }
                OpCode::SSTORE => {
                    if ctx.is_static {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    let (slot, val) = pop2!(stack, gas, snapshot, self);
                    let key = format!("slot:{}", slot);
                    self.state.storage_store(&ctx.address, &key, &format!("0x{}", val.to_hex()));
                }
                OpCode::SDELETE => {
                    if ctx.is_static {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    let slot = pop1!(stack, gas, snapshot, self);
                    let key = format!("slot:{}", slot);
                    self.state.storage_delete(&ctx.address, &key);
                    gas.add_refund(2_400);
                }

                // ── Crypto ───────────────────────────────────
                OpCode::SHA256 => {
                    let a = pop1!(stack, gas, snapshot, self);
                    let input = a.to_hex();
                    let mut hasher = <Sha256 as Digest>::new();
                    Digest::update(&mut hasher, input.as_bytes());
                    let hash = hex::encode(Digest::finalize(hasher));
                    stack.push(U256::from_hex(&hash).unwrap_or(U256::ZERO));
                }
                OpCode::KECCAK => {
                    let a = pop1!(stack, gas, snapshot, self);
                    let input = a.to_hex();
                    let mut hasher = <Sha256 as Digest>::new();
                    Digest::update(&mut hasher, input.as_bytes());
                    let hash = hex::encode(Digest::finalize(hasher));
                    stack.push(U256::from_hex(&hash).unwrap_or(U256::ZERO));
                }

                // ── Context ──────────────────────────────────
                OpCode::CALLER => {
                    // Push the caller's 20-byte canonical body,
                    // right-aligned in a 32-byte U256 word (EVM layout).
                    // The frame-entry pre-registration guarantees that a
                    // subsequent BALANCE / CALL / SELFDESTRUCT pop can
                    // resolve this body back to `ctx.caller` via the
                    // address registry.
                    stack.push(VmAddressBody::from_any(&ctx.caller).to_u256());
                }
                OpCode::CALLVALUE => {
                    stack.push(U256::from_u64(ctx.value));
                }
                OpCode::TIMESTAMP => {
                    stack.push(U256::from_u64(self.block_ctx.timestamp));
                }
                OpCode::BLOCKHASH => {
                    stack.push(U256::from_hex(&self.block_ctx.block_hash).unwrap_or(U256::ZERO));
                }
                OpCode::BALANCE => {
                    let addr_val = pop1!(stack, gas, snapshot, self);
                    // Resolve the stack body back to its ShadowDAG
                    // string via the runtime registry (populated by
                    // CALLER / ADDRESS / CREATE pushes and by the
                    // frame-entry registration of ctx.caller /
                    // ctx.address). Falls back to `{prefix}c{hex}` if
                    // the body was inline-pushed without being
                    // registered — wrong for EOAs/tokens, correct for
                    // contract-type addresses on the current network.
                    let addr = self.resolve_address(addr_val);
                    let balance = self.state.get_balance(&addr);
                    stack.push(U256::from_u64(balance));
                }

                // ── Flow Control ─────────────────────────────
                OpCode::JUMP => {
                    let dest = pop1!(stack, gas, snapshot, self);
                    let d = dest.as_u64() as usize;
                    if !jump_dests.contains(&d) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    pc = d; continue;
                }
                OpCode::JUMPI => {
                    let (dest, cond) = pop2!(stack, gas, snapshot, self);
                    if !cond.is_zero() {
                        let d = dest.as_u64() as usize;
                        if !jump_dests.contains(&d) {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                        pc = d; continue;
                    }
                }
                OpCode::JUMPDEST => { /* marker only */ }

                // ── Memory ───────────────────────────────────
                OpCode::MLOAD => {
                    let offset = pop1!(stack, gas, snapshot, self).as_u64() as usize;
                    if offset + 32 > MAX_MEMORY_SIZE {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    while memory.len() < offset + 32 { memory.push(0); }
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&memory[offset..offset+32]);
                    stack.push(U256::from_be_bytes(&buf));
                }
                OpCode::MSTORE => {
                    let (offset_val, val) = pop2!(stack, gas, snapshot, self);
                    let offset = offset_val.as_u64() as usize;
                    if offset + 32 > MAX_MEMORY_SIZE {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    while memory.len() < offset + 32 { memory.push(0); }
                    let bytes = val.to_be_bytes();
                    memory[offset..offset+32].copy_from_slice(&bytes);
                }

                // ── Logging ──────────────────────────────────
                OpCode::LOG => {
                    if ctx.is_static {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    let data_val = pop1!(stack, gas, snapshot, self);
                    logs.push(LogEntry {
                        contract: ctx.address.clone(),
                        topics: Vec::new(),
                        data: data_val.to_hex().into_bytes(),
                    });
                }

                // ── RETURN ───────────────────────────────────
                OpCode::RETURN => {
                    if stack.len() >= 2 {
                        let offset = stack.pop().unwrap().as_u64() as usize;
                        let size = stack.pop().unwrap().as_u64() as usize;
                        if size > 0 && offset + size <= memory.len() {
                            return_data = memory[offset..offset+size].to_vec();
                        }
                    }
                    self.state.commit(snapshot).ok();
                    return CallOutcome::Success {
                        gas_used: gas.effective_gas_used(),
                        return_data,
                        logs,
                    };
                }
                OpCode::REVERT => {
                    if stack.len() >= 2 {
                        let offset = stack.pop().unwrap().as_u64() as usize;
                        let size = stack.pop().unwrap().as_u64() as usize;
                        if size > 0 && offset + size <= memory.len() {
                            return_data = memory[offset..offset+size].to_vec();
                        }
                    }
                    self.state.rollback(snapshot).ok();
                    return CallOutcome::Revert {
                        gas_used: gas.gas_used(),
                        return_data,
                    };
                }

                // ══════════════════════════════════════════════
                //  CALL OPCODES
                // ══════════════════════════════════════════════

                OpCode::CALL => {
                    // Stack: [gas, addr, value, argsOffset, argsLen, retOffset, retLen]
                    if stack.len() < 7 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let req_gas = stack.pop().unwrap().as_u64();
                    let addr = stack.pop().unwrap();
                    let call_value = stack.pop().unwrap().as_u64();
                    let args_offset = stack.pop().unwrap().as_u64() as usize;
                    let args_len = stack.pop().unwrap().as_u64() as usize;
                    let ret_offset = stack.pop().unwrap().as_u64() as usize;
                    let ret_len = stack.pop().unwrap().as_u64() as usize;

                    // Static check: CALL with value > 0 inside STATICCALL is forbidden
                    if ctx.is_static && call_value > 0 {
                        stack.push(U256::ZERO); // failure
                        pc += 1; continue;
                    }

                    // Resolve the popped stack body back to the target's
                    // ShadowDAG string via the runtime address registry,
                    // then compute it up front so both the "new account"
                    // gas check and the downstream precompile /
                    // child_ctx branches share one source of truth.
                    let target_addr = self.resolve_address(addr);

                    // Extra gas for value transfer. EIP-150 semantics: a
                    // CALL with value > 0 always pays CALL_VALUE_TRANSFER_GAS
                    // (9_000), and additionally pays NEW_ACCOUNT_GAS (25_000)
                    // when the target account does not yet exist, because
                    // the value transfer will materialize the account as a
                    // side effect (`StateManager::transfer` →
                    // `set_balance` → `get_or_create_account`). Previously
                    // this path only charged `CALL_VALUE_TRANSFER_GAS` and
                    // the declared `NEW_ACCOUNT_GAS` constant was unused,
                    // so sending value to a fresh address was silently
                    // under-charged by 25_000 gas.
                    //
                    // Precompile addresses (0x01..=0x09) are ALWAYS treated
                    // as existing — they are built-in and carry no
                    // account state — so calling a precompile with value
                    // does not trigger the new-account surcharge.
                    let target_is_precompile = is_precompile_addr(&target_addr).is_some();
                    let target_is_new = call_value > 0
                        && !target_is_precompile
                        && self.state.get_account(&target_addr).is_none();
                    let mut extra_gas = 0u64;
                    if call_value > 0 {
                        extra_gas = extra_gas.saturating_add(CALL_VALUE_TRANSFER_GAS);
                    }
                    if target_is_new {
                        extra_gas = extra_gas.saturating_add(NEW_ACCOUNT_GAS);
                    }
                    if extra_gas > 0 {
                        if let GasResult::OutOfGas { .. } = gas.consume(extra_gas) {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                    }

                    // EIP-150: sub-call gets min(requested, remaining * 63/64)
                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let mut child_gas = req_gas.min(max_allowed);
                    if call_value > 0 { child_gas += CALL_STIPEND; }

                    // Reserve child gas from parent
                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas.saturating_sub(if call_value > 0 { CALL_STIPEND } else { 0 })) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    // Read calldata from memory
                    let calldata = if args_len > 0 && args_offset + args_len <= memory.len() {
                        memory[args_offset..args_offset+args_len].to_vec()
                    } else {
                        Vec::new()
                    };

                    // Check for precompile (addresses 0x01-0x09)
                    if let Some(precompile_id) = is_precompile_addr(&target_addr) {
                        let registry = PrecompileRegistry::new();
                        let result = registry.execute(precompile_id as u64, &calldata, child_gas);
                        if result.success {
                            gas.return_gas(child_gas.saturating_sub(result.gas_used));
                            self.last_return_data = result.output.clone();
                            if ret_len > 0 && !result.output.is_empty() {
                                let copy_len = ret_len.min(result.output.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset + copy_len].copy_from_slice(&result.output[..copy_len]);
                            }
                            stack.push(U256::ONE);
                        } else {
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                        pc += 1; continue;
                    }

                    let child_ctx = CallContext {
                        address: target_addr.clone(),
                        code_address: target_addr,
                        caller: ctx.address.clone(),
                        value: call_value,
                        gas_limit: child_gas,
                        calldata,
                        is_static: ctx.is_static,
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);

                    match &outcome {
                        CallOutcome::Success { gas_used, return_data: rd, .. } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            // Write return data to memory
                            if ret_len > 0 && !rd.is_empty() {
                                let copy_len = ret_len.min(rd.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset+copy_len].copy_from_slice(&rd[..copy_len]);
                            }
                            stack.push(U256::ONE); // success
                        }
                        CallOutcome::Revert { gas_used, return_data: rd } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            stack.push(U256::ZERO); // failure
                        }
                        CallOutcome::Failure { gas_used } => {
                            // All gas consumed on failure -- no refund
                            let _ = gas_used;
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::STATICCALL => {
                    // Stack: [gas, addr, argsOffset, argsLen, retOffset, retLen]
                    if stack.len() < 6 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let req_gas = stack.pop().unwrap().as_u64();
                    let addr = stack.pop().unwrap();
                    let args_offset = stack.pop().unwrap().as_u64() as usize;
                    let args_len = stack.pop().unwrap().as_u64() as usize;
                    let ret_offset = stack.pop().unwrap().as_u64() as usize;
                    let ret_len = stack.pop().unwrap().as_u64() as usize;

                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let child_gas = req_gas.min(max_allowed);

                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    let calldata = if args_len > 0 && args_offset + args_len <= memory.len() {
                        memory[args_offset..args_offset+args_len].to_vec()
                    } else { Vec::new() };

                    // Resolve the popped body back to its ShadowDAG
                    // address via the runtime registry (see BALANCE
                    // and CALL above for the full rationale).
                    let target_addr = self.resolve_address(addr);

                    // Check for precompile (addresses 0x01-0x09)
                    if let Some(precompile_id) = is_precompile_addr(&target_addr) {
                        let registry = PrecompileRegistry::new();
                        let result = registry.execute(precompile_id as u64, &calldata, child_gas);
                        if result.success {
                            gas.return_gas(child_gas.saturating_sub(result.gas_used));
                            self.last_return_data = result.output.clone();
                            if ret_len > 0 && !result.output.is_empty() {
                                let copy_len = ret_len.min(result.output.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset + copy_len].copy_from_slice(&result.output[..copy_len]);
                            }
                            stack.push(U256::ONE);
                        } else {
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                        pc += 1; continue;
                    }

                    let child_ctx = CallContext {
                        address: target_addr.clone(),
                        code_address: target_addr,
                        caller: ctx.address.clone(),
                        value: 0,
                        gas_limit: child_gas,
                        calldata,
                        is_static: true, // STATICCALL propagates
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);
                    match &outcome {
                        CallOutcome::Success { gas_used, return_data: rd, .. } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            if ret_len > 0 && !rd.is_empty() {
                                let copy_len = ret_len.min(rd.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset+copy_len].copy_from_slice(&rd[..copy_len]);
                            }
                            stack.push(U256::ONE);
                        }
                        CallOutcome::Revert { gas_used, return_data: rd } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            stack.push(U256::ZERO);
                        }
                        CallOutcome::Failure { .. } => {
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::DELEGATECALL => {
                    // Stack: [gas, addr, argsOffset, argsLen, retOffset, retLen]
                    if stack.len() < 6 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let req_gas = stack.pop().unwrap().as_u64();
                    let code_addr = stack.pop().unwrap();
                    let args_offset = stack.pop().unwrap().as_u64() as usize;
                    let args_len = stack.pop().unwrap().as_u64() as usize;
                    let ret_offset = stack.pop().unwrap().as_u64() as usize;
                    let ret_len = stack.pop().unwrap().as_u64() as usize;

                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let child_gas = req_gas.min(max_allowed);
                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    let calldata = if args_len > 0 && args_offset + args_len <= memory.len() {
                        memory[args_offset..args_offset+args_len].to_vec()
                    } else { Vec::new() };

                    // Resolve the popped body back to its ShadowDAG
                    // address. DELEGATECALL uses this as the
                    // code_address so the child frame loads the target's
                    // bytecode but keeps the CURRENT frame's storage
                    // context (ctx.address).
                    let target_code = self.resolve_address(code_addr);
                    // DELEGATECALL: execute target's CODE but in CALLER's storage
                    // msg.sender and msg.value are PRESERVED from parent
                    let child_ctx = CallContext {
                        address: ctx.address.clone(),      // storage = caller's
                        code_address: target_code,          // code = target's
                        caller: ctx.caller.clone(),         // preserved
                        value: ctx.value,                   // preserved
                        gas_limit: child_gas,
                        calldata,
                        is_static: ctx.is_static,
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);
                    match &outcome {
                        CallOutcome::Success { gas_used, return_data: rd, .. } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            if ret_len > 0 && !rd.is_empty() {
                                let copy_len = ret_len.min(rd.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset+copy_len].copy_from_slice(&rd[..copy_len]);
                            }
                            stack.push(U256::ONE);
                        }
                        CallOutcome::Revert { gas_used, return_data: rd } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            stack.push(U256::ZERO);
                        }
                        CallOutcome::Failure { .. } => {
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::CALLCODE => {
                    // Stack: [gas, addr, value, argsOffset, argsLen, retOffset, retLen]
                    if stack.len() < 7 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let req_gas = stack.pop().unwrap().as_u64();
                    let code_addr = stack.pop().unwrap();
                    let call_value = stack.pop().unwrap().as_u64();
                    let args_offset = stack.pop().unwrap().as_u64() as usize;
                    let args_len = stack.pop().unwrap().as_u64() as usize;
                    let ret_offset = stack.pop().unwrap().as_u64() as usize;
                    let ret_len = stack.pop().unwrap().as_u64() as usize;

                    if ctx.is_static && call_value > 0 {
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    }

                    let extra_gas = if call_value > 0 { CALL_VALUE_TRANSFER_GAS } else { 0 };
                    if extra_gas > 0 {
                        if let GasResult::OutOfGas { .. } = gas.consume(extra_gas) {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                    }

                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let mut child_gas = req_gas.min(max_allowed);
                    if call_value > 0 { child_gas += CALL_STIPEND; }
                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas.saturating_sub(if call_value > 0 { CALL_STIPEND } else { 0 })) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    let calldata = if args_len > 0 && args_offset + args_len <= memory.len() {
                        memory[args_offset..args_offset+args_len].to_vec()
                    } else { Vec::new() };

                    // Resolve the popped body back to its ShadowDAG
                    // address via the runtime registry, same as
                    // DELEGATECALL above.
                    let target_code = self.resolve_address(code_addr);
                    // CALLCODE: execute target's CODE in CALLER's storage
                    // msg.sender = caller (NOT preserved like DELEGATECALL)
                    let child_ctx = CallContext {
                        address: ctx.address.clone(),       // storage = caller's
                        code_address: target_code,           // code = target's
                        caller: ctx.address.clone(),         // msg.sender = this contract
                        value: call_value,
                        gas_limit: child_gas,
                        calldata,
                        is_static: ctx.is_static,
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);
                    match &outcome {
                        CallOutcome::Success { gas_used, return_data: rd, .. } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            if ret_len > 0 && !rd.is_empty() {
                                let copy_len = ret_len.min(rd.len());
                                while memory.len() < ret_offset + copy_len { memory.push(0); }
                                memory[ret_offset..ret_offset+copy_len].copy_from_slice(&rd[..copy_len]);
                            }
                            stack.push(U256::ONE);
                        }
                        CallOutcome::Revert { gas_used, return_data: rd } => {
                            gas.return_gas(child_gas.saturating_sub(*gas_used));
                            self.last_return_data = rd.clone();
                            stack.push(U256::ZERO);
                        }
                        CallOutcome::Failure { .. } => {
                            self.last_return_data.clear();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::CREATE => {
                    // Stack: [value, offset, length] -> [address or 0]
                    if ctx.is_static {
                        if stack.len() >= 3 { stack.pop(); stack.pop(); stack.pop(); }
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    }
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let create_value = stack.pop().unwrap().as_u64();
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;

                    // Read init code from memory
                    let init_code = if length > 0 && offset + length <= memory.len() {
                        memory[offset..offset+length].to_vec()
                    } else {
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    };

                    // Charge per-byte cost
                    let byte_cost = init_code.len() as u64 * CODE_DEPOSIT_GAS_PER_BYTE;
                    if let GasResult::OutOfGas { .. } = gas.consume(byte_cost) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    // Compute address. compute_create_address now returns
                    // Result because an unknown deployer prefix must not
                    // silently tag the new contract as mainnet. If the
                    // currently-executing contract address is malformed
                    // (shouldn't happen in practice, but we refuse to
                    // synthesize state from garbage) we treat the CREATE
                    // as a Failure outcome rather than proceeding.
                    let nonce = self.state.get_nonce(&ctx.address);
                    let new_addr = match ContractDeployer::compute_create_address(&ctx.address, nonce) {
                        Ok(addr) => addr,
                        Err(_) => {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                    };

                    // Increment caller's nonce BEFORE taking the CREATE
                    // sub-snapshot so the bump is preserved across a
                    // failed CREATE. EVM semantics: the caller's nonce
                    // is consumed by any CREATE attempt, success or
                    // failure, but every other side effect (new
                    // account, value transfer, temporary init code
                    // install) MUST be reverted on failure so an
                    // unsuccessful deploy does not leave an orphaned
                    // empty account or unspent value sitting at the
                    // would-be contract address.
                    self.state.increment_nonce(&ctx.address).ok();

                    // Check address not occupied
                    if !self.state.get_code(&new_addr).is_empty() {
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    }

                    // EIP-150 gas for init code execution
                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let child_gas = max_allowed;
                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    // Sub-snapshot AFTER the nonce increment. Anything
                    // mutated from this point forward inside the CREATE
                    // path will be undone on failure via
                    // `rollback(create_snapshot)`; the nonce bump sits
                    // BEFORE this point and therefore survives rollback.
                    let create_snapshot = self.state.snapshot();

                    // Create the new account (empty) and install the
                    // init code as its temporary bytecode so the child
                    // frame's get_code lookup can find something to
                    // execute. Value transfer is deliberately NOT done
                    // here — it is delegated to `execute_frame`, which
                    // performs `state.transfer(caller, address, value)`
                    // at frame entry. Doing the transfer in both places
                    // produced a double debit of `create_value` from
                    // the caller, which is the "CREATE fails but
                    // caller loses value twice" bug this fix also
                    // closes.
                    self.state.get_or_create_account(&new_addr);
                    self.state.set_code(&new_addr, init_code).ok();

                    // Execute init code. execute_frame handles the
                    // caller -> new_addr value transfer internally via
                    // its own entry-point transfer + snapshot pair,
                    // and rolls back its own child snapshot on
                    // failure, which automatically reverts that
                    // transfer. On child failure we ALSO rollback
                    // create_snapshot below, which reverts the new
                    // account creation and the temporary set_code.
                    let child_ctx = CallContext {
                        address: new_addr.clone(),
                        code_address: new_addr.clone(),
                        caller: ctx.address.clone(),
                        value: create_value,
                        gas_limit: child_gas,
                        calldata: Vec::new(),
                        is_static: false,
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);

                    match outcome {
                        CallOutcome::Success { gas_used: child_used, return_data: runtime_code, .. } => {
                            gas.return_gas(child_gas.saturating_sub(child_used));
                            if !runtime_code.is_empty() {
                                // Store runtime code
                                self.state.set_code(&new_addr, runtime_code).ok();
                            }
                            self.created_in_tx.insert(new_addr.clone());
                            // Keep all CREATE-side effects: let the
                            // sub-snapshot age into the parent's
                            // snapshot stack via commit so later
                            // snapshots don't observe a stale handle.
                            self.state.commit(create_snapshot).ok();
                            // Push address as U256
                            // Register the new address so later
                            // opcodes that pop its 20-byte body can
                            // resolve it back to this exact string,
                            // then push its canonical body
                            // right-aligned in a U256 (EVM layout).
                            stack.push(self.register_address(&new_addr).to_u256());
                        }
                        _ => {
                            // CREATE failed. Revert every state
                            // change made since create_snapshot:
                            //   - get_or_create_account(new_addr)
                            //   - set_code(new_addr, init_code)
                            //   - any child-frame changes that the
                            //     child's own rollback didn't reach
                            //     (normally none — child rolls back
                            //     via its own snapshot on failure)
                            // The nonce increment, which was done
                            // BEFORE create_snapshot, is preserved
                            // as required by EVM semantics.
                            self.state.rollback(create_snapshot).ok();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::CREATE2 => {
                    // Stack: [value, offset, length, salt] -> [address or 0]
                    if ctx.is_static {
                        if stack.len() >= 4 { stack.pop(); stack.pop(); stack.pop(); stack.pop(); }
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    }
                    if stack.len() < 4 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let create_value = stack.pop().unwrap().as_u64();
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;
                    let salt = stack.pop().unwrap();

                    let init_code = if length > 0 && offset + length <= memory.len() {
                        memory[offset..offset+length].to_vec()
                    } else {
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    };

                    // Charge per-byte + hashing cost
                    let byte_cost = init_code.len() as u64 * CODE_DEPOSIT_GAS_PER_BYTE;
                    let hash_cost = (init_code.len() as u64).div_ceil(32) * CREATE2_WORD_GAS;
                    if let GasResult::OutOfGas { .. } = gas.consume(byte_cost + hash_cost) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    // Same fail-closed rationale as CREATE above: a bogus
                    // deployer prefix must not produce a mainnet-tagged
                    // contract address.
                    let salt_bytes = salt.to_be_bytes();
                    let new_addr = match ContractDeployer::compute_create2_address(
                        &ctx.address, &salt_bytes, &init_code,
                    ) {
                        Ok(addr) => addr,
                        Err(_) => {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                    };

                    // Nonce bump BEFORE sub-snapshot so it survives a
                    // failed CREATE2 — see the full CREATE comment
                    // block above for the rationale.
                    self.state.increment_nonce(&ctx.address).ok();

                    if !self.state.get_code(&new_addr).is_empty() {
                        stack.push(U256::ZERO);
                        pc += 1; continue;
                    }

                    let remaining = gas.gas_remaining();
                    let max_allowed = remaining - remaining / 64;
                    let child_gas = max_allowed;
                    if let GasResult::OutOfGas { .. } = gas.consume(child_gas) {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }

                    // Sub-snapshot AFTER the nonce increment. Any
                    // CREATE2 side effect from here on is reverted on
                    // failure via rollback(create_snapshot); the
                    // nonce bump is not.
                    let create_snapshot = self.state.snapshot();

                    // See CREATE above: value transfer is delegated
                    // to execute_frame so a CREATE2 with value does
                    // not double-debit the caller.
                    self.state.get_or_create_account(&new_addr);
                    self.state.set_code(&new_addr, init_code).ok();

                    let child_ctx = CallContext {
                        address: new_addr.clone(),
                        code_address: new_addr.clone(),
                        caller: ctx.address.clone(),
                        value: create_value,
                        gas_limit: child_gas,
                        calldata: Vec::new(),
                        is_static: false,
                        depth: ctx.depth + 1,
                    };

                    let outcome = self.execute_frame(&child_ctx);

                    match outcome {
                        CallOutcome::Success { gas_used: child_used, return_data: runtime_code, .. } => {
                            gas.return_gas(child_gas.saturating_sub(child_used));
                            if !runtime_code.is_empty() {
                                self.state.set_code(&new_addr, runtime_code).ok();
                            }
                            self.created_in_tx.insert(new_addr.clone());
                            self.state.commit(create_snapshot).ok();
                            // Register the new address so later
                            // opcodes that pop its 20-byte body can
                            // resolve it back to this exact string,
                            // then push its canonical body
                            // right-aligned in a U256 (EVM layout).
                            stack.push(self.register_address(&new_addr).to_u256());
                        }
                        _ => {
                            // Revert every state change made since
                            // create_snapshot (new account creation,
                            // temporary init code install) while
                            // preserving the nonce increment above.
                            self.state.rollback(create_snapshot).ok();
                            stack.push(U256::ZERO);
                        }
                    }
                }

                OpCode::SELFDESTRUCT => {
                    // Stack: [beneficiary]
                    if ctx.is_static {
                        if !stack.is_empty() { stack.pop(); }
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    if stack.is_empty() { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let beneficiary_val = stack.pop().unwrap();
                    // Resolve the beneficiary body back to its
                    // ShadowDAG string via the runtime registry. This
                    // is the same fix as BALANCE / CALL / etc. — a
                    // SELFDESTRUCT that forwards its balance to the
                    // CALLER pushed via the CALLER opcode must target
                    // the actual caller address, not a hex-encoded
                    // stack blob.
                    let beneficiary = self.resolve_address(beneficiary_val);

                    // EIP-6780: only full destruct if created in same tx
                    if self.created_in_tx.contains(&ctx.address) {
                        let balance = self.state.get_balance(&ctx.address);
                        if balance > 0 {
                            self.state.transfer(&ctx.address, &beneficiary, balance).ok();
                        }
                        self.state.destroy_account(&ctx.address).ok();
                        self.destroyed_contracts.insert(ctx.address.clone());
                    } else {
                        // Post EIP-6780: only transfer balance, don't destroy
                        let balance = self.state.get_balance(&ctx.address);
                        if balance > 0 {
                            self.state.transfer(&ctx.address, &beneficiary, balance).ok();
                        }
                    }

                    self.state.commit(snapshot).ok();
                    return CallOutcome::Success {
                        gas_used: gas.effective_gas_used(),
                        return_data: Vec::new(),
                        logs,
                    };
                }

                // ── Context (extended) ───────────────────────
                OpCode::ADDRESS => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    // Push the current frame's 20-byte canonical body
                    // right-aligned in a U256 (EVM layout). See CALLER
                    // above for the round-trip rationale.
                    stack.push(VmAddressBody::from_any(&ctx.address).to_u256());
                }
                OpCode::PC => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(pc as u64));
                }
                OpCode::GAS => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(gas.gas_remaining()));
                }
                OpCode::GASLIMIT => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(ctx.gas_limit));
                }

                // ── Memory (extended) ───────────────────────
                OpCode::MSTORE8 => {
                    let (offset_val, val) = pop2!(stack, gas, snapshot, self);
                    let offset = offset_val.as_u64() as usize;
                    if offset + 1 > MAX_MEMORY_SIZE {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    while memory.len() <= offset { memory.push(0); }
                    memory[offset] = (val.as_u64() & 0xFF) as u8;
                }
                OpCode::MSIZE => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    // Round up to nearest multiple of 32
                    let size = memory.len().div_ceil(32) * 32;
                    stack.push(U256::from_u64(size as u64));
                }

                // ── Logging (with topics) ───────────────────
                OpCode::LOG1 | OpCode::LOG2 | OpCode::LOG3 | OpCode::LOG4 => {
                    if ctx.is_static {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    let num_topics = match op {
                        OpCode::LOG1 => 1usize,
                        OpCode::LOG2 => 2,
                        OpCode::LOG3 => 3,
                        OpCode::LOG4 => 4,
                        _ => unreachable!(),
                    };
                    // Need offset + length + num_topics items on stack
                    if stack.len() < 2 + num_topics {
                        self.state.rollback(snapshot).ok();
                        return CallOutcome::Failure { gas_used: gas.gas_used() };
                    }
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;
                    let mut topics = Vec::with_capacity(num_topics);
                    for _ in 0..num_topics {
                        topics.push(stack.pop().unwrap());
                    }
                    // Read data from memory
                    let data = if length > 0 && offset + length <= memory.len() {
                        memory[offset..offset + length].to_vec()
                    } else if length == 0 {
                        Vec::new()
                    } else {
                        // Extend memory if needed
                        while memory.len() < offset + length { memory.push(0); }
                        memory[offset..offset + length].to_vec()
                    };
                    logs.push(LogEntry {
                        contract: ctx.address.clone(),
                        topics,
                        data,
                    });
                }

                // ── Call data ───────────────────────────────
                OpCode::CALLDATALOAD => {
                    let offset = pop1!(stack, gas, snapshot, self).as_u64() as usize;
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let mut buf = [0u8; 32];
                    for (i, byte) in buf.iter_mut().enumerate() {
                        if offset + i < ctx.calldata.len() {
                            *byte = ctx.calldata[offset + i];
                        }
                    }
                    stack.push(U256::from_be_bytes(&buf));
                }
                OpCode::CALLDATASIZE => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(ctx.calldata.len() as u64));
                }
                OpCode::CALLDATACOPY => {
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let dest = stack.pop().unwrap().as_u64() as usize;
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;
                    if length > 0 {
                        if dest + length > MAX_MEMORY_SIZE {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                        while memory.len() < dest + length { memory.push(0); }
                        for i in 0..length {
                            memory[dest + i] = if offset + i < ctx.calldata.len() { ctx.calldata[offset + i] } else { 0 };
                        }
                    }
                }
                OpCode::CODESIZE => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(code.len() as u64));
                }
                OpCode::CODECOPY => {
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let dest = stack.pop().unwrap().as_u64() as usize;
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;
                    if length > 0 {
                        if dest + length > MAX_MEMORY_SIZE {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                        while memory.len() < dest + length { memory.push(0); }
                        for i in 0..length {
                            memory[dest + i] = if offset + i < code.len() { code[offset + i] } else { 0 };
                        }
                    }
                }
                OpCode::EXTCODESIZE => {
                    let addr_val = pop1!(stack, gas, snapshot, self);
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    // Resolve the popped body back to its ShadowDAG
                    // address via the runtime registry so the code
                    // lookup hits the same key the contract was
                    // stored under (matches BALANCE / CALL above).
                    let addr = self.resolve_address(addr_val);
                    let ext_code = self.state.get_code(&addr);
                    stack.push(U256::from_u64(ext_code.len() as u64));
                }
                OpCode::RETURNDATASIZE => {
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    stack.push(U256::from_u64(self.last_return_data.len() as u64));
                }
                OpCode::RETURNDATACOPY => {
                    if stack.len() < 3 { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let dest = stack.pop().unwrap().as_u64() as usize;
                    let offset = stack.pop().unwrap().as_u64() as usize;
                    let length = stack.pop().unwrap().as_u64() as usize;
                    if length > 0 {
                        // Bounds check against return data (EIP-211)
                        if offset + length > self.last_return_data.len() {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                        if dest + length > MAX_MEMORY_SIZE {
                            self.state.rollback(snapshot).ok();
                            return CallOutcome::Failure { gas_used: gas.gas_used() };
                        }
                        while memory.len() < dest + length { memory.push(0); }
                        memory[dest..dest + length].copy_from_slice(&self.last_return_data[offset..offset + length]);
                    }
                }

                // ── Extended stack (DUP2-DUP8, SWAP2-SWAP4) ─
                OpCode::DUP2 | OpCode::DUP3 | OpCode::DUP4 | OpCode::DUP5 |
                OpCode::DUP6 | OpCode::DUP7 | OpCode::DUP8 => {
                    let n = match op {
                        OpCode::DUP2 => 2usize,
                        OpCode::DUP3 => 3,
                        OpCode::DUP4 => 4,
                        OpCode::DUP5 => 5,
                        OpCode::DUP6 => 6,
                        OpCode::DUP7 => 7,
                        OpCode::DUP8 => 8,
                        _ => unreachable!(),
                    };
                    if stack.len() < n { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    if stack.len() >= MAX_STACK_SIZE { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let idx = stack.len() - n;
                    let val = stack[idx];
                    stack.push(val);
                }
                OpCode::SWAP2 | OpCode::SWAP3 | OpCode::SWAP4 => {
                    let n = match op {
                        OpCode::SWAP2 => 3usize, // swap top with 3rd from top
                        OpCode::SWAP3 => 4,       // swap top with 4th from top
                        OpCode::SWAP4 => 5,       // swap top with 5th from top
                        _ => unreachable!(),
                    };
                    if stack.len() < n { self.state.rollback(snapshot).ok(); return CallOutcome::Failure { gas_used: gas.gas_used() }; }
                    let len = stack.len();
                    stack.swap(len - 1, len - n);
                }

                OpCode::INVALID => {
                    self.state.rollback(snapshot).ok();
                    return CallOutcome::Failure { gas_used: gas.gas_used() };
                }

                // All opcodes are covered — INVALID terminates above
            }

            pc += 1;
        }

        // End of bytecode -- implicit STOP
        self.state.commit(snapshot).ok();
        CallOutcome::Success {
            gas_used: gas.effective_gas_used(),
            return_data,
            logs,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Check if a hex address string maps to a precompile (0x01-0x09).
/// Precompile addresses are the low addresses: "0000...01" through "0000...09".
fn is_precompile_addr(addr: &str) -> Option<u8> {
    let trimmed = addr.trim_start_matches('0');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() <= 2 {
        if let Ok(n) = u8::from_str_radix(trimmed, 16) {
            if (1..=9).contains(&n) {
                return Some(n);
            }
        }
    }
    None
}

/// Parse a storage value to U256 (deterministic: hex > decimal > zero)
fn parse_storage_value(s: &str) -> U256 {
    if let Some(hex_str) = s.strip_prefix("0x") {
        U256::from_hex(hex_str).unwrap_or(U256::ZERO)
    } else if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
        U256::from_u64(s.parse::<u64>().unwrap_or(0))
    } else {
        U256::ZERO
    }
}

/// Find valid JUMPDEST positions in bytecode
fn find_jump_dests(code: &[u8]) -> HashSet<usize> {
    let mut dests = HashSet::new();
    let mut i = 0;
    while i < code.len() {
        let op = OpCode::from_byte(code[i]);
        if op == OpCode::JUMPDEST {
            dests.insert(i);
        }
        // Skip push data
        match op {
            OpCode::PUSH1 => i += 2,
            OpCode::PUSH2 => i += 3,
            OpCode::PUSH4 => i += 5,
            OpCode::PUSH8 => i += 9,
            OpCode::PUSH16 => i += 17,
            OpCode::PUSH32 => i += 33,
            _ => i += 1,
        }
    }
    dests
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(BlockContext {
            timestamp: 1000,
            block_hash: "00".repeat(32),
            network: "mainnet".to_string(),
        })
    }

    #[test]
    fn simple_add_returns_success() {
        let mut env = make_env();
        // PUSH1 5, PUSH1 3, ADD, STOP
        let code: Vec<u8> = vec![
            0x10, 5,   // PUSH1 5
            0x10, 3,   // PUSH1 3
            0x20,      // ADD
            0x00,      // STOP
        ];
        env.state.set_code("contract1", code.clone()).unwrap();
        let ctx = CallContext {
            address: "contract1".into(),
            code_address: "contract1".into(),
            caller: "user1".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));
    }

    #[test]
    fn staticcall_rejects_sstore() {
        let mut env = make_env();
        // PUSH1 42, PUSH1 0, SSTORE -- should fail in static context
        let code: Vec<u8> = vec![
            0x10, 42,  // PUSH1 42
            0x10, 0,   // PUSH1 0
            0x51,      // SSTORE
        ];
        env.state.set_code("target", code).unwrap();
        let ctx = CallContext {
            address: "target".into(),
            code_address: "target".into(),
            caller: "user1".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: true,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        // SSTORE in static context -> Failure
        assert!(matches!(result, CallOutcome::Failure { .. }));
    }

    #[test]
    fn call_depth_limit_enforced() {
        let mut env = make_env();
        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: MAX_CALL_DEPTH + 1,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }));
    }

    #[test]
    fn call_depth_limit_at_exact_max_rejects() {
        // Regression for the off-by-one in the depth check. The old
        // check was `ctx.depth > MAX_CALL_DEPTH`, which allowed a
        // frame at `depth == MAX_CALL_DEPTH` to execute — 1025
        // frames total instead of the EVM-standard 1024. The new
        // check `ctx.depth >= MAX_CALL_DEPTH` rejects the 1025th
        // frame exactly at the boundary, so the valid range of
        // `ctx.depth` is `0..MAX_CALL_DEPTH` (inclusive-exclusive).
        let mut env = make_env();
        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: MAX_CALL_DEPTH, // exactly at the boundary
        };
        let result = env.execute_frame(&ctx);
        assert!(
            matches!(result, CallOutcome::Failure { .. }),
            "ctx.depth == MAX_CALL_DEPTH must be rejected (1025th frame is one past the EVM limit), got: {:?}",
            result
        );
    }

    #[test]
    fn call_depth_limit_one_below_max_passes_depth_check() {
        // Complement of the boundary-rejection test: the frame at
        // `ctx.depth == MAX_CALL_DEPTH - 1` is the LAST allowed
        // frame (the 1024th frame), and the depth check must let it
        // through. We can't easily check that `execute_frame` runs
        // the contract to completion here because the target has no
        // code, so `execute_frame` takes the "empty-code success"
        // fast-path and returns `Success`. That's still sufficient
        // to prove the depth check did NOT short-circuit to Failure,
        // which is the regression we care about.
        let mut env = make_env();
        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: MAX_CALL_DEPTH - 1, // last allowed frame
        };
        let result = env.execute_frame(&ctx);
        assert!(
            matches!(result, CallOutcome::Success { .. }),
            "ctx.depth == MAX_CALL_DEPTH - 1 is the last allowed frame and must not be rejected by the depth check, got: {:?}",
            result
        );
    }

    #[test]
    fn call_transfers_value() {
        let mut env = make_env();
        env.state.set_balance("caller", 1000).unwrap();
        // Target has code that just STOPs
        env.state.set_code("target", vec![0x00]).unwrap(); // STOP

        let ctx = CallContext {
            address: "target".into(),
            code_address: "target".into(),
            caller: "caller".into(),
            value: 100,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));
        assert_eq!(env.state.get_balance("caller"), 900);
        assert_eq!(env.state.get_balance("target"), 100);
    }

    #[test]
    fn selfdestruct_eip6780_same_tx() {
        let mut env = make_env();
        env.state.set_balance("contract", 500).unwrap();
        env.state.set_code("contract", vec![0x00]).unwrap();
        env.created_in_tx.insert("contract".into());

        // Bytecode: PUSH1 0xFF (beneficiary), SELFDESTRUCT
        let code: Vec<u8> = vec![
            0x10, 0xFF, // PUSH1 0xFF (beneficiary address)
            0xB8,       // SELFDESTRUCT
        ];
        env.state.set_code("contract", code).unwrap();
        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));
        assert!(env.destroyed_contracts.contains("contract"));
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Integration tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn deploy_and_call_contract() {
        // Deploy: code that stores calldata[0..32] into slot 0, then STOPs
        // PUSH1 0 (offset), CALLDATALOAD, PUSH1 0 (slot), SSTORE, STOP
        let runtime_code: Vec<u8> = vec![
            0x10, 0,    // PUSH1 0 (offset)
            0xC0,       // CALLDATALOAD
            0x10, 0,    // PUSH1 0 (slot)
            0x51,       // SSTORE  (stores calldata[0..32] at slot 0)
            0x00,       // STOP
        ];

        let mut env = make_env();
        env.state.set_code("contract1", runtime_code).unwrap();

        // Call with calldata = [0,0,0,...,42] (U256 value 42)
        let mut calldata = vec![0u8; 32];
        calldata[31] = 42; // big-endian: value = 42

        let ctx = CallContext {
            address: "contract1".into(),
            code_address: "contract1".into(),
            caller: "user1".into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata,
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }), "Contract call should succeed");

        // Verify storage was written
        let stored = env.state.storage_load("contract1", "slot:0");
        assert!(stored.is_some(), "Slot 0 should have a value");
    }

    #[test]
    fn failed_create_rolls_back_side_effects_but_keeps_nonce() {
        // Regression for two adjacent bugs in the CREATE opcode
        // handler:
        //
        //   1. Failed CREATE left the new-address account creation
        //      and the temporary init-code install on the parent's
        //      state. EVM semantics require these to be reverted on
        //      failure; only the caller's nonce bump survives.
        //
        //   2. The parent-level `state.transfer(caller, new_addr,
        //      create_value)` happened BEFORE the child frame, and
        //      then execute_frame's own entry-level transfer re-ran
        //      the transfer a SECOND time — a CREATE with value > 0
        //      silently double-debited the caller.
        //
        // The fix defers the transfer entirely to execute_frame's
        // own entry path and adds a sub-snapshot after the nonce
        // bump so the new-account + set_code side effects are
        // reverted on failure.
        //
        // Test bytecode for contract_a:
        //   1. MSTORE a 32-byte word whose last 5 bytes encode an
        //      init code that PUSH1 0 PUSH1 0 REVERT (i.e. reverts
        //      immediately).
        //   2. CREATE with value=50, offset=27, length=5 — the
        //      init code will revert, so CREATE must return 0 on
        //      the stack AND leave contract_a's balance unchanged.
        let mut env = make_env();
        let parent = "SD1parent";
        env.state.set_balance(parent, 1_000).unwrap();

        // Init code bytes: PUSH1 0, PUSH1 0, REVERT (0x10 00 0x10 00 0xB7)
        //
        // Container bytecode for the parent, built by hand:
        //   PUSH32 <27 zero bytes + [0x10, 0x00, 0x10, 0x00, 0xB7]>
        //   PUSH1  0       (MSTORE offset)
        //   MSTORE         (mem[0..32] = the word)
        //   PUSH1  5       (CREATE length)
        //   PUSH1  27      (CREATE offset)
        //   PUSH1  50      (CREATE value)
        //   CREATE
        //   STOP
        let mut code_a: Vec<u8> = Vec::with_capacity(64);
        code_a.push(0x15); // PUSH32
        for _ in 0..27 { code_a.push(0x00); }
        code_a.extend_from_slice(&[0x10, 0x00, 0x10, 0x00, 0xB7]);
        code_a.extend_from_slice(&[
            0x10, 0x00,   // PUSH1 0   (MSTORE offset)
            0x91,         // MSTORE
            0x10, 0x05,   // PUSH1 5   (CREATE length)
            0x10, 0x1B,   // PUSH1 27  (CREATE offset)
            0x10, 0x32,   // PUSH1 50  (CREATE value)
            0xB4,         // CREATE
            0x00,         // STOP
        ]);
        env.state.set_code(parent, code_a).unwrap();

        // Snapshot the pre-CREATE state
        let bal_before = env.state.get_balance(parent);
        let nonce_before = env.state.get_nonce(parent);
        assert_eq!(bal_before, 1_000);

        let ctx = CallContext {
            address: parent.into(),
            code_address: parent.into(),
            caller: "SD1user".into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let outcome = env.execute_frame(&ctx);
        assert!(
            matches!(outcome, CallOutcome::Success { .. }),
            "parent frame itself must succeed (CREATE failure is an in-frame failure, not a frame failure), got: {:?}",
            outcome
        );

        // Nonce must be incremented — EVM preserves the nonce bump
        // across a failed CREATE.
        assert_eq!(
            env.state.get_nonce(parent),
            nonce_before + 1,
            "caller's nonce must be incremented even on failed CREATE"
        );

        // Balance must be unchanged: execute_frame rolls back its own
        // entry-level transfer when the child frame fails, and we no
        // longer do a second parent-level transfer that the old code
        // would have left behind as a double debit.
        assert_eq!(
            env.state.get_balance(parent),
            bal_before,
            "failed CREATE must not debit the caller (regression for the \
             double-transfer bug: old code debited `create_value` at the \
             parent level before calling execute_frame, then execute_frame \
             debited again, so a failed CREATE with value left the caller \
             short by `create_value`)"
        );

        // The new contract address must have no code installed —
        // rollback(create_snapshot) must have undone the temporary
        // init-code set_code. Compute the expected address the same
        // way the CREATE handler does.
        let expected_addr = crate::runtime::vm::contracts::contract_deployer::ContractDeployer::compute_create_address(parent, nonce_before).unwrap();
        assert!(
            env.state.get_code(&expected_addr).is_empty(),
            "failed CREATE must not leave init code installed at the new address ({})",
            expected_addr
        );
    }

    #[test]
    fn caller_balance_round_trips_via_address_registry() {
        // Regression for the address-encoding mismatch. The old
        // CALLER opcode pushed `U256::from_hex(hex::encode(addr.as_bytes()))`
        // onto the stack — for any real 43/44-char ShadowDAG address
        // the resulting 88-char hex string exceeded
        // `U256::from_hex`'s 64-char limit and silently fell back to
        // `U256::ZERO`, so `CALLER` literally pushed 0. The matching
        // BALANCE opcode then called `to_hex()` on the popped word
        // (a 64-char hex string of all zeros) and looked up the
        // wrong key in state, returning 0 instead of the actual
        // caller balance.
        //
        // With the VmAddressBody fix:
        //   1. `register_address(&ctx.caller)` at frame entry maps the
        //      caller's canonical 20-byte body to the full ShadowDAG
        //      address string.
        //   2. CALLER pushes `VmAddressBody::from_any(&ctx.caller).to_u256()`,
        //      the 20-byte body right-aligned in a 32-byte U256.
        //   3. BALANCE pops, extracts the low 20 bytes, and looks
        //      them up in the address registry, recovering the
        //      original `ctx.caller` string and the correct balance.
        //
        // Test flow:
        //   - Pre-fund caller "SD1cAAAA...AA" (canonical mainnet
        //     contract address) with 7777 units.
        //   - Deploy a contract whose bytecode is
        //         CALLER BALANCE PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
        //     i.e. it returns the caller's balance as a 32-byte word.
        //   - Invoke it with that caller; assert the returned U256
        //     equals 7777 (not 0).
        let mut env = make_env();
        // Use a canonical SD1c address so we can reason about the
        // registry hit — derive_from_nonstandard would work too, but
        // the canonical path is the one that used to overflow the
        // 64-char hex limit and fall back to zero.
        let caller: String = format!("SD1c{}", "a".repeat(40));
        env.state.set_balance(&caller, 7_777).unwrap();

        // CALLER → BALANCE → MSTORE(0) → RETURN(0, 32)
        // Opcodes (from v1_spec.rs): CALLER=0x70, BALANCE=0x74,
        // MSTORE=0x91, RETURN=0xB6, PUSH1=0x10.
        let code: Vec<u8> = vec![
            0x70,        // CALLER
            0x74,        // BALANCE
            0x10, 0,     // PUSH1 0        (MSTORE offset)
            0x91,        // MSTORE
            0x10, 32,    // PUSH1 32       (RETURN length)
            0x10, 0,     // PUSH1 0        (RETURN offset)
            0xB6,        // RETURN
        ];
        env.state.set_code("contract", code).unwrap();

        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: caller.clone(),
            value: 0,
            gas_limit: 1_000_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let outcome = env.execute_frame(&ctx);
        let return_data = match outcome {
            CallOutcome::Success { return_data, .. } => return_data,
            other => panic!(
                "CALLER/BALANCE round-trip must succeed against a \
                 canonical ShadowDAG caller address, got: {:?}",
                other
            ),
        };
        assert_eq!(
            return_data.len(),
            32,
            "RETURN must emit exactly one 32-byte word, got {} bytes",
            return_data.len()
        );

        // Decode the 32-byte big-endian word back into a u64 — the
        // low 8 bytes hold the balance, the high 24 are zero.
        let mut high_buf = [0u8; 24];
        high_buf.copy_from_slice(&return_data[..24]);
        assert_eq!(
            high_buf, [0u8; 24],
            "high 24 bytes of BALANCE result must be zero, got: {:?}",
            high_buf
        );
        let mut low_buf = [0u8; 8];
        low_buf.copy_from_slice(&return_data[24..32]);
        let returned_balance = u64::from_be_bytes(low_buf);
        assert_eq!(
            returned_balance, 7_777,
            "BALANCE(CALLER) must return the caller's actual balance \
             (pre-funded to 7_777) — the old hex-encoded round-trip \
             returned 0 here because `CALLER` pushed U256::ZERO \
             silently. Got: {}",
            returned_balance
        );
    }

    #[test]
    fn call_opcode_charges_new_account_gas_on_fresh_target() {
        // Regression for the dead NEW_ACCOUNT_GAS constant. EIP-150
        // requires a CALL opcode that transfers value to a NON-EXISTENT
        // account to pay NEW_ACCOUNT_GAS (25_000) on top of the usual
        // CALL_VALUE_TRANSFER_GAS (9_000), because the transfer will
        // materialize the account as a side effect of set_balance.
        // The old CALL path only charged CALL_VALUE_TRANSFER_GAS and
        // left NEW_ACCOUNT_GAS as a dead constant.
        //
        // We prove the fix by running the same contract twice with
        // identical bytecode and gas schedule, differing only in
        // whether the target address already exists in state before
        // the CALL runs. The gas delta between the two runs must be
        // exactly NEW_ACCOUNT_GAS — that isolates the surcharge from
        // all other gas costs, which are identical.
        //
        // The CALL target is the ShadowDAG canonical reconstruction of
        // the 20-byte body `[0u8; 19, 0x0a]` — i.e. the body produced
        // by `PUSH1 0x0a`. `resolve_address` reconstructs this as
        // `"SD1c" + hex([0u8; 19, 0x0a])`, a 44-char mainnet contract
        // address. 0x0a is not in the precompile range 0x01..=0x09,
        // so the "precompiles are always existing" fast path is not
        // taken.
        fn run_call_scenario(preexist_target: bool) -> u64 {
            let mut env = make_env();
            env.state.set_balance("user", 10_000).unwrap();

            // Bytecode: CALL to 0x0a with value=50, then STOP.
            // Stack order for CALL: gas, addr, value, argsOffset,
            // argsLen, retOffset, retLen — pushed in reverse.
            let code_a: Vec<u8> = vec![
                0x10, 0,     // PUSH1 0 (retLen)
                0x10, 0,     // PUSH1 0 (retOffset)
                0x10, 0,     // PUSH1 0 (argsLen)
                0x10, 0,     // PUSH1 0 (argsOffset)
                0x10, 50,    // PUSH1 50 (value)
                0x10, 0x0a,  // PUSH1 0x0a (target addr — fresh in one run)
                0x12, 0x00, 0x00, 0xC3, 0x50, // PUSH4 50000 (gas)
                0xB0,        // CALL
                0x00,        // STOP
            ];
            env.state.set_code("contract_a", code_a).unwrap();
            env.state.set_balance("contract_a", 1_000).unwrap();

            if preexist_target {
                // `resolve_address` reconstructs the PUSH1 0x0a body as
                // "SD1c" + hex([0u8; 19, 0x0a]). Pre-materialize the
                // account at that EXACT key so the CALL's target_is_new
                // check sees it as already existing. The address is
                // the 44-char mainnet contract form.
                let mut body = [0u8; 20];
                body[19] = 0x0a;
                let target_key = format!("SD1c{}", hex::encode(body));
                env.state.set_balance(&target_key, 0).unwrap();
            }

            let ctx = CallContext {
                address: "contract_a".into(),
                code_address: "contract_a".into(),
                caller: "user".into(),
                value: 0,
                gas_limit: 1_000_000,
                calldata: vec![],
                is_static: false,
                depth: 0,
            };
            match env.execute_frame(&ctx) {
                CallOutcome::Success { gas_used, .. } => gas_used,
                other => panic!(
                    "expected Success (preexist_target={}), got: {:?}",
                    preexist_target, other
                ),
            }
        }

        let gas_fresh = run_call_scenario(false);
        let gas_existing = run_call_scenario(true);
        let delta = gas_fresh.saturating_sub(gas_existing);
        assert_eq!(
            delta, NEW_ACCOUNT_GAS,
            "CALL with value to a fresh target must charge exactly \
             NEW_ACCOUNT_GAS ({}) more than the same CALL to an existing \
             target; fresh={} existing={} delta={}",
            NEW_ACCOUNT_GAS, gas_fresh, gas_existing, delta
        );
    }

    #[test]
    fn contract_a_calls_contract_b() {
        let mut env = make_env();
        env.state.set_balance("user", 10000).unwrap();

        // Contract B: just stores CALLVALUE into slot 0, then STOP
        // CALLVALUE, PUSH1 0, SSTORE, STOP
        let code_b: Vec<u8> = vec![0x71, 0x10, 0, 0x51, 0x00];
        env.state.set_code("contract_b", code_b).unwrap();

        // Contract A: CALLs contract B with value=50
        // Stack for CALL: gas, addr, value, argsOffset, argsLen, retOffset, retLen
        // We push in reverse order so the first pop is gas:
        // PUSH1 0 (retLen), PUSH1 0 (retOffset), PUSH1 0 (argsLen), PUSH1 0 (argsOffset),
        // PUSH1 50 (value), PUSH1 addr, PUSH4 gas, CALL, STOP
        //
        // Set up contract B also at address "0b" so we can push a small numeric address
        env.state.set_code("0b", vec![0x71, 0x10, 0, 0x51, 0x00]).unwrap();

        let code_a: Vec<u8> = vec![
            0x10, 0,     // PUSH1 0 (retLen)
            0x10, 0,     // PUSH1 0 (retOffset)
            0x10, 0,     // PUSH1 0 (argsLen)
            0x10, 0,     // PUSH1 0 (argsOffset)
            0x10, 50,    // PUSH1 50 (value)
            0x10, 0x0b,  // PUSH1 0x0b (target addr)
            0x12, 0x00, 0x00, 0xC3, 0x50, // PUSH4 50000 (gas)
            0xB0,        // CALL
            0x00,        // STOP
        ];
        env.state.set_code("contract_a", code_a).unwrap();
        env.state.set_balance("contract_a", 1000).unwrap();

        let ctx = CallContext {
            address: "contract_a".into(),
            code_address: "contract_a".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }), "A calling B should succeed");
    }

    #[test]
    fn staticcall_prevents_sstore_in_nested_call() {
        let mut env = make_env();

        // Target contract tries SSTORE -- should fail under STATICCALL
        env.state.set_code("target", vec![0x10, 1, 0x10, 0, 0x51, 0x00]).unwrap();

        let ctx = CallContext {
            address: "target".into(),
            code_address: "target".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: true,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }), "SSTORE in static context must fail");

        // Verify no storage was written
        assert!(env.state.storage_load("target", "slot:0").is_none());
    }

    #[test]
    fn delegatecall_writes_to_callers_storage() {
        let mut env = make_env();

        // Library code: stores value 42 in slot 0, then STOP
        // PUSH1 42, PUSH1 0, SSTORE, STOP
        env.state.set_code("library", vec![0x10, 42, 0x10, 0, 0x51, 0x00]).unwrap();

        // Execute via DELEGATECALL context: address="caller_contract" but code_address="library"
        let ctx = CallContext {
            address: "caller_contract".into(),     // storage context
            code_address: "library".into(),        // code source
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));

        // Storage written to CALLER's contract, not library's
        assert!(env.state.storage_load("caller_contract", "slot:0").is_some(),
            "Storage should be in caller_contract");
        assert!(env.state.storage_load("library", "slot:0").is_none(),
            "Library storage should be untouched");
    }

    #[test]
    fn revert_discards_all_state() {
        let mut env = make_env();

        // Contract: SSTORE(slot=0, val=99), then REVERT
        // PUSH1 99, PUSH1 0, SSTORE, PUSH1 0, PUSH1 0, REVERT
        let code: Vec<u8> = vec![
            0x10, 99,   // PUSH1 99
            0x10, 0,    // PUSH1 0
            0x51,       // SSTORE
            0x10, 0,    // PUSH1 0 (size)
            0x10, 0,    // PUSH1 0 (offset)
            0xB7,       // REVERT
        ];
        env.state.set_code("contract", code).unwrap();

        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 100_000,
            calldata: vec![],
            is_static: false,
            depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Revert { .. }));

        // Storage should NOT have the value (reverted)
        assert!(env.state.storage_load("contract", "slot:0").is_none(),
            "REVERT should discard SSTORE");
    }

    #[test]
    fn calldatasize_returns_correct_length() {
        let mut env = make_env();
        // CALLDATASIZE, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let code: Vec<u8> = vec![
            0xC1,       // CALLDATASIZE
            0x10, 0,    // PUSH1 0
            0x91,       // MSTORE
            0x10, 32,   // PUSH1 32
            0x10, 0,    // PUSH1 0
            0xB6,       // RETURN
        ];
        env.state.set_code("c", code).unwrap();

        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![1, 2, 3, 4, 5], // 5 bytes
            is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 32);
                // Last byte should be 5 (calldata length)
                assert_eq!(return_data[31], 5);
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn return_data_from_memory() {
        let mut env = make_env();
        // Store 0xDEAD in memory[0..32], then RETURN(offset=30, size=2)
        // PUSH2 0xDEAD, PUSH1 0, MSTORE, PUSH1 2, PUSH1 30, RETURN
        let code: Vec<u8> = vec![
            0x11, 0xDE, 0xAD, // PUSH2 0xDEAD
            0x10, 0,           // PUSH1 0
            0x91,              // MSTORE
            0x10, 2,           // PUSH1 2 (size)
            0x10, 30,          // PUSH1 30 (offset)
            0xB6,              // RETURN
        ];
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 2);
                assert_eq!(return_data, vec![0xDE, 0xAD]);
            }
            _ => panic!("Expected success with return data"),
        }
    }

    #[test]
    fn out_of_gas_returns_failure() {
        let mut env = make_env();
        // Infinite loop: JUMPDEST, PUSH1 0, JUMP
        let code: Vec<u8> = vec![
            0x82,      // JUMPDEST at position 0
            0x10, 0,   // PUSH1 0
            0x80,      // JUMP back to 0
        ];
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0,
            gas_limit: 100, // Very low gas
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }), "Should run out of gas");
    }

    #[test]
    fn storage_persists_across_calls() {
        let mut env = make_env();

        // First call: store value 77 in slot 5
        // PUSH1 77, PUSH1 5, SSTORE, STOP
        let code: Vec<u8> = vec![0x10, 77, 0x10, 5, 0x51, 0x00];
        env.state.set_code("c", code).unwrap();

        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        env.execute_frame(&ctx);

        // Second call: load slot 5, store it in slot 6
        // PUSH1 5, SLOAD, PUSH1 6, SSTORE, STOP
        let code2: Vec<u8> = vec![0x10, 5, 0x50, 0x10, 6, 0x51, 0x00];
        env.state.set_code("c", code2).unwrap();

        let ctx2 = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx2);
        assert!(matches!(result, CallOutcome::Success { .. }));

        // Verify slot 6 has the value copied from slot 5
        let val = env.state.storage_load("c", "slot:6");
        assert!(val.is_some(), "Slot 6 should have value copied from slot 5");
    }

    #[test]
    fn codesize_returns_correct_value() {
        let mut env = make_env();
        // CODESIZE, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let code: Vec<u8> = vec![
            0xC3,       // CODESIZE
            0x10, 0,    // PUSH1 0
            0x91,       // MSTORE
            0x10, 32,   // PUSH1 32 (size)
            0x10, 0,    // PUSH1 0 (offset)
            0xB6,       // RETURN
        ];
        let code_len = code.len(); // 9 bytes
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 32);
                assert_eq!(return_data[31], code_len as u8, "CODESIZE should equal code length");
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn log_emits_event_entry() {
        let mut env = make_env();
        // PUSH1 0xFF, LOG0, STOP
        let code: Vec<u8> = vec![
            0x10, 0xFF, // PUSH1 0xFF (data value)
            0xA0,       // LOG0
            0x00,       // STOP
        ];
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { logs, .. } => {
                assert!(!logs.is_empty(), "Should have at least one log entry");
                assert_eq!(logs[0].contract, "c");
            }
            _ => panic!("Expected success with logs"),
        }
    }

    #[test]
    fn dup2_duplicates_second_element() {
        let mut env = make_env();
        // PUSH1 10, PUSH1 20, DUP2 (should dup 10), PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let code: Vec<u8> = vec![
            0x10, 10,   // PUSH1 10  (bottom)
            0x10, 20,   // PUSH1 20  (top)
            0xD0,       // DUP2 (duplicate 10)
            0x10, 0,    // PUSH1 0
            0x91,       // MSTORE
            0x10, 32,   // PUSH1 32
            0x10, 0,    // PUSH1 0
            0xB6,       // RETURN
        ];
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { return_data, .. } => {
                assert_eq!(return_data[31], 10, "DUP2 should duplicate second element (10)");
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn selfdestruct_not_same_tx_only_transfers() {
        let mut env = make_env();
        env.state.set_balance("contract", 500).unwrap();
        env.state.set_balance("beneficiary", 100).unwrap();
        // NOT in created_in_tx -- so EIP-6780 means only transfer, no destroy

        let code: Vec<u8> = vec![
            0x10, 0x01, // PUSH1 1 (beneficiary addr as small number)
            0xB8,       // SELFDESTRUCT
        ];
        env.state.set_code("contract", code).unwrap();
        let ctx = CallContext {
            address: "contract".into(), code_address: "contract".into(),
            caller: "user".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));
        // Contract should NOT be in destroyed set (EIP-6780)
        assert!(!env.destroyed_contracts.contains("contract"),
            "Contract not created in this tx should NOT be destroyed");
    }

    #[test]
    fn call_with_insufficient_balance_fails() {
        let mut env = make_env();
        env.state.set_balance("sender", 10).unwrap(); // Only 10
        env.state.set_code("target", vec![0x00]).unwrap(); // STOP

        // Try to send 1000 (more than balance)
        let ctx = CallContext {
            address: "target".into(), code_address: "target".into(),
            caller: "sender".into(), value: 1000, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }), "Insufficient balance should fail");
    }

    #[test]
    fn gas_opcode_returns_remaining() {
        let mut env = make_env();
        // GAS, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let code: Vec<u8> = vec![
            0x03,       // GAS
            0x10, 0,    // PUSH1 0
            0x91,       // MSTORE
            0x10, 32,   // PUSH1 32
            0x10, 0,    // PUSH1 0
            0xB6,       // RETURN
        ];
        env.state.set_code("c", code).unwrap();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 100_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { return_data, .. } => {
                // Gas should be a non-zero value less than 100_000
                let gas_val = return_data.iter().fold(0u64, |acc, &b| acc * 256 + b as u64);
                assert!(gas_val > 0 && gas_val < 100_000,
                    "GAS should return remaining gas, got {}", gas_val);
            }
            _ => panic!("Expected success"),
        }
    }
}
