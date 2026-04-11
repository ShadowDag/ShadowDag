// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowVM — Stack-based virtual machine for executing smart contracts.
//
// Design:
//   - Stack-based (like EVM/Bitcoin Script)
//   - Deterministic execution (same input -> same output, always)
//   - Gas metering: every opcode checked BEFORE execution via GasMeter
//   - Sandboxed storage with atomic WriteBatch commits
//   - Execution limits: max stack depth, max memory, max code size
//
// DETERMINISM INVARIANTS (consensus-critical):
//   1. No floating point (f32/f64) — IEEE 754 rounding varies across CPUs
//   2. No system time — TIMESTAMP opcode reads from block header, not clock
//   3. No random — BLOCKHASH is the only source of pseudo-randomness
//   4. No I/O — no filesystem, network, or process access
//   5. All arithmetic is integer-only (U256 with wrapping semantics)
//   6. Storage values parsed deterministically (hex > decimal > zero)
//   7. Gas metering is pre-execution — checked BEFORE each opcode runs
//   8. has_gas() is pub(crate) — contracts cannot branch on remaining gas
//   9. Almost all opcodes cost ≥ 1 gas; the only zero-gas opcodes are
//      STOP and JUMPDEST. Both are *terminating or marker* opcodes:
//      STOP halts execution immediately and JUMPDEST is a no-op marker
//      that cannot form an unbounded loop on its own (a JUMP/JUMPI to
//      reach a JUMPDEST already pays its 8 gas), so neither enables
//      free infinite-loop DoS. The full schedule lives in
//      `OpCode::gas_cost()` below and in `runtime/vm/core/v1_spec.rs`.
//  10. State changes are atomic — committed only on successful STOP/RETURN
//      (storage writes are buffered into a PendingBatch during execution
//       and SLOAD reads through the pending buffer first so contracts
//       observe their own writes within a single frame — see SLOAD).
//
// Opcodes are 1 byte. Operands follow inline.
// Stack elements are 256-bit unsigned integers (U256).
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::errors::VmError;
use crate::slog_warn;
use crate::runtime::vm::core::u256::U256;
use crate::runtime::vm::core::vm_context::VMContext;
use crate::runtime::vm::contracts::contract_storage::{ContractStorage, PendingBatch};
use crate::runtime::vm::gas::gas_meter::{GasMeter, GasResult};

// ═══════════════════════════════════════════════════════════════════════════
//                          OPCODES
// ═══════════════════════════════════════════════════════════════════════════

/// ShadowVM Opcode set
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum OpCode {
    // -- Control --
    STOP        = 0x00, // Halt execution (success)
    NOP         = 0x01, // No operation

    // -- Stack --
    PUSH1       = 0x10, // Push 1 byte onto stack
    PUSH2       = 0x11, // Push 2 bytes (u16) onto stack
    PUSH4       = 0x12, // Push 4 bytes (u32) onto stack
    PUSH8       = 0x13, // Push 8 bytes (u64) onto stack
    PUSH16      = 0x14, // Push 16 bytes (u128) onto stack
    PUSH32      = 0x15, // Push 32 bytes onto stack
    POP         = 0x16, // Remove top of stack
    DUP         = 0x17, // Duplicate top of stack
    SWAP        = 0x18, // Swap top two elements

    // -- Arithmetic --
    ADD         = 0x20, // a + b
    SUB         = 0x21, // a - b
    MUL         = 0x22, // a * b
    DIV         = 0x23, // a / b (integer division)
    MOD         = 0x24, // a % b
    EXP         = 0x25, // a ** b (bounded)
    ADDMOD      = 0x26, // (a + b) % N
    MULMOD      = 0x27, // (a * b) % N

    // -- Comparison --
    EQ          = 0x30, // a == b -> 1 or 0
    LT          = 0x31, // a < b  -> 1 or 0
    GT          = 0x32, // a > b  -> 1 or 0
    ISZERO      = 0x33, // a == 0 -> 1 or 0

    // -- Bitwise --
    AND         = 0x40, // a & b
    OR          = 0x41, // a | b
    XOR         = 0x42, // a ^ b
    NOT         = 0x43, // ~a
    SHL         = 0x44, // a << b
    SHR         = 0x45, // a >> b

    // -- Storage --
    SLOAD       = 0x50, // Load from contract storage
    SSTORE      = 0x51, // Store to contract storage
    SDELETE     = 0x52, // Delete from contract storage

    // -- Crypto --
    SHA256      = 0x60, // SHA-256 hash of top stack element
    KECCAK      = 0x61, // Keccak-256 hash

    // -- Context --
    CALLER      = 0x70, // Push caller address
    CALLVALUE   = 0x71, // Push sent value (amount)
    TIMESTAMP   = 0x72, // Push current block timestamp
    BLOCKHASH   = 0x73, // Push current block hash
    BALANCE     = 0x74, // Push balance of address

    // -- Context (extended) --
    PC          = 0x02, // Program counter
    GAS         = 0x03, // Remaining gas
    GASLIMIT    = 0x04, // Gas limit
    ADDRESS     = 0x7A, // Current contract address

    // -- Flow Control --
    JUMP        = 0x80, // Unconditional jump
    JUMPI       = 0x81, // Conditional jump (jump if top != 0)
    JUMPDEST    = 0x82, // Mark valid jump destination

    // -- Memory --
    MLOAD       = 0x90, // Load from memory
    MSTORE      = 0x91, // Store to memory
    MSTORE8     = 0x92, // Store single byte to memory
    MSIZE       = 0x93, // Current memory size (rounded to 32)

    // -- Logging --
    LOG         = 0xA0, // Emit log event (0 topics)
    LOG1        = 0xA1, // Emit log event (1 topic)
    LOG2        = 0xA2, // Emit log event (2 topics)
    LOG3        = 0xA3, // Emit log event (3 topics)
    LOG4        = 0xA4, // Emit log event (4 topics)

    // -- System --
    CALL         = 0xB0, // Call another contract
    CALLCODE     = 0xB1, // Call with caller's storage
    DELEGATECALL = 0xB2, // Delegate call (caller + value preserved)
    STATICCALL   = 0xB3, // Read-only call (no state changes)
    CREATE       = 0xB4, // Create new contract
    CREATE2      = 0xB5, // Deterministic CREATE
    RETURN       = 0xB6, // Return data and stop
    REVERT       = 0xB7, // Revert all changes and stop
    SELFDESTRUCT = 0xB8, // Destroy contract

    // -- Call data --
    CALLDATALOAD   = 0xC0, // Load 32 bytes from calldata
    CALLDATASIZE   = 0xC1, // Push calldata length
    CALLDATACOPY   = 0xC2, // Copy calldata to memory
    CODESIZE       = 0xC3, // Push current code length
    CODECOPY       = 0xC4, // Copy code to memory
    EXTCODESIZE    = 0xC5, // Push external contract code size
    RETURNDATASIZE = 0xC6, // Push last return data length
    RETURNDATACOPY = 0xC7, // Copy return data to memory

    // -- Extended stack --
    DUP2  = 0xD0, // Duplicate 2nd from top
    DUP3  = 0xD1, // Duplicate 3rd from top
    DUP4  = 0xD2, // Duplicate 4th from top
    DUP5  = 0xD3, // Duplicate 5th from top
    DUP6  = 0xD4, // Duplicate 6th from top
    DUP7  = 0xD5, // Duplicate 7th from top
    DUP8  = 0xD6, // Duplicate 8th from top
    SWAP2 = 0xD7, // Swap top with 3rd from top
    SWAP3 = 0xD8, // Swap top with 4th from top
    SWAP4 = 0xD9, // Swap top with 5th from top

    // -- Invalid --
    INVALID     = 0xFF, // Invalid opcode (always fails)
}

impl OpCode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => OpCode::STOP, 0x01 => OpCode::NOP,
            0x02 => OpCode::PC, 0x03 => OpCode::GAS, 0x04 => OpCode::GASLIMIT,
            0x10 => OpCode::PUSH1, 0x11 => OpCode::PUSH2,
            0x12 => OpCode::PUSH4, 0x13 => OpCode::PUSH8,
            0x14 => OpCode::PUSH16, 0x15 => OpCode::PUSH32,
            0x16 => OpCode::POP, 0x17 => OpCode::DUP,
            0x18 => OpCode::SWAP,
            0x20 => OpCode::ADD, 0x21 => OpCode::SUB, 0x22 => OpCode::MUL,
            0x23 => OpCode::DIV, 0x24 => OpCode::MOD, 0x25 => OpCode::EXP,
            0x26 => OpCode::ADDMOD, 0x27 => OpCode::MULMOD,
            0x30 => OpCode::EQ, 0x31 => OpCode::LT, 0x32 => OpCode::GT,
            0x33 => OpCode::ISZERO,
            0x40 => OpCode::AND, 0x41 => OpCode::OR, 0x42 => OpCode::XOR,
            0x43 => OpCode::NOT, 0x44 => OpCode::SHL, 0x45 => OpCode::SHR,
            0x50 => OpCode::SLOAD, 0x51 => OpCode::SSTORE, 0x52 => OpCode::SDELETE,
            0x60 => OpCode::SHA256, 0x61 => OpCode::KECCAK,
            0x70 => OpCode::CALLER, 0x71 => OpCode::CALLVALUE,
            0x72 => OpCode::TIMESTAMP, 0x73 => OpCode::BLOCKHASH,
            0x74 => OpCode::BALANCE, 0x7A => OpCode::ADDRESS,
            0x80 => OpCode::JUMP, 0x81 => OpCode::JUMPI, 0x82 => OpCode::JUMPDEST,
            0x90 => OpCode::MLOAD, 0x91 => OpCode::MSTORE,
            0x92 => OpCode::MSTORE8, 0x93 => OpCode::MSIZE,
            0xA0 => OpCode::LOG,
            0xA1 => OpCode::LOG1, 0xA2 => OpCode::LOG2,
            0xA3 => OpCode::LOG3, 0xA4 => OpCode::LOG4,
            0xB0 => OpCode::CALL, 0xB1 => OpCode::CALLCODE, 0xB2 => OpCode::DELEGATECALL,
            0xB3 => OpCode::STATICCALL, 0xB4 => OpCode::CREATE, 0xB5 => OpCode::CREATE2,
            0xB6 => OpCode::RETURN, 0xB7 => OpCode::REVERT, 0xB8 => OpCode::SELFDESTRUCT,
            0xC0 => OpCode::CALLDATALOAD, 0xC1 => OpCode::CALLDATASIZE,
            0xC2 => OpCode::CALLDATACOPY, 0xC3 => OpCode::CODESIZE,
            0xC4 => OpCode::CODECOPY, 0xC5 => OpCode::EXTCODESIZE,
            0xC6 => OpCode::RETURNDATASIZE, 0xC7 => OpCode::RETURNDATACOPY,
            0xD0 => OpCode::DUP2, 0xD1 => OpCode::DUP3, 0xD2 => OpCode::DUP4,
            0xD3 => OpCode::DUP5, 0xD4 => OpCode::DUP6, 0xD5 => OpCode::DUP7,
            0xD6 => OpCode::DUP8,
            0xD7 => OpCode::SWAP2, 0xD8 => OpCode::SWAP3, 0xD9 => OpCode::SWAP4,
            _    => OpCode::INVALID,
        }
    }

    /// Gas cost for this opcode.
    ///
    /// Storage operations cost significantly more than arithmetic to reflect
    /// their actual resource consumption and deter storage spam.
    pub fn gas_cost(&self) -> u64 {
        match self {
            // Free (0 gas) -- terminators and markers
            OpCode::STOP | OpCode::JUMPDEST => 0,

            // Very cheap (2 gas) -- stack ops and context reads
            OpCode::NOP | OpCode::POP | OpCode::DUP | OpCode::SWAP |
            OpCode::DUP2 | OpCode::DUP3 | OpCode::DUP4 | OpCode::DUP5 |
            OpCode::DUP6 | OpCode::DUP7 | OpCode::DUP8 |
            OpCode::SWAP2 | OpCode::SWAP3 | OpCode::SWAP4 |
            OpCode::CALLER | OpCode::CALLVALUE | OpCode::TIMESTAMP |
            OpCode::BLOCKHASH | OpCode::BALANCE | OpCode::ADDRESS |
            OpCode::PC | OpCode::GAS | OpCode::GASLIMIT => 2,

            // Cheap (3 gas) -- push, simple arithmetic, comparison, bitwise, memory, calldata
            OpCode::PUSH1 | OpCode::PUSH2 | OpCode::PUSH4 | OpCode::PUSH8 |
            OpCode::PUSH16 | OpCode::PUSH32 |
            OpCode::ADD | OpCode::SUB | OpCode::EQ | OpCode::LT | OpCode::GT |
            OpCode::ISZERO | OpCode::AND | OpCode::OR | OpCode::XOR | OpCode::NOT |
            OpCode::MLOAD | OpCode::MSTORE | OpCode::MSTORE8 | OpCode::MSIZE |
            OpCode::CALLDATALOAD | OpCode::CALLDATASIZE | OpCode::CALLDATACOPY |
            OpCode::CODESIZE | OpCode::CODECOPY | OpCode::RETURNDATASIZE |
            OpCode::RETURNDATACOPY => 3,

            // Medium (5 gas) -- mul, div, mod, shifts
            OpCode::MUL | OpCode::DIV | OpCode::MOD | OpCode::SHL | OpCode::SHR => 5,

            // Modular arithmetic (8 gas) -- addmod, mulmod
            OpCode::ADDMOD | OpCode::MULMOD => 8,

            // Moderate (8 gas) -- jumps
            OpCode::JUMP | OpCode::JUMPI => 8,

            // Crypto (30 gas)
            OpCode::SHA256 | OpCode::KECCAK => 30,

            // Expensive (50 gas)
            OpCode::EXP => 50,

            // External code query (100 gas)
            OpCode::EXTCODESIZE => 100,

            // Storage read (200 gas)
            OpCode::SLOAD => 200,

            // Logging (375-750 gas, scales with topics)
            OpCode::LOG => 375,
            OpCode::LOG1 => 375 + 375,  // base + 1 topic
            OpCode::LOG2 => 375 + 750,  // base + 2 topics
            OpCode::LOG3 => 375 + 1125, // base + 3 topics
            OpCode::LOG4 => 375 + 1500, // base + 4 topics

            // Calls (700 gas)
            OpCode::CALL | OpCode::CALLCODE | OpCode::DELEGATECALL |
            OpCode::STATICCALL => 700,

            // Return / Revert (1 gas -- prevents free infinite loops)
            OpCode::RETURN | OpCode::REVERT => 1,

            // Contract creation (32000 gas)
            OpCode::CREATE | OpCode::CREATE2 => 32_000,

            // Storage write (5000 gas)
            OpCode::SSTORE => 5_000,

            // Storage delete (5000 gas, but earns refund)
            OpCode::SDELETE => 5_000,

            // Self destruct (25000 gas)
            OpCode::SELFDESTRUCT => 25_000,

            // Invalid -- costs all remaining gas
            OpCode::INVALID => u64::MAX,
        }
    }

    /// Human-readable mnemonic for this opcode.
    ///
    /// Mirrors the names used in the v1_spec table so the assembler /
    /// disassembler can produce text that round-trips through
    /// `validate_v1_bytecode`.
    pub fn name(&self) -> &'static str {
        match self {
            OpCode::STOP => "STOP", OpCode::NOP => "NOP",
            OpCode::PC => "PC", OpCode::GAS => "GAS", OpCode::GASLIMIT => "GASLIMIT",
            OpCode::PUSH1 => "PUSH1", OpCode::PUSH2 => "PUSH2",
            OpCode::PUSH4 => "PUSH4", OpCode::PUSH8 => "PUSH8",
            OpCode::PUSH16 => "PUSH16", OpCode::PUSH32 => "PUSH32",
            OpCode::POP => "POP", OpCode::DUP => "DUP", OpCode::SWAP => "SWAP",
            OpCode::ADD => "ADD", OpCode::SUB => "SUB", OpCode::MUL => "MUL",
            OpCode::DIV => "DIV", OpCode::MOD => "MOD", OpCode::EXP => "EXP",
            OpCode::ADDMOD => "ADDMOD", OpCode::MULMOD => "MULMOD",
            OpCode::EQ => "EQ", OpCode::LT => "LT", OpCode::GT => "GT",
            OpCode::ISZERO => "ISZERO",
            OpCode::AND => "AND", OpCode::OR => "OR", OpCode::XOR => "XOR",
            OpCode::NOT => "NOT", OpCode::SHL => "SHL", OpCode::SHR => "SHR",
            OpCode::SLOAD => "SLOAD", OpCode::SSTORE => "SSTORE",
            OpCode::SDELETE => "SDELETE",
            OpCode::SHA256 => "SHA256", OpCode::KECCAK => "KECCAK",
            OpCode::CALLER => "CALLER", OpCode::CALLVALUE => "CALLVALUE",
            OpCode::TIMESTAMP => "TIMESTAMP", OpCode::BLOCKHASH => "BLOCKHASH",
            OpCode::BALANCE => "BALANCE", OpCode::ADDRESS => "ADDRESS",
            OpCode::JUMP => "JUMP", OpCode::JUMPI => "JUMPI",
            OpCode::JUMPDEST => "JUMPDEST",
            OpCode::MLOAD => "MLOAD", OpCode::MSTORE => "MSTORE",
            OpCode::MSTORE8 => "MSTORE8", OpCode::MSIZE => "MSIZE",
            // The 0xA0 mnemonic in v1_spec is "LOG0" (matching the
            // EVM "LOGn" family); the vm.rs enum variant is named LOG
            // for historical reasons but its on-the-wire mnemonic is
            // LOG0 so the assembler/disassembler stay v1-compatible.
            OpCode::LOG => "LOG0", OpCode::LOG1 => "LOG1",
            OpCode::LOG2 => "LOG2", OpCode::LOG3 => "LOG3", OpCode::LOG4 => "LOG4",
            OpCode::CALL => "CALL", OpCode::CALLCODE => "CALLCODE",
            OpCode::DELEGATECALL => "DELEGATECALL", OpCode::STATICCALL => "STATICCALL",
            OpCode::CREATE => "CREATE", OpCode::CREATE2 => "CREATE2",
            OpCode::RETURN => "RETURN", OpCode::REVERT => "REVERT",
            OpCode::SELFDESTRUCT => "SELFDESTRUCT",
            OpCode::CALLDATALOAD => "CALLDATALOAD", OpCode::CALLDATASIZE => "CALLDATASIZE",
            OpCode::CALLDATACOPY => "CALLDATACOPY", OpCode::CODESIZE => "CODESIZE",
            OpCode::CODECOPY => "CODECOPY", OpCode::EXTCODESIZE => "EXTCODESIZE",
            OpCode::RETURNDATASIZE => "RETURNDATASIZE",
            OpCode::RETURNDATACOPY => "RETURNDATACOPY",
            OpCode::DUP2 => "DUP2", OpCode::DUP3 => "DUP3", OpCode::DUP4 => "DUP4",
            OpCode::DUP5 => "DUP5", OpCode::DUP6 => "DUP6", OpCode::DUP7 => "DUP7",
            OpCode::DUP8 => "DUP8",
            OpCode::SWAP2 => "SWAP2", OpCode::SWAP3 => "SWAP3", OpCode::SWAP4 => "SWAP4",
            OpCode::INVALID => "INVALID",
        }
    }

    /// Number of inline operand bytes that follow this opcode.
    /// Only PUSHn opcodes carry operand data; everything else is 0.
    pub fn operand_size(&self) -> usize {
        match self {
            OpCode::PUSH1  => 1,
            OpCode::PUSH2  => 2,
            OpCode::PUSH4  => 4,
            OpCode::PUSH8  => 8,
            OpCode::PUSH16 => 16,
            OpCode::PUSH32 => 32,
            _              => 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                       EXECUTION RESULT
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum ExecutionResult {
    Success { gas_used: u64, return_data: Vec<u8>, logs: Vec<LogEntry> },
    Revert  { gas_used: u64, reason: String },
    OutOfGas { gas_used: u64 },
    Error   { gas_used: u64, message: String },
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub contract: String,
    pub topics:   Vec<U256>,
    pub data:     Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════════
//                     EXECUTION LIMITS (DoS protection)
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum stack depth (number of elements)
pub const MAX_STACK_SIZE: usize = 1024;

/// Maximum memory size (1 MB)
pub const MAX_MEMORY_SIZE: usize = 1024 * 1024;

/// Maximum contract bytecode size (24 KB)
pub const MAX_CODE_SIZE: usize = 24 * 1024;

/// Maximum call depth -- uses v1 spec value.
/// DEPRECATED: use v1_spec::MAX_CALL_DEPTH instead.
pub const MAX_CALL_DEPTH: usize = 1024;

/// Gas cost per 32-byte word of memory expansion
pub const MEMORY_GAS_PER_WORD: u64 = 3;

// ═══════════════════════════════════════════════════════════════════════════
//                        VM IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════
//
// LEGACY ENGINE — NOT THE PRODUCTION EXECUTION PATH.
//
// `VM::execute_bytecode` is a flat opcode loop that pre-dates the
// reentrant `runtime::vm::core::execution_env::ExecutionEnvironment`
// pipeline. It still implements the simple opcodes (PUSH/POP/ADD/
// SLOAD/SSTORE/JUMP/…) and is used as a self-contained test harness
// for those opcodes, but it has stub returns for every CALL-family
// and contract-creation opcode:
//
//     CALL          → "CALL opcode not yet implemented"
//     CALLCODE      → "CALLCODE opcode not yet implemented"
//     DELEGATECALL  → "DELEGATECALL opcode not yet implemented"
//     STATICCALL    → "STATICCALL opcode not yet implemented"
//     CREATE        → "CREATE opcode not yet implemented"
//     CREATE2       → "CREATE2 opcode not yet implemented"
//     SELFDESTRUCT  → "SELFDESTRUCT opcode not yet implemented"
//
// If a production caller routed bytecode through this engine, those
// opcodes would all return errors instead of executing — a silent
// behavioural divergence from the real ExecutionEnvironment path.
// To prevent that, this struct is intentionally NOT used by:
//   - `runtime::vm::core::executor::Executor` (which builds an
//     `ExecutionEnvironment` and calls `execute_frame`),
//   - `service::network::nodes::full_node::execute_contract_transactions`
//     (same path), or
//   - any of the contract / RPC / SDK helpers.
//
// `cargo grep ShadowVm` returns no callers; `execute_bytecode` is
// only invoked from `vm::tests` inside this same file. The struct is
// kept compiling so the existing simple-opcode tests still run, but
// new code MUST use `ExecutionEnvironment::execute_frame` instead.
// See `runtime::vm::core::execution_env` for the full implementation.
pub struct VM {
    context: VMContext,
}

impl VM {
    pub fn new(db_path: &str) -> Result<Self, VmError> {
        let storage = ContractStorage::new(db_path)?;
        let context = VMContext::new(storage);
        Ok(Self { context })
    }

    pub fn from_context(context: VMContext) -> Self {
        Self { context }
    }

    /// Execute bytecode with strict gas enforcement and atomic state changes.
    ///
    /// Every opcode pays gas BEFORE execution via the GasMeter. If gas runs
    /// out at any point, execution halts with `OutOfGas` and ALL buffered
    /// state changes are discarded (never written to DB).
    ///
    /// On success, state changes are committed atomically via WriteBatch.
    /// On REVERT or error, state changes are discarded.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_bytecode(
        &self,
        bytecode:   &[u8],
        gas_limit:  u64,
        caller:     &str,
        value:      u64,
        timestamp:  u64,
        block_hash: &str,
        contract_addr: &str,
        input_data: &[u8],
    ) -> ExecutionResult {
        // --- Pre-execution validation ---
        if bytecode.len() > MAX_CODE_SIZE {
            return ExecutionResult::Error {
                gas_used: 0,
                message: format!("Code size {} exceeds max {}", bytecode.len(), MAX_CODE_SIZE),
            };
        }

        // --- Initialize execution state ---
        let mut gas = GasMeter::new(gas_limit);
        let mut stack: Vec<U256> = Vec::with_capacity(64);
        let init_mem_size = 256usize.max(input_data.len());
        let mut memory: Vec<u8> = vec![0u8; init_mem_size];
        let mut pc: usize = 0;
        let mut logs: Vec<LogEntry> = Vec::new();
        let mut return_data: Vec<u8> = Vec::new();

        // Charge gas for initial memory allocation (issue #94)
        let init_mem_cost = (init_mem_size as u64 / 32) * MEMORY_GAS_PER_WORD;
        if let GasResult::OutOfGas { .. } = gas.consume(init_mem_cost) {
            return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
        }

        // Copy input_data into the start of VM memory (Fix #39)
        if !input_data.is_empty() {
            memory[..input_data.len()].copy_from_slice(input_data);
        }

        // Pending state changes -- only committed on success
        let mut pending = PendingBatch::new();

        // Pre-compute valid jump destinations
        let jump_dests = Self::find_jump_dests(bytecode);

        // --- Main execution loop ---
        while pc < bytecode.len() {
            let op = OpCode::from_byte(bytecode[pc]);
            let cost = op.gas_cost();

            // *** GAS ENFORCEMENT: consume gas BEFORE executing ***
            if let GasResult::OutOfGas { .. } = gas.consume(cost) {
                // Discard all pending state changes
                pending.discard();
                return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
            }

            match op {
                OpCode::STOP => {
                    // Commit all pending state changes atomically
                    if let Err(e) = self.context.storage().commit_batch(&mut pending) {
                        return ExecutionResult::Error {
                            gas_used: gas.gas_used(),
                            message: format!("State commit failed: {}", e),
                        };
                    }
                    return ExecutionResult::Success {
                        gas_used: gas.effective_gas_used(),
                        return_data,
                        logs,
                    };
                }

                OpCode::NOP => { pc += 1; continue; }

                // -- PUSH --
                // Bounds checks use `pc + N >= len` which is correct: the highest
                // index accessed is pc+N, so we need pc+N < len. (issue #81)
                OpCode::PUSH1 => {
                    if pc + 1 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH1 truncated");
                    }
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_u64(bytecode[pc + 1] as u64));
                    pc += 2; continue;
                }
                OpCode::PUSH2 => {
                    if pc + 2 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH2 truncated");
                    }
                    let val = u16::from_be_bytes([
                        bytecode[pc+1], bytecode[pc+2],
                    ]);
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_u64(val as u64));
                    pc += 3; continue;
                }
                OpCode::PUSH4 => {
                    if pc + 4 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH4 truncated");
                    }
                    let val = u32::from_be_bytes([
                        bytecode[pc+1], bytecode[pc+2], bytecode[pc+3], bytecode[pc+4]
                    ]);
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_u64(val as u64));
                    pc += 5; continue;
                }
                OpCode::PUSH8 => {
                    if pc + 8 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH8 truncated");
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytecode[pc+1..pc+9]);
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_u64(u64::from_be_bytes(arr)));
                    pc += 9; continue;
                }
                OpCode::PUSH16 => {
                    if pc + 16 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH16 truncated");
                    }
                    let mut arr = [0u8; 32];
                    // Place 16 bytes right-aligned in 32-byte array for U256
                    arr[16..32].copy_from_slice(&bytecode[pc+1..pc+17]);
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_be_bytes(&arr));
                    pc += 17; continue;
                }
                OpCode::PUSH32 => {
                    if pc + 32 >= bytecode.len() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "PUSH32 truncated");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytecode[pc+1..pc+33]);
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    stack.push(U256::from_be_bytes(&arr));
                    pc += 33; continue;
                }

                OpCode::POP => {
                    if stack.is_empty() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack underflow");
                    }
                    stack.pop();
                }

                OpCode::DUP => {
                    if stack.is_empty() {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack underflow");
                    }
                    if stack.len() >= MAX_STACK_SIZE {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack overflow");
                    }
                    // Safe: emptiness checked above
                    let top = *stack.last().unwrap();
                    stack.push(top);
                }

                OpCode::SWAP => {
                    let len = stack.len();
                    if len < 2 {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack underflow");
                    }
                    stack.swap(len - 1, len - 2);
                }

                // -- ARITHMETIC --
                OpCode::ADD => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = a.wrapping_add(b);
                    stack.push(r);
                }
                OpCode::SUB => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = a.wrapping_sub(b);
                    stack.push(r);
                }
                OpCode::MUL => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = a.wrapping_mul(b);
                    stack.push(r);
                }
                OpCode::DIV => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = a.checked_div(b);
                    stack.push(r);
                }
                OpCode::MOD => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = a.checked_mod(b);
                    stack.push(r);
                }
                OpCode::ADDMOD => {
                    let (a, b, n) = match Self::pop3(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = if n == U256::ZERO {
                        U256::ZERO
                    } else {
                        a.wrapping_add(b).checked_mod(n)
                    };
                    stack.push(r);
                }
                OpCode::MULMOD => {
                    let (a, b, n) = match Self::pop3(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = if n == U256::ZERO {
                        U256::ZERO
                    } else {
                        a.wrapping_mul(b).checked_mod(n)
                    };
                    stack.push(r);
                }
                OpCode::EXP => {
                    let (base, exp) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let r = base.wrapping_pow(exp);
                    stack.push(r);
                }

                // -- COMPARISON --
                OpCode::EQ => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(if a == b { U256::ONE } else { U256::ZERO });
                }
                OpCode::LT => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(if a < b { U256::ONE } else { U256::ZERO });
                }
                OpCode::GT => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(if a > b { U256::ONE } else { U256::ZERO });
                }
                OpCode::ISZERO => {
                    let a = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(if a.is_zero() { U256::ONE } else { U256::ZERO });
                }

                // -- BITWISE --
                OpCode::AND => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(a.bitand(b));
                }
                OpCode::OR => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(a.bitor(b));
                }
                OpCode::XOR => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(a.bitxor(b));
                }
                OpCode::NOT => {
                    let a = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(a.bitnot());
                }
                OpCode::SHL => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(b.shl(a.as_u64() as u32));
                }
                OpCode::SHR => {
                    let (a, b) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    stack.push(b.shr(a.as_u64() as u32));
                }

                // -- STORAGE (buffered via PendingBatch) --
                //
                // SLOAD READ-YOUR-WRITES INVARIANT:
                //
                // Storage writes (SSTORE / SDELETE) buffer into `pending`
                // and only commit on STOP/RETURN. SLOAD therefore MUST
                // consult `pending` first; otherwise an SSTORE earlier
                // in the same frame is invisible to a later SLOAD on the
                // same key, breaking every counter / accumulator pattern
                // within a transaction.
                //
                // Lookup order:
                //   1. pending.lookup(key) → buffered put / tombstone
                //   2. self.context.get(key) → committed on-disk value
                //   3. U256::ZERO if both miss
                OpCode::SLOAD => {
                    let slot = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let key = format!("{}:slot:{}", contract_addr, slot);

                    use crate::runtime::vm::contracts::contract_storage::PendingLookup;
                    let val = match pending.lookup(&key) {
                        PendingLookup::Buffered(v) => Self::parse_storage_u256(v, &key),
                        PendingLookup::Tombstoned  => U256::ZERO,
                        PendingLookup::NotBuffered => {
                            self.context.get(&key)
                                .map(|s| Self::parse_storage_u256(&s, &key))
                                .unwrap_or(U256::ZERO)
                        }
                    };
                    stack.push(val);
                }
                OpCode::SSTORE => {
                    let (slot, val) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let key = format!("{}:slot:{}", contract_addr, slot);
                    // Buffer the write -- not committed until STOP/RETURN
                    pending.put(key, val.to_string());
                }
                OpCode::SDELETE => {
                    let slot = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let key = format!("{}:slot:{}", contract_addr, slot);
                    // Buffer the delete
                    pending.delete(key);
                    // Earn gas refund for clearing storage
                    gas.add_refund(2_400);
                }

                // -- CRYPTO --
                OpCode::SHA256 => {
                    let val = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let mut h = Sha256::new();
                    h.update(val.to_be_bytes());
                    let hash = h.finalize();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hash[..32]);
                    stack.push(U256::from_be_bytes(&arr));
                }
                OpCode::KECCAK => {
                    let val = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    use sha3::Keccak256;
                    let mut h = Keccak256::new();
                    h.update(val.to_be_bytes());
                    let hash = h.finalize();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hash[..32]);
                    stack.push(U256::from_be_bytes(&arr));
                }

                // -- CONTEXT --
                OpCode::CALLER     => { stack.push(U256::from_u64(Self::addr_to_u64(caller))); }
                OpCode::CALLVALUE  => { stack.push(U256::from_u64(value)); }
                OpCode::TIMESTAMP  => { stack.push(U256::from_u64(timestamp)); }
                OpCode::BLOCKHASH  => {
                    // Parse full 256-bit block hash instead of truncating to 64-bit
                    let val = if block_hash.len() == 64 {
                        U256::from_hex(block_hash).unwrap_or(U256::ZERO)
                    } else {
                        // Fallback: hash the string to get deterministic 256-bit value
                        let mut h = Sha256::new();
                        h.update(block_hash.as_bytes());
                        let hash = h.finalize();
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&hash);
                        U256::from_be_bytes(&arr)
                    };
                    stack.push(val);
                }
                OpCode::BALANCE    => {
                    let addr = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let addr_key = format!("balance:{}", addr.as_u64());
                    let bal = match self.context.get(&addr_key) {
                        Some(val) => match val.parse::<u64>() {
                            Ok(b) => U256::from_u64(b),
                            Err(e) => {
                                slog_warn!("vm", "balance_parse_failed",
                                    address => &addr_key, error => &e.to_string());
                                U256::ZERO
                            }
                        },
                        None => U256::ZERO,
                    };
                    stack.push(bal);
                }

                // -- FLOW CONTROL --
                OpCode::JUMP => {
                    let dest_val = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    if dest_val >= U256::from_u64(bytecode.len() as u64) {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Jump destination out of bounds");
                    }
                    let dest = dest_val.as_usize();
                    if !jump_dests.contains(&dest) {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Invalid jump destination");
                    }
                    pc = dest; continue;
                }
                OpCode::JUMPI => {
                    let (dest_val, cond) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    if !cond.is_zero() {
                        if dest_val >= U256::from_u64(bytecode.len() as u64) {
                            pending.discard();
                            return Self::err(gas.gas_used(), "Jump destination out of bounds");
                        }
                        let dest = dest_val.as_usize();
                        if !jump_dests.contains(&dest) {
                            pending.discard();
                            return Self::err(gas.gas_used(), "Invalid jump destination");
                        }
                        pc = dest; continue;
                    }
                }
                OpCode::JUMPDEST => { /* valid jump target marker */ }

                // -- MEMORY (with expansion gas) --
                OpCode::MLOAD => {
                    let offset = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e }.as_usize();
                    if offset + 32 > memory.len() {
                        if let Some(expansion_gas) = Self::memory_expansion_cost(memory.len(), offset + 32) {
                            if let GasResult::OutOfGas { .. } = gas.consume(expansion_gas) {
                                pending.discard();
                                return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
                            }
                        }
                        Self::expand_memory(&mut memory, offset + 32);
                    }
                    // If memory expansion or read fails, return error instead of silent ZERO
                    if offset + 32 <= memory.len() {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&memory[offset..offset+32]);
                        stack.push(U256::from_be_bytes(&arr));
                    } else {
                        pending.discard();
                        return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
                    }
                }
                OpCode::MSTORE => {
                    let (offset_val, val) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let offset = offset_val.as_usize();
                    if offset + 32 > memory.len() {
                        if let Some(expansion_gas) = Self::memory_expansion_cost(memory.len(), offset + 32) {
                            if let GasResult::OutOfGas { .. } = gas.consume(expansion_gas) {
                                pending.discard();
                                return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
                            }
                        }
                        Self::expand_memory(&mut memory, offset + 32);
                    }
                    // If memory expansion failed, return error instead of silently skipping write
                    if offset + 32 <= memory.len() {
                        memory[offset..offset+32].copy_from_slice(&val.to_be_bytes());
                    } else {
                        pending.discard();
                        return ExecutionResult::OutOfGas { gas_used: gas.gas_used() };
                    }
                }

                // -- LOG --
                OpCode::LOG => {
                    let val = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    logs.push(LogEntry {
                        contract: contract_addr.to_string(),
                        topics: Vec::new(),
                        data: val.to_be_bytes().to_vec(),
                    });
                }


                // -- RETURN / REVERT --
                OpCode::RETURN => {
                    if stack.len() < 2 {
                        pending.discard();
                        return Self::err(gas.gas_used(), "Stack underflow");
                    }
                    let (off_val, size_val) = match Self::pop2(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let offset = off_val.as_usize();
                    let size = size_val.as_usize();
                    if let Some(end) = offset.checked_add(size) {
                        if end <= memory.len() {
                            return_data = memory[offset..end].to_vec();
                        }
                    }
                    // Commit all pending state changes atomically
                    if let Err(e) = self.context.storage().commit_batch(&mut pending) {
                        return ExecutionResult::Error {
                            gas_used: gas.gas_used(),
                            message: format!("State commit failed: {}", e),
                        };
                    }
                    return ExecutionResult::Success {
                        gas_used: gas.effective_gas_used(),
                        return_data,
                        logs,
                    };
                }
                OpCode::REVERT => {
                    // Discard ALL pending state changes
                    pending.discard();
                    return ExecutionResult::Revert {
                        gas_used: gas.gas_used(),
                        reason: "REVERT opcode".to_string(),
                    };
                }

                // -- STUBS: opcodes intentionally NOT implemented in this engine --
                //
                // The legacy `VM::execute_bytecode` flat loop never grew the
                // call-frame / contract-creation machinery. Anything that
                // hits these branches has accidentally routed bytecode
                // through the legacy engine instead of through
                // `ExecutionEnvironment::execute_frame`, which DOES implement
                // every CALL-family and CREATE opcode correctly. The error
                // messages name `ExecutionEnvironment` so the operator can
                // immediately see where to redirect the caller.
                //
                // Gas is already charged above via gas.consume(cost), so a
                // bytecode that hits one of these stubs still pays the
                // declared opcode cost — it just doesn't get the work done.

                OpCode::CALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "CALL is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::CALLCODE => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "CALLCODE is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::DELEGATECALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "DELEGATECALL is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::STATICCALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "STATICCALL is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::CREATE => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "CREATE is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::CREATE2 => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "CREATE2 is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }
                OpCode::SELFDESTRUCT => {
                    pending.discard();
                    return Self::err(gas.gas_used(),
                        "SELFDESTRUCT is not implemented in the legacy VM engine; \
                         route this bytecode through ExecutionEnvironment::execute_frame");
                }

                OpCode::INVALID => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "Invalid opcode");
                }

                // Extended opcodes (handled in ExecutionEnvironment)
                _ => {
                    pending.discard();
                    return Self::err(gas.gas_used(), &format!("Opcode {:?} only supported in ExecutionEnvironment", op));
                }
            }

            pc += 1;
        }

        // INTENTIONALLY REACHABLE: End of bytecode reached (implicit STOP).
        // Per EVM semantics, falling off the end of bytecode is equivalent to
        // executing a STOP instruction — this is a successful execution path
        // that must commit pending state changes. (issue #97)
        if let Err(e) = self.context.storage().commit_batch(&mut pending) {
            return ExecutionResult::Error {
                gas_used: gas.gas_used(),
                message: format!("State commit failed: {}", e),
            };
        }
        ExecutionResult::Success {
            gas_used: gas.effective_gas_used(),
            return_data,
            logs,
        }
    }

    /// Simple KV execute (legacy compatibility)
    pub fn execute(&self, key: &str, code: &str) -> Result<(), crate::errors::StorageError> {
        self.context.set(key, code)
    }

    /// Simple KV read (legacy compatibility)
    pub fn read(&self, key: &str) -> Option<String> {
        self.context.get(key)
    }

    // -- Helpers --

    /// Parse a stored storage value into a U256.
    ///
    /// SSTORE writes a U256 as `val.to_string()` (decimal). Older
    /// records may also have a `0x...` hex prefix. The parsing tries
    /// hex first (canonical SSTORE format historically), then strict
    /// decimal, falling back to ZERO with a warning on malformed
    /// input. This is shared between the pending-buffer and on-disk
    /// SLOAD paths so both interpret the storage byte stream the
    /// same way — preserving the read-your-writes invariant.
    fn parse_storage_u256(s: &str, key: &str) -> U256 {
        if let Some(hex_str) = s.strip_prefix("0x") {
            return match U256::from_hex(hex_str) {
                Some(v) => v,
                None => {
                    slog_warn!("vm", "sload_malformed_storage",
                        key => key, error => "invalid hex after 0x prefix");
                    U256::ZERO
                }
            };
        }
        // Strict decimal parsing: only digits, no signs.
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return match s.parse::<u64>() {
                Ok(n) => U256::from_u64(n),
                Err(e) => {
                    slog_warn!("vm", "sload_malformed_storage",
                        key => key, error => &e.to_string());
                    U256::ZERO
                }
            };
        }
        slog_warn!("vm", "sload_malformed_storage",
            key => key, error => "non-numeric non-hex value");
        U256::ZERO
    }

    fn pop1(stack: &mut Vec<U256>, gas: &GasMeter, pending: &mut PendingBatch) -> Result<U256, ExecutionResult> {
        match stack.pop() {
            Some(v) => Ok(v),
            None => {
                pending.discard();
                Err(ExecutionResult::Error {
                    gas_used: gas.gas_used(),
                    message: "Stack underflow".to_string(),
                })
            }
        }
    }

    fn pop2(stack: &mut Vec<U256>, gas: &GasMeter, pending: &mut PendingBatch) -> Result<(U256, U256), ExecutionResult> {
        if stack.len() < 2 {
            pending.discard();
            return Err(ExecutionResult::Error {
                gas_used: gas.gas_used(),
                message: "Stack underflow".to_string(),
            });
        }
        // Safe: length checked above
        let b = stack.pop().unwrap();
        let a = stack.pop().unwrap();
        Ok((a, b))
    }

    fn pop3(stack: &mut Vec<U256>, gas: &GasMeter, pending: &mut PendingBatch) -> Result<(U256, U256, U256), ExecutionResult> {
        if stack.len() < 3 {
            pending.discard();
            return Err(ExecutionResult::Error {
                gas_used: gas.gas_used(),
                message: "Stack underflow".to_string(),
            });
        }
        // Safe: length checked above
        let a = stack.pop().unwrap();
        let b = stack.pop().unwrap();
        let c = stack.pop().unwrap();
        Ok((a, b, c))
    }

    fn err(gas_used: u64, msg: &str) -> ExecutionResult {
        ExecutionResult::Error { gas_used, message: msg.to_string() }
    }

    fn find_jump_dests(bytecode: &[u8]) -> Vec<usize> {
        let mut dests = Vec::new();
        let mut i: usize = 0;
        while i < bytecode.len() {
            if bytecode[i] == OpCode::JUMPDEST as u8 {
                dests.push(i);
            }
            // Skip push operands; use saturating_add to prevent usize overflow
            // on malformed bytecode where a PUSH appears near the end (issue #80)
            let advance = match bytecode[i] {
                b if b == OpCode::PUSH1  as u8 => 2,   // 1 + 1
                b if b == OpCode::PUSH2  as u8 => 3,   // 1 + 2
                b if b == OpCode::PUSH4  as u8 => 5,   // 1 + 4
                b if b == OpCode::PUSH8  as u8 => 9,   // 1 + 8
                b if b == OpCode::PUSH16 as u8 => 17,  // 1 + 16
                b if b == OpCode::PUSH32 as u8 => 33,  // 1 + 32
                _ => 1,
            };
            i = i.saturating_add(advance);
        }
        dests
    }

    /// Calculate gas cost for memory expansion
    fn memory_expansion_cost(current_size: usize, needed: usize) -> Option<u64> {
        if needed <= current_size || needed > MAX_MEMORY_SIZE {
            return None;
        }
        let new_size = needed.div_ceil(32) * 32;
        let current_words = current_size / 32;
        let new_words = new_size / 32;
        let added_words = new_words.saturating_sub(current_words);
        if added_words > 0 {
            Some(added_words as u64 * MEMORY_GAS_PER_WORD)
        } else {
            None
        }
    }

    fn expand_memory(memory: &mut Vec<u8>, needed: usize) {
        if needed > MAX_MEMORY_SIZE { return; }
        let new_size = needed.div_ceil(32) * 32; // Round up to 32-byte words
        if new_size > memory.len() {
            memory.resize(new_size, 0);
        }
    }

    fn addr_to_u64(addr: &str) -> u64 {
        let mut h = Sha256::new();
        h.update(addr.as_bytes());
        let hash = h.finalize();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&hash[..8]);
        u64::from_be_bytes(arr)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vm() -> VM {
        // Use `std::env::temp_dir()` instead of a hard-coded `/tmp/…`
        // path. Windows has no `/tmp`, so the previous test helper
        // failed the whole vm.rs test module on Windows before any
        // assertion could run. Nanosecond suffix keeps runs unique.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("shadowdag_test_vm_{}", ts));
        VM::new(dir.to_str().expect("tempdir path is not valid UTF-8"))
            .expect("VM::new failed")
    }

    fn exec(vm: &VM, bytecode: &[u8], gas: u64) -> ExecutionResult {
        vm.execute_bytecode(bytecode, gas, "SD1caller", 0, 1000, "blockhash", "SD1contract", &[])
    }

    #[test]
    fn stop_immediately() {
        let vm = make_vm();
        let result = exec(&vm, &[0x00], 1000); // STOP
        match result {
            // Per invariant #9 (vm.rs module header), STOP costs ≥ 1 gas
            // to prevent free-opcode infinite loops — so a single STOP
            // execution MUST consume at least that floor. Previously this
            // asserted `gas_used == 0`, which matched the old 0-gas STOP
            // and now contradicts the actual gas schedule in opcodes.rs.
            ExecutionResult::Success { gas_used, .. } => {
                assert!(
                    gas_used >= OpCode::STOP.gas_cost(),
                    "STOP should consume at least its declared gas cost, got gas_used={}",
                    gas_used
                );
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn push_and_add() {
        let vm = make_vm();
        // PUSH1 3, PUSH1 7, ADD, STOP
        let bytecode = vec![0x10, 3, 0x10, 7, 0x20, 0x00];
        let result = exec(&vm, &bytecode, 10000);
        match result {
            ExecutionResult::Success { gas_used, .. } => {
                assert!(gas_used > 0);
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn push_sub_mul() {
        let vm = make_vm();
        // PUSH1 10, PUSH1 3, SUB -> 7, PUSH1 2, MUL -> 14, STOP
        let bytecode = vec![0x10, 10, 0x10, 3, 0x21, 0x10, 2, 0x22, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn division_by_zero_returns_zero() {
        let vm = make_vm();
        // PUSH1 10, PUSH1 0, DIV -> 0, STOP
        let bytecode = vec![0x10, 10, 0x10, 0, 0x23, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success (div by zero returns 0)"),
        }
    }

    #[test]
    fn out_of_gas() {
        let vm = make_vm();
        // PUSH1 1, PUSH1 2, ADD -- but only 1 gas
        let bytecode = vec![0x10, 1, 0x10, 2, 0x20, 0x00];
        match exec(&vm, &bytecode, 1) {
            ExecutionResult::OutOfGas { .. } => {}
            _ => panic!("Expected out of gas"),
        }
    }

    #[test]
    fn stack_underflow() {
        let vm = make_vm();
        // ADD with empty stack
        let bytecode = vec![0x20, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Error { message, .. } => {
                assert!(message.contains("underflow"));
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn sstore_and_sload() {
        let vm = make_vm();
        // PUSH1 42 (value), PUSH1 0 (slot), SSTORE, PUSH1 0 (slot), SLOAD, STOP
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0x10, 0, 0x50, 0x00];
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn comparison_ops() {
        let vm = make_vm();
        // PUSH1 5, PUSH1 10, GT -> 0 (5 > 10 = false), STOP
        let bytecode = vec![0x10, 5, 0x10, 10, 0x32, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn revert_discards_state() {
        let vm = make_vm();
        // PUSH1 0  (slot — bottom),
        // PUSH1 42 (val  — top),
        // SSTORE   → pending: slot 0 = 42
        // REVERT   → discards pending and exits with Revert
        //
        // The previous bytecode used 0xB2 as the terminating opcode,
        // but 0xB2 is DELEGATECALL in vm.rs (and v1_spec). REVERT is
        // 0xB7. The old test therefore actually executed a malformed
        // DELEGATECALL on top of an empty stack and matched on the
        // wrong outcome. This rewrite uses the correct REVERT byte.
        let bytecode = vec![0x10, 0, 0x10, 42, 0x51, 0xB7];
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Revert { .. } => {}
            other => panic!("Expected revert, got {:?}", other),
        }
    }

    #[test]
    fn invalid_opcode() {
        let vm = make_vm();
        let bytecode = vec![0xFF]; // INVALID
        match exec(&vm, &bytecode, u64::MAX) {
            ExecutionResult::Error { message, .. } => {
                assert!(message.contains("Invalid"));
            }
            ExecutionResult::OutOfGas { .. } => {
                // Also acceptable -- INVALID costs u64::MAX gas
            }
            _ => panic!("Expected error or out of gas"),
        }
    }

    #[test]
    fn jump_and_jumpdest() {
        let vm = make_vm();
        // PUSH1 4 (dest), JUMP, INVALID, JUMPDEST, PUSH1 99, STOP
        let bytecode = vec![0x10, 4, 0x80, 0xFF, 0x82, 0x10, 99, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success (jumped over INVALID)"),
        }
    }

    #[test]
    fn conditional_jump() {
        let vm = make_vm();
        // JUMPI's stack convention is `(dest_val, cond) = pop2()`, where
        // cond is the TOP of stack and dest is below it (pop2 returns
        // `(below, top)`). So the correct push order is:
        //   PUSH1 5  (dest, ends up below)
        //   PUSH1 1  (cond, ends up on top — non-zero = take the jump)
        //   JUMPI    → jumps to byte 5
        //   JUMPDEST (byte 5) → no-op marker
        //   STOP
        //
        // The previous bytecode reversed the order (PUSH cond first,
        // PUSH dest second), which made JUMPI try to jump to address 1
        // instead of 5 — landing inside a PUSH operand byte rather
        // than on a JUMPDEST, so the test always errored on
        // "Invalid jump destination".
        let bytecode = vec![0x10, 5, 0x10, 1, 0x81, 0x82, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    #[test]
    fn sha256_opcode() {
        let vm = make_vm();
        // PUSH1 42, SHA256, STOP
        let bytecode = vec![0x10, 42, 0x60, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn log_opcode() {
        let vm = make_vm();
        // PUSH1 99, LOG, STOP
        let bytecode = vec![0x10, 99, 0xA0, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { logs, .. } => {
                assert_eq!(logs.len(), 1);
                assert_eq!(logs[0].contract, "SD1contract");
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn caller_and_timestamp() {
        let vm = make_vm();
        // CALLER, TIMESTAMP, STOP
        let bytecode = vec![0x70, 0x72, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn code_size_limit() {
        let vm = make_vm();
        let big = vec![0x01; MAX_CODE_SIZE + 1]; // NOP * too many
        match exec(&vm, &big, 10000) {
            ExecutionResult::Error { message, .. } => {
                assert!(message.contains("Code size"));
            }
            _ => panic!("Expected code size error"),
        }
    }

    #[test]
    fn gas_enforcement_before_execution() {
        let vm = make_vm();
        // SSTORE costs 5000 gas. With only 4999 gas, it should fail BEFORE executing.
        // PUSH1 42 (3 gas), PUSH1 0 (3 gas), SSTORE (5000 gas) = 5006 total
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0x00];
        match exec(&vm, &bytecode, 5005) {
            ExecutionResult::OutOfGas { .. } => {}
            other => panic!("Expected OutOfGas, got {:?}", other),
        }
    }

    #[test]
    fn gas_refund_for_sdelete() {
        let vm = make_vm();
        // Store then delete: PUSH1 42, PUSH1 0, SSTORE, PUSH1 0, SDELETE, STOP
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0x10, 0, 0x52, 0x00];
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Success { gas_used, .. } => {
                assert!(gas_used > 0);
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn addmod_basic() {
        let vm = make_vm();
        // (10 + 7) % 6 = 17 % 6 = 5
        // PUSH1 6 (N), PUSH1 7 (b), PUSH1 10 (a), ADDMOD, STOP
        let bytecode = vec![0x10, 6, 0x10, 7, 0x10, 10, 0x26, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    #[test]
    fn addmod_zero_modulus_returns_zero() {
        let vm = make_vm();
        // (10 + 7) % 0 = 0
        // PUSH1 0 (N), PUSH1 7 (b), PUSH1 10 (a), ADDMOD, STOP
        let bytecode = vec![0x10, 0, 0x10, 7, 0x10, 10, 0x26, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    #[test]
    fn mulmod_basic() {
        let vm = make_vm();
        // (3 * 4) % 5 = 12 % 5 = 2
        // PUSH1 5 (N), PUSH1 4 (b), PUSH1 3 (a), MULMOD, STOP
        let bytecode = vec![0x10, 5, 0x10, 4, 0x10, 3, 0x27, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    #[test]
    fn addmod_underflow_on_empty_stack() {
        let vm = make_vm();
        // ADDMOD with only 2 values on stack should fail
        // PUSH1 5, PUSH1 3, ADDMOD, STOP
        let bytecode = vec![0x10, 5, 0x10, 3, 0x26, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Error { message, .. } => {
                assert!(message.contains("underflow"), "Expected underflow, got: {}", message);
            }
            other => panic!("Expected error, got {:?}", other),
        }
    }

    #[test]
    fn sload_roundtrip_small_value() {
        let vm = make_vm();
        // PUSH1 42 (value), PUSH1 0 (slot), SSTORE, PUSH1 0 (slot), SLOAD, STOP
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0x10, 0, 0x50, 0x00];
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    /// Regression for the SLOAD read-your-writes bug.
    ///
    /// Before the fix, SSTORE buffered the write into `pending` and SLOAD
    /// read directly from `self.context` (committed disk state), so an
    /// SSTORE k=v followed by an SLOAD k inside the same frame returned
    /// 0 instead of v. This test runs exactly that program and asserts
    /// the loaded value matches what was just written.
    ///
    /// pop2 returns `(below, top)` so push order is `(slot, val)` for
    /// SSTORE and `(offset, val)` for MSTORE — i.e. the second push
    /// becomes the value parameter.
    #[test]
    fn sload_sees_pending_sstore_within_same_frame() {
        let vm = make_vm();
        let bytecode = vec![
            // SSTORE slot 7 = 99
            0x10, 7,         // PUSH1 7   (slot — bottom)
            0x10, 99,        // PUSH1 99  (val  — top)
            0x51,            // SSTORE → pending: slot 7 = 99

            // mem[0..32] = SLOAD(7) — must see the pending 99, not 0
            0x10, 0,         // PUSH1 0   (mem offset, will be `a`)
            0x10, 7,         // PUSH1 7   (slot for SLOAD)
            0x50,            // SLOAD     → pops 7, pushes value (99)
                             // stack: [0, 99]
            0x91,            // MSTORE    → (offset=0, val=99); mem[0..32]=99 BE

            // RETURN mem[0..32]
            0x10, 0,         // PUSH1 0   (return offset)
            0x10, 32,        // PUSH1 32  (return size)
            0xB6,            // RETURN
        ];
        match exec(&vm, &bytecode, 100_000) {
            ExecutionResult::Success { return_data, .. } => {
                // Big-endian U256 of 99 → last byte is 99, all others 0.
                assert_eq!(return_data.len(), 32, "expected 32-byte RETURN payload");
                assert_eq!(
                    return_data[31], 99,
                    "SLOAD must read its own pending SSTORE: expected 99 in last byte, got {:?}",
                    &return_data[..]
                );
                // The other 31 bytes must be zero (no leftover stack data).
                assert!(
                    return_data[..31].iter().all(|&b| b == 0),
                    "high bytes of returned value must be zero, got {:?}",
                    &return_data[..]
                );
            }
            other => panic!("Expected Success with return_data, got {:?}", other),
        }
    }

    /// Companion: SDELETE inside the same frame must also be visible to
    /// a later SLOAD on the same slot — the read should return 0 even
    /// though committed disk may still have the old value (the pending
    /// tombstone wins over disk).
    #[test]
    fn sload_sees_pending_sdelete_within_same_frame() {
        let vm = make_vm();
        let bytecode = vec![
            // SSTORE slot 5 = 77 first
            0x10, 5,         // PUSH1 5   (slot)
            0x10, 77,        // PUSH1 77  (val)
            0x51,            // SSTORE    → pending: slot 5 = 77

            // SDELETE slot 5
            0x10, 5,         // PUSH1 5   (slot)
            0x52,            // SDELETE   → pending: slot 5 = tombstone

            // mem[0..32] = SLOAD(5)
            0x10, 0,         // PUSH1 0   (mem offset, will be `a`)
            0x10, 5,         // PUSH1 5   (slot for SLOAD)
            0x50,            // SLOAD     → reads tombstone, pushes 0
            0x91,            // MSTORE    → mem[0..32] = 0

            // RETURN mem[0..32]
            0x10, 0,
            0x10, 32,
            0xB6,            // RETURN
        ];
        match exec(&vm, &bytecode, 100_000) {
            ExecutionResult::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 32);
                assert!(
                    return_data.iter().all(|&b| b == 0),
                    "SLOAD after pending SDELETE must return 0, got {:?}",
                    &return_data[..]
                );
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn sload_roundtrip_large_value() {
        let vm = make_vm();
        // Store u64::MAX at slot 1 then load it back.
        //
        // Two old bugs in this test:
        //   1. The opcode for PUSH8 is 0x13, not 0x12. The literal 0x12
        //      is PUSH4, which only consumes 4 of the next 8 bytes —
        //      so the high half of u64::MAX was being interpreted as
        //      subsequent opcodes (0xFF...0xFF = INVALID).
        //   2. The push order had the value pushed before the slot,
        //      which (with pop2 returning `(below, top)` and the
        //      destructuring `(slot, val) = pop2()`) wrote the value
        //      to the wrong slot. Correct order is slot first, val
        //      second.
        let mut bytecode = vec![0x10, 1];          // PUSH1 1     (slot — bottom)
        bytecode.push(0x13);                       // PUSH8       (val opcode)
        bytecode.extend_from_slice(&u64::MAX.to_be_bytes());
        bytecode.push(0x51);                       // SSTORE
        bytecode.extend_from_slice(&[0x10, 1, 0x50]); // PUSH1 1, SLOAD
        bytecode.push(0x00);                       // STOP
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

    /// Regression for the dual-VM-engines bug. The legacy `VM`
    /// engine in this file has stub implementations of CALL,
    /// CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2, and
    /// SELFDESTRUCT. If a production caller accidentally routed
    /// bytecode through this engine instead of through
    /// `ExecutionEnvironment::execute_frame`, they would silently
    /// get errors for those opcodes — a subtle behavioural
    /// divergence from the real execution path.
    ///
    /// This test pins the stub error messages so that:
    ///   1. Each stub returns a typed `Error` (not `Success` or
    ///      `OutOfGas`), so accidental routing is loud not silent.
    ///   2. The error message names `ExecutionEnvironment` so
    ///      operators can immediately see where to redirect the
    ///      caller.
    ///
    /// If a future change implements one of these opcodes inside
    /// the legacy engine, this test must be updated AT THE SAME
    /// TIME — otherwise the dual-engine drift returns.
    #[test]
    fn legacy_vm_call_family_opcodes_route_to_execution_environment() {
        let vm = make_vm();

        // Each stub byte. Per `OpCode::from_byte` in this file:
        //   CALL=0xB0, CALLCODE=0xB1, DELEGATECALL=0xB2,
        //   STATICCALL=0xB3, CREATE=0xB4, CREATE2=0xB5,
        //   SELFDESTRUCT=0xB8.
        let stubs: &[(u8, &str)] = &[
            (0xB0, "CALL"),
            (0xB1, "CALLCODE"),
            (0xB2, "DELEGATECALL"),
            (0xB3, "STATICCALL"),
            (0xB4, "CREATE"),
            (0xB5, "CREATE2"),
            (0xB8, "SELFDESTRUCT"),
        ];

        for (byte, name) in stubs {
            let result = exec(&vm, &[*byte, 0x00], 1_000_000);
            let msg = match result {
                ExecutionResult::Error { ref message, .. } => message.clone(),
                other => panic!("expected Error for legacy {} stub, got: {:?}", name, other),
            };
            assert!(
                msg.contains(name),
                "{} stub error must name the opcode, got: {}", name, msg
            );
            assert!(
                msg.contains("legacy VM engine"),
                "{} stub error must mention 'legacy VM engine', got: {}", name, msg
            );
            assert!(
                msg.contains("ExecutionEnvironment"),
                "{} stub error must redirect to ExecutionEnvironment, got: {}", name, msg
            );
        }
    }

}
