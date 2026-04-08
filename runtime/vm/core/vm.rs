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
//   9. All opcodes cost ≥ 1 gas — prevents infinite-loop DoS
//  10. State changes are atomic — committed only on successful STOP/RETURN
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
                OpCode::SLOAD => {
                    let slot = match Self::pop1(&mut stack, &gas, &mut pending) { Ok(v) => v, Err(e) => return e };
                    let key = format!("{}:slot:{}", contract_addr, slot);
                    let val = self.context.get(&key)
                        .map(|s| {
                            // DETERMINISTIC parsing: try hex first (canonical format
                            // written by SSTORE), then decimal as fallback for
                            // backward compatibility. Both paths produce identical
                            // U256 values regardless of input format.
                            if let Some(hex_str) = s.strip_prefix("0x") {
                                match U256::from_hex(hex_str) {
                                    Some(v) => v,
                                    None => {
                                        slog_warn!("vm", "sload_malformed_storage",
                                            key => &key, error => "invalid hex after 0x prefix");
                                        U256::ZERO
                                    }
                                }
                            } else if s.starts_with("0x") {
                                match U256::from_hex(&s) {
                                    Some(v) => v,
                                    None => {
                                        slog_warn!("vm", "sload_malformed_storage",
                                            key => &key, error => "invalid hex value");
                                        U256::ZERO
                                    }
                                }
                            } else {
                                // Strict decimal parsing: only digits, no signs
                                if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
                                    match s.parse::<u64>() {
                                        Ok(n) => U256::from_u64(n),
                                        Err(e) => {
                                            slog_warn!("vm", "sload_malformed_storage",
                                                key => &key, error => &e.to_string());
                                            U256::ZERO
                                        }
                                    }
                                } else {
                                    slog_warn!("vm", "sload_malformed_storage",
                                        key => &key, error => "non-numeric non-hex value");
                                    U256::ZERO
                                }
                            }
                        })
                        .unwrap_or(U256::ZERO);
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

                // -- STUBS: opcodes recognized but not yet fully implemented --
                // Gas is already charged above via gas.consume(cost).
                // These return a typed VM error identifying the specific opcode.

                // CALL: inter-contract call. Stub -- requires full message-call
                // frame implementation (value transfer, gas stipend, call depth).
                OpCode::CALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "CALL opcode not yet implemented");
                }
                // CALLCODE: like CALL but executes callee code in caller's storage.
                // Stub -- requires full message-call frame implementation.
                OpCode::CALLCODE => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "CALLCODE opcode not yet implemented");
                }
                // DELEGATECALL: like CALLCODE but preserves caller and value.
                // Stub -- requires full message-call frame implementation.
                OpCode::DELEGATECALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "DELEGATECALL opcode not yet implemented");
                }
                // STATICCALL: read-only call (no state changes allowed).
                // Stub -- requires full message-call frame implementation.
                OpCode::STATICCALL => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "STATICCALL opcode not yet implemented");
                }
                // CREATE: deploy a new contract. Stub -- requires contract
                // deployment logic (init code execution, address derivation).
                OpCode::CREATE => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "CREATE opcode not yet implemented");
                }
                // CREATE2: deterministic contract deployment. Stub -- requires
                // contract deployment with salt-based address derivation.
                OpCode::CREATE2 => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "CREATE2 opcode not yet implemented");
                }
                // SELFDESTRUCT: destroy the contract and transfer remaining balance.
                // Stub -- requires balance transfer and account cleanup.
                OpCode::SELFDESTRUCT => {
                    pending.discard();
                    return Self::err(gas.gas_used(), "SELFDESTRUCT opcode not yet implemented");
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
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        VM::new(&format!("/tmp/test_vm_{}", ts)).expect("VM::new failed")
    }

    fn exec(vm: &VM, bytecode: &[u8], gas: u64) -> ExecutionResult {
        vm.execute_bytecode(bytecode, gas, "SD1caller", 0, 1000, "blockhash", "SD1contract", &[])
    }

    #[test]
    fn stop_immediately() {
        let vm = make_vm();
        let result = exec(&vm, &[0x00], 1000); // STOP
        match result {
            ExecutionResult::Success { gas_used, .. } => assert_eq!(gas_used, 0),
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
        // PUSH1 42, PUSH1 0, SSTORE, REVERT
        // The SSTORE should be discarded because of REVERT
        let bytecode = vec![0x10, 42, 0x10, 0, 0x51, 0xB2];
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Revert { .. } => {}
            _ => panic!("Expected revert"),
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
        // PUSH1 1 (condition=true), PUSH1 5 (dest), JUMPI, JUMPDEST, STOP
        let bytecode = vec![0x10, 1, 0x10, 5, 0x81, 0x82, 0x00];
        match exec(&vm, &bytecode, 10000) {
            ExecutionResult::Success { .. } => {}
            _ => panic!("Expected success"),
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

    #[test]
    fn sload_roundtrip_large_value() {
        let vm = make_vm();
        // Store u64::MAX then load it back
        // PUSH8 <u64::MAX>, PUSH1 1 (slot), SSTORE, PUSH1 1 (slot), SLOAD, STOP
        let mut bytecode = vec![0x12]; // PUSH8
        bytecode.extend_from_slice(&u64::MAX.to_be_bytes());
        bytecode.extend_from_slice(&[0x10, 1, 0x51]); // PUSH1 1, SSTORE
        bytecode.extend_from_slice(&[0x10, 1, 0x50]); // PUSH1 1, SLOAD
        bytecode.push(0x00); // STOP
        match exec(&vm, &bytecode, 100000) {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }

}
