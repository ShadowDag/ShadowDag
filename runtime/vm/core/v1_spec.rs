// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// ShadowVM v1 Opcode Specification
//
// This file is the AUTHORITATIVE source for v1 opcode definitions.
// All other components (vm.rs, execution_env.rs, assembler, validator)
// must use these definitions. Any opcode not listed here MUST be rejected
// at deploy time by validate_v1_bytecode().
// =============================================================================

/// V1 Opcodes -- the complete set supported in ShadowVM v1.
/// Each entry: (byte_value, name, gas_cost, stack_pop, stack_push)
pub const V1_OPCODES: &[(u8, &str, u64, usize, usize)] = &[
    // Control
    (0x00, "STOP",      0, 0, 0),
    (0x01, "NOP",       1, 0, 0),

    // Stack
    (0x10, "PUSH1",     3, 0, 1),
    (0x11, "PUSH2",     3, 0, 1),
    (0x12, "PUSH4",     3, 0, 1),
    (0x13, "PUSH8",     3, 0, 1),
    (0x14, "PUSH16",    3, 0, 1),
    (0x15, "PUSH32",    3, 0, 1),
    (0x16, "POP",       2, 1, 0),
    (0x17, "DUP",       2, 1, 2),
    (0x18, "SWAP",      2, 2, 2),

    // Arithmetic
    (0x20, "ADD",       3, 2, 1),
    (0x21, "SUB",       3, 2, 1),
    (0x22, "MUL",       5, 2, 1),
    (0x23, "DIV",       5, 2, 1),
    (0x24, "MOD",       5, 2, 1),
    (0x25, "EXP",       50, 2, 1),
    (0x26, "ADDMOD",    8, 3, 1),
    (0x27, "MULMOD",    8, 3, 1),

    // Comparison
    (0x30, "EQ",        3, 2, 1),
    (0x31, "LT",        3, 2, 1),
    (0x32, "GT",        3, 2, 1),
    (0x33, "ISZERO",    3, 1, 1),

    // Bitwise
    (0x40, "AND",       3, 2, 1),
    (0x41, "OR",        3, 2, 1),
    (0x42, "XOR",       3, 2, 1),
    (0x43, "NOT",       3, 1, 1),
    (0x44, "SHL",       3, 2, 1),
    (0x45, "SHR",       3, 2, 1),

    // Storage
    (0x50, "SLOAD",     200, 1, 1),
    (0x51, "SSTORE",    5000, 2, 0),
    (0x52, "SDELETE",   5000, 1, 0),

    // Crypto
    (0x60, "SHA256",    30, 1, 1),
    (0x61, "KECCAK",    30, 1, 1),

    // Context
    (0x02, "PC",        2, 0, 1),
    (0x03, "GAS",       2, 0, 1),
    (0x04, "GASLIMIT",  2, 0, 1),
    (0x70, "CALLER",    2, 0, 1),
    (0x71, "CALLVALUE", 2, 0, 1),
    (0x72, "TIMESTAMP", 2, 0, 1),
    (0x73, "BLOCKHASH", 2, 0, 1),
    (0x74, "BALANCE",   2, 1, 1),
    (0x7A, "ADDRESS",   2, 0, 1),

    // Flow control
    (0x80, "JUMP",      8, 1, 0),
    (0x81, "JUMPI",     8, 2, 0),
    (0x82, "JUMPDEST",  1, 0, 0),

    // Memory
    (0x90, "MLOAD",     3, 1, 1),
    (0x91, "MSTORE",    3, 2, 0),
    (0x92, "MSTORE8",   3, 2, 0),
    (0x93, "MSIZE",     2, 0, 1),

    // Logging
    (0xA0, "LOG0",      375, 1, 0),
    (0xA1, "LOG1",      750, 2, 0),
    (0xA2, "LOG2",      1125, 3, 0),
    (0xA3, "LOG3",      1500, 4, 0),
    (0xA4, "LOG4",      1875, 5, 0),

    // System calls
    (0xB0, "CALL",      700, 7, 1),
    (0xB1, "CALLCODE",  700, 7, 1),
    (0xB2, "DELEGATECALL", 700, 6, 1),
    (0xB3, "STATICCALL", 700, 6, 1),
    (0xB4, "CREATE",    32000, 3, 1),
    (0xB5, "CREATE2",   32000, 4, 1),
    (0xB6, "RETURN",    1, 2, 0),
    (0xB7, "REVERT",    1, 2, 0),
    (0xB8, "SELFDESTRUCT", 25000, 1, 0),

    // Call data
    (0xC0, "CALLDATALOAD", 3, 1, 1),
    (0xC1, "CALLDATASIZE", 2, 0, 1),
    (0xC2, "CALLDATACOPY", 3, 3, 0),
    (0xC3, "CODESIZE",     2, 0, 1),
    (0xC4, "CODECOPY",     3, 3, 0),
    (0xC5, "EXTCODESIZE",  100, 1, 1),
    (0xC6, "RETURNDATASIZE", 2, 0, 1),
    (0xC7, "RETURNDATACOPY", 3, 3, 0),

    // Extended stack
    (0xD0, "DUP2",  2, 2, 3),
    (0xD1, "DUP3",  2, 3, 4),
    (0xD2, "DUP4",  2, 4, 5),
    (0xD3, "DUP5",  2, 5, 6),
    (0xD4, "DUP6",  2, 6, 7),
    (0xD5, "DUP7",  2, 7, 8),
    (0xD6, "DUP8",  2, 8, 9),
    (0xD7, "SWAP2", 2, 3, 3),
    (0xD8, "SWAP3", 2, 4, 4),
    (0xD9, "SWAP4", 2, 5, 5),

    // Invalid (sentinel)
    (0xFF, "INVALID", u64::MAX, 0, 0),
];

/// Check if a byte value is a valid v1 opcode.
pub fn is_v1_opcode(byte: u8) -> bool {
    V1_OPCODES.iter().any(|(b, _, _, _, _)| *b == byte)
}

/// Validate that bytecode contains ONLY v1 opcodes.
/// Returns Ok(()) if valid, Err with the first invalid opcode byte and position.
pub fn validate_v1_bytecode(bytecode: &[u8]) -> Result<(), (usize, u8)> {
    let mut i = 0;
    while i < bytecode.len() {
        let byte = bytecode[i];
        if !is_v1_opcode(byte) {
            return Err((i, byte));
        }
        // Skip PUSH data bytes
        match byte {
            0x10 => i += 2,  // PUSH1
            0x11 => i += 3,  // PUSH2
            0x12 => i += 5,  // PUSH4
            0x13 => i += 9,  // PUSH8
            0x14 => i += 17, // PUSH16
            0x15 => i += 33, // PUSH32
            _ => i += 1,
        }
    }
    Ok(())
}

/// Execution limits -- single source of truth for all VM components.
pub const MAX_STACK_SIZE: usize = 1024;
pub const MAX_MEMORY_SIZE: usize = 1_048_576; // 1 MB
pub const MAX_CODE_SIZE: usize = 24_576;      // 24 KB
pub const MAX_CALL_DEPTH: usize = 1024;

/// Memory gas model (quadratic, EVM-compatible)
pub const MEMORY_GAS_PER_WORD: u64 = 3;
pub const MEMORY_QUADRATIC_DIVISOR: u64 = 512;

/// Memory expansion cost (quadratic model)
/// cost = new_words * 3 + new_words^2 / 512 - old_cost
pub fn memory_expansion_cost(current_words: u64, new_words: u64) -> u64 {
    if new_words <= current_words { return 0; }
    let new_cost = new_words * MEMORY_GAS_PER_WORD + (new_words * new_words) / MEMORY_QUADRATIC_DIVISOR;
    let old_cost = current_words * MEMORY_GAS_PER_WORD + (current_words * current_words) / MEMORY_QUADRATIC_DIVISOR;
    new_cost.saturating_sub(old_cost)
}

/// Gas refund cap: 50% of gas used (pre-London).
/// This is a chain-level parameter, defined here as the v1 default.
pub const GAS_REFUND_QUOTIENT: u64 = 2;

/// GAS opcode policy for v1:
/// The GAS opcode IS available (returns remaining gas).
/// has_gas() on GasMeter is pub(crate) to prevent non-deterministic branching
/// from Rust code, but contracts CAN use the GAS opcode to read remaining gas.
/// This matches EVM behavior.
pub const GAS_OPCODE_ENABLED: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_v1_opcodes_have_unique_bytes() {
        let mut seen = std::collections::HashSet::new();
        for (byte, name, _, _, _) in V1_OPCODES {
            assert!(seen.insert(byte), "Duplicate byte 0x{:02X} for {}", byte, name);
        }
    }

    #[test]
    fn v1_validation_rejects_unknown_opcode() {
        // 0xEE is not in v1
        assert!(validate_v1_bytecode(&[0xEE]).is_err());
    }

    #[test]
    fn v1_validation_accepts_valid_code() {
        // PUSH1 42, PUSH1 0, SSTORE, STOP
        assert!(validate_v1_bytecode(&[0x10, 42, 0x10, 0, 0x51, 0x00]).is_ok());
    }

    #[test]
    fn v1_validation_skips_push_data() {
        // PUSH1 0xFF, STOP -- 0xFF in push data should NOT be rejected
        assert!(validate_v1_bytecode(&[0x10, 0xFF, 0x00]).is_ok());
    }

    #[test]
    fn memory_cost_quadratic() {
        let cost_1 = memory_expansion_cost(0, 1);
        let cost_100 = memory_expansion_cost(0, 100);
        // Quadratic: cost(100) > 100 * cost(1) due to n^2/512 term
        assert!(cost_100 > 100 * cost_1);
    }
}
