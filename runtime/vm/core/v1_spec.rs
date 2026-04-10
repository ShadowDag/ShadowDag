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

/// VM version identifier for v1.
pub const VERSION: u8 = 1;

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

/// Resolve a v1 mnemonic (case-insensitive) to its on-the-wire byte
/// value. Returns `None` for any name that the v1 spec does not
/// declare.
///
/// This is the SINGLE SOURCE OF TRUTH the assembler must consult
/// when emitting a non-PUSH opcode. Hand-coded byte literals in the
/// assembler historically drifted away from `V1_OPCODES` (e.g.
/// `JUMPDEST` was emitted as `0x05` instead of `0x82`, `EQ` as
/// `0x34` instead of `0x30`, …); routing every mnemonic through
/// this function makes such drift impossible by construction.
///
/// Names are matched case-insensitively against the entries in
/// `V1_OPCODES`. Aliases that the spec does NOT define (for
/// example `BLAKE3`, `ORIGIN`, `NEQ`, `MIN`, `MAX`, `BLOCKHEIGHT`)
/// are intentionally NOT resolved here, so the assembler will
/// reject them with an "unknown mnemonic" error rather than emit a
/// byte the live VM would interpret as something else.
pub fn byte_for_mnemonic(mnemonic: &str) -> Option<u8> {
    V1_OPCODES.iter()
        .find(|(_, name, _, _, _)| name.eq_ignore_ascii_case(mnemonic))
        .map(|(byte, _, _, _, _)| *byte)
}

/// Look up the gas cost for a v1 opcode mnemonic. Returns `None` for
/// unknown names. Mostly useful for tooling and tests; the live VM
/// uses `vm::OpCode::gas_cost()` directly.
pub fn gas_cost_for_mnemonic(mnemonic: &str) -> Option<u64> {
    V1_OPCODES.iter()
        .find(|(_, name, _, _, _)| name.eq_ignore_ascii_case(mnemonic))
        .map(|(_, _, gas, _, _)| *gas)
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

    /// Regression guard: every byte that the v1 spec defines must round-trip
    /// through `vm::OpCode::from_byte` to a non-INVALID variant whose name
    /// matches the spec entry. This catches drift between the consensus
    /// execution path (vm.rs OpCode) and the authoritative byte layout
    /// declared here. If a future refactor moves an opcode in vm.rs without
    /// updating v1_spec.rs (or vice versa), this test will fail BEFORE the
    /// change reaches consensus.
    ///
    /// This is the test that would have caught the parallel
    /// `core::opcodes::OpCode` enum drift (JUMPDEST = 0x05 vs 0x82, etc.)
    /// if the assembler had been built against vm::OpCode from the start.
    #[test]
    fn vm_opcode_table_matches_v1_spec_byte_layout() {
        use crate::runtime::vm::core::vm::OpCode;
        for (byte, name, _gas, _pop, _push) in V1_OPCODES {
            let op = OpCode::from_byte(*byte);
            assert!(
                op != OpCode::INVALID || *byte == 0xFF,
                "v1 spec defines byte 0x{:02X} as {} but vm::OpCode treats it as INVALID",
                byte, name
            );
            // The names must match too. The spec stores short mnemonics
            // and vm::OpCode::name() returns the same canonical strings.
            assert_eq!(
                op.name(), *name,
                "v1 spec byte 0x{:02X} = {} but vm::OpCode = {}",
                byte, name, op.name()
            );
        }
    }

    /// And the inverse direction: every byte that vm::OpCode treats as a
    /// real opcode (i.e. not INVALID) MUST be declared in the v1 spec.
    /// This catches the case where vm.rs grows a new opcode but forgets
    /// to update the spec — the new opcode would then deploy successfully
    /// (because the v1 validator wouldn't know to reject it … or would
    /// reject it on every block, breaking consensus).
    #[test]
    fn every_vm_opcode_is_declared_in_v1_spec() {
        use crate::runtime::vm::core::vm::OpCode;
        for b in 0u8..=255 {
            let op = OpCode::from_byte(b);
            if op == OpCode::INVALID {
                continue;
            }
            assert!(
                is_v1_opcode(b),
                "vm::OpCode::{:?} (byte 0x{:02X}) is not declared in v1_spec::V1_OPCODES",
                op, b
            );
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

    #[test]
    fn byte_for_mnemonic_resolves_known_v1_opcodes() {
        // The handful of opcodes that historically drifted in the
        // assembler — these MUST resolve to the v1 byte values.
        assert_eq!(byte_for_mnemonic("STOP"),     Some(0x00));
        assert_eq!(byte_for_mnemonic("JUMPDEST"), Some(0x82));
        assert_eq!(byte_for_mnemonic("MOD"),      Some(0x24));
        assert_eq!(byte_for_mnemonic("EXP"),      Some(0x25));
        assert_eq!(byte_for_mnemonic("EQ"),       Some(0x30));
        assert_eq!(byte_for_mnemonic("LT"),       Some(0x31));
        assert_eq!(byte_for_mnemonic("GT"),       Some(0x32));
        assert_eq!(byte_for_mnemonic("REVERT"),   Some(0xB7));
        assert_eq!(byte_for_mnemonic("PUSH1"),    Some(0x10));
    }

    #[test]
    fn byte_for_mnemonic_is_case_insensitive() {
        assert_eq!(byte_for_mnemonic("stop"),     Some(0x00));
        assert_eq!(byte_for_mnemonic("Stop"),     Some(0x00));
        assert_eq!(byte_for_mnemonic("jumpdest"), Some(0x82));
    }

    #[test]
    fn byte_for_mnemonic_rejects_non_v1_names() {
        // Names that exist in the parallel core::opcodes::OpCode enum
        // but NOT in v1 — the assembler must refuse to emit bytes for
        // these instead of silently mapping them to the wrong opcode.
        assert_eq!(byte_for_mnemonic("BLAKE3"),      None);
        assert_eq!(byte_for_mnemonic("SHA3"),        None);
        assert_eq!(byte_for_mnemonic("ORIGIN"),      None);
        assert_eq!(byte_for_mnemonic("BLOCKHEIGHT"), None);
        assert_eq!(byte_for_mnemonic("CHAINID"),     None);
        assert_eq!(byte_for_mnemonic("NEQ"),         None);
        assert_eq!(byte_for_mnemonic("MIN"),         None);
        assert_eq!(byte_for_mnemonic("MAX"),         None);
        assert_eq!(byte_for_mnemonic("DEBUG"),       None);
        assert_eq!(byte_for_mnemonic("not_an_op"),   None);
    }
}
