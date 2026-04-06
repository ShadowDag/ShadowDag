// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowVM Assembler — Converts human-readable assembly to bytecode.
//
// Syntax:
//   PUSH1 42         → [0x10, 0x2A]
//   PUSH8 1000       → [0x13, 0x00,0x00,0x00,0x00,0x00,0x00,0x03,0xE8]
//   ADD              → [0x20]
//   SSTORE           → [0x51]
//   STOP             → [0x00]
//
// Labels:
//   :loop            → JUMPDEST marker
//   JUMP :loop       → PUSH address, JUMP
//
// Example:
//   PUSH1 10         ; initial counter
//   :loop
//   PUSH1 1
//   SUB
//   DUP1
//   PUSH1 :loop
//   JUMPI
//   STOP
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use hex;
use crate::runtime::vm::core::opcodes::OpCode;

/// Assembly error
#[derive(Debug, Clone)]
pub struct AsmError {
    pub line:    usize,
    pub message: String,
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Line {}: {}", self.line, self.message)
    }
}

/// ShadowVM Assembler
pub struct Assembler;

impl Assembler {
    /// Assemble source code into bytecode
    pub fn assemble(source: &str) -> Result<Vec<u8>, AsmError> {
        let mut bytecode: Vec<u8> = Vec::with_capacity(256);
        let mut labels: BTreeMap<String, usize> = BTreeMap::new();
        let mut label_refs: Vec<(usize, String, usize)> = Vec::new(); // (bytecode_pos, label, line)

        // Pass 1: Assemble and collect labels
        for (line_num, raw_line) in source.lines().enumerate() {
            let line = raw_line.split(';').next().unwrap_or("").trim();
            if line.is_empty() { continue; }

            // Label definition
            if let Some(rest) = line.strip_prefix(':') {
                let label = rest.trim().to_string();
                labels.insert(label, bytecode.len());
                bytecode.push(OpCode::JUMPDEST as u8);
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() { continue; }

            let mnemonic = parts[0].to_uppercase();
            let operand = parts.get(1).copied();

            match mnemonic.as_str() {
                "STOP"     => bytecode.push(0x00),
                "NOP"      => bytecode.push(0x01),
                "PC"       => bytecode.push(0x02),
                "GAS"      => bytecode.push(0x03),
                "GASLIMIT" => bytecode.push(0x04),

                "PUSH1" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFF {
                        return Err(AsmError { line: line_num, message: format!("PUSH1 value too large: max 255, got {}", val) });
                    }
                    bytecode.push(0x10);
                    bytecode.push(val as u8);
                }
                "PUSH2" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFFFF {
                        return Err(AsmError { line: line_num, message: format!("PUSH2 value too large: max 65535, got {}", val) });
                    }
                    bytecode.push(0x11);
                    bytecode.extend_from_slice(&(val as u16).to_be_bytes());
                }
                "PUSH4" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFFFF_FFFF {
                        return Err(AsmError { line: line_num, message: format!("PUSH4 value too large: max 4294967295, got {}", val) });
                    }
                    bytecode.push(0x12);
                    bytecode.extend_from_slice(&(val as u32).to_be_bytes());
                }
                "PUSH8" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    bytecode.push(0x13);
                    bytecode.extend_from_slice(&val.to_be_bytes());
                }
                "PUSH16" => {
                    let bytes = Self::parse_hex_bytes(operand, 16, line_num)?;
                    bytecode.push(0x14);
                    bytecode.extend_from_slice(&bytes);
                }
                "PUSH32" => {
                    let bytes = Self::parse_hex_bytes(operand, 32, line_num)?;
                    bytecode.push(0x15);
                    bytecode.extend_from_slice(&bytes);
                }

                "POP"   => bytecode.push(0x16),
                "DUP" | "DUP1"  => bytecode.push(0x17),
                "DUP2"  => bytecode.push(0xD0),
                "DUP3"  => bytecode.push(0xD1),
                "DUP4"  => bytecode.push(0xD2),
                "SWAP" | "SWAP1" => bytecode.push(0x18),
                "SWAP2" => bytecode.push(0xD8),
                "SWAP3" => bytecode.push(0xD9),

                "ADD"  => bytecode.push(0x20),
                "SUB"  => bytecode.push(0x21),
                "MUL"  => bytecode.push(0x22),
                "DIV"  => bytecode.push(0x23),
                "MOD"  => bytecode.push(0x25),
                "EXP"  => bytecode.push(0x29),
                "MIN"  => bytecode.push(0x2B),
                "MAX"  => bytecode.push(0x2C),

                "LT"     => bytecode.push(0x30),
                "GT"     => bytecode.push(0x31),
                "EQ"     => bytecode.push(0x34),
                "ISZERO" => bytecode.push(0x35),
                "NEQ"    => bytecode.push(0x36),

                "AND"  => bytecode.push(0x40),
                "OR"   => bytecode.push(0x41),
                "XOR"  => bytecode.push(0x42),
                "NOT"  => bytecode.push(0x43),
                "SHL"  => bytecode.push(0x45),
                "SHR"  => bytecode.push(0x46),

                "SLOAD"   => bytecode.push(0x50),
                "SSTORE"  => bytecode.push(0x51),
                "SDELETE" => bytecode.push(0x52),

                "SHA256"    => bytecode.push(0x60),
                "KECCAK256" => bytecode.push(0x61),
                "SHA3"      => bytecode.push(0x62),
                "BLAKE3"    => bytecode.push(0x63),

                "CALLER"      => bytecode.push(0x70),
                "CALLVALUE"   => bytecode.push(0x71),
                "ORIGIN"      => bytecode.push(0x72),
                "TIMESTAMP"   => bytecode.push(0x73),
                "BLOCKHASH"   => bytecode.push(0x74),
                "BLOCKHEIGHT" => bytecode.push(0x75),
                "CHAINID"     => bytecode.push(0x77),
                "ADDRESS"     => bytecode.push(0x7A),
                "BALANCE"     => bytecode.push(0x7B),

                "JUMP" => {
                    if let Some(op) = operand {
                        if let Some(label) = op.strip_prefix(':') {
                            // Label reference — use PUSH4 (0x11, 4-byte operand) to
                            // support contracts >255 bytes. Resolved in pass 2.
                            bytecode.push(0x11); // PUSH4
                            label_refs.push((bytecode.len(), label.to_string(), line_num));
                            bytecode.extend_from_slice(&[0x00; 4]); // 4-byte placeholder
                        } else {
                            let dest = Self::parse_operand(Some(op), line_num)?;
                            Self::emit_push_smallest(&mut bytecode, dest);
                        }
                    }
                    bytecode.push(0x80);
                }
                "JUMPI" => {
                    if let Some(op) = operand {
                        if let Some(label) = op.strip_prefix(':') {
                            bytecode.push(0x11); // PUSH4
                            label_refs.push((bytecode.len(), label.to_string(), line_num));
                            bytecode.extend_from_slice(&[0x00; 4]); // 4-byte placeholder
                        }
                    }
                    bytecode.push(0x81);
                }
                "JUMPDEST" => bytecode.push(0x05),

                "MLOAD"  => bytecode.push(0x90),
                "MSTORE" => bytecode.push(0x91),
                "MSIZE"  => bytecode.push(0x93),

                "LOG0" => bytecode.push(0xA0),
                "LOG1" => bytecode.push(0xA1),
                "LOG2" => bytecode.push(0xA2),
                "LOG"  => bytecode.push(0xA0), // Alias

                "CALL"         => bytecode.push(0xB0),
                "DELEGATECALL" => bytecode.push(0xB2),
                "STATICCALL"   => bytecode.push(0xB3),
                "CREATE"       => bytecode.push(0xB4),
                "CREATE2"      => bytecode.push(0xB5),
                "RETURN"       => bytecode.push(0xB6),
                "REVERT"       => bytecode.push(0xB7),
                "SELFDESTRUCT" => bytecode.push(0xB8),

                "CALLDATALOAD" => bytecode.push(0xC0),
                "CALLDATASIZE" => bytecode.push(0xC1),
                "CALLDATACOPY" => bytecode.push(0xC2),
                "CODESIZE"     => bytecode.push(0xC3),
                "CODECOPY"     => bytecode.push(0xC4),

                "STEALTHCHECK" => bytecode.push(0xE0),
                "RINGPROOF"    => bytecode.push(0xE1),
                "CTVERIFY"     => bytecode.push(0xE2),
                "DAGTIPS"      => bytecode.push(0xE3),
                "DAGBPS"       => bytecode.push(0xE4),
                "DEBUG"        => bytecode.push(0xEF),

                "INVALID"      => bytecode.push(0xFF),

                other => {
                    return Err(AsmError { line: line_num, message: format!("Unknown mnemonic: {}", other) });
                }
            }
        }

        // Pass 2: Resolve label references (4-byte big-endian offsets)
        for (pos, label, line) in &label_refs {
            let dest = labels.get(label)
                .ok_or_else(|| AsmError { line: *line, message: format!("Undefined label: {}", label) })?;
            let bytes = (*dest as u32).to_be_bytes();
            bytecode[*pos..*pos + 4].copy_from_slice(&bytes);
        }

        Ok(bytecode)
    }

    /// Disassemble bytecode into human-readable assembly
    pub fn disassemble(bytecode: &[u8]) -> String {
        let mut output = String::with_capacity(bytecode.len() * 10);
        let mut pc = 0;

        while pc < bytecode.len() {
            let op = OpCode::from_byte(bytecode[pc]);
            let op_size = op.operand_size();

            output.push_str(&format!("{:04x}: ", pc));

            if op_size > 0 && pc + op_size < bytecode.len() {
                let operand_bytes = &bytecode[pc + 1..pc + 1 + op_size];
                let val = Self::bytes_to_u64(operand_bytes);
                output.push_str(&format!("{} {}", op.name(), val));
                pc += 1 + op_size;
            } else {
                output.push_str(op.name());
                pc += 1;
            }

            output.push_str(&format!("  ; gas={}\n", op.gas_cost()));
        }

        output
    }

    /// Emit the smallest push instruction that can hold `val`.
    fn emit_push_smallest(bytecode: &mut Vec<u8>, val: u64) {
        if val <= 0xFF {
            bytecode.push(0x10); // PUSH1 — 1 byte
            bytecode.push(val as u8);
        } else if val <= 0xFFFF {
            bytecode.push(0x11); // PUSH2 — 2 bytes
            bytecode.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= 0xFFFF_FFFF {
            bytecode.push(0x12); // PUSH4 — 4 bytes
            bytecode.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            bytecode.push(0x13); // PUSH8 — 8 bytes
            bytecode.extend_from_slice(&val.to_be_bytes());
        }
    }

    fn parse_operand(operand: Option<&str>, line: usize) -> Result<u64, AsmError> {
        let s = operand.ok_or_else(|| AsmError { line, message: "Missing operand".to_string() })?;

        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16)
                .map_err(|e| AsmError { line, message: format!("Invalid hex: {}", e) })
        } else {
            s.parse::<u64>()
                .map_err(|e| AsmError { line, message: format!("Invalid number: {}", e) })
        }
    }

    /// Parse a hex operand into exactly `expected_len` bytes.
    /// Accepts "0x"-prefixed or bare hex strings and zero-pads on the left
    /// if the caller supplies fewer hex digits than `expected_len * 2`.
    fn parse_hex_bytes(operand: Option<&str>, expected_len: usize, line: usize) -> Result<Vec<u8>, AsmError> {
        let s = operand.ok_or_else(|| AsmError { line, message: "Missing operand".to_string() })?;
        let hex_str = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };

        if hex_str.len() > expected_len * 2 {
            return Err(AsmError {
                line,
                message: format!(
                    "PUSH{} operand too large: max {} hex digits, got {}",
                    expected_len, expected_len * 2, hex_str.len()
                ),
            });
        }

        let decoded = hex::decode(
            format!("{:0>width$}", hex_str, width = expected_len * 2)
        ).map_err(|e| AsmError { line, message: format!("Invalid hex: {}", e) })?;

        Ok(decoded)
    }

    fn bytes_to_u64(bytes: &[u8]) -> u64 {
        let mut arr = [0u8; 8];
        let start = 8usize.saturating_sub(bytes.len());
        let copy_len = bytes.len().min(8);
        arr[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
        u64::from_be_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_simple_add() {
        let source = "PUSH1 3\nPUSH1 7\nADD\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x10, 3, 0x10, 7, 0x20, 0x00]);
    }

    #[test]
    fn assemble_with_comments() {
        let source = "PUSH1 42 ; the answer\nSTOP ; done";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x10, 42, 0x00]);
    }

    #[test]
    fn assemble_hex_operand() {
        let source = "PUSH1 0xFF\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x10, 255, 0x00]);
    }

    #[test]
    fn assemble_storage_ops() {
        let source = "PUSH1 100\nPUSH1 0\nSSTORE\nPUSH1 0\nSLOAD\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode[4], 0x51); // SSTORE
        assert_eq!(bytecode[7], 0x50); // SLOAD
    }

    #[test]
    fn assemble_labels() {
        // :start at byte 0 → JUMPDEST (0x05)
        // PUSH1 1 → [0x10, 0x01]          bytes 1-2
        // PUSH1 0 → [0x10, 0x00]          bytes 3-4
        // JUMP :start → PUSH4 0, JUMP     bytes 5-10
        //   0x11, 0x00,0x00,0x00,0x00, 0x80
        let source = ":start\nPUSH1 1\nPUSH1 0\nJUMP :start";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode[0], 0x05); // JUMPDEST
        assert_eq!(bytecode[5], 0x11); // PUSH4
        // 4-byte big-endian offset to :start (byte 0)
        assert_eq!(&bytecode[6..10], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(bytecode[10], 0x80); // JUMP
    }

    #[test]
    fn assemble_label_offset_above_255() {
        // Build a contract where the label lands past offset 255.
        // Each "NOP" is 1 byte, so 260 NOPs pushes the label to byte 260.
        let mut source = String::new();
        for _ in 0..260 {
            source.push_str("NOP\n");
        }
        source.push_str(":target\nSTOP\n");
        // Jump from the beginning — prepend a jump
        let full = format!("JUMP :target\n{}", source);
        let bytecode = Assembler::assemble(&full).unwrap();
        // JUMP :target → PUSH4 <offset>, JUMP = 6 bytes at start
        // Then 260 NOPs, then JUMPDEST at byte 6 + 260 = 266
        assert_eq!(bytecode[0], 0x11); // PUSH4
        let offset = u32::from_be_bytes([bytecode[1], bytecode[2], bytecode[3], bytecode[4]]);
        assert_eq!(offset, 266, "label must resolve to offset 266, got {}", offset);
        assert_eq!(bytecode[266], 0x05); // JUMPDEST at the target
    }

    #[test]
    fn assemble_unknown_mnemonic_fails() {
        let source = "NOTAREAL_OPCODE";
        assert!(Assembler::assemble(source).is_err());
    }

    #[test]
    fn disassemble_roundtrip() {
        let source = "PUSH1 42\nPUSH1 10\nADD\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        let disasm = Assembler::disassemble(&bytecode);
        assert!(disasm.contains("PUSH1 42"));
        assert!(disasm.contains("ADD"));
        assert!(disasm.contains("STOP"));
    }

    #[test]
    fn disassemble_shows_gas_costs() {
        let bytecode = vec![0x10, 5, 0x51, 0x00]; // PUSH1 5, SSTORE, STOP
        let disasm = Assembler::disassemble(&bytecode);
        assert!(disasm.contains("gas=3"));   // PUSH1
        assert!(disasm.contains("gas=5000")); // SSTORE
        assert!(disasm.contains("gas=0"));    // STOP
    }

    #[test]
    fn assemble_empty_lines_and_whitespace() {
        let source = "\n\n  PUSH1 1  \n  \n  STOP  \n\n";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x10, 1, 0x00]);
    }

    #[test]
    fn assemble_context_opcodes() {
        let source = "CALLER\nCALLVALUE\nTIMESTAMP\nBLOCKHASH\nCHAINID\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x70, 0x71, 0x73, 0x74, 0x77, 0x00]);
    }

    #[test]
    fn assemble_privacy_opcodes() {
        let source = "STEALTHCHECK\nDAGTIPS\nDAGBPS\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0xE0, 0xE3, 0xE4, 0x00]);
    }

    #[test]
    fn assemble_counter_loop() {
        let source = r#"
            PUSH1 5           ; counter = 5
            :loop
            PUSH1 1           ; decrement by 1
            SUB
            DUP               ; duplicate counter for check
            PUSH1 0
            EQ                ; counter == 0?
            PUSH1 0           ; not using label here for simplicity
            JUMPI             ; if zero, would jump (simplified)
            STOP
        "#;
        let bytecode = Assembler::assemble(source).unwrap();
        assert!(!bytecode.is_empty());
        assert_eq!(bytecode[bytecode.len() - 1], 0x00); // Ends with STOP
    }

    #[test]
    fn assemble_push8_large_value() {
        let source = "PUSH8 1000000\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode[0], 0x13); // PUSH8
        assert_eq!(bytecode.len(), 10); // 1 + 8 + 1
    }

    #[test]
    fn full_contract_example() {
        // Simple storage contract: store(slot, value) and load(slot)
        let source = r#"
            ; Store function: PUSH1 value, PUSH1 slot, SSTORE
            PUSH1 42          ; value to store
            PUSH1 0           ; storage slot 0
            SSTORE            ; store 42 at slot 0

            ; Load function: PUSH1 slot, SLOAD
            PUSH1 0           ; storage slot 0
            SLOAD             ; load from slot 0 → 42 on stack

            ; Log the result
            LOG0

            STOP
        "#;
        let bytecode = Assembler::assemble(source).unwrap();
        assert!(!bytecode.is_empty());
    }
}
