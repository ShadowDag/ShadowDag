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

use hex;
use std::collections::BTreeMap;
// IMPORTANT: this assembler MUST use the consensus-correct opcode table
// from `vm::OpCode`, which mirrors the authoritative `v1_spec` byte
// layout (e.g. JUMPDEST = 0x82). The parallel `core::opcodes::OpCode`
// enum has drifted away from v1_spec (its JUMPDEST is 0x05) and is NOT
// the consensus opcode set; assembling against it would produce
// bytecode that the live VM rejects as INVALID.
//
// Mnemonic-to-byte lookup goes through `v1_spec::byte_for_mnemonic`,
// which is the SINGLE SOURCE OF TRUTH. Hand-coded byte literals are
// only allowed for the PUSHn family (where the assembler also needs
// to consume operand bytes) and even those are cross-checked against
// v1_spec at the start of `assemble()`. Any mnemonic not declared in
// v1_spec — for example aliases that exist in `core/opcodes.rs` like
// BLAKE3, ORIGIN, NEQ, MIN, MAX, BLOCKHEIGHT, CHAINID — is rejected
// rather than emitted, because the live v1 VM has no opcode at
// those byte slots.
use crate::runtime::vm::core::v1_spec::byte_for_mnemonic;
use crate::runtime::vm::core::vm::OpCode;

/// Assembly error
#[derive(Debug, Clone)]
pub struct AsmError {
    pub line: usize,
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
            if line.is_empty() {
                continue;
            }

            // Label definition
            if let Some(rest) = line.strip_prefix(':') {
                let label = rest.trim().to_string();
                labels.insert(label, bytecode.len());
                bytecode.push(OpCode::JUMPDEST as u8);
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let mnemonic = parts[0].to_uppercase();
            let operand = parts.get(1).copied();

            // PUSHn opcodes are handled inline because the assembler must
            // also consume the operand bytes after the opcode. The opcode
            // bytes themselves are still cross-checked against v1_spec
            // via debug_assert! below. JUMP and JUMPI also need inline
            // handling for label references.
            match mnemonic.as_str() {
                "PUSH1" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFF {
                        return Err(AsmError {
                            line: line_num,
                            message: format!("PUSH1 value too large: max 255, got {}", val),
                        });
                    }
                    bytecode.push(Self::v1_byte("PUSH1", line_num)?);
                    bytecode.push(val as u8);
                }
                "PUSH2" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFFFF {
                        return Err(AsmError {
                            line: line_num,
                            message: format!("PUSH2 value too large: max 65535, got {}", val),
                        });
                    }
                    bytecode.push(Self::v1_byte("PUSH2", line_num)?);
                    bytecode.extend_from_slice(&(val as u16).to_be_bytes());
                }
                "PUSH4" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    if val > 0xFFFF_FFFF {
                        return Err(AsmError {
                            line: line_num,
                            message: format!("PUSH4 value too large: max 4294967295, got {}", val),
                        });
                    }
                    bytecode.push(Self::v1_byte("PUSH4", line_num)?);
                    bytecode.extend_from_slice(&(val as u32).to_be_bytes());
                }
                "PUSH8" => {
                    let val = Self::parse_operand(operand, line_num)?;
                    bytecode.push(Self::v1_byte("PUSH8", line_num)?);
                    bytecode.extend_from_slice(&val.to_be_bytes());
                }
                "PUSH16" => {
                    let bytes = Self::parse_hex_bytes(operand, 16, line_num)?;
                    bytecode.push(Self::v1_byte("PUSH16", line_num)?);
                    bytecode.extend_from_slice(&bytes);
                }
                "PUSH32" => {
                    let bytes = Self::parse_hex_bytes(operand, 32, line_num)?;
                    bytecode.push(Self::v1_byte("PUSH32", line_num)?);
                    bytecode.extend_from_slice(&bytes);
                }

                "JUMP" => {
                    if let Some(op) = operand {
                        if let Some(label) = op.strip_prefix(':') {
                            // Label reference — use PUSH4 to support
                            // contracts >255 bytes. Resolved in pass 2.
                            bytecode.push(Self::v1_byte("PUSH4", line_num)?);
                            label_refs.push((bytecode.len(), label.to_string(), line_num));
                            bytecode.extend_from_slice(&[0x00; 4]); // 4-byte placeholder
                        } else {
                            let dest = Self::parse_operand(Some(op), line_num)?;
                            Self::emit_push_smallest(&mut bytecode, dest)?;
                        }
                    }
                    bytecode.push(Self::v1_byte("JUMP", line_num)?);
                }
                "JUMPI" => {
                    if let Some(op) = operand {
                        if let Some(label) = op.strip_prefix(':') {
                            bytecode.push(Self::v1_byte("PUSH4", line_num)?);
                            label_refs.push((bytecode.len(), label.to_string(), line_num));
                            bytecode.extend_from_slice(&[0x00; 4]); // 4-byte placeholder
                        }
                    }
                    bytecode.push(Self::v1_byte("JUMPI", line_num)?);
                }

                // The "DUP" / "SWAP" bare aliases used to map to DUP1/SWAP1
                // (vm::OpCode::DUP and SWAP at 0x17/0x18). v1_spec only
                // declares "DUP" / "SWAP" as the canonical mnemonics, so
                // we accept either form and route them through v1_spec.
                "DUP" | "DUP1" => bytecode.push(Self::v1_byte("DUP", line_num)?),
                "SWAP" | "SWAP1" => bytecode.push(Self::v1_byte("SWAP", line_num)?),

                // The 0xA0 mnemonic in v1 is "LOG0"; "LOG" is a shell
                // alias kept for backwards-compatible source files.
                "LOG" => bytecode.push(Self::v1_byte("LOG0", line_num)?),

                // EVERYTHING ELSE goes through v1_spec::byte_for_mnemonic.
                // No more hand-coded byte literals — names that v1 doesn't
                // declare (BLAKE3, SHA3, ORIGIN, NEQ, MIN, MAX, BLOCKHEIGHT,
                // CHAINID, BALANCE, DEBUG, …) are rejected with a clear
                // "unknown mnemonic" error rather than silently emitted as
                // a byte the live VM would interpret as something else.
                other => {
                    let byte = byte_for_mnemonic(other).ok_or_else(|| AsmError {
                        line: line_num,
                        message: format!(
                            "Unknown mnemonic '{}': not declared in v1_spec::V1_OPCODES. \
                             If this is a v2/aspirational opcode it cannot be assembled \
                             against the live VM.",
                            other
                        ),
                    })?;
                    bytecode.push(byte);
                }
            }
        }

        // Pass 2: Resolve label references (4-byte big-endian offsets)
        for (pos, label, line) in &label_refs {
            let dest = labels.get(label).ok_or_else(|| AsmError {
                line: *line,
                message: format!("Undefined label: {}", label),
            })?;
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

    /// Resolve a v1 mnemonic to its byte value via `v1_spec::byte_for_mnemonic`.
    ///
    /// This is the only place in the assembler that turns a mnemonic
    /// string into a byte. It centralizes the lookup so the assembler
    /// can never accidentally drift from `v1_spec::V1_OPCODES` again
    /// (the previous implementation hand-coded byte literals like
    /// `JUMPDEST = 0x05`, `MOD = 0x25`, `EQ = 0x34`, …, none of which
    /// matched the live VM).
    ///
    /// Returns an `AsmError` for any name not declared in v1_spec.
    /// The PUSHn family is intentionally routed through this helper too
    /// (instead of using the literal `0x10`..`0x15`) so that even the
    /// PUSH bytes are cross-checked against the spec at every emit.
    fn v1_byte(mnemonic: &str, line: usize) -> Result<u8, AsmError> {
        byte_for_mnemonic(mnemonic).ok_or_else(|| AsmError {
            line,
            message: format!(
                "internal: assembler tried to emit mnemonic '{}' but v1_spec::V1_OPCODES \
                 has no entry for it. This indicates a drift between the assembler and \
                 the v1 spec — fix v1_spec.rs or the assembler match arm.",
                mnemonic
            ),
        })
    }

    /// Emit the smallest PUSHn instruction that can hold `val`.
    ///
    /// All four byte values come from `v1_spec::byte_for_mnemonic` so
    /// that this path stays consistent with the rest of the assembler.
    fn emit_push_smallest(bytecode: &mut Vec<u8>, val: u64) -> Result<(), AsmError> {
        if val <= 0xFF {
            bytecode.push(Self::v1_byte("PUSH1", 0)?);
            bytecode.push(val as u8);
        } else if val <= 0xFFFF {
            bytecode.push(Self::v1_byte("PUSH2", 0)?);
            bytecode.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= 0xFFFF_FFFF {
            bytecode.push(Self::v1_byte("PUSH4", 0)?);
            bytecode.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            bytecode.push(Self::v1_byte("PUSH8", 0)?);
            bytecode.extend_from_slice(&val.to_be_bytes());
        }
        Ok(())
    }

    fn parse_operand(operand: Option<&str>, line: usize) -> Result<u64, AsmError> {
        let s = operand.ok_or_else(|| AsmError {
            line,
            message: "Missing operand".to_string(),
        })?;

        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|e| AsmError {
                line,
                message: format!("Invalid hex: {}", e),
            })
        } else {
            s.parse::<u64>().map_err(|e| AsmError {
                line,
                message: format!("Invalid number: {}", e),
            })
        }
    }

    /// Parse a hex operand into exactly `expected_len` bytes.
    /// Accepts "0x"-prefixed or bare hex strings and zero-pads on the left
    /// if the caller supplies fewer hex digits than `expected_len * 2`.
    fn parse_hex_bytes(
        operand: Option<&str>,
        expected_len: usize,
        line: usize,
    ) -> Result<Vec<u8>, AsmError> {
        let s = operand.ok_or_else(|| AsmError {
            line,
            message: "Missing operand".to_string(),
        })?;
        let hex_str = if s.starts_with("0x") || s.starts_with("0X") {
            &s[2..]
        } else {
            s
        };

        if hex_str.len() > expected_len * 2 {
            return Err(AsmError {
                line,
                message: format!(
                    "PUSH{} operand too large: max {} hex digits, got {}",
                    expected_len,
                    expected_len * 2,
                    hex_str.len()
                ),
            });
        }

        let decoded = hex::decode(format!("{:0>width$}", hex_str, width = expected_len * 2))
            .map_err(|e| AsmError {
                line,
                message: format!("Invalid hex: {}", e),
            })?;

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
        // :start at byte 0 → JUMPDEST (0x82, per v1_spec / vm::OpCode)
        // PUSH1 1 → [0x10, 0x01]          bytes 1-2
        // PUSH1 0 → [0x10, 0x00]          bytes 3-4
        // JUMP :start → PUSH4 0, JUMP     bytes 5-10
        //   0x12, 0x00,0x00,0x00,0x00, 0x80
        //
        // Two old bugs were stacked here:
        //   1. JUMPDEST was emitted as 0x05 (the parallel
        //      `core::opcodes::OpCode::JUMPDEST` value), which the
        //      live VM rejects as INVALID. Now 0x82.
        //   2. The PUSH4 inside JUMP was emitted as 0x11 with the
        //      wrong comment "PUSH4 (0x11, 4-byte operand)" — but
        //      0x11 is PUSH2 in v1_spec, not PUSH4. PUSH4 is 0x12.
        //      The OLD assembler emitted PUSH2 + 4 placeholder bytes,
        //      so two of those placeholder bytes were interpreted as
        //      additional opcodes. With the v1_spec lookup we now
        //      correctly emit 0x12.
        let source = ":start\nPUSH1 1\nPUSH1 0\nJUMP :start";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode[0], 0x82, "JUMPDEST must be the v1 byte 0x82");
        assert_eq!(
            bytecode[5], 0x12,
            "PUSH4 must be the v1 byte 0x12 (PUSH2 is 0x11)"
        );
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
        assert_eq!(bytecode[0], 0x12, "PUSH4 must be the v1 byte 0x12");
        let offset = u32::from_be_bytes([bytecode[1], bytecode[2], bytecode[3], bytecode[4]]);
        assert_eq!(
            offset, 266,
            "label must resolve to offset 266, got {}",
            offset
        );
        // JUMPDEST at the target — 0x82 in v1 / vm::OpCode (was 0x05
        // in the obsolete `core::opcodes::OpCode` table).
        assert_eq!(
            bytecode[266], 0x82,
            "JUMPDEST at label must be the v1 byte 0x82"
        );
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
        assert!(disasm.contains("gas=3")); // PUSH1
        assert!(disasm.contains("gas=5000")); // SSTORE
        assert!(disasm.contains("gas=0")); // STOP
    }

    #[test]
    fn assemble_empty_lines_and_whitespace() {
        let source = "\n\n  PUSH1 1  \n  \n  STOP  \n\n";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x10, 1, 0x00]);
    }

    #[test]
    fn assemble_context_opcodes() {
        // Only the v1-declared context opcodes are valid here.
        // CHAINID and similar EVM-style context opcodes are NOT in v1
        // and the assembler must REJECT them — see
        // `assemble_rejects_non_v1_mnemonics_*` below.
        // v1 byte values from V1_OPCODES:
        //   CALLER    = 0x70
        //   CALLVALUE = 0x71
        //   TIMESTAMP = 0x72  (NOT 0x73 — that's BLOCKHASH)
        //   BLOCKHASH = 0x73
        //   STOP      = 0x00
        let source = "CALLER\nCALLVALUE\nTIMESTAMP\nBLOCKHASH\nSTOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x70, 0x71, 0x72, 0x73, 0x00]);
    }

    #[test]
    fn assemble_privacy_opcodes() {
        // STEALTHCHECK is NOT in v1_spec — the parallel
        // `core::opcodes::OpCode` enum has it at 0xE0, but the live VM
        // never executed those bytes. Only v1-declared opcodes here:
        //   DAGTIPS, DAGBPS — these were never in v1 either.
        // The whole "privacy / DAG context" opcode family is a
        // v2/aspirational design and the assembler must reject it.
        // (See `assemble_rejects_non_v1_mnemonics_*`.) This test now
        // only verifies that a STOP-only program assembles cleanly,
        // so the file still has at least one privacy-/dag-aware
        // smoke test slot if those opcodes are added to v1 later.
        let source = "STOP";
        let bytecode = Assembler::assemble(source).unwrap();
        assert_eq!(bytecode, vec![0x00]);
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_chainid() {
        // CHAINID is in `core::opcodes::OpCode` (0x77) but NOT in
        // `v1_spec::V1_OPCODES`. The assembler must refuse it loudly
        // rather than silently emit 0x77, which the live VM would
        // interpret as INVALID at execution time.
        assert!(Assembler::assemble("CHAINID").is_err());
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_blake3() {
        // BLAKE3 is in opcodes.rs (0x63) but not v1.
        assert!(Assembler::assemble("BLAKE3").is_err());
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_origin() {
        // ORIGIN is in opcodes.rs (0x72) but vm::OpCode at 0x72 is
        // TIMESTAMP. Emitting "ORIGIN" as 0x72 would silently produce
        // a TIMESTAMP read at runtime — exactly the kind of cross-file
        // semantic drift the user flagged. Reject.
        assert!(Assembler::assemble("ORIGIN").is_err());
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_stealthcheck() {
        assert!(Assembler::assemble("STEALTHCHECK").is_err());
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_dagtips() {
        assert!(Assembler::assemble("DAGTIPS").is_err());
    }

    #[test]
    fn assemble_rejects_non_v1_mnemonics_neq_min_max() {
        assert!(Assembler::assemble("NEQ").is_err());
        assert!(Assembler::assemble("MIN").is_err());
        assert!(Assembler::assemble("MAX").is_err());
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
