// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// Source Map -- maps bytecode positions to source lines for debugging.
// =============================================================================

use serde::{Serialize, Deserialize};

/// A single mapping entry: bytecode position -> source location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapping {
    /// Byte offset in the compiled bytecode
    pub pc: usize,
    /// Source file index (into SourceMap::files)
    pub file_index: usize,
    /// Line number in the source file (1-based)
    pub line: usize,
    /// Column number (0-based, optional)
    pub column: usize,
}

/// Debug information for a compiled contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMap {
    /// Source file paths
    pub files: Vec<String>,
    /// PC -> source mappings (sorted by PC)
    pub mappings: Vec<SourceMapping>,
}

impl SourceMap {
    pub fn new() -> Self {
        Self { files: Vec::new(), mappings: Vec::new() }
    }

    pub fn add_file(&mut self, path: &str) -> usize {
        let idx = self.files.len();
        self.files.push(path.to_string());
        idx
    }

    pub fn add_mapping(&mut self, pc: usize, file_index: usize, line: usize, column: usize) {
        self.mappings.push(SourceMapping { pc, file_index, line, column });
    }

    /// Find the source location for a given PC value.
    /// Returns the closest mapping at or before the PC.
    pub fn lookup(&self, pc: usize) -> Option<&SourceMapping> {
        // Binary search for the closest mapping <= pc
        let idx = self.mappings.partition_point(|m| m.pc <= pc);
        if idx > 0 { Some(&self.mappings[idx - 1]) } else { None }
    }

    /// Build a stack trace from a list of PC values (deepest first).
    pub fn build_trace(&self, pcs: &[usize]) -> Vec<String> {
        pcs.iter().map(|&pc| {
            match self.lookup(pc) {
                Some(m) => {
                    let file = self.files.get(m.file_index).map(|s| s.as_str()).unwrap_or("?");
                    format!("  at {}:{} (pc=0x{:04x})", file, m.line, pc)
                }
                None => format!("  at <unknown> (pc=0x{:04x})", pc),
            }
        }).collect()
    }

    /// Decode a REVERT reason from return data.
    pub fn decode_revert_reason(data: &[u8]) -> String {
        if data.is_empty() {
            return "REVERT (no reason)".into();
        }
        // Try UTF-8 first
        if let Ok(s) = std::str::from_utf8(data) {
            return format!("REVERT: {}", s);
        }
        // Hex fallback
        format!("REVERT: 0x{}", hex::encode(data))
    }
}

impl Default for SourceMap {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_map_lookup() {
        let mut sm = SourceMap::new();
        let f = sm.add_file("token.sasm");
        sm.add_mapping(0, f, 1, 0);   // PC 0 -> line 1
        sm.add_mapping(3, f, 2, 0);   // PC 3 -> line 2
        sm.add_mapping(7, f, 5, 0);   // PC 7 -> line 5

        assert_eq!(sm.lookup(0).unwrap().line, 1);
        assert_eq!(sm.lookup(2).unwrap().line, 1);  // between 0 and 3 -> line 1
        assert_eq!(sm.lookup(3).unwrap().line, 2);
        assert_eq!(sm.lookup(5).unwrap().line, 2);
        assert_eq!(sm.lookup(10).unwrap().line, 5);
    }

    #[test]
    fn build_trace() {
        let mut sm = SourceMap::new();
        let f = sm.add_file("contract.sasm");
        sm.add_mapping(0, f, 1, 0);
        sm.add_mapping(5, f, 3, 0);

        let trace = sm.build_trace(&[5, 0]);
        assert_eq!(trace.len(), 2);
        assert!(trace[0].contains("contract.sasm:3"));
        assert!(trace[1].contains("contract.sasm:1"));
    }

    #[test]
    fn decode_revert_utf8() {
        assert_eq!(SourceMap::decode_revert_reason(b"insufficient balance"),
            "REVERT: insufficient balance");
    }

    #[test]
    fn decode_revert_hex() {
        assert_eq!(SourceMap::decode_revert_reason(&[0xFF, 0x00]),
            "REVERT: 0xff00");
    }

    #[test]
    fn decode_revert_empty() {
        assert_eq!(SourceMap::decode_revert_reason(&[]),
            "REVERT (no reason)");
    }
}
