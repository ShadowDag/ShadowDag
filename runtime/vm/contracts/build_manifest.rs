// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Build Manifest -- reproducible build metadata for contract verification.
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Build manifest for reproducible contract compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    /// Assembler/compiler that produced this bytecode
    pub compiler: String,
    /// Compiler version
    pub compiler_version: String,
    /// VM version targeted
    pub vm_version: u8,
    /// Optimization level (0=none, 1=basic, 2=full)
    pub optimization_level: u8,
    /// Source file hashes: (filename, sha256)
    pub source_files: Vec<(String, String)>,
    /// Resulting bytecode hash
    pub bytecode_hash: String,
    /// Build timestamp (for reference, not determinism)
    pub build_timestamp: u64,
    /// Manifest format version
    pub manifest_version: u8,
}

impl BuildManifest {
    pub fn new(compiler: &str, version: &str) -> Self {
        Self {
            compiler: compiler.to_string(),
            compiler_version: version.to_string(),
            vm_version: 1,
            optimization_level: 0,
            source_files: Vec::new(),
            bytecode_hash: String::new(),
            build_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            manifest_version: 1,
        }
    }

    /// Add a source file with its hash.
    pub fn add_source(&mut self, filename: &str, content: &[u8]) {
        let mut h = Sha256::new();
        h.update(content);
        self.source_files.push((filename.to_string(), hex::encode(h.finalize())));
    }

    /// Set the final bytecode hash.
    pub fn set_bytecode_hash(&mut self, bytecode: &[u8]) {
        let mut h = Sha256::new();
        h.update(bytecode);
        self.bytecode_hash = hex::encode(h.finalize());
    }

    /// Verify that the same source + settings should produce the same bytecode.
    pub fn matches_package(&self, package: &crate::runtime::vm::contracts::contract_package::ContractPackage) -> bool {
        self.bytecode_hash == package.bytecode_hash && self.vm_version == package.vm_version
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_create_and_serialize() {
        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.add_source("token.sasm", b"PUSH1 42\nSTOP");
        m.set_bytecode_hash(&[0x10, 42, 0x00]);

        let json = m.to_json().unwrap();
        let loaded = BuildManifest::from_json(&json).unwrap();
        assert_eq!(loaded.compiler, "shadowasm");
        assert_eq!(loaded.source_files.len(), 1);
        assert!(!loaded.bytecode_hash.is_empty());
    }

    #[test]
    fn manifest_matches_package() {
        use crate::runtime::vm::contracts::contract_abi::ContractAbi;
        use crate::runtime::vm::contracts::contract_package::ContractPackage;

        let bytecode = vec![0x10, 42, 0x00];
        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.set_bytecode_hash(&bytecode);

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", bytecode, abi);

        assert!(m.matches_package(&pkg));
    }
}
