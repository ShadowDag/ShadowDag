// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract Package — standardized deployment artifact format.
//
// A ContractPackage bundles everything needed to deploy and interact
// with a contract: bytecode, ABI, VM version, and verification hashes.
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::runtime::vm::contracts::contract_abi::ContractAbi;

/// A self-contained contract deployment package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPackage {
    /// Human-readable contract name
    pub name: String,
    /// Contract bytecode (compiled)
    pub bytecode: Vec<u8>,
    /// ABI definition for encoding/decoding calls and events
    pub abi: ContractAbi,
    /// VM version this contract targets
    pub vm_version: u8,
    /// SHA-256 hash of the bytecode (for verification)
    pub bytecode_hash: String,
    /// Optional source code hash (for verification/audit)
    pub source_hash: Option<String>,
    /// Optional constructor arguments (already encoded)
    pub constructor_args: Option<Vec<u8>>,
    /// Package format version
    pub format_version: u8,
}

impl ContractPackage {
    /// Create a new contract package.
    pub fn new(name: &str, bytecode: Vec<u8>, abi: ContractAbi) -> Self {
        let bytecode_hash = {
            let mut h = Sha256::new();
            h.update(&bytecode);
            hex::encode(h.finalize())
        };
        Self {
            name: name.to_string(),
            bytecode,
            abi,
            vm_version: 1,
            bytecode_hash,
            source_hash: None,
            constructor_args: None,
            format_version: 1,
        }
    }

    /// Verify bytecode hash matches.
    pub fn verify(&self) -> bool {
        let mut h = Sha256::new();
        h.update(&self.bytecode);
        hex::encode(h.finalize()) == self.bytecode_hash
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| e.to_string())
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }

    /// Get the bytecode size in bytes.
    pub fn code_size(&self) -> usize {
        self.bytecode.len()
    }

    /// Get estimated deployment gas cost.
    pub fn estimated_deploy_gas(&self) -> u64 {
        32_000 + (self.bytecode.len() as u64 * 200) // base + per-byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_create_and_verify() {
        let abi = ContractAbi::new("TestContract");
        let pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        assert!(pkg.verify());
        assert_eq!(pkg.vm_version, 1);
        assert_eq!(pkg.format_version, 1);
        assert_eq!(pkg.code_size(), 3);
    }

    #[test]
    fn package_json_roundtrip() {
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        let json = pkg.to_json().unwrap();
        let loaded = ContractPackage::from_json(&json).unwrap();
        assert_eq!(loaded.name, "Test");
        assert!(loaded.verify());
    }

    #[test]
    fn package_bytes_roundtrip() {
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        let bytes = pkg.to_bytes().unwrap();
        let loaded = ContractPackage::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.bytecode_hash, pkg.bytecode_hash);
    }

    #[test]
    fn tampered_bytecode_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        pkg.bytecode[1] = 99; // tamper
        assert!(!pkg.verify());
    }

    #[test]
    fn estimated_gas() {
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0; 100], abi);
        assert_eq!(pkg.estimated_deploy_gas(), 32_000 + 100 * 200);
    }
}
