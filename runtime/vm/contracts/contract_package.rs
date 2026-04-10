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

    /// Deserialize from JSON **with automatic integrity verification**.
    ///
    /// The returned `ContractPackage` is guaranteed to satisfy
    /// `verify()` — that is, its `bytecode_hash` field matches a
    /// fresh SHA-256 of its `bytecode` field. If the two disagree
    /// (tampering, partial corruption, or a deliberate mismatch by
    /// a malicious deployer), deserialization fails with an error
    /// rather than handing back a "valid-looking" struct that the
    /// caller is expected to manually verify. This closes the
    /// "load now, verify later (maybe)" pattern the previous API
    /// had.
    ///
    /// If you genuinely need to load an unverified package — for
    /// example a forensic tool inspecting a known-bad artifact —
    /// use [`Self::from_json_unverified`] and call `verify()`
    /// explicitly when you're ready.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let pkg: Self = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if !pkg.verify() {
            return Err(format!(
                "package '{}' failed integrity check: stored bytecode_hash does \
                 not match SHA-256 of the embedded bytecode — load rejected",
                pkg.name
            ));
        }
        Ok(pkg)
    }

    /// Deserialize from JSON **without** integrity verification.
    ///
    /// Use only from tooling that needs to inspect deliberately
    /// malformed packages (fuzzer harnesses, forensic audits, etc.).
    /// Regular deployment / verification code MUST use
    /// [`Self::from_json`] so a tampered package cannot be loaded
    /// silently.
    pub fn from_json_unverified(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| e.to_string())
    }

    /// Deserialize from bytes **with automatic integrity verification**.
    ///
    /// Same guarantee as [`Self::from_json`]: the returned package
    /// always satisfies `verify()`. Tampered or truncated bytes
    /// produce an error instead of a structurally valid but
    /// semantically wrong package.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let pkg: Self = bincode::deserialize(data).map_err(|e| e.to_string())?;
        if !pkg.verify() {
            return Err(format!(
                "package '{}' failed integrity check: stored bytecode_hash does \
                 not match SHA-256 of the embedded bytecode — load rejected",
                pkg.name
            ));
        }
        Ok(pkg)
    }

    /// Deserialize from bytes without integrity verification.
    /// See [`Self::from_json_unverified`] for when to use this.
    pub fn from_bytes_unverified(data: &[u8]) -> Result<Self, String> {
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
    fn from_json_rejects_tampered_package() {
        // Regression for the "load now, verify later" bug. If a
        // package's on-disk JSON has a bytecode field that doesn't
        // match its bytecode_hash, from_json must refuse to load
        // it instead of returning a structurally-valid-but-wrong
        // package that the caller is expected to remember to
        // verify manually.
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        let mut json: serde_json::Value = serde_json::from_str(&pkg.to_json().unwrap()).unwrap();

        // Edit ONLY the bytecode field inside the serialized JSON,
        // leaving bytecode_hash pointing at the original hash.
        json["bytecode"] = serde_json::json!([0x10, 99, 0x00]);
        let tampered_json = serde_json::to_string(&json).unwrap();

        let result = ContractPackage::from_json(&tampered_json);
        assert!(result.is_err(), "tampered package must not load via from_json");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("integrity check"),
            "error must describe integrity failure, got: {}", msg
        );

        // The escape hatch still works for tooling that needs to
        // inspect bad packages directly.
        let unverified = ContractPackage::from_json_unverified(&tampered_json);
        assert!(unverified.is_ok(), "from_json_unverified should still load the bytes");
        assert!(!unverified.unwrap().verify(),
            "the unverified load must still fail verify() so the caller sees it");
    }

    #[test]
    fn from_bytes_rejects_tampered_package() {
        // Same test for the bincode path.
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        let good_bytes = pkg.to_bytes().unwrap();

        // Load the bytes unverified, tamper, re-encode — this
        // simulates an attacker who produced malformed bytes
        // directly without going through the `new` constructor.
        let mut tampered_pkg = ContractPackage::from_bytes_unverified(&good_bytes).unwrap();
        tampered_pkg.bytecode[1] = 99;
        let tampered_bytes = tampered_pkg.to_bytes().unwrap();

        let result = ContractPackage::from_bytes(&tampered_bytes);
        assert!(result.is_err(), "tampered bytes must not load via from_bytes");
        assert!(result.unwrap_err().contains("integrity check"));
    }

    #[test]
    fn estimated_gas() {
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0; 100], abi);
        assert_eq!(pkg.estimated_deploy_gas(), 32_000 + 100 * 200);
    }
}
