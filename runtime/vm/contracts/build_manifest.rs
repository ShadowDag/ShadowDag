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

    /// Quick boolean check: does this manifest describe the given
    /// package? Returns `true` only when **every** reproducibility
    /// field the two types share agrees AND the package's own
    /// bytecode hash is internally consistent (i.e. the package
    /// hasn't been tampered with in place).
    ///
    /// Prefer [`Self::verify_matches_package`] in code paths that
    /// need the reason a match failed — the boolean form here just
    /// squashes every mismatch into `false`.
    pub fn matches_package(
        &self,
        package: &crate::runtime::vm::contracts::contract_package::ContractPackage,
    ) -> bool {
        self.verify_matches_package(package).is_ok()
    }

    /// Strict reproducibility check that returns a descriptive error
    /// for the first mismatch encountered. The check order is:
    ///
    /// 1. `package.verify()` — the package's stored bytecode hash
    ///    must match a fresh SHA-256 of its bytecode field. Catches
    ///    in-place tampering where someone edited the bytes but
    ///    forgot to update the hash.
    /// 2. `bytecode_hash` on both sides must match.
    /// 3. `vm_version` on both sides must match.
    /// 4. Manifest format version must match the package's
    ///    `format_version`. A package produced by a different
    ///    manifest format family cannot have been built by this
    ///    manifest, regardless of whether the final hash happens
    ///    to line up.
    ///
    /// The previous implementation only compared `bytecode_hash`
    /// and `vm_version`. That was lenient enough to accept a package
    /// built with a completely different compiler, compiler version,
    /// or optimization level as long as the final bytes happened to
    /// match — which is exactly the false-positive class this
    /// module was supposed to prevent.
    ///
    /// Note on fields NOT in the comparison: `compiler`,
    /// `compiler_version`, `optimization_level`, and `source_files`
    /// live only in the BuildManifest, not in the ContractPackage,
    /// so this function cannot enforce them against a given
    /// package without extending the package format. Callers that
    /// need end-to-end build provenance should cross-check the
    /// manifest against the original source tree separately; this
    /// function catches the strict subset that a package CAN prove
    /// on its own.
    pub fn verify_matches_package(
        &self,
        package: &crate::runtime::vm::contracts::contract_package::ContractPackage,
    ) -> Result<(), String> {
        if !package.verify() {
            return Err(format!(
                "package '{}' failed self-verification: stored bytecode_hash \
                 does not match SHA-256 of its bytecode field",
                package.name
            ));
        }
        if self.bytecode_hash != package.bytecode_hash {
            return Err(format!(
                "bytecode_hash mismatch: manifest has '{}' but package '{}' has '{}'",
                self.bytecode_hash, package.name, package.bytecode_hash
            ));
        }
        if self.vm_version != package.vm_version {
            return Err(format!(
                "vm_version mismatch: manifest targets v{} but package '{}' targets v{}",
                self.vm_version, package.name, package.vm_version
            ));
        }
        if self.manifest_version != package.format_version {
            return Err(format!(
                "format version mismatch: manifest is format v{} but package '{}' \
                 is format v{} — a package produced by a different manifest \
                 format family cannot have been built by this manifest",
                self.manifest_version, package.name, package.format_version
            ));
        }
        Ok(())
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
        assert!(m.verify_matches_package(&pkg).is_ok());
    }

    #[test]
    fn manifest_rejects_tampered_package() {
        use crate::runtime::vm::contracts::contract_abi::ContractAbi;
        use crate::runtime::vm::contracts::contract_package::ContractPackage;

        // Build a package, then edit the bytecode in place WITHOUT
        // updating bytecode_hash. `matches_package` must refuse it
        // even if the manifest's hash happens to match the stored
        // (stale) package hash — because the package fails its own
        // internal verify().
        let bytecode = vec![0x10, 42, 0x00];
        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.set_bytecode_hash(&bytecode);

        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", bytecode, abi);
        pkg.bytecode[1] = 99; // tamper — now pkg.verify() is false

        assert!(!m.matches_package(&pkg));
        let err = m.verify_matches_package(&pkg).unwrap_err();
        assert!(err.contains("failed self-verification"), "got: {}", err);
    }

    #[test]
    fn manifest_rejects_vm_version_mismatch() {
        use crate::runtime::vm::contracts::contract_abi::ContractAbi;
        use crate::runtime::vm::contracts::contract_package::ContractPackage;

        let bytecode = vec![0x10, 42, 0x00];
        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.set_bytecode_hash(&bytecode);
        m.vm_version = 2; // target v2

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", bytecode, abi); // package is v1

        let err = m.verify_matches_package(&pkg).unwrap_err();
        assert!(err.contains("vm_version mismatch"), "got: {}", err);
    }

    #[test]
    fn manifest_rejects_format_version_mismatch() {
        use crate::runtime::vm::contracts::contract_abi::ContractAbi;
        use crate::runtime::vm::contracts::contract_package::ContractPackage;

        let bytecode = vec![0x10, 42, 0x00];
        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.set_bytecode_hash(&bytecode);
        m.manifest_version = 2;

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", bytecode, abi); // format_version 1

        let err = m.verify_matches_package(&pkg).unwrap_err();
        assert!(err.contains("format version mismatch"), "got: {}", err);
    }

    #[test]
    fn manifest_rejects_bytecode_hash_mismatch() {
        use crate::runtime::vm::contracts::contract_abi::ContractAbi;
        use crate::runtime::vm::contracts::contract_package::ContractPackage;

        let mut m = BuildManifest::new("shadowasm", "1.0.0");
        m.set_bytecode_hash(&[0x10, 42, 0x00]);

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 99, 0x00], abi);

        let err = m.verify_matches_package(&pkg).unwrap_err();
        assert!(err.contains("bytecode_hash mismatch"), "got: {}", err);
    }
}
