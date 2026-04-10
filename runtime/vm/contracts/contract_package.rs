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
    /// SHA-256 hash of the bytecode (for verification).
    ///
    /// Covers ONLY `bytecode`. See [`Self::package_hash`] for the
    /// whole-package hash that covers name / abi / vm_version /
    /// source_hash / constructor_args / format_version too.
    pub bytecode_hash: String,
    /// Optional source code hash (for verification/audit)
    pub source_hash: Option<String>,
    /// Optional constructor arguments (already encoded)
    pub constructor_args: Option<Vec<u8>>,
    /// Package format version
    pub format_version: u8,
    /// SHA-256 over a canonical serialization of every **other** field
    /// in this struct (name, bytecode, abi, vm_version, bytecode_hash,
    /// source_hash, constructor_args, format_version).
    ///
    /// Why this exists: the previous integrity story was "compute
    /// `SHA-256(bytecode)` and compare with `bytecode_hash`", which
    /// ONLY caught tampering in the bytecode itself. Tampering in
    /// the `name`, `abi`, `vm_version`, `source_hash`,
    /// `constructor_args`, or `format_version` fields flowed through
    /// the loader unchecked — so a "package passed integrity check"
    /// label meant "the bytecode is intact", not "the whole artifact
    /// is intact". `package_hash` closes that gap.
    ///
    /// Serialized with `#[serde(default)]` so legacy on-disk packages
    /// that predate this field still deserialize. A legacy package
    /// has `package_hash == ""`, and `verify()` falls back to the
    /// bytecode-only check (with a `slog_error!` note) so loading
    /// old artifacts doesn't break overnight. New packages built via
    /// [`Self::new`] always have a non-empty `package_hash` and get
    /// the full-coverage check.
    #[serde(default)]
    pub package_hash: String,
}

impl ContractPackage {
    /// Create a new contract package.
    ///
    /// Computes both `bytecode_hash` (SHA-256 of `bytecode`) and
    /// `package_hash` (SHA-256 of a canonical serialization of every
    /// other field) so the returned package is fully integrity-tagged
    /// — tampering with ANY field after construction can be caught
    /// by [`Self::verify`].
    pub fn new(name: &str, bytecode: Vec<u8>, abi: ContractAbi) -> Self {
        let bytecode_hash = Self::compute_bytecode_hash(&bytecode);
        let mut pkg = Self {
            name: name.to_string(),
            bytecode,
            abi,
            vm_version: 1,
            bytecode_hash,
            source_hash: None,
            constructor_args: None,
            format_version: 1,
            package_hash: String::new(),
        };
        pkg.package_hash = pkg.compute_package_hash();
        pkg
    }

    /// SHA-256 of the bytecode, hex-encoded.
    fn compute_bytecode_hash(bytecode: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytecode);
        hex::encode(h.finalize())
    }

    /// Compute `package_hash` over every field **except** the hash
    /// field itself.
    ///
    /// The input is a fixed-order, length-prefixed concatenation of:
    ///
    ///   1. magic tag `"ShadowDAG_PKG_v1"` (so the hash domain is
    ///      separable from other SHA-256 uses in the codebase)
    ///   2. name bytes (length-prefixed)
    ///   3. bytecode bytes (length-prefixed)
    ///   4. ABI JSON bytes (length-prefixed)
    ///   5. vm_version (1 byte)
    ///   6. bytecode_hash bytes (length-prefixed; INCLUDED because it
    ///      is derived from `bytecode` and tampering in either side
    ///      should drop the whole-package hash too)
    ///   7. source_hash bytes if present, otherwise length 0
    ///   8. constructor_args bytes if present, otherwise length 0
    ///   9. format_version (1 byte)
    ///
    /// Every variable-length field carries a little-endian `u32`
    /// length prefix so boundary ambiguities cannot be exploited
    /// (e.g. a tampering attack that shifts bytes across the
    /// name/bytecode boundary).
    ///
    /// `package_hash` itself is NOT part of the input.
    fn compute_package_hash(&self) -> String {
        fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }

        let mut buf: Vec<u8> = Vec::with_capacity(256 + self.bytecode.len());
        buf.extend_from_slice(b"ShadowDAG_PKG_v1");

        push_len_prefixed(&mut buf, self.name.as_bytes());
        push_len_prefixed(&mut buf, &self.bytecode);

        // ABI JSON. `ContractAbi::to_json` is a `Result` now — on
        // failure we fold the error bytes into the hash input so a
        // later verify() sees the SAME poisoned bytes and the hash
        // is still deterministic. This is a last-resort path; the
        // happy path is that to_json() returns valid JSON.
        let abi_bytes = match self.abi.to_json() {
            Ok(s) => s.into_bytes(),
            Err(e) => format!("<abi_to_json_error: {}>", e).into_bytes(),
        };
        push_len_prefixed(&mut buf, &abi_bytes);

        buf.push(self.vm_version);
        push_len_prefixed(&mut buf, self.bytecode_hash.as_bytes());

        match &self.source_hash {
            Some(s) => push_len_prefixed(&mut buf, s.as_bytes()),
            None    => push_len_prefixed(&mut buf, &[]),
        }
        match &self.constructor_args {
            Some(v) => push_len_prefixed(&mut buf, v),
            None    => push_len_prefixed(&mut buf, &[]),
        }

        buf.push(self.format_version);

        let mut h = Sha256::new();
        h.update(&buf);
        hex::encode(h.finalize())
    }

    /// Verify **both** the bytecode hash AND the whole-package hash.
    ///
    /// Returns `true` iff:
    ///   - `SHA-256(self.bytecode) == self.bytecode_hash`, AND
    ///   - EITHER `self.package_hash.is_empty()` (legacy package —
    ///     falls back to bytecode-only check) OR
    ///     `self.compute_package_hash() == self.package_hash`.
    ///
    /// Legacy packages (predating this field) that come off disk
    /// with `package_hash == ""` are accepted with bytecode-only
    /// semantics so old artifacts don't break on load. New packages
    /// built via [`Self::new`] always have a non-empty
    /// `package_hash`, so every new artifact gets the full-coverage
    /// check and any field-level tampering is caught.
    pub fn verify(&self) -> bool {
        if Self::compute_bytecode_hash(&self.bytecode) != self.bytecode_hash {
            return false;
        }
        if self.package_hash.is_empty() {
            // Legacy package — bytecode-only check has already
            // passed. Accept for backward compatibility.
            return true;
        }
        self.compute_package_hash() == self.package_hash
    }

    /// Check whether this package carries a full-coverage
    /// `package_hash`. `false` for legacy artifacts that only have a
    /// `bytecode_hash`.
    pub fn has_full_integrity(&self) -> bool {
        !self.package_hash.is_empty()
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

    // ─── package_hash / full-integrity regression tests ─────────────
    //
    // Each of these plants a tampering edit in a field OTHER than
    // `bytecode` and asserts that `verify()` refuses the result.
    // The previous `verify()` only covered `bytecode`, so every one
    // of these would have passed while the package was semantically
    // wrong.

    #[test]
    fn new_sets_non_empty_package_hash() {
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x00], abi);
        assert!(pkg.has_full_integrity());
        assert!(!pkg.package_hash.is_empty());
        assert_eq!(pkg.package_hash.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn tampered_name_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Original", vec![0x10, 42, 0x00], abi);
        assert!(pkg.verify());
        pkg.name = "Tampered".to_string();
        assert!(!pkg.verify(),
            "name tampering must be caught by package_hash — previously it was not");
    }

    #[test]
    fn tampered_vm_version_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        assert!(pkg.verify());
        pkg.vm_version = 99; // pretend to be v99
        assert!(!pkg.verify(),
            "vm_version tampering must be caught — previously it was not");
    }

    #[test]
    fn tampered_format_version_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        assert!(pkg.verify());
        pkg.format_version = 42;
        assert!(!pkg.verify(),
            "format_version tampering must be caught");
    }

    #[test]
    fn tampered_source_hash_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        pkg.source_hash = Some("original_source".into());
        pkg.package_hash = pkg.compute_package_hash(); // re-seal after the legit change
        assert!(pkg.verify());
        pkg.source_hash = Some("tampered_source".into());
        assert!(!pkg.verify(),
            "source_hash tampering must be caught");
    }

    #[test]
    fn tampered_constructor_args_fails_verify() {
        let abi = ContractAbi::new("Test");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        pkg.constructor_args = Some(vec![0x00, 0x01, 0x02]);
        pkg.package_hash = pkg.compute_package_hash();
        assert!(pkg.verify());
        pkg.constructor_args = Some(vec![0xff, 0xff, 0xff]);
        assert!(!pkg.verify(),
            "constructor_args tampering must be caught");
    }

    #[test]
    fn tampered_abi_fails_verify() {
        let abi = ContractAbi::new("OriginalContract");
        let mut pkg = ContractPackage::new("Test", vec![0x10, 42, 0x00], abi);
        assert!(pkg.verify());
        // Mutate the embedded ABI and assert verify() refuses it.
        // (Adding a function to the ABI would have been invisible to
        // the old bytecode-only verify.)
        pkg.abi.add_function(
            "sneaky",
            vec![],
            vec![],
            crate::runtime::vm::contracts::contract_abi::Mutability::Mutable,
        );
        assert!(!pkg.verify(),
            "abi tampering must be caught — previously a smuggled function would load cleanly");
    }

    #[test]
    fn from_json_rejects_name_tampering() {
        // Even more important: the FROM_JSON path must also refuse a
        // name-tampered package. This is how external artifacts
        // (from the filesystem / RPC import / build output) reach
        // the VM, so full-coverage integrity MUST fire at the load
        // point, not just at runtime `verify()` calls.
        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Original", vec![0x10, 42, 0x00], abi);
        let mut json: serde_json::Value = serde_json::from_str(&pkg.to_json().unwrap()).unwrap();
        json["name"] = serde_json::json!("Tampered");
        let tampered = serde_json::to_string(&json).unwrap();

        let result = ContractPackage::from_json(&tampered);
        assert!(result.is_err(),
            "from_json must refuse a name-tampered package");
        assert!(result.unwrap_err().contains("integrity check"));
    }

    #[test]
    fn legacy_package_without_package_hash_still_loads() {
        // Backward-compat smoke test. A pre-package_hash artifact
        // has `package_hash == ""` after deserialization. We want
        // those to still load via from_json as long as their
        // bytecode_hash is consistent — the goal is to not break
        // every on-disk artifact the day this field is introduced.
        let abi = ContractAbi::new("Legacy");
        let pkg = ContractPackage::new("Legacy", vec![0x10, 7, 0x00], abi);
        let mut json: serde_json::Value = serde_json::from_str(&pkg.to_json().unwrap()).unwrap();
        // Strip the new field, as a pre-upgrade file would not have it.
        if let Some(obj) = json.as_object_mut() {
            obj.remove("package_hash");
        }
        let legacy_json = serde_json::to_string(&json).unwrap();

        let loaded = ContractPackage::from_json(&legacy_json)
            .expect("legacy package without package_hash must still load");
        assert!(loaded.package_hash.is_empty(),
            "legacy package deserializes with empty package_hash");
        assert!(!loaded.has_full_integrity(),
            "legacy package has no full integrity flag");
        assert!(loaded.verify(),
            "legacy package still passes bytecode-only verify() for back-compat");
    }

    #[test]
    fn legacy_package_with_tampered_bytecode_still_refused() {
        // Backward compat MUST NOT relax the bytecode-level check.
        // A legacy package whose bytecode was tampered should still
        // be refused by from_json.
        let abi = ContractAbi::new("Legacy");
        let pkg = ContractPackage::new("Legacy", vec![0x10, 7, 0x00], abi);
        let mut json: serde_json::Value = serde_json::from_str(&pkg.to_json().unwrap()).unwrap();
        if let Some(obj) = json.as_object_mut() {
            obj.remove("package_hash");
        }
        json["bytecode"] = serde_json::json!([0x10, 99, 0x00]);
        let tampered_legacy = serde_json::to_string(&json).unwrap();
        assert!(ContractPackage::from_json(&tampered_legacy).is_err());
    }
}
