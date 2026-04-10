// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract Verification -- matches deployed bytecode against a ContractPackage.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use crate::runtime::vm::contracts::contract_package::ContractPackage;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::errors::StorageError;
use crate::slog_error;

/// Verification result for a deployed contract.
///
/// `vm_version` is `None` when the on-disk metadata is missing or
/// corrupt — it is NOT silently coerced to "1" any more (see the
/// `verify` doc comment for the rationale). Callers that observe
/// `vm_version: None` together with `verified: false` should treat
/// the contract as unverifiable until the metadata is restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub address: String,
    pub verified: bool,
    pub contract_name: Option<String>,
    pub bytecode_match: bool,
    pub vm_version_match: bool,
    pub deployed_bytecode_hash: String,
    pub package_bytecode_hash: Option<String>,
    pub deployed_code_size: usize,
    /// Resolved VM version from `vm_version:{addr}` metadata, or
    /// `None` if the metadata is absent OR cannot be parsed as a
    /// `u8`. The previous implementation collapsed both cases into
    /// `1`, which silently produced "verified=true" results for v1
    /// packages on contracts whose metadata was actually missing
    /// or corrupt.
    pub vm_version: Option<u8>,
    pub error: Option<String>,
}

/// Persistent verification store
pub struct ContractVerifier;

impl ContractVerifier {
    /// Verify a deployed contract against a package artifact.
    ///
    /// VM version handling: the previous implementation read
    /// `vm_version:{addr}` and used `parse::<u8>().ok().unwrap_or(1)`,
    /// which collapsed three distinct cases — "metadata present and
    /// parseable", "metadata missing", and "metadata corrupt" — into
    /// the same value of `1`. A v1 package would therefore verify
    /// `vm_version_match == true` against a contract whose on-disk
    /// version metadata was missing or unreadable, producing a
    /// false-positive `verified == true`.
    ///
    /// The new logic distinguishes the cases explicitly:
    ///
    ///   - present + parses → `Some(v)`, normal compare
    ///   - present + does NOT parse → `None`, vm_version_match=false,
    ///     error message logged + recorded
    ///   - absent → `None`, vm_version_match=false, error recorded
    ///
    /// In every "version unknown" case the result has `verified=false`
    /// even if the bytecode hash happens to match, so a corrupt
    /// metadata entry can never silently signal a verified contract.
    pub fn verify(
        storage: &ContractStorage,
        address: &str,
        package: &ContractPackage,
    ) -> VerificationResult {
        // Load deployed code
        let deployed_code = match storage.get_state(&format!("code:{}", address)) {
            Some(hex_code) => match hex::decode(&hex_code) {
                Ok(bytes) => bytes,
                Err(e) => return VerificationResult {
                    address: address.into(),
                    verified: false,
                    contract_name: Some(package.name.clone()),
                    bytecode_match: false,
                    vm_version_match: false,
                    deployed_bytecode_hash: String::new(),
                    package_bytecode_hash: Some(package.bytecode_hash.clone()),
                    deployed_code_size: 0,
                    vm_version: None,
                    error: Some(format!("invalid hex in stored code: {}", e)),
                },
            },
            None => return VerificationResult {
                address: address.into(),
                verified: false,
                contract_name: Some(package.name.clone()),
                bytecode_match: false,
                vm_version_match: false,
                deployed_bytecode_hash: String::new(),
                package_bytecode_hash: Some(package.bytecode_hash.clone()),
                deployed_code_size: 0,
                vm_version: None,
                error: Some("no code deployed at address".into()),
            },
        };

        // Compute hash of deployed code
        let deployed_hash = {
            let mut h = Sha256::new();
            h.update(&deployed_code);
            hex::encode(h.finalize())
        };

        // Resolve VM version from metadata, distinguishing absent / corrupt
        // / parsed cases. NEVER collapse them into a default of 1.
        let raw_version = storage.get_state(&format!("vm_version:{}", address));
        let (deployed_vm_version, version_error): (Option<u8>, Option<String>) = match raw_version {
            None => (None, Some("vm_version metadata is absent".to_string())),
            Some(v) => match v.parse::<u8>() {
                Ok(parsed) => (Some(parsed), None),
                Err(e) => {
                    slog_error!("vm", "verify_corrupt_vm_version_metadata",
                        contract => address, raw => &v, error => &e.to_string());
                    (
                        None,
                        Some(format!(
                            "vm_version metadata is corrupt: cannot parse '{}' as u8: {}",
                            v, e
                        )),
                    )
                }
            },
        };

        let bytecode_match = deployed_hash == package.bytecode_hash;
        let vm_version_match = deployed_vm_version == Some(package.vm_version);
        // Critical: a contract whose vm_version metadata is missing
        // or corrupt is NOT verified, even if its bytecode hash
        // happens to line up with the package. The fix-the-metadata
        // path is the operator's responsibility.
        let verified = bytecode_match && vm_version_match;

        VerificationResult {
            address: address.into(),
            verified,
            contract_name: Some(package.name.clone()),
            bytecode_match,
            vm_version_match,
            deployed_bytecode_hash: deployed_hash,
            package_bytecode_hash: Some(package.bytecode_hash.clone()),
            deployed_code_size: deployed_code.len(),
            vm_version: deployed_vm_version,
            error: version_error,
        }
    }

    /// Store verification result in the contract DB for explorer queries.
    ///
    /// Returns `Err(StorageError::Serialization)` if the metadata
    /// fails to serialize, instead of silently writing an empty
    /// string. The previous implementation used
    /// `serde_json::to_string(...).unwrap_or_default()`, which would
    /// store `""` on serialize failure — that empty string would
    /// later parse as `None` from `get_verification`, making it look
    /// like the contract had no verification metadata at all even
    /// though `is_verified` would still return `true`. The new
    /// behaviour either stores valid JSON or surfaces the error.
    pub fn save_verification(
        storage: &ContractStorage,
        result: &VerificationResult,
        package: &ContractPackage,
    ) -> Result<(), StorageError> {
        if !result.verified { return Ok(()); } // Only store verified contracts

        // Store verification metadata.
        //
        // `ContractAbi::to_json` now returns `Result<String, VmError>`
        // — previously it swallowed serialize failures and returned
        // `""`. A verified record with `abi_json: ""` parsed back as a
        // valid `VerificationMeta` and made downstream decoders /
        // explorers show a "verified" contract with no ABI at all, so
        // we propagate the error as `StorageError::Serialization` and
        // refuse to persist the meaningless record.
        let abi_json = package.abi.to_json().map_err(|e| {
            slog_error!("vm", "save_verification_abi_serialize_failed",
                address => &result.address, error => &e.to_string());
            StorageError::Serialization(format!(
                "verification abi_json serialize failed for {}: {}",
                result.address, e
            ))
        })?;

        let key = format!("verified:{}", result.address);
        let meta_value = VerificationMeta {
            name: package.name.clone(),
            verified: true,
            bytecode_hash: package.bytecode_hash.clone(),
            vm_version: package.vm_version,
            format_version: package.format_version,
            code_size: result.deployed_code_size,
            abi_json,
            source_hash: package.source_hash.clone(),
        };
        let meta = serde_json::to_string(&meta_value).map_err(|e| {
            slog_error!("vm", "save_verification_serialize_failed",
                address => &result.address, error => &e.to_string());
            StorageError::Serialization(format!(
                "verification metadata serialize failed for {}: {}",
                result.address, e
            ))
        })?;

        storage.set_state(&key, &meta)
    }

    /// Check if a contract has verification metadata stored.
    ///
    /// **Note**: this only checks for the presence of the key — it does
    /// NOT validate the payload. Use [`Self::get_verification`] (which
    /// now logs corruption explicitly) if you need to know whether the
    /// stored bytes are still readable.
    pub fn is_verified(storage: &ContractStorage, address: &str) -> bool {
        storage.get_state(&format!("verified:{}", address)).is_some()
    }

    /// Load verification metadata for a contract.
    ///
    /// Returns `None` only on **genuine absence** of the verification
    /// key. A read error or a corrupt JSON payload is logged loudly
    /// via `slog_error!` AND still returns `None` so callers don't
    /// break, but operators get a visible signal that the metadata
    /// is broken instead of silently treating it as "not verified".
    /// Use [`Self::get_verification_strict`] if you must distinguish
    /// "absent" from "corrupt" — for example in audit / explorer
    /// pipelines that need to flag damaged metadata.
    pub fn get_verification(storage: &ContractStorage, address: &str) -> Option<VerificationMeta> {
        let key = format!("verified:{}", address);
        let json = storage.get_state(&key)?;
        match serde_json::from_str::<VerificationMeta>(&json) {
            Ok(meta) => Some(meta),
            Err(e) => {
                slog_error!("vm", "get_verification_corrupt_json_may_be_false_negative",
                    address => address, error => &e.to_string(),
                    note => "returning None but verified key exists with malformed JSON payload");
                None
            }
        }
    }

    /// Strict variant of [`Self::get_verification`] that distinguishes
    /// the three possible states:
    ///
    ///   - `Ok(None)`         → key is genuinely absent (no metadata)
    ///   - `Ok(Some(meta))`   → key exists with a valid payload
    ///   - `Err(StorageError)` → key exists but the payload is corrupt
    ///
    /// Audit / explorer code should use this so a damaged record
    /// is flagged instead of being silently treated as "not verified".
    pub fn get_verification_strict(
        storage: &ContractStorage,
        address: &str,
    ) -> Result<Option<VerificationMeta>, StorageError> {
        let key = format!("verified:{}", address);
        let json = match storage.get_state(&key) {
            Some(j) => j,
            None => return Ok(None),
        };
        serde_json::from_str::<VerificationMeta>(&json)
            .map(Some)
            .map_err(|e| {
                slog_error!("vm", "get_verification_corrupt_json_strict",
                    address => address, error => &e.to_string());
                StorageError::Serialization(format!(
                    "verification metadata for {} is corrupt JSON: {}",
                    address, e
                ))
            })
    }
}

/// Stored verification metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMeta {
    pub name: String,
    pub verified: bool,
    pub bytecode_hash: String,
    pub vm_version: u8,
    pub format_version: u8,
    pub code_size: usize,
    pub abi_json: String,
    pub source_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::vm::contracts::contract_abi::ContractAbi;

    fn tmp_path() -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_nanos();
        format!("{}/shadowdag_verify_{}", std::env::temp_dir().display(), ts)
    }

    #[test]
    fn verify_matching_bytecode() {
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();
        let bytecode = vec![0x10, 42, 0x00]; // PUSH1 42, STOP

        // Deploy
        storage.set_state("code:SD1c_test", &hex::encode(&bytecode)).unwrap();
        storage.set_state("vm_version:SD1c_test", "1").unwrap();

        // Package
        let abi = ContractAbi::new("TestContract");
        let pkg = ContractPackage::new("TestContract", bytecode, abi);

        let result = ContractVerifier::verify(&storage, "SD1c_test", &pkg);
        assert!(result.verified, "Matching bytecode should verify");
        assert!(result.bytecode_match);
        assert!(result.vm_version_match);
        assert!(result.error.is_none());
    }

    #[test]
    fn verify_mismatched_bytecode() {
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();

        storage.set_state("code:SD1c_test", &hex::encode(&[0x10, 42, 0x00])).unwrap();

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x10, 99, 0x00], abi); // different

        let result = ContractVerifier::verify(&storage, "SD1c_test", &pkg);
        assert!(!result.verified, "Mismatched bytecode should not verify");
        assert!(!result.bytecode_match);
    }

    #[test]
    fn verify_no_deployed_code() {
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", vec![0x00], abi);

        let result = ContractVerifier::verify(&storage, "SD1c_nonexistent", &pkg);
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn save_and_load_verification() {
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();
        let bytecode = vec![0x10, 42, 0x00];

        storage.set_state("code:SD1c_test", &hex::encode(&bytecode)).unwrap();
        storage.set_state("vm_version:SD1c_test", "1").unwrap();

        let abi = ContractAbi::new("MyToken");
        let pkg = ContractPackage::new("MyToken", bytecode, abi);

        let result = ContractVerifier::verify(&storage, "SD1c_test", &pkg);
        assert!(result.verified);

        ContractVerifier::save_verification(&storage, &result, &pkg).unwrap();

        assert!(ContractVerifier::is_verified(&storage, "SD1c_test"));
        let meta = ContractVerifier::get_verification(&storage, "SD1c_test").unwrap();
        assert_eq!(meta.name, "MyToken");
        assert!(meta.verified);
    }

    #[test]
    fn missing_vm_version_metadata_does_not_verify() {
        // Regression for the `unwrap_or(1)` bug. A v1 package against
        // a contract whose vm_version metadata is ABSENT must NOT be
        // marked verified — the previous code silently coerced
        // missing metadata to "1" and produced a false positive.
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();
        let bytecode = vec![0x10, 42, 0x00];

        storage.set_state("code:SD1c_no_meta", &hex::encode(&bytecode)).unwrap();
        // NOTE: vm_version metadata deliberately NOT set.

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", bytecode, abi);

        let result = ContractVerifier::verify(&storage, "SD1c_no_meta", &pkg);
        assert!(!result.verified, "missing vm_version metadata must not produce verified=true");
        assert!(!result.vm_version_match);
        assert_eq!(result.vm_version, None);
        assert!(result.error.as_ref().map(|e| e.contains("absent")).unwrap_or(false));
    }

    #[test]
    fn corrupt_vm_version_metadata_does_not_verify() {
        // Same protection for corrupt (un-parseable) vm_version metadata.
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();
        let bytecode = vec![0x10, 42, 0x00];

        storage.set_state("code:SD1c_bad_meta", &hex::encode(&bytecode)).unwrap();
        storage.set_state("vm_version:SD1c_bad_meta", "not-a-number").unwrap();

        let abi = ContractAbi::new("Test");
        let pkg = ContractPackage::new("Test", bytecode, abi);

        let result = ContractVerifier::verify(&storage, "SD1c_bad_meta", &pkg);
        assert!(!result.verified, "corrupt vm_version metadata must not produce verified=true");
        assert!(!result.vm_version_match);
        assert_eq!(result.vm_version, None);
        assert!(result.error.as_ref().map(|e| e.contains("corrupt")).unwrap_or(false));
    }

    #[test]
    fn get_verification_strict_distinguishes_missing_from_corrupt_json() {
        let path = tmp_path();
        let storage = ContractStorage::new(&path).unwrap();

        // Genuine miss → Ok(None)
        assert!(matches!(
            ContractVerifier::get_verification_strict(&storage, "SD1c_absent"),
            Ok(None)
        ));

        // Plant a corrupt JSON payload directly under the verified key.
        storage.set_state("verified:SD1c_corrupt", "this-is-not-json").unwrap();

        // Non-strict masks corruption as None (with log)
        assert!(ContractVerifier::get_verification(&storage, "SD1c_corrupt").is_none());
        // Strict surfaces it as an explicit error
        let strict = ContractVerifier::get_verification_strict(&storage, "SD1c_corrupt");
        assert!(strict.is_err(), "strict get_verification must expose corruption, got: {:?}", strict);
    }
}
