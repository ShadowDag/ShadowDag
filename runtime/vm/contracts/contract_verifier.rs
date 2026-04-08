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

/// Verification result for a deployed contract
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
    pub vm_version: u8,
    pub error: Option<String>,
}

/// Persistent verification store
pub struct ContractVerifier;

impl ContractVerifier {
    /// Verify a deployed contract against a package artifact.
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
                    vm_version: 0,
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
                vm_version: 0,
                error: Some("no code deployed at address".into()),
            },
        };

        // Compute hash of deployed code
        let deployed_hash = {
            let mut h = Sha256::new();
            h.update(&deployed_code);
            hex::encode(h.finalize())
        };

        // Check VM version from metadata
        let deployed_vm_version = storage.get_state(&format!("vm_version:{}", address))
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(1);

        let bytecode_match = deployed_hash == package.bytecode_hash;
        let vm_version_match = deployed_vm_version == package.vm_version;
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
            error: None,
        }
    }

    /// Store verification result in the contract DB for explorer queries.
    pub fn save_verification(
        storage: &ContractStorage,
        result: &VerificationResult,
        package: &ContractPackage,
    ) -> Result<(), StorageError> {
        if !result.verified { return Ok(()); } // Only store verified contracts

        // Store verification metadata
        let key = format!("verified:{}", result.address);
        let meta = serde_json::to_string(&VerificationMeta {
            name: package.name.clone(),
            verified: true,
            bytecode_hash: package.bytecode_hash.clone(),
            vm_version: package.vm_version,
            format_version: package.format_version,
            code_size: result.deployed_code_size,
            abi_json: package.abi.to_json(),
            source_hash: package.source_hash.clone(),
        }).unwrap_or_default();

        storage.set_state(&key, &meta)
    }

    /// Check if a contract is verified.
    pub fn is_verified(storage: &ContractStorage, address: &str) -> bool {
        storage.get_state(&format!("verified:{}", address)).is_some()
    }

    /// Load verification metadata for a contract.
    pub fn get_verification(storage: &ContractStorage, address: &str) -> Option<VerificationMeta> {
        let key = format!("verified:{}", address);
        storage.get_state(&key)
            .and_then(|json| serde_json::from_str(&json).ok())
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
}
