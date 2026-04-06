// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract Deployer — CREATE and CREATE2 contract deployment.
//
// CREATE:  address = SHA-256(deployer || nonce)
// CREATE2: address = SHA-256(0xFF || deployer || salt || code_hash)
//   (deterministic — same inputs always produce same address)
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use crate::errors::VmError;

/// Gas cost for contract creation
pub const CREATE_BASE_GAS: u64 = 32_000;
pub const CREATE2_BASE_GAS: u64 = 32_000;
pub const CODE_DEPOSIT_GAS_PER_BYTE: u64 = 200;

/// Maximum contract code size (24 KB)
pub const MAX_CODE_SIZE: usize = 24_576;

/// Maximum init code size (48 KB — 2x max code)
pub const MAX_INIT_CODE_SIZE: usize = 49_152;

/// Deployed contract metadata
#[derive(Debug, Clone)]
pub struct DeployedContract {
    /// Contract address
    pub address: String,
    /// Runtime bytecode
    pub code: Vec<u8>,
    /// Deployer address
    pub deployer: String,
    /// Block height of deployment
    pub deploy_height: u64,
    /// Creation method
    pub method: CreateMethod,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateMethod {
    Create { nonce: u64 },
    Create2 { salt: [u8; 32] },
}

/// Contract Deployer
pub struct ContractDeployer;

impl ContractDeployer {
    /// CREATE: deploy contract with nonce-based address
    ///
    /// address = hex(SHA-256("ShadowDAG_CREATE" || deployer || nonce))[0..40]
    pub fn create(
        deployer: &str,
        nonce: u64,
        init_code: &[u8],
    ) -> Result<DeployResult, VmError> {
        // Validate init code size
        if init_code.is_empty() {
            return Err(VmError::ContractError("empty init code".to_string()));
        }
        if init_code.len() > MAX_INIT_CODE_SIZE {
            return Err(VmError::CodeTooLarge { size: init_code.len(), limit: MAX_INIT_CODE_SIZE });
        }

        // Compute address
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"ShadowDAG_CREATE");
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, nonce.to_le_bytes());
        let hash = Digest::finalize(h);
        let address = format!("SD{}", hex::encode(&hash[..20]));

        // Calculate gas
        let gas = CREATE_BASE_GAS
            .saturating_add((init_code.len() as u64).saturating_mul(CODE_DEPOSIT_GAS_PER_BYTE));

        Ok(DeployResult {
            address,
            deployer: deployer.to_string(),
            method: CreateMethod::Create { nonce },
            gas_cost: gas,
            init_code: init_code.to_vec(),
        })
    }

    /// CREATE2: deploy contract with deterministic address
    ///
    /// address = hex(SHA-256(0xFF || deployer || salt || SHA-256(init_code)))[0..40]
    pub fn create2(
        deployer: &str,
        salt: [u8; 32],
        init_code: &[u8],
    ) -> Result<DeployResult, VmError> {
        if init_code.is_empty() {
            return Err(VmError::ContractError("empty init code".to_string()));
        }
        if init_code.len() > MAX_INIT_CODE_SIZE {
            return Err(VmError::CodeTooLarge { size: init_code.len(), limit: MAX_INIT_CODE_SIZE });
        }

        // Hash init code
        let mut code_hasher = <Sha256 as Digest>::new();
        Digest::update(&mut code_hasher, init_code);
        let code_hash = Digest::finalize(code_hasher);

        // Compute address: SHA-256(0xFF || deployer || salt || code_hash)
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, [0xFF]);
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, salt);
        Digest::update(&mut h, code_hash);
        let hash = Digest::finalize(h);
        let address = format!("SD{}", hex::encode(&hash[..20]));

        let gas = CREATE2_BASE_GAS
            .saturating_add((init_code.len() as u64).saturating_mul(CODE_DEPOSIT_GAS_PER_BYTE));

        Ok(DeployResult {
            address,
            deployer: deployer.to_string(),
            method: CreateMethod::Create2 { salt },
            gas_cost: gas,
            init_code: init_code.to_vec(),
        })
    }

    /// Predict CREATE2 address without deploying
    pub fn predict_create2_address(
        deployer: &str,
        salt: [u8; 32],
        init_code: &[u8],
    ) -> String {
        let mut code_hasher = <Sha256 as Digest>::new();
        Digest::update(&mut code_hasher, init_code);
        let code_hash = Digest::finalize(code_hasher);

        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, [0xFF]);
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, salt);
        Digest::update(&mut h, code_hash);
        let hash = Digest::finalize(h);
        format!("SD{}", hex::encode(&hash[..20]))
    }

    /// Validate runtime code after init execution
    pub fn validate_runtime_code(code: &[u8]) -> Result<(), VmError> {
        if code.is_empty() {
            return Err(VmError::ContractError("contract returned empty runtime code".to_string()));
        }
        if code.len() > MAX_CODE_SIZE {
            return Err(VmError::CodeTooLarge { size: code.len(), limit: MAX_CODE_SIZE });
        }
        // EIP-3541: reject code starting with 0xEF
        if code[0] == 0xEF {
            return Err(VmError::InvalidOpcode(0xEF));
        }
        Ok(())
    }
}

/// Result of a contract deployment
#[derive(Debug, Clone)]
pub struct DeployResult {
    pub address: String,
    pub deployer: String,
    pub method: CreateMethod,
    pub gas_cost: u64,
    pub init_code: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_deterministic() {
        let r1 = ContractDeployer::create("deployer_a", 0, &[0x60, 0x00]).unwrap();
        let r2 = ContractDeployer::create("deployer_a", 0, &[0x60, 0x00]).unwrap();
        assert_eq!(r1.address, r2.address);
    }

    #[test]
    fn create_different_nonce_different_address() {
        let r1 = ContractDeployer::create("deployer_a", 0, &[0x60, 0x00]).unwrap();
        let r2 = ContractDeployer::create("deployer_a", 1, &[0x60, 0x00]).unwrap();
        assert_ne!(r1.address, r2.address);
    }

    #[test]
    fn create2_deterministic() {
        let salt = [0xAA; 32];
        let code = vec![0x60, 0x00, 0x60, 0x00];
        let r1 = ContractDeployer::create2("deployer_b", salt, &code).unwrap();
        let r2 = ContractDeployer::create2("deployer_b", salt, &code).unwrap();
        assert_eq!(r1.address, r2.address);
    }

    #[test]
    fn create2_predict_matches() {
        let salt = [0xBB; 32];
        let code = vec![0x60, 0x00];
        let predicted = ContractDeployer::predict_create2_address("x", salt, &code);
        let deployed = ContractDeployer::create2("x", salt, &code).unwrap();
        assert_eq!(predicted, deployed.address);
    }

    #[test]
    fn address_starts_with_sd() {
        let r = ContractDeployer::create("test", 0, &[0x00]).unwrap();
        assert!(r.address.starts_with("SD"));
    }

    #[test]
    fn empty_code_rejected() {
        assert!(ContractDeployer::create("a", 0, &[]).is_err());
    }

    #[test]
    fn oversized_code_rejected() {
        let big = vec![0x00; MAX_INIT_CODE_SIZE + 1];
        assert!(ContractDeployer::create("a", 0, &big).is_err());
    }

    #[test]
    fn ef_prefix_rejected() {
        assert!(ContractDeployer::validate_runtime_code(&[0xEF, 0x00]).is_err());
    }

    #[test]
    fn valid_code_passes() {
        assert!(ContractDeployer::validate_runtime_code(&[0x60, 0x00]).is_ok());
    }
}
