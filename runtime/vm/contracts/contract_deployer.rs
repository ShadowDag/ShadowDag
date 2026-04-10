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
//
// Network-aware prefixes: every contract address produced by this module
// **inherits the network of the deployer**. A mainnet deployer (`SD1…`)
// creates a `SD1c…` contract, a testnet deployer (`ST1…`) creates a
// `ST1c…` contract, and a regtest deployer (`SR1…`) creates a `SR1c…`
// contract. Unknown-prefix deployers are rejected with a structured
// `VmError::ContractError` so the VM never silently tags output with
// the wrong network.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use crate::domain::address::address::prefix_from_address;
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
    /// Look up the network prefix for `deployer` and fail fast with a
    /// structured error when it is not a known ShadowDAG address.
    /// Centralizing this means the four address-computing entry points
    /// below can't silently disagree on what "mainnet" means.
    fn deployer_prefix(deployer: &str) -> Result<&'static str, VmError> {
        prefix_from_address(deployer).ok_or_else(|| {
            VmError::ContractError(format!(
                "contract deployer '{}' has unknown network prefix \
                 (expected SD1/ST1/SR1)",
                deployer
            ))
        })
    }

    /// CREATE: deploy contract with nonce-based address.
    ///
    /// The generated address inherits the deployer's network:
    /// `{net}c` || hex(SHA-256("ShadowDAG_CREATE" || deployer || nonce))[0..40]
    pub fn create(
        deployer: &str,
        nonce: u64,
        init_code: &[u8],
    ) -> Result<DeployResult, VmError> {
        // Resolve the network FIRST — a bogus deployer should fail
        // before we spend cycles validating the init code.
        let net_prefix = Self::deployer_prefix(deployer)?;

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
        let address = format!("{}c{}", net_prefix, hex::encode(&hash[..20]));

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

    /// CREATE2: deploy contract with deterministic address.
    ///
    /// The generated address inherits the deployer's network:
    /// `{net}c` || hex(SHA-256(0xFF || deployer || salt || SHA-256(init_code)))[0..40]
    pub fn create2(
        deployer: &str,
        salt: [u8; 32],
        init_code: &[u8],
    ) -> Result<DeployResult, VmError> {
        let net_prefix = Self::deployer_prefix(deployer)?;

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
        let address = format!("{}c{}", net_prefix, hex::encode(&hash[..20]));

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

    /// Compute CREATE address from deployer and nonce (no size validation).
    /// Used by ExecutionEnvironment for the inline CREATE opcode.
    ///
    /// Returns `Err(VmError::ContractError)` if the deployer has no
    /// recognized network prefix, so the in-VM CREATE opcode can
    /// refuse to mint an address from a malformed account string
    /// instead of silently tagging it as mainnet.
    ///
    /// hash = SHA-256("ShadowDAG_CREATE" || deployer || nonce_le_bytes)
    /// address = `{net}c` + hex(hash[0..20])
    pub fn compute_create_address(deployer: &str, nonce: u64) -> Result<String, VmError> {
        let net_prefix = Self::deployer_prefix(deployer)?;
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"ShadowDAG_CREATE");
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, nonce.to_le_bytes());
        let hash = Digest::finalize(h);
        Ok(format!("{}c{}", net_prefix, hex::encode(&hash[..20])))
    }

    /// Compute CREATE2 address from deployer, salt, and init code (no
    /// size validation). Used by ExecutionEnvironment for the inline
    /// CREATE2 opcode.
    ///
    /// Returns `Err(VmError::ContractError)` for an unknown deployer
    /// prefix. See [`Self::compute_create_address`] for rationale.
    ///
    /// # Salt is exactly 32 bytes
    ///
    /// The salt parameter is typed as `&[u8; 32]` so the caller
    /// cannot accidentally feed a slice of the wrong length. The
    /// sibling entry points [`Self::create2`] and
    /// [`Self::predict_create2_address`] both already take
    /// `salt: [u8; 32]` — the previous signature of this function
    /// was `salt: &[u8]`, which accepted a slice of ANY length and
    /// produced addresses that the real CREATE2 path could never
    /// reproduce for a 31- or 33-byte salt. That meant `predict` /
    /// `create2` / `compute` could silently disagree on the address
    /// for the "same" deployment as soon as a caller forgot to
    /// normalize the salt to 32 bytes. The type system now catches
    /// the mismatch at compile time.
    ///
    /// code_hash = SHA-256(init_code)
    /// hash = SHA-256(0xFF || deployer || salt || code_hash)
    /// address = `{net}c` + hex(hash[0..20])
    pub fn compute_create2_address(
        deployer: &str,
        salt: &[u8; 32],
        init_code: &[u8],
    ) -> Result<String, VmError> {
        let net_prefix = Self::deployer_prefix(deployer)?;

        let mut code_hasher = <Sha256 as Digest>::new();
        Digest::update(&mut code_hasher, init_code);
        let code_hash = Digest::finalize(code_hasher);

        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, [0xFF]);
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, salt);
        Digest::update(&mut h, code_hash);
        let hash = Digest::finalize(h);
        Ok(format!("{}c{}", net_prefix, hex::encode(&hash[..20])))
    }

    /// Predict CREATE2 address without deploying.
    ///
    /// Returns `Err(VmError::ContractError)` for an unknown deployer
    /// prefix. This keeps predict / create / compute in agreement:
    /// you can't predict an address the real CREATE2 path would refuse
    /// to produce.
    pub fn predict_create2_address(
        deployer: &str,
        salt: [u8; 32],
        init_code: &[u8],
    ) -> Result<String, VmError> {
        let net_prefix = Self::deployer_prefix(deployer)?;

        let mut code_hasher = <Sha256 as Digest>::new();
        Digest::update(&mut code_hasher, init_code);
        let code_hash = Digest::finalize(code_hasher);

        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, [0xFF]);
        Digest::update(&mut h, deployer.as_bytes());
        Digest::update(&mut h, salt);
        Digest::update(&mut h, code_hash);
        let hash = Digest::finalize(h);
        Ok(format!("{}c{}", net_prefix, hex::encode(&hash[..20])))
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

    // ── Test addresses — always network-valid ────────────────────────
    // The deployer strings in these tests deliberately start with a
    // real ShadowDAG network prefix (SD1/ST1/SR1) rather than
    // generic placeholders like "deployer_a". The old tests used
    // placeholders and therefore silently worked against a
    // hard-coded "SD1c" output, hiding the network-bias bug.
    const MAINNET_DEPLOYER: &str = "SD1deployeralpha";
    const TESTNET_DEPLOYER: &str = "ST1deployerbeta";
    const REGTEST_DEPLOYER: &str = "SR1deployergamma";

    #[test]
    fn create_deterministic() {
        let r1 = ContractDeployer::create(MAINNET_DEPLOYER, 0, &[0x60, 0x00]).unwrap();
        let r2 = ContractDeployer::create(MAINNET_DEPLOYER, 0, &[0x60, 0x00]).unwrap();
        assert_eq!(r1.address, r2.address);
    }

    #[test]
    fn create_different_nonce_different_address() {
        let r1 = ContractDeployer::create(MAINNET_DEPLOYER, 0, &[0x60, 0x00]).unwrap();
        let r2 = ContractDeployer::create(MAINNET_DEPLOYER, 1, &[0x60, 0x00]).unwrap();
        assert_ne!(r1.address, r2.address);
    }

    #[test]
    fn create2_deterministic() {
        let salt = [0xAA; 32];
        let code = vec![0x60, 0x00, 0x60, 0x00];
        let r1 = ContractDeployer::create2(MAINNET_DEPLOYER, salt, &code).unwrap();
        let r2 = ContractDeployer::create2(MAINNET_DEPLOYER, salt, &code).unwrap();
        assert_eq!(r1.address, r2.address);
    }

    #[test]
    fn create2_predict_matches() {
        let salt = [0xBB; 32];
        let code = vec![0x60, 0x00];
        let predicted = ContractDeployer::predict_create2_address(MAINNET_DEPLOYER, salt, &code).unwrap();
        let deployed = ContractDeployer::create2(MAINNET_DEPLOYER, salt, &code).unwrap();
        assert_eq!(predicted, deployed.address);
    }

    #[test]
    fn mainnet_deployer_produces_sd1c_address() {
        let r = ContractDeployer::create(MAINNET_DEPLOYER, 0, &[0x00]).unwrap();
        assert!(r.address.starts_with("SD1c"), "got: {}", r.address);
    }

    #[test]
    fn testnet_deployer_produces_st1c_address() {
        // Regression for the bug where CREATE hard-coded "SD1c" and
        // silently mis-tagged all non-mainnet deployments.
        let r = ContractDeployer::create(TESTNET_DEPLOYER, 0, &[0x00]).unwrap();
        assert!(r.address.starts_with("ST1c"), "got: {}", r.address);
        assert!(!r.address.starts_with("SD1"), "testnet contract must not be tagged mainnet");
    }

    #[test]
    fn regtest_deployer_produces_sr1c_address() {
        let r = ContractDeployer::create(REGTEST_DEPLOYER, 0, &[0x00]).unwrap();
        assert!(r.address.starts_with("SR1c"), "got: {}", r.address);
        assert!(!r.address.starts_with("SD1"), "regtest contract must not be tagged mainnet");
    }

    #[test]
    fn create2_inherits_network_across_all_three_networks() {
        let salt = [0xCC; 32];
        let code = vec![0x60, 0x00];

        let mainnet = ContractDeployer::create2(MAINNET_DEPLOYER, salt, &code).unwrap();
        let testnet = ContractDeployer::create2(TESTNET_DEPLOYER, salt, &code).unwrap();
        let regtest = ContractDeployer::create2(REGTEST_DEPLOYER, salt, &code).unwrap();

        assert!(mainnet.address.starts_with("SD1c"));
        assert!(testnet.address.starts_with("ST1c"));
        assert!(regtest.address.starts_with("SR1c"));

        // The address bytes must also differ: the hash input doesn't
        // change, but the VISIBLE prefix does — clients reading the
        // address must see the right network.
        assert_ne!(mainnet.address, testnet.address);
        assert_ne!(testnet.address, regtest.address);
    }

    #[test]
    fn compute_create_address_inherits_network() {
        let m = ContractDeployer::compute_create_address(MAINNET_DEPLOYER, 0).unwrap();
        let t = ContractDeployer::compute_create_address(TESTNET_DEPLOYER, 0).unwrap();
        let r = ContractDeployer::compute_create_address(REGTEST_DEPLOYER, 0).unwrap();
        assert!(m.starts_with("SD1c"));
        assert!(t.starts_with("ST1c"));
        assert!(r.starts_with("SR1c"));
    }

    #[test]
    fn compute_create2_address_inherits_network() {
        let salt = [0xDD; 32];
        let code = vec![0x60, 0x00];
        let m = ContractDeployer::compute_create2_address(MAINNET_DEPLOYER, &salt, &code).unwrap();
        let t = ContractDeployer::compute_create2_address(TESTNET_DEPLOYER, &salt, &code).unwrap();
        let r = ContractDeployer::compute_create2_address(REGTEST_DEPLOYER, &salt, &code).unwrap();
        assert!(m.starts_with("SD1c"));
        assert!(t.starts_with("ST1c"));
        assert!(r.starts_with("SR1c"));
    }

    #[test]
    fn predict_create2_address_inherits_network() {
        let salt = [0xEE; 32];
        let code = vec![0x60, 0x00];
        let m = ContractDeployer::predict_create2_address(MAINNET_DEPLOYER, salt, &code).unwrap();
        let t = ContractDeployer::predict_create2_address(TESTNET_DEPLOYER, salt, &code).unwrap();
        let r = ContractDeployer::predict_create2_address(REGTEST_DEPLOYER, salt, &code).unwrap();
        assert!(m.starts_with("SD1c"));
        assert!(t.starts_with("ST1c"));
        assert!(r.starts_with("SR1c"));
    }

    #[test]
    fn unknown_deployer_prefix_rejected_on_all_entry_points() {
        let bad = "BTC1notours";
        let salt = [0x00; 32];
        let code = vec![0x60, 0x00];

        assert!(ContractDeployer::create(bad, 0, &code).is_err());
        assert!(ContractDeployer::create2(bad, salt, &code).is_err());
        assert!(ContractDeployer::compute_create_address(bad, 0).is_err());
        assert!(ContractDeployer::compute_create2_address(bad, &salt, &code).is_err());
        assert!(ContractDeployer::predict_create2_address(bad, salt, &code).is_err());
    }

    #[test]
    fn empty_deployer_string_rejected() {
        assert!(ContractDeployer::create("", 0, &[0x00]).is_err());
    }

    #[test]
    fn empty_code_rejected() {
        assert!(ContractDeployer::create(MAINNET_DEPLOYER, 0, &[]).is_err());
    }

    #[test]
    fn oversized_code_rejected() {
        let big = vec![0x00; MAX_INIT_CODE_SIZE + 1];
        assert!(ContractDeployer::create(MAINNET_DEPLOYER, 0, &big).is_err());
    }

    #[test]
    fn ef_prefix_rejected() {
        assert!(ContractDeployer::validate_runtime_code(&[0xEF, 0x00]).is_err());
    }

    #[test]
    fn valid_code_passes() {
        assert!(ContractDeployer::validate_runtime_code(&[0x60, 0x00]).is_ok());
    }

    #[test]
    fn compute_create2_address_matches_create2_and_predict_for_32_byte_salt() {
        // Regression for the bug where `compute_create2_address` took
        // `salt: &[u8]` while `create2` / `predict_create2_address`
        // took `salt: [u8; 32]`. A direct caller of compute could pass
        // a 31- or 33-byte slice and compute an address that the real
        // CREATE2 path could never produce. The new signature is
        // `salt: &[u8; 32]` so the mismatch is a type error at
        // compile time.
        //
        // This runtime test only verifies the positive path: a 32-byte
        // salt produces the same address across all three entry
        // points. The compile-time check cannot be exercised from a
        // passing test — it exists in the type system.
        let salt: [u8; 32] = [0x11; 32];
        let code = vec![0x60, 0x00, 0x60, 0x20];

        let predicted = ContractDeployer::predict_create2_address(
            MAINNET_DEPLOYER, salt, &code,
        ).unwrap();
        let deployed = ContractDeployer::create2(
            MAINNET_DEPLOYER, salt, &code,
        ).unwrap();
        let computed = ContractDeployer::compute_create2_address(
            MAINNET_DEPLOYER, &salt, &code,
        ).unwrap();

        assert_eq!(predicted, deployed.address,
            "predict_create2_address must match create2 for the same inputs");
        assert_eq!(deployed.address, computed,
            "compute_create2_address must match create2 for the same 32-byte salt");
    }
}
