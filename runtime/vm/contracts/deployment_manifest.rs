// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// Deployment Manifest -- per-network contract registry.
// =============================================================================

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

use crate::errors::VmError;

/// Per-network deployment registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentManifest {
    /// Network name (mainnet, testnet, regtest)
    pub network: String,
    /// Deployed contracts: name -> deployment info
    pub contracts: BTreeMap<String, DeployedContract>,
    /// Manifest format version
    pub version: u8,
    /// Chain ID for this network deployment
    pub chain_id: u32,
    /// RPC URL for this network
    pub rpc_url: String,
    /// Migration version (incremented on each deployment run)
    pub migration_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContract {
    /// Contract name
    pub name: String,
    /// Deployed address (SD1c...)
    pub address: String,
    /// Bytecode hash of the deployed artifact
    pub bytecode_hash: String,
    /// Block height where deployed
    pub deploy_height: u64,
    /// TX hash of the deployment
    pub deploy_tx: String,
    /// VM version at deployment
    pub vm_version: u8,
    /// Whether the contract has been verified
    pub verified: bool,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Optional: path to the package file used
    pub package_file: Option<String>,
}

/// Canonicalize a network name into one of the three on-chain
/// networks: `"mainnet"`, `"testnet"`, `"regtest"`. The alias
/// `"local"` is accepted and folded into `"regtest"` for historical
/// compatibility with existing scripts and `ScriptRunner` tests.
/// Any other name returns `None` so the caller can fail-closed
/// instead of producing a manifest with `chain_id = 0` and a
/// random default RPC URL.
fn canonical_network(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("mainnet"),
        "testnet" => Some("testnet"),
        "regtest" | "local" => Some("regtest"),
        _ => None,
    }
}

impl DeploymentManifest {
    /// Create an empty deployment manifest for the given network.
    ///
    /// Returns `Err(VmError::ContractError)` if `network` is not one
    /// of the known ShadowDAG networks (`mainnet` / `testnet` /
    /// `regtest`, plus `local` as an alias for `regtest`).
    ///
    /// The previous implementation accepted ANY string and silently
    /// coerced unknown names to `chain_id = 0` with a default RPC
    /// URL pointing at `localhost:29332`. A typo like `"mainmet"`
    /// therefore produced a manifest that looked valid but was
    /// bound to the wrong (non-)chain. The new signature forces
    /// the caller to handle the error path explicitly, and the
    /// returned manifest always has a well-defined `chain_id` and
    /// `rpc_url` for one of the three real networks.
    pub fn new(network: &str) -> Result<Self, VmError> {
        let canonical = canonical_network(network).ok_or_else(|| {
            VmError::ContractError(format!(
                "unknown deployment network '{}': expected one of \
                 mainnet, testnet, regtest (or 'local' as alias for regtest)",
                network
            ))
        })?;

        let chain_id = match canonical {
            "mainnet" => 0xDA0C_0001,
            "testnet" => 0xDA0C_0002,
            "regtest" => 0xDA0C_0003,
            // Unreachable: canonical_network only returns the three
            // strings above.
            _ => unreachable!("canonical_network returned unknown value"),
        };
        let rpc_url = match canonical {
            "mainnet" => "http://localhost:9332".into(),
            "testnet" => "http://localhost:19332".into(),
            "regtest" => "http://localhost:29332".into(),
            _ => unreachable!(),
        };

        Ok(Self {
            network: canonical.to_string(),
            contracts: BTreeMap::new(),
            version: 1,
            chain_id,
            rpc_url,
            migration_version: 0,
        })
    }

    pub fn increment_migration(&mut self) {
        self.migration_version += 1;
    }

    pub fn add_deployment(&mut self, contract: DeployedContract) {
        self.contracts.insert(contract.name.clone(), contract);
    }

    pub fn get_address(&self, name: &str) -> Option<&str> {
        self.contracts.get(name).map(|c| c.address.as_str())
    }

    pub fn is_deployed(&self, name: &str) -> bool {
        self.contracts.contains_key(name)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = self.to_json().map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_json(&json).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_create_and_query() {
        let mut m = DeploymentManifest::new("testnet").expect("testnet is valid");
        assert_eq!(m.network, "testnet");
        assert_eq!(m.chain_id, 0xDA0C_0002);
        assert_eq!(m.rpc_url, "http://localhost:19332");
        assert_eq!(m.migration_version, 0);

        // Use a testnet-prefixed address (ST1c…) so the test doesn't
        // silently drift into mainnet-tagged contract addresses on a
        // testnet manifest.
        m.add_deployment(DeployedContract {
            name: "MyToken".into(),
            address: "ST1c_abc123".into(),
            bytecode_hash: "hash123".into(),
            deploy_height: 1000,
            deploy_tx: "tx_abc".into(),
            vm_version: 1,
            verified: true,
            deployed_at: 1700000000,
            package_file: Some("token.pkg.json".into()),
        });

        assert!(m.is_deployed("MyToken"));
        assert_eq!(m.get_address("MyToken"), Some("ST1c_abc123"));
        assert!(!m.is_deployed("Other"));
    }

    #[test]
    fn manifest_chain_ids() {
        let mainnet = DeploymentManifest::new("mainnet").unwrap();
        assert_eq!(mainnet.network, "mainnet");
        assert_eq!(mainnet.chain_id, 0xDA0C_0001);
        assert_eq!(mainnet.rpc_url, "http://localhost:9332");

        // "local" canonicalizes to "regtest" — same chain_id AND same
        // network string, so there is no drift between scripts that
        // pass "local" and scripts that pass "regtest".
        let local = DeploymentManifest::new("local").unwrap();
        assert_eq!(local.network, "regtest");
        assert_eq!(local.chain_id, 0xDA0C_0003);
        assert_eq!(local.rpc_url, "http://localhost:29332");

        let regtest = DeploymentManifest::new("regtest").unwrap();
        assert_eq!(regtest.network, "regtest");
        assert_eq!(regtest.chain_id, 0xDA0C_0003);
    }

    #[test]
    fn manifest_rejects_unknown_network() {
        // Regression for the silent-chain_id-0 fallback bug. A typo
        // must produce a structured error, not a manifest bound to
        // a non-network.
        let err = DeploymentManifest::new("mainmet").unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("unknown deployment network"),
            "error must describe the problem, got: {}", msg
        );
        assert!(msg.contains("mainmet"), "error must include the offending name");

        assert!(DeploymentManifest::new("").is_err());
        assert!(DeploymentManifest::new("devnet").is_err());
        assert!(DeploymentManifest::new("Mainnet").is_err()); // case-sensitive
    }

    #[test]
    fn manifest_increment_migration() {
        let mut m = DeploymentManifest::new("local").unwrap();
        assert_eq!(m.migration_version, 0);
        m.increment_migration();
        assert_eq!(m.migration_version, 1);
        m.increment_migration();
        assert_eq!(m.migration_version, 2);
    }

    #[test]
    fn manifest_json_roundtrip() {
        let mut m = DeploymentManifest::new("mainnet").unwrap();
        m.add_deployment(DeployedContract {
            name: "Token".into(),
            address: "SD1c_xyz".into(),
            bytecode_hash: "abc".into(),
            deploy_height: 500,
            deploy_tx: "tx".into(),
            vm_version: 1,
            verified: false,
            deployed_at: 0,
            package_file: None,
        });

        let json = m.to_json().unwrap();
        let loaded = DeploymentManifest::from_json(&json).unwrap();
        assert_eq!(loaded.network, "mainnet");
        assert_eq!(loaded.contracts.len(), 1);
        assert_eq!(loaded.chain_id, 0xDA0C_0001);
        assert_eq!(loaded.rpc_url, "http://localhost:9332");
        assert_eq!(loaded.migration_version, 0);
    }
}
