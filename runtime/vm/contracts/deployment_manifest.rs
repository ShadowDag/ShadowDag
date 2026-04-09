// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// Deployment Manifest -- per-network contract registry.
// =============================================================================

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

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

impl DeploymentManifest {
    pub fn new(network: &str) -> Self {
        Self {
            network: network.to_string(),
            contracts: BTreeMap::new(),
            version: 1,
            chain_id: match network {
                "mainnet" => 0xDA0C_0001,
                "testnet" => 0xDA0C_0002,
                "regtest" | "local" => 0xDA0C_0003,
                _ => 0,
            },
            rpc_url: match network {
                "mainnet" => "http://localhost:9332".into(),
                "testnet" => "http://localhost:19332".into(),
                _ => "http://localhost:29332".into(),
            },
            migration_version: 0,
        }
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
        let mut m = DeploymentManifest::new("testnet");
        assert_eq!(m.chain_id, 0xDA0C_0002);
        assert_eq!(m.rpc_url, "http://localhost:19332");
        assert_eq!(m.migration_version, 0);

        m.add_deployment(DeployedContract {
            name: "MyToken".into(),
            address: "SD1c_abc123".into(),
            bytecode_hash: "hash123".into(),
            deploy_height: 1000,
            deploy_tx: "tx_abc".into(),
            vm_version: 1,
            verified: true,
            deployed_at: 1700000000,
            package_file: Some("token.pkg.json".into()),
        });

        assert!(m.is_deployed("MyToken"));
        assert_eq!(m.get_address("MyToken"), Some("SD1c_abc123"));
        assert!(!m.is_deployed("Other"));
    }

    #[test]
    fn manifest_chain_ids() {
        let mainnet = DeploymentManifest::new("mainnet");
        assert_eq!(mainnet.chain_id, 0xDA0C_0001);
        assert_eq!(mainnet.rpc_url, "http://localhost:9332");

        let local = DeploymentManifest::new("local");
        assert_eq!(local.chain_id, 0xDA0C_0003);
        assert_eq!(local.rpc_url, "http://localhost:29332");

        let regtest = DeploymentManifest::new("regtest");
        assert_eq!(regtest.chain_id, 0xDA0C_0003);
    }

    #[test]
    fn manifest_increment_migration() {
        let mut m = DeploymentManifest::new("local");
        assert_eq!(m.migration_version, 0);
        m.increment_migration();
        assert_eq!(m.migration_version, 1);
        m.increment_migration();
        assert_eq!(m.migration_version, 2);
    }

    #[test]
    fn manifest_json_roundtrip() {
        let mut m = DeploymentManifest::new("mainnet");
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
