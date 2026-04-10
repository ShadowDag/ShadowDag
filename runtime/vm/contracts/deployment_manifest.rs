// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// Deployment Manifest -- per-network contract registry.
// =============================================================================

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

use crate::domain::address::address::network_prefix;
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

    /// Register a deployed contract in the manifest.
    ///
    /// Returns `Err(VmError::ContractError)` if `contract.address`
    /// does not carry the network prefix this manifest is bound to —
    /// e.g. trying to register `SD1c_foo` on a testnet manifest.
    /// The previous implementation was a bare
    /// `self.contracts.insert(...)` with no check, so after all the
    /// network-aware fixes in the VM / contract_deployer / wasm /
    /// script_runner layers, a manifest could still accumulate
    /// mainnet-tagged entries on a testnet / regtest chain from any
    /// caller that skipped the checks — for example an RPC import
    /// path or a hand-written JSON.
    ///
    /// An empty or prefix-less address is also refused so the
    /// manifest never holds an entry whose address cannot be
    /// classified at all.
    pub fn add_deployment(&mut self, contract: DeployedContract) -> Result<(), VmError> {
        self.check_address_matches_network(&contract.address)
            .map_err(|e| VmError::ContractError(format!(
                "cannot add deployment '{}': {}", contract.name, e
            )))?;
        self.contracts.insert(contract.name.clone(), contract);
        Ok(())
    }

    /// Validate that `address` carries the manifest's network prefix.
    ///
    /// Returns `Err(String)` for:
    ///   - empty address
    ///   - address whose 3-character prefix does not map to any
    ///     known ShadowDAG network
    ///   - address whose prefix maps to a DIFFERENT network than the
    ///     manifest (e.g. `SD1c_foo` on a testnet manifest)
    ///
    /// The manifest's own network is ALWAYS canonical (set by
    /// `Self::new` or `Self::validate_loaded`), so the comparison is
    /// unambiguous.
    fn check_address_matches_network(&self, address: &str) -> Result<(), String> {
        if address.is_empty() {
            return Err("contract address is empty".to_string());
        }
        // Expected prefix for the manifest's network (e.g. "SD1").
        let expected = network_prefix(&self.network)
            .ok_or_else(|| format!(
                "manifest has unknown network '{}' — cannot validate address prefix \
                 (manifest should have been constructed via DeploymentManifest::new)",
                self.network
            ))?;
        if !address.starts_with(expected) {
            return Err(format!(
                "address '{}' does not match manifest network '{}' (expected \
                 '{}' prefix) — this would let a {} manifest accumulate entries \
                 from a different chain",
                address, self.network, expected, self.network
            ));
        }
        Ok(())
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

    /// Deserialize a manifest from JSON **with full network / address
    /// validation**.
    ///
    /// Unlike raw `serde_json::from_str`, this:
    ///
    ///   1. Canonicalizes the deserialized `network` field via the
    ///      same `canonical_network` helper `Self::new` uses, so a
    ///      file that stores `"local"` is normalized to `"regtest"`
    ///      and a typo like `"mainmet"` is rejected.
    ///   2. Verifies that the deserialized `chain_id` matches the
    ///      canonical value for the canonicalized network. A file
    ///      that claims `network: "mainnet"` with
    ///      `chain_id: 0xDA0C_0002` (the testnet value) is rejected
    ///      so a tampered manifest cannot pretend to be on a network
    ///      it is not actually bound to.
    ///   3. Verifies that every `contracts[*].address` carries the
    ///      3-character prefix of the canonicalized network.
    ///
    /// The previous implementation was a bare
    /// `serde_json::from_str(json)`, so any hand-written or
    /// externally-tampered manifest could bypass all the protection
    /// `Self::new` added. The `contracts` map in particular could
    /// contain mainnet-tagged addresses on a testnet manifest, and
    /// the `chain_id` / `rpc_url` could drift arbitrarily from the
    /// `network` string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut parsed: Self = serde_json::from_str(json)
            .map_err(|e| format!("manifest JSON parse error: {}", e))?;
        parsed.validate_loaded()?;
        Ok(parsed)
    }

    /// Post-deserialization validator.
    ///
    /// Used by `from_json` / `load_from_file` to enforce the
    /// invariants listed in the `from_json` doc comment. On success,
    /// mutates `self` so that the `network` field is the canonical
    /// name (`"local"` → `"regtest"`).
    fn validate_loaded(&mut self) -> Result<(), String> {
        // (1) Canonicalize the network.
        let canonical = canonical_network(&self.network).ok_or_else(|| format!(
            "manifest has unknown network '{}': expected one of \
             mainnet, testnet, regtest (or 'local' as alias for regtest)",
            self.network
        ))?;
        self.network = canonical.to_string();

        // (2) Verify chain_id matches the canonical value for the
        //     network. A mismatched chain_id would let a file claim
        //     to be on one network while using another network's
        //     chain_id.
        let expected_chain_id = match canonical {
            "mainnet" => 0xDA0C_0001,
            "testnet" => 0xDA0C_0002,
            "regtest" => 0xDA0C_0003,
            _ => unreachable!("canonical_network returned unknown value"),
        };
        if self.chain_id != expected_chain_id {
            return Err(format!(
                "manifest chain_id mismatch: network '{}' expects chain_id \
                 0x{:08X} but file has 0x{:08X} — the manifest is not bound \
                 to the chain it claims",
                canonical, expected_chain_id, self.chain_id
            ));
        }

        // (3) Verify every contract's address carries the network
        //     prefix. We DO NOT mutate the manifest on failure —
        //     either every entry passes or the whole load is refused
        //     so a caller never ends up with a partially-validated
        //     manifest.
        for (name, contract) in &self.contracts {
            self.check_address_matches_network(&contract.address)
                .map_err(|e| format!(
                    "manifest contract '{}' has invalid address: {}",
                    name, e
                ))?;
        }

        Ok(())
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = self.to_json().map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_json(&json)
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
        }).expect("ST1c prefix matches testnet manifest");

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
        }).expect("SD1c prefix matches mainnet manifest");

        let json = m.to_json().unwrap();
        let loaded = DeploymentManifest::from_json(&json).unwrap();
        assert_eq!(loaded.network, "mainnet");
        assert_eq!(loaded.contracts.len(), 1);
        assert_eq!(loaded.chain_id, 0xDA0C_0001);
        assert_eq!(loaded.rpc_url, "http://localhost:9332");
        assert_eq!(loaded.migration_version, 0);
    }

    // ─── add_deployment network validation ──────────────────────────

    #[test]
    fn add_deployment_rejects_mainnet_address_on_testnet_manifest() {
        // Regression for the bare-insert bug. A testnet manifest
        // must NOT accumulate mainnet-tagged addresses even if a
        // caller hands them in directly.
        let mut m = DeploymentManifest::new("testnet").unwrap();
        let err = m.add_deployment(DeployedContract {
            name: "Drift".into(),
            address: "SD1c_from_mainnet".into(), // wrong network
            bytecode_hash: "hash".into(),
            deploy_height: 1,
            deploy_tx: "tx".into(),
            vm_version: 1,
            verified: false,
            deployed_at: 0,
            package_file: None,
        }).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("does not match manifest network"),
            "error must explain the prefix mismatch, got: {}", msg);
        assert!(!m.is_deployed("Drift"),
            "refused deployment must NOT be recorded");
    }

    #[test]
    fn add_deployment_rejects_empty_address() {
        let mut m = DeploymentManifest::new("mainnet").unwrap();
        let err = m.add_deployment(DeployedContract {
            name: "Empty".into(),
            address: "".into(),
            bytecode_hash: "h".into(),
            deploy_height: 0,
            deploy_tx: "tx".into(),
            vm_version: 1,
            verified: false,
            deployed_at: 0,
            package_file: None,
        }).unwrap_err();
        assert!(format!("{}", err).contains("empty"));
    }

    #[test]
    fn add_deployment_rejects_unknown_prefix() {
        let mut m = DeploymentManifest::new("mainnet").unwrap();
        let err = m.add_deployment(DeployedContract {
            name: "Wrong".into(),
            address: "BTC1foreign".into(), // not ours at all
            bytecode_hash: "h".into(),
            deploy_height: 0,
            deploy_tx: "tx".into(),
            vm_version: 1,
            verified: false,
            deployed_at: 0,
            package_file: None,
        }).unwrap_err();
        assert!(format!("{}", err).contains("does not match manifest network"));
    }

    // ─── from_json / load_from_file validation ───────────────────────

    #[test]
    fn from_json_rejects_unknown_network_in_file() {
        // A manifest file stored with a typo'd network must be
        // refused by from_json just like DeploymentManifest::new
        // refuses it directly. Previously the raw serde_json::from_str
        // would happily accept any string.
        let tampered = r#"{
            "network": "mainmet",
            "contracts": {},
            "version": 1,
            "chain_id": 0,
            "rpc_url": "http://evil.example",
            "migration_version": 0
        }"#;
        let err = DeploymentManifest::from_json(tampered).unwrap_err();
        assert!(err.contains("unknown network"),
            "from_json must refuse a typo'd network, got: {}", err);
    }

    // Canonical chain_id decimal values, for readers: these are just
    // the three hex constants used by `DeploymentManifest::new` written
    // in decimal so they can be embedded in JSON (which has no hex
    // literal syntax).
    //   0xDA0C_0001 == 3658219521 (mainnet)
    //   0xDA0C_0002 == 3658219522 (testnet)
    //   0xDA0C_0003 == 3658219523 (regtest)

    #[test]
    fn from_json_rejects_chain_id_mismatch() {
        // Regression: a file could previously claim one network but
        // use another network's chain_id. from_json must now bind the
        // two together.
        //
        // The file below claims `network: "mainnet"` but stores the
        // TESTNET chain_id (0xDA0C_0002 = 3658219522).
        let tampered = r#"{
            "network": "mainnet",
            "contracts": {},
            "version": 1,
            "chain_id": 3658219522,
            "rpc_url": "http://localhost:9332",
            "migration_version": 0
        }"#;
        let err = DeploymentManifest::from_json(tampered).unwrap_err();
        assert!(err.contains("chain_id mismatch"),
            "from_json must refuse a drifted chain_id, got: {}", err);
    }

    #[test]
    fn from_json_rejects_cross_network_contract_entry() {
        // A file claims testnet (chain_id 3658219522 = 0xDA0C_0002)
        // but has a mainnet-tagged contract address inside its
        // contracts map. from_json must refuse.
        let tampered = r#"{
            "network": "testnet",
            "contracts": {
                "Bad": {
                    "name": "Bad",
                    "address": "SD1c_leaked",
                    "bytecode_hash": "h",
                    "deploy_height": 1,
                    "deploy_tx": "tx",
                    "vm_version": 1,
                    "verified": false,
                    "deployed_at": 0,
                    "package_file": null
                }
            },
            "version": 1,
            "chain_id": 3658219522,
            "rpc_url": "http://localhost:19332",
            "migration_version": 0
        }"#;
        let err = DeploymentManifest::from_json(tampered).unwrap_err();
        assert!(err.contains("does not match manifest network")
             || err.contains("invalid address"),
            "from_json must refuse a cross-network contract entry, got: {}", err);
    }

    #[test]
    fn from_json_canonicalizes_local_to_regtest() {
        // A stored `"local"` network must be normalized to `"regtest"`
        // on load, matching `DeploymentManifest::new`'s behaviour.
        // 3658219523 = 0xDA0C_0003 (regtest chain_id).
        let stored = r#"{
            "network": "local",
            "contracts": {},
            "version": 1,
            "chain_id": 3658219523,
            "rpc_url": "http://localhost:29332",
            "migration_version": 0
        }"#;
        let loaded = DeploymentManifest::from_json(stored).unwrap();
        assert_eq!(loaded.network, "regtest",
            "from_json must canonicalize 'local' to 'regtest'");
        assert_eq!(loaded.chain_id, 0xDA0C_0003);
    }

    #[test]
    fn from_json_accepts_a_well_formed_manifest() {
        // Positive-path smoke test: a manifest produced by
        // `to_json()` and reloaded via `from_json()` round-trips
        // cleanly.
        let mut m = DeploymentManifest::new("regtest").unwrap();
        m.add_deployment(DeployedContract {
            name: "A".into(),
            address: "SR1c_abc".into(),
            bytecode_hash: "h".into(),
            deploy_height: 1,
            deploy_tx: "tx".into(),
            vm_version: 1,
            verified: false,
            deployed_at: 0,
            package_file: None,
        }).unwrap();
        let json = m.to_json().unwrap();
        let loaded = DeploymentManifest::from_json(&json).unwrap();
        assert_eq!(loaded.network, "regtest");
        assert_eq!(loaded.contracts.len(), 1);
        assert_eq!(loaded.get_address("A"), Some("SR1c_abc"));
    }
}
