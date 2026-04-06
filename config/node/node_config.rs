// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::path::PathBuf;
use serde::{Serialize, Deserialize};

/// Get user's home directory (cross-platform)
fn dirs_home() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

use crate::config::genesis::genesis::create_genesis_block_for;
use crate::config::network::bootstrap_nodes::BootstrapNodes;

pub const MAINNET_MAGIC:  [u8; 4] = [0x53, 0x44, 0x41, 0x47];
pub const TESTNET_MAGIC:  [u8; 4] = [0x53, 0x44, 0x54, 0x4e];
pub const REGTEST_MAGIC:  [u8; 4] = [0x53, 0x44, 0x52, 0x54];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Mainnet,
    Testnet,
    Regtest,
}

/// Error returned when parsing an unrecognized network mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetwork(pub String);

impl std::fmt::Display for UnknownNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown network mode '{}' (expected mainnet/testnet/regtest)", self.0)
    }
}

impl std::str::FromStr for NetworkMode {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "mainnet" | "main" => Ok(NetworkMode::Mainnet),
            "testnet" | "test" => Ok(NetworkMode::Testnet),
            "regtest" | "reg"  => Ok(NetworkMode::Regtest),
            other => Err(UnknownNetwork(other.to_string())),
        }
    }
}

impl NetworkMode {

    pub fn name(&self) -> &'static str {
        match self {
            NetworkMode::Mainnet => "shadowdag-mainnet",
            NetworkMode::Testnet => "shadowdag-testnet",
            NetworkMode::Regtest => "shadowdag-regtest",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            NetworkMode::Mainnet => "mainnet",
            NetworkMode::Testnet => "testnet",
            NetworkMode::Regtest => "regtest",
        }
    }

    pub fn p2p_port(&self) -> u16 {
        match self {
            NetworkMode::Mainnet => 9333,
            NetworkMode::Testnet => 19333,
            NetworkMode::Regtest => 29333,
        }
    }

    pub fn rpc_port(&self) -> u16 {
        match self {
            NetworkMode::Mainnet => 9332,
            NetworkMode::Testnet => 19332,
            NetworkMode::Regtest => 29332,
        }
    }

    pub fn magic(&self) -> [u8; 4] {
        match self {
            NetworkMode::Mainnet => MAINNET_MAGIC,
            NetworkMode::Testnet => TESTNET_MAGIC,
            NetworkMode::Regtest => REGTEST_MAGIC,
        }
    }

    /// Data directory — configurable via SHADOWDAG_DATA_DIR env var.
    /// Defaults to ~/.shadowdag/<network> (platform-specific home directory).
    /// NEVER uses a relative path inside the project directory.
    pub fn data_dir(&self) -> PathBuf {
        let base = Self::base_data_dir();
        match self {
            NetworkMode::Mainnet => base.join("mainnet"),
            NetworkMode::Testnet => base.join("testnet"),
            NetworkMode::Regtest => base.join("regtest"),
        }
    }

    /// Get the base data directory from environment or platform default.
    /// Priority: SHADOWDAG_DATA_DIR env > ~/.shadowdag/
    pub fn base_data_dir() -> PathBuf {
        if let Ok(custom) = std::env::var("SHADOWDAG_DATA_DIR") {
            return PathBuf::from(custom);
        }
        // Platform-specific home directory
        if let Some(home) = dirs_home() {
            return home.join(".shadowdag");
        }
        // Fallback (should not happen on any modern OS)
        PathBuf::from(".shadowdag")
    }

    pub fn blocks_path(&self)   -> PathBuf { self.data_dir().join("blocks") }
    pub fn utxo_path(&self)     -> PathBuf { self.data_dir().join("utxo") }
    pub fn peers_path(&self)    -> PathBuf { self.data_dir().join("peers") }
    pub fn mempool_path(&self)  -> PathBuf { self.data_dir().join("mempool") }
    pub fn dag_path(&self)      -> PathBuf { self.data_dir().join("dag") }
    pub fn wallet_path(&self)   -> PathBuf { self.data_dir().join("wallet") }
    pub fn snapshot_path(&self) -> PathBuf { self.data_dir().join("snapshots") }
    pub fn dsp_path(&self)      -> PathBuf { self.data_dir().join("dsp") }

    /// Returns the genesis block hash for this network by computing it
    /// from the actual genesis block definition.
    pub fn genesis_hash(&self) -> String {
        let genesis = create_genesis_block_for(self);
        genesis.header.hash
    }

    pub fn initial_difficulty(&self) -> u64 {
        match self {
            NetworkMode::Mainnet => 1_000_000,
            NetworkMode::Testnet => 1_000,
            NetworkMode::Regtest => 1,
        }
    }

    pub fn max_peers(&self) -> usize {
        match self {
            NetworkMode::Mainnet => 64,
            NetworkMode::Testnet => 32,
            NetworkMode::Regtest => 8,
        }
    }

    pub fn bootstrap_peers(&self) -> Vec<String> {
        BootstrapNodes::for_network_owned(self)
    }

    pub fn is_mainnet(&self) -> bool { *self == NetworkMode::Mainnet }
    pub fn is_testnet(&self) -> bool { *self == NetworkMode::Testnet }
    pub fn is_regtest(&self) -> bool { *self == NetworkMode::Regtest }

    pub fn init_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.blocks_path())?;
        std::fs::create_dir_all(self.utxo_path())?;
        std::fs::create_dir_all(self.peers_path())?;
        std::fs::create_dir_all(self.mempool_path())?;
        std::fs::create_dir_all(self.dag_path())?;
        std::fs::create_dir_all(self.wallet_path())?;
        std::fs::create_dir_all(self.snapshot_path())?;
        std::fs::create_dir_all(self.dsp_path())?;
        Ok(())
    }
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub network:    NetworkMode,
    pub p2p_port:   u16,
    pub rpc_port:   u16,
    pub max_peers:  usize,
    pub data_dir:   PathBuf,
    pub log_level:  String,
    pub enable_rpc: bool,
    pub enable_mining: bool,
    pub miner_addr: String,
}

impl NodeConfig {
    pub fn for_network(net: NetworkMode) -> Self {
        let p2p_port = net.p2p_port();
        let rpc_port = net.rpc_port();
        let max_peers = net.max_peers();
        let data_dir  = net.data_dir();
        Self {
            network:        net,
            p2p_port,
            rpc_port,
            max_peers,
            data_dir,
            log_level:      "info".to_string(),
            enable_rpc:     true,
            enable_mining:  false,
            miner_addr:     String::new(),
        }
    }

    pub fn from_cli_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut network = NetworkMode::Mainnet;
        let mut p2p_override = None;
        let mut rpc_override = None;
        let mut mining = false;
        let mut miner_addr = String::new();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--testnet" => { network = NetworkMode::Testnet; }
                "--regtest" => { network = NetworkMode::Regtest; }
                "--network" if i+1 < args.len() => {
                    network = args[i+1].parse().unwrap_or(NetworkMode::Mainnet);
                    i += 1;
                }
                "--port" if i+1 < args.len() => {
                    p2p_override = args[i+1].parse().ok();
                    i += 1;
                }
                "--rpcport" if i+1 < args.len() => {
                    rpc_override = args[i+1].parse().ok();
                    i += 1;
                }
                "--mine" => { mining = true; }
                "--miner-addr" if i+1 < args.len() => {
                    miner_addr = args[i+1].clone();
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }

        let mut cfg = Self::for_network(network);
        if let Some(p) = p2p_override { cfg.p2p_port  = p; }
        if let Some(r) = rpc_override { cfg.rpc_port  = r; }
        cfg.enable_mining = mining;
        cfg.miner_addr    = miner_addr;
        cfg
    }

    pub fn blocks_path(&self)   -> std::path::PathBuf { self.network.blocks_path() }
    pub fn peers_path(&self)    -> std::path::PathBuf { self.network.peers_path() }
    pub fn utxo_path(&self)     -> std::path::PathBuf { self.network.utxo_path() }
    pub fn mempool_path(&self)  -> std::path::PathBuf { self.network.mempool_path() }
    pub fn dag_path(&self)      -> std::path::PathBuf { self.network.dag_path() }
    pub fn snapshot_path(&self) -> std::path::PathBuf { self.network.snapshot_path() }
    pub fn dsp_path(&self)      -> std::path::PathBuf { self.network.dsp_path() }
    pub fn runtime_path(&self)  -> std::path::PathBuf { self.network.data_dir().join("runtime") }

    pub fn peers_path_str(&self)    -> String { self.network.peers_path().to_string_lossy().into_owned() }
    pub fn mempool_path_str(&self)  -> String { self.network.mempool_path().to_string_lossy().into_owned() }
    pub fn blocks_path_str(&self)   -> String { self.network.blocks_path().to_string_lossy().into_owned() }
    pub fn dag_path_str(&self)      -> String { self.network.dag_path().to_string_lossy().into_owned() }
    pub fn snapshot_path_str(&self) -> String { self.network.snapshot_path().to_string_lossy().into_owned() }
    pub fn dsp_path_str(&self)      -> String { self.network.dsp_path().to_string_lossy().into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn network_separation() {
        let mn = NodeConfig::for_network(NetworkMode::Mainnet);
        let tn = NodeConfig::for_network(NetworkMode::Testnet);
        let rn = NodeConfig::for_network(NetworkMode::Regtest);

        assert_ne!(mn.p2p_port, tn.p2p_port);
        assert_ne!(mn.p2p_port, rn.p2p_port);
        assert_ne!(tn.p2p_port, rn.p2p_port);

        assert_ne!(mn.data_dir, tn.data_dir);
        assert_ne!(mn.data_dir, rn.data_dir);

        assert_ne!(mn.network.magic(), tn.network.magic());
        assert_ne!(mn.network.magic(), rn.network.magic());
    }

    #[test]
    fn from_str_parsing() {
        assert_eq!(NetworkMode::from_str("testnet").unwrap(), NetworkMode::Testnet);
        assert_eq!(NetworkMode::from_str("REGTEST").unwrap(), NetworkMode::Regtest);
        assert_eq!(NetworkMode::from_str("mainnet").unwrap(), NetworkMode::Mainnet);
        // Short aliases work too
        assert_eq!(NetworkMode::from_str("main").unwrap(), NetworkMode::Mainnet);
        assert_eq!(NetworkMode::from_str("test").unwrap(), NetworkMode::Testnet);
        assert_eq!(NetworkMode::from_str("reg").unwrap(), NetworkMode::Regtest);
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(NetworkMode::from_str("unknown").is_err());
        assert!(NetworkMode::from_str("bitcoin").is_err());
        assert!(NetworkMode::from_str("").is_err());
    }

    #[test]
    fn genesis_hashes_unique() {
        let mn = NetworkMode::Mainnet.genesis_hash();
        let tn = NetworkMode::Testnet.genesis_hash();
        let rn = NetworkMode::Regtest.genesis_hash();
        assert_ne!(mn, tn);
        assert_ne!(mn, rn);
    }
}
