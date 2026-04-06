// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::network::bootstrap_nodes::BootstrapNodes;
use crate::config::node::node_config::NetworkMode;

pub struct NetworkParams;

impl NetworkParams {
    pub const NETWORK_NAME:      &'static str = "shadowdag-mainnet";
    pub const TESTNET_NAME:      &'static str = "shadowdag-testnet";
    pub const REGTEST_NAME:      &'static str = "shadowdag-regtest";

    pub const DEFAULT_PORT:      u16 = 9333;
    pub const TESTNET_PORT:      u16 = 19333;
    pub const REGTEST_PORT:      u16 = 29333;

    pub const RPC_PORT:          u16 = 9332;
    pub const TESTNET_RPC_PORT:  u16 = 19332;
    pub const REGTEST_RPC_PORT:  u16 = 29332;

    pub const MAINNET_MAGIC:  [u8; 4] = [0x53, 0x44, 0x41, 0x47];
    pub const TESTNET_MAGIC:  [u8; 4] = [0x53, 0x44, 0x54, 0x4E];
    pub const REGTEST_MAGIC:  [u8; 4] = [0x53, 0x44, 0x52, 0x54];

    pub const MAX_PEERS:      usize = 64;
    pub const MIN_PEERS:      usize = 8;
    pub const TESTNET_MAX_PEERS: usize = 32;
    pub const REGTEST_MAX_PEERS: usize = 8;

    pub const MAX_BLOCK_SIZE:    usize = 2_000_000;
    pub const TARGET_BLOCK_TIME: u64   = 1;
    pub const GHOSTDAG_K:        u64   = 18;

    pub const PEER_TIMEOUT:      u64 = 30;
    pub const HANDSHAKE_TIMEOUT: u64 = 10;

    pub const PROTOCOL_VERSION:  u32 = 1;
    pub const MIN_PEER_VERSION:  u32 = 1;

    pub const MAINNET_PREFIX:    &'static str = "SD";
    pub const TESTNET_PREFIX:    &'static str = "ST";
    pub const REGTEST_PREFIX:    &'static str = "SR";
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub name:          &'static str,
    pub p2p_port:      u16,
    pub rpc_port:      u16,
    pub magic:         [u8; 4],
    pub max_peers:     usize,
    pub min_peers:     usize,
    pub data_subdir:   &'static str,
    pub address_prefix: &'static str,
    pub dns_seeds:     Vec<&'static str>,
    pub is_mainnet:    bool,
    pub is_testnet:    bool,
    pub is_regtest:    bool,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            name:           NetworkParams::NETWORK_NAME,
            p2p_port:       NetworkParams::DEFAULT_PORT,
            rpc_port:       NetworkParams::RPC_PORT,
            magic:          NetworkParams::MAINNET_MAGIC,
            max_peers:      NetworkParams::MAX_PEERS,
            min_peers:      NetworkParams::MIN_PEERS,
            data_subdir:    "mainnet",
            address_prefix: NetworkParams::MAINNET_PREFIX,
            dns_seeds:      BootstrapNodes::dns_seeds(&NetworkMode::Mainnet),
            is_mainnet: true,
            is_testnet: false,
            is_regtest: false,
        }
    }

    pub fn testnet() -> Self {
        Self {
            name:           NetworkParams::TESTNET_NAME,
            p2p_port:       NetworkParams::TESTNET_PORT,
            rpc_port:       NetworkParams::TESTNET_RPC_PORT,
            magic:          NetworkParams::TESTNET_MAGIC,
            max_peers:      NetworkParams::TESTNET_MAX_PEERS,
            min_peers:      4,
            data_subdir:    "testnet",
            address_prefix: NetworkParams::TESTNET_PREFIX,
            dns_seeds:      BootstrapNodes::dns_seeds(&NetworkMode::Testnet),
            is_mainnet: false,
            is_testnet: true,
            is_regtest: false,
        }
    }

    pub fn regtest() -> Self {
        Self {
            name:           NetworkParams::REGTEST_NAME,
            p2p_port:       NetworkParams::REGTEST_PORT,
            rpc_port:       NetworkParams::REGTEST_RPC_PORT,
            magic:          NetworkParams::REGTEST_MAGIC,
            max_peers:      NetworkParams::REGTEST_MAX_PEERS,
            min_peers:      1,
            data_subdir:    "regtest",
            address_prefix: NetworkParams::REGTEST_PREFIX,
            dns_seeds:      BootstrapNodes::dns_seeds(&NetworkMode::Regtest),
            is_mainnet: false,
            is_testnet: false,
            is_regtest: true,
        }
    }

    pub fn from_name(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "testnet" => Self::testnet(),
            "regtest" => Self::regtest(),
            _          => Self::mainnet(),
        }
    }

    pub fn data_dir(&self, base: &str) -> String {
        format!("{}/{}", base, self.data_subdir)
    }

    pub fn peers_db_path(&self, base: &str) -> String {
        format!("{}/{}/peers", base, self.data_subdir)
    }

    pub fn blocks_db_path(&self, base: &str) -> String {
        format!("{}/{}/blocks", base, self.data_subdir)
    }

    pub fn utxo_db_path(&self, base: &str) -> String {
        format!("{}/{}/utxo", base, self.data_subdir)
    }

    pub fn mempool_db_path(&self, base: &str) -> String {
        format!("{}/{}/mempool", base, self.data_subdir)
    }

    pub fn dag_db_path(&self, base: &str) -> String {
        format!("{}/{}/dag", base, self.data_subdir)
    }

    pub fn snapshot_db_path(&self, base: &str) -> String {
        format!("{}/{}/snapshots", base, self.data_subdir)
    }

    pub fn dsp_db_path(&self, base: &str) -> String {
        format!("{}/{}/dsp", base, self.data_subdir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_config() {
        let c = NetworkConfig::mainnet();
        assert_eq!(c.p2p_port, 9333);
        assert_eq!(c.rpc_port, 9332);
        assert!(c.is_mainnet);
        assert!(!c.is_testnet);
        assert!(!c.dns_seeds.is_empty());
    }

    #[test]
    fn testnet_config() {
        let c = NetworkConfig::testnet();
        assert_eq!(c.p2p_port, 19333);
        assert!(c.is_testnet);
    }

    #[test]
    fn regtest_has_no_seeds() {
        let c = NetworkConfig::regtest();
        // Regtest uses localhost seeds (127.0.0.1), not public DNS seeds
        for seed in &c.dns_seeds {
            assert!(seed.starts_with("127.0.0.1"),
                "Regtest seed '{}' must be localhost, not a public seed", seed);
        }
        assert!(c.is_regtest);
    }

    #[test]
    fn data_paths_are_separate() {
        let m = NetworkConfig::mainnet().data_dir("/data");
        let t = NetworkConfig::testnet().data_dir("/data");
        let r = NetworkConfig::regtest().data_dir("/data");
        assert_ne!(m, t);
        assert_ne!(t, r);
        assert_eq!(m, "/data/mainnet");
        assert_eq!(t, "/data/testnet");
        assert_eq!(r, "/data/regtest");
    }

    #[test]
    fn from_str_fallback() {
        let c = NetworkConfig::from_name("unknown");
        assert!(c.is_mainnet);
    }
}
