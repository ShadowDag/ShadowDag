// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::network::bootstrap_nodes::BootstrapNodes;
use crate::config::node::node_config::NetworkMode;

pub const DNS_LOOKUP_TIMEOUT_SECS: u64 = 10;
pub const MAX_SEEDS_PER_QUERY:     usize = 32;

pub struct BootstrapManager;

impl BootstrapManager {
    pub fn seeds_for(network: &NetworkMode) -> Vec<&'static str> {
        match network {
            NetworkMode::Mainnet => BootstrapNodes::mainnet(),
            NetworkMode::Testnet => BootstrapNodes::testnet(),
            NetworkMode::Regtest => BootstrapNodes::localhost(),
        }
    }

    pub fn bootstrap(network: &NetworkMode) -> Vec<String> {
        let seeds = Self::seeds_for(network);
        for _seed in &seeds {
        }
        seeds.iter().map(|s| s.to_string()).collect()
    }

    pub fn seed_count(network: &NetworkMode) -> usize {
        Self::seeds_for(network).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_seeds_use_port_9333() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Mainnet);
        for s in seeds { assert!(s.ends_with(":9333")); }
    }

    #[test]
    fn testnet_seeds_use_port_19333() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Testnet);
        for s in seeds { assert!(s.ends_with(":19333")); }
    }

    #[test]
    fn regtest_uses_localhost() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Regtest);
        for s in seeds { assert!(s.starts_with("127.0.0.1")); }
    }

    #[test]
    fn bootstrap_returns_non_empty() {
        let list = BootstrapManager::bootstrap(&NetworkMode::Mainnet);
        assert!(!list.is_empty());
    }
}
